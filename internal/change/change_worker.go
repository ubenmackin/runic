package change

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	ic "runic/internal/common"
	runiclog "runic/internal/common/log"
	"runic/internal/db"
	"runic/internal/engine"
)

type ChangeWorker struct {
	workCh    chan changeWork
	done      chan struct{}
	mu        sync.RWMutex
	stopped   bool
	startOnce sync.Once
	stopOnce  sync.Once
	// started is a plain bool guarded by mu. A single mutex-guarded
	// primitive serializes Start/Stop against close(workCh); no atomic is
	// needed alongside the mutex.
	started bool
	sseHub  PendingChangeNotifier
	db      *sql.DB
}

type changeWork struct {
	ctx          context.Context
	peerIDs      []int
	changeType   string
	changeAction string
	changeID     int
	summary      string
	isGroup      bool
	compiler     *engine.Compiler
	groupID      int
	sseHub       PendingChangeNotifier
}

func NewChangeWorker(sseHub PendingChangeNotifier, database *sql.DB) *ChangeWorker {
	return &ChangeWorker{
		workCh: make(chan changeWork, 100),
		done:   make(chan struct{}),
		sseHub: sseHub,
		db:     database,
	}
}

// Start starts the change worker goroutine. Call once during application startup.
// Single-use only: Start after Stop silently no-ops and the worker cannot be
// restarted (startOnce is consumed on the first Start). Create a new
// ChangeWorker to restart.
func (w *ChangeWorker) Start(ctx context.Context) {
	if w == nil {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	w.startOnce.Do(func() {
		// Store started under the mutex so Stop's started check (which holds
		// the same mutex) is serialized with this store.
		w.mu.Lock()
		if w.workCh == nil {
			w.workCh = make(chan changeWork, 100)
		}
		if w.done == nil {
			w.done = make(chan struct{})
		}
		if w.stopped {
			w.mu.Unlock()
			return
		}
		if w.started {
			w.mu.Unlock()
			return
		}
		w.started = true
		workCh := w.workCh
		done := w.done
		w.mu.Unlock()
		process := func(work changeWork) {
			if work.isGroup {
				if err := w.processGroupChange(&work); err != nil {
					runiclog.Error("change worker failed to process group change", "group_id", work.groupID, "error", err)
				}
			} else {
				if err := w.processPeerChange(&work); err != nil {
					runiclog.Error("change worker failed to process peer change", "peer_count", len(work.peerIDs), "error", err)
				}
			}
		}
		go func() {
			defer close(done)
			for {
				select {
				case <-ctx.Done():
					// Drain buffered work before exiting so an
					// enqueue-then-cancel race never loses buffered items.
					// The drain is non-blocking: it processes what is
					// buffered and returns when the queue is empty. Stops
					// via Stop() close(workCh) are handled the same way:
					// remaining buffered items are readable with ok=true
					// until empty, then ok=false exits.
					for {
						select {
						case work, ok := <-workCh:
							if !ok {
								return
							}
							process(work)
						default:
							return
						}
					}
				case work, ok := <-workCh:
					if !ok {
						return // channel closed, exit cleanly
					}
					process(work)
				}
			}
		}()
	})
}

// isDoneClosed reports whether the worker goroutine has exited (done closed).
// Callers must hold at least RLock so the done channel value is stable; the
// select itself is non-blocking and safe on a nil channel (blocks, default
// taken, reported as not closed).
func (w *ChangeWorker) isDoneClosed(done chan struct{}) bool {
	if done == nil {
		return false
	}
	select {
	case <-done:
		return true
	default:
		return false
	}
}

func (w *ChangeWorker) QueuePeerChange(ctx context.Context, peerIDs []int, changeType, changeAction string, changeID int, summary string) error {
	if w == nil {
		return fmt.Errorf("cannot queue %s %s %d: change worker is nil", changeType, changeAction, changeID)
	}
	if w.db == nil {
		return fmt.Errorf("cannot queue %s %s %d: change worker has no database", changeType, changeAction, changeID)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	// Detach from the request context so queued work survives handler return.
	// Values are preserved but cancellation is not; the worker bounds
	// execution with its own timeout when processing.
	detached := context.WithoutCancel(ctx)
	ids := append([]int(nil), peerIDs...)
	work := changeWork{
		ctx: detached, peerIDs: ids,
		changeType: changeType, changeAction: changeAction, changeID: changeID, summary: summary,
		sseHub: w.sseHub,
	}
	// Hold RLock across the non-blocking send so Stop (which takes the write
	// lock to set stopped and close workCh) cannot race with the send. No
	// timer is used: the enqueue never parks the request goroutine, and no
	// recover is needed because send-on-closed cannot happen under the lock.
	// The pending signal is DB-driven, so a full or stopped queue must not
	// ack success with zero pending_changes rows. Fall back to synchronous
	// processing (same processPeerChange the worker would run) so the DB
	// rows still land; the lock is released before the fallback so the
	// synchronous DB work does not hold the read lock. The fallback error is
	// returned so callers fail the request instead of acking success with a
	// lost signal. A nil return means the work was accepted for background
	// processing; background worker failures after a successful enqueue are
	// logged by the worker loop and require manual recompile.
	//
	// Durability: a worker whose Start context was canceled has exited
	// (done closed) without Stop setting stopped, so the stopped check alone
	// would still buffer into a workCh that is never drained. Detect that
	// case (never started or done closed) and fall back to synchronous
	// processing so handlers never ack 2xx with zero rows.
	w.mu.RLock()
	if w.stopped {
		w.mu.RUnlock()
		runiclog.Warn("changeworker: stopped, processing peer change synchronously", "peer_ids", ids, "change_type", changeType, "change_action", changeAction, "change_id", changeID)
		return w.processPeerChange(&work)
	}
	if w.workCh == nil {
		w.mu.RUnlock()
		runiclog.Warn("changeworker: enqueue on nil channel, processing peer change synchronously", "peer_ids", ids, "change_type", changeType, "change_action", changeAction, "change_id", changeID)
		return w.processPeerChange(&work)
	}
	if !w.started {
		w.mu.RUnlock()
		runiclog.Warn("changeworker: never started, processing peer change synchronously", "peer_ids", ids, "change_type", changeType, "change_action", changeAction, "change_id", changeID)
		return w.processPeerChange(&work)
	}
	if w.isDoneClosed(w.done) {
		w.mu.RUnlock()
		runiclog.Warn("changeworker: worker exited, processing peer change synchronously", "peer_ids", ids, "change_type", changeType, "change_action", changeAction, "change_id", changeID)
		return w.processPeerChange(&work)
	}
	// Non-blocking enqueue so a burst of policy/group edits cannot park HTTP
	// handlers. Note: no <-done case here. With a default clause the done branch would
	// be starved/random, logging "stopped" vs "queue full" nondeterministically
	// when done is closed and the queue is full. Stopped detection stays solely
	// on the RLock+stopped/done checks above, under which send-on-closed is impossible.
	// No post-send liveness re-check: a successful send transfers ownership to
	// the worker drain. Running the work synchronously after a successful send
	// would duplicate the INSERT and emit a double SSE signal.
	workCh := w.workCh
	select {
	case workCh <- work:
		w.mu.RUnlock()
		return nil
	default:
		w.mu.RUnlock()
		runiclog.Warn("changeworker: queue full, processing peer change synchronously", "peer_ids", ids, "change_type", changeType, "change_action", changeAction, "change_id", changeID)
		return w.processPeerChange(&work)
	}
}

func (w *ChangeWorker) QueueGroupChange(ctx context.Context, compiler *engine.Compiler, groupID int, changeAction string, summary string) error {
	if w == nil {
		return fmt.Errorf("cannot queue group %d %s: change worker is nil", groupID, changeAction)
	}
	if compiler == nil {
		return fmt.Errorf("cannot queue group %d %s: compiler is nil", groupID, changeAction)
	}
	if w.db == nil {
		return fmt.Errorf("cannot queue group %d %s: change worker has no database", groupID, changeAction)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	// Detach from the request context so queued work survives handler return.
	detached := context.WithoutCancel(ctx)
	work := changeWork{
		ctx: detached, compiler: compiler, groupID: groupID,
		changeAction: changeAction, summary: summary, isGroup: true,
		sseHub: w.sseHub,
	}
	// Hold RLock across the non-blocking send so Stop cannot race with the
	// send. No timer is used and no recover is needed; see QueuePeerChange.
	// DB-driven pending signal: fall back to synchronous processing when the
	// queue cannot accept the work so handlers never ack success with zero
	// pending_changes rows. The lock is released before the fallback. The
	// fallback error is returned so callers fail the request; nil means the
	// work was accepted for background processing (see QueuePeerChange for
	// the background-failure contract). Like QueuePeerChange, a never-started
	// or exited (done closed) worker falls back synchronously for durability.
	w.mu.RLock()
	if w.stopped {
		w.mu.RUnlock()
		runiclog.Warn("changeworker: stopped, processing group change synchronously", "group_id", groupID, "change_action", changeAction)
		return w.processGroupChange(&work)
	}
	if w.workCh == nil {
		w.mu.RUnlock()
		runiclog.Warn("changeworker: enqueue on nil channel, processing group change synchronously", "group_id", groupID, "change_action", changeAction)
		return w.processGroupChange(&work)
	}
	if !w.started {
		w.mu.RUnlock()
		runiclog.Warn("changeworker: never started, processing group change synchronously", "group_id", groupID, "change_action", changeAction)
		return w.processGroupChange(&work)
	}
	if w.isDoneClosed(w.done) {
		w.mu.RUnlock()
		runiclog.Warn("changeworker: worker exited, processing group change synchronously", "group_id", groupID, "change_action", changeAction)
		return w.processGroupChange(&work)
	}
	// Non-blocking enqueue so bursts cannot park HTTP handlers. No <-done
	// case: with default the done branch would be starved/random (see
	// QueuePeerChange); stopped detection stays on the RLock+stopped/done checks.
	// No post-send re-check (see QueuePeerChange): a successful send transfers
	// ownership to the worker drain and must not also run synchronously.
	workCh := w.workCh
	select {
	case workCh <- work:
		w.mu.RUnlock()
		return nil
	default:
		w.mu.RUnlock()
		runiclog.Warn("changeworker: queue full, processing group change synchronously", "group_id", groupID, "change_action", changeAction)
		return w.processGroupChange(&work)
	}
}

func (w *ChangeWorker) Stop() {
	if w == nil {
		return
	}
	// Start and Stop are safe for concurrent use. The started check and the
	// close below are serialized under the same write lock (inside stopOnce)
	// so a concurrent Start cannot slip between the check and the close and
	// leak its goroutine.
	w.stopOnce.Do(func() {
		// Mark stopped and close workCh under the write lock. Queuers hold
		// RLock across their non-blocking send, so this close cannot race
		// with a send and no recover is needed. A nil workCh (zero-value
		// worker) is skipped so close(nil) never panics. When never started,
		// only mark stopped so a concurrent or later Start observes it and
		// does not leak a goroutine; there is no worker to wait for.
		w.mu.Lock()
		if w.stopped {
			w.mu.Unlock()
			return
		}
		if !w.started {
			w.stopped = true
			w.mu.Unlock()
			return
		}
		w.stopped = true
		if w.workCh != nil {
			close(w.workCh)
		}
		done := w.done
		w.mu.Unlock()
		if done == nil {
			return
		}
		timer := time.NewTimer(10 * time.Second)
		defer timer.Stop()
		select {
		case <-done:
		case <-timer.C:
			runiclog.Warn("changeworker: stop timed out after 10s")
		}
	})
}

// notifyPeers batch-queries hostnames for the given peer IDs and fans out SSE
// notifications to both agent and frontend subscribers.
func (w *ChangeWorker) notifyPeers(ctx context.Context, sseHub PendingChangeNotifier, peerIDs []int) error {
	// NewChangeWorker(nil, nil) is constructible, so fail closed on nil
	// receiver, nil DB, or nil hub with an error instead of returning nil,
	// which callers would treat as SSE success.
	if w == nil {
		return fmt.Errorf("notify peers: change worker is nil")
	}
	if w.db == nil {
		return fmt.Errorf("notify peers: database is nil")
	}
	if sseHub == nil {
		return fmt.Errorf("notify peers: SSE hub is nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	// Fail closed on empty input: "WHERE id IN ()" is a syntax error.
	if len(peerIDs) == 0 {
		return nil
	}
	// Chunk the IN query so a large fan-out never exceeds the SQLite
	// 999-variable limit (500 IDs per batch leaves headroom).
	const notifyBatchSize = 500
	hostnameMap := make(map[int]string)
	for start := 0; start < len(peerIDs); start += notifyBatchSize {
		end := start + notifyBatchSize
		if end > len(peerIDs) {
			end = len(peerIDs)
		}
		batch := peerIDs[start:end]
		placeholders := make([]string, len(batch))
		args := make([]any, len(batch))
		for i, id := range batch {
			placeholders[i] = "?"
			args[i] = id
		}
		query := fmt.Sprintf("SELECT id, hostname FROM peers WHERE id IN (%s)", strings.Join(placeholders, ","))

		rows, err := w.db.QueryContext(ctx, query, args...)
		if err != nil {
			return fmt.Errorf("query peer hostnames for notify: %w", err)
		}
		// Fail-fast row-scan contract: a single corrupt row aborts the
		// lookup with an error instead of being skipped, so one bad row
		// can never silently drop peers from SSE fan-out.
		scanErr := func() error {
			defer func() {
				if err := rows.Close(); err != nil {
					runiclog.Warn("failed to close rows", "error", err)
				}
			}()
			for rows.Next() {
				var id int
				var hostname string
				if err := rows.Scan(&id, &hostname); err != nil {
					return fmt.Errorf("scan peer hostname for notify: %w", err)
				}
				if hostname != "" {
					hostnameMap[id] = hostname
				}
			}
			if err := rows.Err(); err != nil {
				return fmt.Errorf("iterate peer hostnames for notify: %w", err)
			}
			return nil
		}()
		if scanErr != nil {
			return scanErr
		}
	}

	// Fan out only to verified rows. Peers missing from hostnameMap were not
	// returned by the hostname query (deleted or unknown IDs); signaling
	// them would notify frontend subscribers about unverified peers.
	for _, peerID := range peerIDs {
		hostname, ok := hostnameMap[peerID]
		if !ok {
			continue
		}
		sseHub.NotifyPendingChangeAdded("host-"+hostname, peerID)
		sseHub.NotifyFrontendPendingChangeAdded(peerID)
	}
	return nil
}

func (w *ChangeWorker) processPeerChange(work *changeWork) error {
	// work.ctx was detached from the request at enqueue time, so valid work is
	// never dropped here after handler return. Each DB operation gets its own
	// timeout instead of one timeout bounding the whole fan-out, so a large
	// peer set cannot expire mid-loop and leave half-queued peers with no
	// retry. queueChangeForPeer is idempotent (single INSERT ... WHERE NOT
	// EXISTS), so a per-peer timeout failure only skips that peer's attempt.
	// Per-peer failures are joined and returned (callers log or fail the
	// request) instead of only being logged, so a synchronous fallback never
	// acks success with a lost signal.
	// Fail closed on nil receiver, nil DB, or nil work instead of panicking
	// on dereference (mirrors notifyPeers and processGroupChange).
	if work == nil {
		return fmt.Errorf("cannot process peer change: work is nil")
	}
	if w == nil || w.db == nil {
		return fmt.Errorf("peer change missing worker or db, dropping change with %d peers", len(work.peerIDs))
	}
	base := work.ctx
	if base == nil {
		base = context.Background()
	}

	var errs error
	var succeededPeerIDs []int
	for _, peerID := range work.peerIDs {
		opCtx, cancel := context.WithTimeout(base, 5*time.Second)
		err := queueChangeForPeer(opCtx, w.db, peerID, work.changeType, work.changeAction, work.changeID, work.summary)
		cancel()
		if err != nil {
			errs = errors.Join(errs, fmt.Errorf("peer %d: %w", peerID, err))
			continue
		}
		succeededPeerIDs = append(succeededPeerIDs, peerID)
	}

	// Notify only successfully-inserted peers: a per-peer INSERT failure
	// must not fan out SSE for a peer with no pending_changes row.
	if work.sseHub != nil && len(succeededPeerIDs) > 0 {
		notifyCtx, cancel := context.WithTimeout(base, 5*time.Second)
		if err := w.notifyPeers(notifyCtx, work.sseHub, succeededPeerIDs); err != nil {
			runiclog.Error("failed to notify peers for peer change", "error", err, "peer_count", len(succeededPeerIDs))
		}
		cancel()
	}
	return errs
}

// processGroupChange is invoked from the worker goroutine when a group
// changes. It walks every policy that references the group, asks the
// compiler which peers each policy affects, and queues a pending change
// per affected peer.
//
// Performance note (N+1, partial): this function still issues one
// SQL query per affected policy via the compiler's batched helper
// (GetAffectedPeersByPolicies, which currently loops
// GetAffectedPeersByPolicy internally) and one idempotent INSERT per
// affected peer via the shared queueChangeForPeer helper. The remaining
// N+1 lives inside the engine layer; the worker side is now a single
// call to the batched helper with an honest comment in the engine
// flagging the real fix (a single "policies IN (...)" query) as
// future work. The cost is acceptable in practice because the
// worker is serial and group changes are infrequent.
func (w *ChangeWorker) processGroupChange(work *changeWork) error {
	// work.ctx was detached from the request at enqueue time so group work
	// survives handler return. Each stage gets its own timeout instead of one
	// timeout bounding the whole fan-out (N compiler queries plus per-peer
	// idempotent inserts plus hostname lookup), so a large group cannot expire
	// mid-loop and leave half-queued peers. All writes are idempotent
	// (single-statement INSERT ... WHERE NOT EXISTS via queueChangeForPeer),
	// so a retry simply skips rows that already exist. Every drop below
	// returns an error (callers log or fail the request) instead of only
	// logging, so a synchronous fallback never acks success with zero fan-out
	// and a lost DB pending signal.
	// Fail closed on nil receiver or nil DB instead of panicking on
	// w.db.QueryContext (mirrors notifyPeers).
	if w == nil || w.db == nil {
		groupID := 0
		if work != nil {
			groupID = work.groupID
		}
		return fmt.Errorf("group change missing worker or db, dropping change for group %d", groupID)
	}
	if work == nil || work.compiler == nil {
		groupID := 0
		if work != nil {
			groupID = work.groupID
		}
		return fmt.Errorf("group change missing compiler, dropping change for group %d", groupID)
	}
	base := work.ctx
	if base == nil {
		base = context.Background()
	}

	// Verify the group exists before querying its policies, mirroring
	// Compiler.GetAffectedPeersByPolicy's groupExists→sql.ErrNoRows contract.
	// The check omits the is_pending_delete filter so a legitimate delete
	// (soft-deleted then queued with zero referencing policies and zero
	// fan-out) succeeds instead of surfacing a spurious sql.ErrNoRows. A
	// missing group must not yield silent success with zero fan-out.
	existsCtx, existsCancel := context.WithTimeout(base, 5*time.Second)
	var existsID int
	existsErr := w.db.QueryRowContext(existsCtx, "SELECT id FROM groups WHERE id = ?", work.groupID).Scan(&existsID)
	existsCancel()
	if existsErr != nil {
		if errors.Is(existsErr, sql.ErrNoRows) {
			return fmt.Errorf("group %d not found for group change, dropping change: %w", work.groupID, sql.ErrNoRows)
		}
		return fmt.Errorf("verify group %d for group change: %w", work.groupID, existsErr)
	}

	policyCtx, cancel := context.WithTimeout(base, 5*time.Second)
	policyIDs, err := work.compiler.FindPoliciesByGroup(policyCtx, work.groupID)
	cancel()
	if err != nil {
		return fmt.Errorf("find policies for group %d: %w", work.groupID, err)
	}

	peerSlices := make([][]int, 0, len(policyIDs))
	var resolveErr error
	if len(policyIDs) > 0 {
		compilerCtx, compilerCancel := context.WithTimeout(base, 10*time.Second)
		affectedByPolicy, err := work.compiler.GetAffectedPeersByPolicies(compilerCtx, policyIDs)
		compilerCancel()
		if err != nil {
			// GetAffectedPeersByPolicies returns partial results alongside
			// the aggregated error, so merge what resolved instead of
			// dropping all peers because of one bad policy.
			runiclog.Warn("failed to get affected peers for policies", "group_id", work.groupID, "error", err)
			resolveErr = err
		}
		for _, affectedPeers := range affectedByPolicy {
			peerSlices = append(peerSlices, affectedPeers)
		}
	}

	// Shared MergePeerIDs from the leaf common package so map-dedup+sort
	// lives in one place for the engine and the change worker alike.
	peerIDs := ic.MergePeerIDs(peerSlices...)
	// Never silently succeed with zero fan-out when resolution failed: an
	// all-fail compiler resolution would otherwise lose the DB pending
	// signal with zero INSERTs and zero SSE (mirrors
	// RecompilePeersForGroup's fail-fast on this case). A legitimate
	// empty-group resolution (nil error, zero peers) succeeds with zero
	// fan-out below instead of erroring.
	if len(policyIDs) > 0 && len(peerIDs) == 0 && resolveErr != nil {
		return fmt.Errorf("no peers resolved for group %d with %d policies, dropping change: %w", work.groupID, len(policyIDs), resolveErr)
	}

	// Single shared helper for the idempotent enqueue so the peer and group
	// paths cannot diverge. queueChangeForPeer is a single atomic
	// INSERT ... WHERE NOT EXISTS statement (no racy COUNT then INSERT N+1).
	// Per-peer insert failures are joined and returned so a synchronous
	// fallback fails the request instead of acking partial success as full.
	var insertErrs error
	var succeededPeerIDs []int
	for _, peerID := range peerIDs {
		opCtx, opCancel := context.WithTimeout(base, 5*time.Second)
		if err := queueChangeForPeer(opCtx, w.db, peerID, "group", work.changeAction, work.groupID, work.summary); err != nil {
			insertErrs = errors.Join(insertErrs, fmt.Errorf("peer %d: %w", peerID, err))
		} else {
			succeededPeerIDs = append(succeededPeerIDs, peerID)
		}
		opCancel()
	}

	// Notify only successfully-inserted peers: a per-peer INSERT failure
	// must not fan out SSE for a peer with no pending_changes row.
	if len(succeededPeerIDs) > 0 && work.sseHub != nil {
		notifyCtx, notifyCancel := context.WithTimeout(base, 5*time.Second)
		if err := w.notifyPeers(notifyCtx, work.sseHub, succeededPeerIDs); err != nil {
			runiclog.Error("failed to notify peers for group change", "error", err, "group_id", work.groupID, "peer_count", len(succeededPeerIDs))
		}
		notifyCancel()
	}
	// Report partial resolution failures after queueing and notifying the
	// resolved peers so callers never see silent success with missing
	// fan-out (mirrors RecompileAffectedPeers and queueServiceChange).
	if insertErrs != nil && resolveErr != nil {
		return errors.Join(
			fmt.Errorf("queue group %d change: %w", work.groupID, insertErrs),
			fmt.Errorf("get affected peers for group %d: %w", work.groupID, resolveErr),
		)
	}
	if insertErrs != nil {
		return fmt.Errorf("queue group %d change: %w", work.groupID, insertErrs)
	}
	if resolveErr != nil {
		return fmt.Errorf("get affected peers for group %d: %w", work.groupID, resolveErr)
	}
	return nil
}

func queueChangeForPeer(ctx context.Context, database db.Querier, peerID int, changeType, changeAction string, changeID int, summary string) error {
	// Guard direct calls with nil context or nil database; worker paths
	// always supply both, but a nil deref here would panic on ExecContext.
	if ctx == nil {
		ctx = context.Background()
	}
	if database == nil {
		return fmt.Errorf("failed to queue pending change: database is nil")
	}
	// Single-source idempotent enqueue: delegate to db.AddPendingChange so
	// the dedup predicate (peer_id, change_type, change_id, change_action)
	// lives in exactly one place (internal/db). The shared helper is a
	// single atomic INSERT ... WHERE NOT EXISTS statement (no racy COUNT
	// then INSERT N+1). Shared by the peer-change and group-change paths.
	if err := db.AddPendingChange(ctx, database, peerID, changeType, changeAction, changeID, summary); err != nil {
		return fmt.Errorf("failed to queue pending change: %w", err)
	}
	return nil
}
