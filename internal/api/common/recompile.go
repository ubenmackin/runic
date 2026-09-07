package common

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"runic/internal/api/events"
	runiclog "runic/internal/common/log"
	"runic/internal/db"
	"runic/internal/engine"
)

type ChangeWorker struct {
	workCh    chan changeWork
	done      chan struct{}
	startOnce sync.Once
	stopOnce  sync.Once
	started   atomic.Bool
	sseHub    *events.SSEHub
	db        *sql.DB
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
	sseHub       *events.SSEHub
}

func NewChangeWorker(sseHub *events.SSEHub, database *sql.DB) *ChangeWorker {
	return &ChangeWorker{
		workCh: make(chan changeWork, 100),
		done:   make(chan struct{}),
		sseHub: sseHub,
		db:     database,
	}
}

// Start starts the change worker goroutine. Call once during application startup.
func (w *ChangeWorker) Start(ctx context.Context) {
	w.startOnce.Do(func() {
		w.started.Store(true)
		go func() {
			defer close(w.done)
			for {
				select {
				case <-ctx.Done():
					return
				case work, ok := <-w.workCh:
					if !ok {
						return // channel closed, exit cleanly
					}
					if work.isGroup {
						w.processGroupChange(&work)
					} else {
						w.processPeerChange(&work)
					}
				}
			}
		}()
	})
}

func (w *ChangeWorker) QueuePeerChange(ctx context.Context, peerIDs []int, changeType, changeAction string, changeID int, summary string) {
	select {
	case w.workCh <- changeWork{
		ctx: ctx, peerIDs: peerIDs,
		changeType: changeType, changeAction: changeAction, changeID: changeID, summary: summary,
		sseHub: w.sseHub,
	}:
	case <-ctx.Done():
	}
}

func (w *ChangeWorker) QueueGroupChange(ctx context.Context, compiler *engine.Compiler, groupID int, changeAction string, summary string) {
	select {
	case w.workCh <- changeWork{
		ctx: ctx, compiler: compiler, groupID: groupID,
		changeAction: changeAction, summary: summary, isGroup: true,
		sseHub: w.sseHub,
	}:
	case <-ctx.Done():
	}
}

func (w *ChangeWorker) Stop() {
	w.stopOnce.Do(func() {
		if !w.started.Load() {
			return
		}
		close(w.workCh)
		timer := time.NewTimer(10 * time.Second)
		defer timer.Stop()
		select {
		case <-w.done:
		case <-timer.C:
			runiclog.Warn("ChangeWorker.Stop() timed out after 10s")
		}
	})
}

// notifyPeers batch-queries hostnames for the given peer IDs and fans out SSE
// notifications to both agent and frontend subscribers.
func (w *ChangeWorker) notifyPeers(ctx context.Context, sseHub *events.SSEHub, peerIDs []int) {
	placeholders := make([]string, len(peerIDs))
	args := make([]any, len(peerIDs))
	for i, id := range peerIDs {
		placeholders[i] = "?"
		args[i] = id
	}
	query := fmt.Sprintf("SELECT id, hostname FROM peers WHERE id IN (%s)", strings.Join(placeholders, ","))

	hostnameMap := make(map[int]string)
	rows, err := w.db.QueryContext(ctx, query, args...)
	if err == nil {
		func() {
			defer func() {
				if err := rows.Close(); err != nil {
					runiclog.Warn("Failed to close rows", "error", err)
				}
			}()
			for rows.Next() {
				var id int
				var hostname string
				if err := rows.Scan(&id, &hostname); err == nil && hostname != "" {
					hostnameMap[id] = hostname
				}
			}
		}()
	}

	for _, peerID := range peerIDs {
		if hostname, ok := hostnameMap[peerID]; ok {
			sseHub.NotifyPendingChangeAdded("host-"+hostname, peerID)
		}
		sseHub.NotifyFrontendPendingChangeAdded(peerID)
	}
}

func (w *ChangeWorker) processPeerChange(work *changeWork) {
	select {
	case <-work.ctx.Done():
		runiclog.Warn("context canceled before processing peer change", "ctx_err", work.ctx.Err())
		return
	default:
	}

	for _, peerID := range work.peerIDs {
		if err := queueChangeForPeer(work.ctx, w.db, peerID, work.changeType, work.changeAction, work.changeID, work.summary); err != nil {
			runiclog.Error("failed to queue change", "peer_id", peerID, "error", err)
		}
	}

	if work.sseHub != nil && len(work.peerIDs) > 0 {
		w.notifyPeers(work.ctx, work.sseHub, work.peerIDs)
	}
}

// processGroupChange is invoked from the worker goroutine when a group
// changes. It walks every policy that references the group, asks the
// compiler which peers each policy affects, and queues a pending change
// per affected peer.
//
// Performance note (N+1, partial): this function still issues one
// SQL query per affected policy via the compiler's batched helper
// (GetAffectedPeersByPolicies, which currently loops
// GetAffectedPeersByPolicy internally) and one COUNT query per
// affected peer to detect duplicate pending changes. The remaining
// N+1 lives inside the engine layer; the worker side is now a single
// call to the batched helper with an honest comment in the engine
// flagging the real fix (a single "policies IN (...)" query) as
// future work. The cost is acceptable in practice because the
// worker is serial and group changes are infrequent.
func (w *ChangeWorker) processGroupChange(work *changeWork) {
	rows, err := w.db.QueryContext(work.ctx, `
	SELECT DISTINCT id FROM policies
	WHERE ((source_type = 'group' AND source_id = ?)
	OR (target_type = 'group' AND target_id = ?))
	AND enabled = 1 AND is_pending_delete = 0
	`, work.groupID, work.groupID)
	if err != nil {
		runiclog.Error("failed to find policies for group", "group_id", work.groupID, "error", err)
		return
	}

	policyIDs := make([]int, 0)
	rowErr := func() error {
		defer func() {
			if err := rows.Close(); err != nil {
				runiclog.Error("Failed to close rows", "error", err)
			}
		}()
		for rows.Next() {
			var policyID int
			if err := rows.Scan(&policyID); err != nil {
				continue
			}
			policyIDs = append(policyIDs, policyID)
		}
		return rows.Err()
	}()
	if rowErr != nil {
		runiclog.Error("failed to iterate policies for group", "group_id", work.groupID, "error", rowErr)
		return
	}

	peerSet := make(map[int]bool)
	if len(policyIDs) > 0 {
		affectedByPolicy, err := work.compiler.GetAffectedPeersByPolicies(work.ctx, policyIDs)
		if err != nil {
			runiclog.Warn("failed to get affected peers for policies", "group_id", work.groupID, "error", err)
			return
		}
		for _, affectedPeers := range affectedByPolicy {
			for _, peerID := range affectedPeers {
				peerSet[peerID] = true
			}
		}
	}

	for peerID := range peerSet {
		var count int
		err := w.db.QueryRowContext(work.ctx, `SELECT COUNT(*) FROM pending_changes WHERE peer_id = ? AND change_type = ? AND change_id = ? AND change_action = ?`, peerID, "group", work.groupID, work.changeAction).Scan(&count)
		if err != nil {
			runiclog.Error("failed to check for duplicate", "error", err)
			continue
		}
		if count > 0 {
			continue // Already queued
		}
		if err := db.AddPendingChange(work.ctx, w.db, peerID, "group", work.changeAction, work.groupID, work.summary); err != nil {
			runiclog.Error("failed to queue group change", "peer_id", peerID, "error", err)
		}
	}

	if len(peerSet) > 0 && work.sseHub != nil {
		peerIDs := make([]int, 0, len(peerSet))
		for peerID := range peerSet {
			peerIDs = append(peerIDs, peerID)
		}
		w.notifyPeers(work.ctx, work.sseHub, peerIDs)
	}
}

func queueChangeForPeer(ctx context.Context, database db.Querier, peerID int, changeType, changeAction string, changeID int, summary string) error {
	var count int
	err := database.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM pending_changes
		WHERE peer_id = ? AND change_type = ? AND change_id = ? AND change_action = ?
	`, peerID, changeType, changeID, changeAction).Scan(&count)
	if err != nil {
		return fmt.Errorf("failed to check for duplicate pending change: %w", err)
	}

	if count > 0 {
		return nil // Already queued
	}

	return db.AddPendingChange(ctx, database, peerID, changeType, changeAction, changeID, summary)
}
