package common

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"runic/internal/change"
	runiccommon "runic/internal/common"
	"runic/internal/common/constants"
	runiclog "runic/internal/common/log"
	"runic/internal/db"
	"runic/internal/engine"
	"runic/internal/models"
)

// AlertTrigger is an interface for triggering alert events.
// This decouples the push worker from the alerts package, avoiding import cycles.
type AlertTrigger interface {
	TriggerAlert(ctx context.Context, event *models.AlertEvent) error
}

// BundleNotifier is an alias for change.BundleNotifier so existing API
// callers keep importing internal/api/common. The definition lives in the
// low-level internal/change package (with its NotifyOutcome result type) so
// the store layer and the SSE hub share one definition without the change
// package importing the API layer.
type BundleNotifier = change.BundleNotifier

// DefaultPushWorkerQueueSize is the default buffer size for the push worker's job queue.
const DefaultPushWorkerQueueSize = 100

// ErrPushQueueFull is returned when a push job cannot be queued because the
// worker queue is full. Callers should translate it to a 503 so clients can
// retry with backoff instead of assuming the job was accepted.
var ErrPushQueueFull = errors.New("push worker queue full")

var pushQueueDepth = prometheus.NewGauge(prometheus.GaugeOpts{
	Name: "runic_push_queue_depth",
	Help: "Current depth of the push worker job queue",
})

func init() {
	if err := prometheus.Register(pushQueueDepth); err != nil {
		var already prometheus.AlreadyRegisteredError
		if !errors.As(err, &already) {
			runiclog.Warn("failed to register push queue depth metric", "error", err)
		}
	}
}

type PushWorker struct {
	db           *sql.DB
	compiler     *engine.Compiler
	alertService AlertTrigger
	sseHub       BundleNotifier
	workCh       chan string
	done         chan struct{}
	startOnce    sync.Once
	stopOnce     sync.Once
	// started and closed are plain bools guarded by closeMu. A single
	// mutex-guarded primitive pair serializes Start/Stop/Enqueue against
	// close(workCh); no atomic is needed alongside the mutex.
	started bool
	closed  bool
	closeMu sync.RWMutex
}

// FinalizeCtxWithTimeout returns a detached context for must-succeed writes
// that must survive parent cancellation, bounded by the given timeout. It is
// the shared helper for PushWorker finalizeCtx and agent heartbeatFinalizeCtx
// so the detached pattern (values without cancellation) stays in one place;
// callers parameterize the budget via constants (e.g.
// constants.DetachedFinalizeTimeout) and must request a fresh context per
// sequential operation so statements cannot starve on a shared deadline.
func FinalizeCtxWithTimeout(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	return runiccommon.DetachedTimeout(parent, timeout)
}

// finalizeCtx returns a detached context for final DB writes that must
// succeed even when the job context has been canceled (shutdown or timeout).
// The detached context carries values but not cancellation, bounded by
// constants.DetachedFinalizeTimeout so shutdown cannot hang indefinitely.
// Retry budget: each Exec can block up to 5s in busy_timeout and retries up
// to db.BusyRetryAttempts (3), so one finalize spans up to ~15s.
func finalizeCtx(parent context.Context) (context.Context, context.CancelFunc) {
	return FinalizeCtxWithTimeout(parent, constants.DetachedFinalizeTimeout)
}

func NewPushWorker(database *sql.DB, compiler *engine.Compiler, alertService AlertTrigger, sseHub BundleNotifier) *PushWorker {
	return &PushWorker{
		db:           database,
		compiler:     compiler,
		alertService: alertService,
		sseHub:       sseHub,
		workCh:       make(chan string, DefaultPushWorkerQueueSize),
		done:         make(chan struct{}),
	}
}

// Start starts the push worker goroutine. Call once during application startup.
// Single-use only: Start after Stop silently no-ops and the worker cannot be
// restarted (startOnce is consumed on the first Start). Create a new
// PushWorker to restart.
// It tolerates a zero-value PushWorker by lazily initializing the channels
// under the mutex, so Start on PushWorker{} never blocks on a nil channel.
func (w *PushWorker) Start(ctx context.Context) {
	if w == nil {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	w.startOnce.Do(func() {
		// Store started under the mutex so Stop's started check (which holds
		// the same mutex) is serialized with this store. Respect closed so a
		// prior Stop prevents launching a goroutine that would block forever.
		w.closeMu.Lock()
		if w.workCh == nil {
			w.workCh = make(chan string, DefaultPushWorkerQueueSize)
		}
		if w.done == nil {
			w.done = make(chan struct{})
		}
		if w.closed {
			w.closeMu.Unlock()
			return
		}
		if w.started {
			w.closeMu.Unlock()
			return
		}
		w.started = true
		workCh := w.workCh
		done := w.done
		w.closeMu.Unlock()
		go func() {
			defer close(done)
			for {
				select {
				case <-ctx.Done():
					// Drain buffered jobs before exiting so an
					// enqueue-then-cancel race never leaves a 202-acked job
					// buffered forever. Drained jobs run through processJob
					// (which marks terminal state via a detached context),
					// so they fail visibly instead of stalling as queued.
					// The drain uses a detached context: ctx is already Done
					// here, so passing it to processJob would instantly cancel
					// its 5-minute timeout and finalize writes.
					drainCtx := context.WithoutCancel(ctx)
					for {
						select {
						case jobID, ok := <-workCh:
							if !ok {
								return
							}
							pushQueueDepth.Set(float64(len(workCh)))
							w.processJob(drainCtx, jobID)
						default:
							return
						}
					}
				case jobID, ok := <-workCh:
					if !ok {
						return // channel closed, exit cleanly
					}
					pushQueueDepth.Set(float64(len(workCh)))
					w.processJob(ctx, jobID)
				}
			}
		}()
	})
}

// QueueDepth reports the current number of jobs waiting in the work queue.
// It tolerates a zero-value worker with a nil channel.
func (w *PushWorker) QueueDepth() int {
	if w == nil {
		return 0
	}
	w.closeMu.RLock()
	defer w.closeMu.RUnlock()
	if w.workCh == nil {
		return 0
	}
	return len(w.workCh)
}

// QueueCapacity reports the maximum number of jobs the work queue can hold.
// It tolerates a zero-value worker with a nil channel.
func (w *PushWorker) QueueCapacity() int {
	if w == nil {
		return 0
	}
	w.closeMu.RLock()
	defer w.closeMu.RUnlock()
	if w.workCh == nil {
		return 0
	}
	return cap(w.workCh)
}

// Enqueue submits a job ID to the work queue. It is non-blocking: if the queue
// is full it returns an error so callers can signal backpressure instead of
// silently dropping the job. It never panics: sends are serialized against
// Stop's close via closeMu, guarded by the closed flag, with recover as a
// final guard against a send-on-closed race. A zero-value worker with a nil
// channel fails closed with ErrPushQueueFull instead of panicking. A worker
// whose Start context was canceled has exited (done closed) without Stop
// setting closed, so Enqueue also fails closed on done-closed instead of
// buffering a job that is never processed and letting the handler ack 202.
func (w *PushWorker) Enqueue(jobID string) (err error) {
	if w == nil {
		return fmt.Errorf("enqueue push job %s: %w", jobID, ErrPushQueueFull)
	}
	w.closeMu.RLock()
	defer w.closeMu.RUnlock()
	defer func() {
		if recover() != nil {
			runiclog.Warn("pushworker: enqueue on closed channel, dropping job", "job_id", jobID)
			err = fmt.Errorf("enqueue push job %s: push worker stopped: %w", jobID, ErrPushQueueFull)
		}
	}()
	if w.closed {
		return fmt.Errorf("enqueue push job %s: push worker stopped: %w", jobID, ErrPushQueueFull)
	}
	if w.workCh == nil {
		runiclog.Warn("pushworker: enqueue on nil channel, dropping job", "job_id", jobID)
		return fmt.Errorf("enqueue push job %s: push worker stopped: %w", jobID, ErrPushQueueFull)
	}
	if w.done != nil {
		select {
		case <-w.done:
			return fmt.Errorf("enqueue push job %s: push worker stopped: %w", jobID, ErrPushQueueFull)
		default:
		}
	}
	select {
	case w.workCh <- jobID:
		pushQueueDepth.Set(float64(len(w.workCh)))
		return nil
	default:
		runiclog.Warn("pushworker: queue full, dropping job", "job_id", jobID)
		return fmt.Errorf("enqueue push job %s: %w", jobID, ErrPushQueueFull)
	}
}

func (w *PushWorker) Stop() {
	if w == nil {
		return
	}
	// Start and Stop are safe for concurrent use. The started check and the
	// close below are serialized under the same write lock (inside stopOnce)
	// so a concurrent Start cannot slip between the check and the close and
	// leak its goroutine.
	w.stopOnce.Do(func() {
		// Mark closed and close workCh under the write lock. Enqueuers hold
		// RLock across their non-blocking send, so this close cannot race
		// with a send and no recover is needed beyond the existing guard.
		// A nil workCh (zero-value worker that was marked started without
		// Start) is skipped so close(nil) never panics. When never started,
		// only mark closed so a concurrent or later Start observes it and
		// does not leak a goroutine; there is no worker to wait for.
		w.closeMu.Lock()
		if w.closed {
			w.closeMu.Unlock()
			return
		}
		if !w.started {
			w.closed = true
			w.closeMu.Unlock()
			return
		}
		w.closed = true
		if w.workCh != nil {
			close(w.workCh)
		}
		done := w.done
		w.closeMu.Unlock()
		if done == nil {
			return
		}
		timer := time.NewTimer(30 * time.Second)
		defer timer.Stop()
		select {
		case <-done:
		case <-timer.C:
			runiclog.Warn("pushworker: stop timed out after 30s")
		}
	})
}

// triggerAlert is a helper that fires an alert through the alert service if one is configured.
// It handles the nil check and error logging in a single place, reducing call-site duplication.
func (w *PushWorker) triggerAlert(ctx context.Context, event *models.AlertEvent) {
	if w == nil || w.alertService == nil || event == nil {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := w.alertService.TriggerAlert(ctx, event); err != nil {
		runiclog.Warn("failed to trigger alert", "error", err, "alert_type", event.Type)
	}
}

// processJob is the Push path worker (never clears pending).
//
// Push lifecycle: per peer CompileAndStore (advancing
// rule_bundles.version_number) + SSE NotifyBundleUpdated. This function never
// deletes pending_changes, previews, or snapshots, and never updates
// peers.bundle_version or rule_bundles.applied_at — only Apply
// (ApplyPeerPendingBundle/ApplyEntityPendingChanges/applyBundleForPeer) clears
// pending, and only ConfirmBundleApplied confirms (peers.bundle_version +
// rule_bundles.applied_at). Per-peer push_job_peers status "notified" and the
// "notified" counter mean SSE delivered, not agent-confirmed; the terminal job
// status stays "complete"/"completed_with_errors" (notified counts) and UI
// copy must render notified distinctly from confirmed. ListPeers stays
// "pending" while pending_changes > 0 and "pending_sync" while the latest
// version != bundle_version, so a Push without a prior Apply leaves the peer
// "pending" by design.
func (w *PushWorker) processJob(ctx context.Context, jobID string) {
	if ctx == nil {
		ctx = context.Background()
	}
	// NewPushWorker(db, nil, nil, hub) is constructible, so fail closed on
	// nil receiver, nil DB, nil compiler, or nil hub instead of panicking
	// on dereference (mirrors ChangeWorker.process* fail-closed behavior).
	// The failure is terminal for the job: log with the job ID and move the
	// row out of queued/running via a detached context so it never stalls
	// forever.
	if w == nil || w.db == nil || w.compiler == nil || w.sseHub == nil {
		runiclog.Error("pushworker: missing worker dependencies, failing job", "job_id", jobID)
		if w != nil && w.db != nil {
			fctx, fcancel := finalizeCtx(ctx)
			if err := db.UpdatePushJobStatus(fctx, w.db, jobID, "failed"); err != nil {
				runiclog.Error("pushworker: failed to mark job failed", "job_id", jobID, "error", err)
			}
			fcancel()
			// notified is canonical (SSE delivered, not agent-confirmed);
			// succeeded/success are deprecated aliases for notified kept for
			// backward compatibility. Terminal status stays failed here;
			// confirmed is only via ConfirmBundleApplied.
			w.notifyProgress(jobID, "complete", map[string]any{
				"status":      "failed",
				"total_peers": 0,
				"total":       0,
				"notified":    0,
				"succeeded":   0,
				"success":     0,
				"failed":      1,
			})
		}
		return
	}
	jobCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	job, peers, err := db.GetPushJobWithPeers(jobCtx, w.db, jobID)
	if err != nil {
		runiclog.Error("pushworker: failed to load job", "job_id", jobID, "error", err)
		fctx, fcancel := finalizeCtx(ctx)
		if ferr := db.UpdatePushJobStatus(fctx, w.db, jobID, "failed"); ferr != nil {
			runiclog.Error("pushworker: failed to mark job failed", "job_id", jobID, "error", ferr)
		}
		fcancel()
		w.notifyProgress(jobID, "complete", map[string]any{
			"status":      "failed",
			"total_peers": 0,
			"total":       0,
			"notified":    0,
			"succeeded":   0,
			"success":     0,
			"failed":      1,
		})
		return
	}

	if err := db.UpdatePushJobStatus(jobCtx, w.db, jobID, "running"); err != nil {
		runiclog.Error("pushworker: failed to update job status to running", "job_id", jobID, "error", err)
		// Continue processing - this is non-fatal
	}

	total := len(peers)
	if total == 0 {
		fctx, fcancel := finalizeCtx(ctx)
		ferr := db.FinalizePushJob(fctx, w.db, jobID)
		fcancel()
		if ferr != nil {
			runiclog.Error("failed to finalize push job on complete", "error", ferr)
		}
		// total_peers is canonical; total is a deprecated alias kept for
		// backward compatibility. notified is canonical (SSE delivered, not
		// agent-confirmed); succeeded/success are deprecated aliases for
		// notified kept for backward compatibility so existing SSE consumers
		// keep working.
		w.notifyProgress(jobID, "complete", map[string]any{
			"status":      "completed",
			"total_peers": 0,
			"total":       0,
			"notified":    0,
			"succeeded":   0,
			"success":     0,
			"failed":      0,
		})
		return
	}

	runiclog.Info("pushworker: processing job", "job_id", jobID, "initiated_by", job.InitiatedBy, "total_peers", total)

	// notified counts SSE-delivered peers (per-peer status "notified"), not
	// agent-confirmed peers. Confirmed happens only via ConfirmBundleApplied
	// (peers.bundle_version + rule_bundles.applied_at). The succeeded_count
	// column stores this notified count for backward compatibility.
	notified := 0
	failed := 0

	for _, peer := range peers {
		// Check context before each peer — abort on shutdown
		select {
		case <-jobCtx.Done():
			runiclog.Warn("pushworker: job context canceled, aborting",
				"job_id", jobID, "error", jobCtx.Err())
			fctx, fcancel := finalizeCtx(ctx)
			_ = db.FinalizePushJobWithCounts(fctx, w.db, jobID, notified, failed)
			fcancel()
			return
		default:
		}

		w.notifyProgress(jobID, "progress", map[string]any{
			"peer_id":     peer.PeerID,
			"hostname":    peer.Hostname,
			"status":      "processing",
			"total_peers": total,
			"total":       total,
			"notified":    notified,
			"succeeded":   notified,
			"failed":      failed,
		})

		bundle, err := w.compiler.CompileAndStore(jobCtx, peer.PeerID)
		if err != nil {
			failed++
			if err := db.UpdatePushJobPeerStatus(jobCtx, w.db, jobID, peer.PeerID, "failed", err.Error()); err != nil {
				runiclog.Error("failed to update push job peer status", "error", err)
			}
			runiclog.Error("pushworker: failed to compile for peer", "peer_id", peer.PeerID, "hostname", peer.Hostname, "error", err)
			w.notifyProgress(jobID, "peer_failed", map[string]any{
				"peer_id":     peer.PeerID,
				"hostname":    peer.Hostname,
				"error":       err.Error(),
				"total_peers": total,
				"total":       total,
				"notified":    notified,
				"succeeded":   notified,
				"failed":      failed,
			})

			w.triggerAlert(jobCtx, &models.AlertEvent{
				Type:     models.AlertTypeBundleFailed,
				PeerID:   peer.PeerID,
				PeerName: peer.Hostname,
				Subject:  fmt.Sprintf("Bundle deployment failed: %s", peer.Hostname),
				Message:  err.Error(),
				Metadata: map[string]any{
					"hostname": peer.Hostname,
					"job_id":   jobID,
					"error":    err.Error(),
				},
			})

			continue
		}

		// Notify peer via SSE (reuse existing infrastructure)
		delivered := w.sseHub.NotifyBundleUpdated("host-"+peer.Hostname, bundle.Version)

		if !delivered.Sent() {
			failed++
			if err := db.UpdatePushJobPeerStatus(jobCtx, w.db, jobID, peer.PeerID, "failed", "SSE delivery failed: agent not connected"); err != nil {
				runiclog.Error("failed to update push job peer status", "error", err)
			}
			runiclog.Error("pushworker: SSE delivery failed for peer", "peer_id", peer.PeerID, "hostname", peer.Hostname)
			w.notifyProgress(jobID, "peer_failed", map[string]any{
				"peer_id":     peer.PeerID,
				"hostname":    peer.Hostname,
				"error":       "SSE delivery failed: agent not connected",
				"total_peers": total,
				"total":       total,
				"notified":    notified,
				"succeeded":   notified,
				"failed":      failed,
			})

			w.triggerAlert(jobCtx, &models.AlertEvent{
				Type:     models.AlertTypeBundleFailed,
				PeerID:   peer.PeerID,
				PeerName: peer.Hostname,
				Subject:  fmt.Sprintf("Bundle delivery failed: %s", peer.Hostname),
				Message:  "SSE delivery failed: agent not connected",
				Metadata: map[string]any{
					"hostname": peer.Hostname,
					"version":  bundle.Version,
					"job_id":   jobID,
				},
			})

			continue
		}

		// Per-peer status "notified" means SSE delivered, not agent-confirmed.
		// Confirmed happens only via ConfirmBundleApplied (peers.bundle_version
		// + rule_bundles.applied_at). The peer_success event name and the
		// succeeded/success payload keys are deprecated aliases for notified
		// kept so existing SSE consumers keep working; new UI copy must read
		// notified and render it distinctly from confirmed.
		if err := db.UpdatePushJobPeerStatus(jobCtx, w.db, jobID, peer.PeerID, "notified", ""); err != nil {
			runiclog.Error("failed to update push job peer status", "error", err)
		}

		notified++
		w.notifyProgress(jobID, "peer_success", map[string]any{
			"peer_id":     peer.PeerID,
			"hostname":    peer.Hostname,
			"version":     bundle.Version,
			"total_peers": total,
			"total":       total,
			"notified":    notified,
			"succeeded":   notified,
			"failed":      failed,
		})

		// Notified, not confirmed: the agent has been told a new bundle
		// exists via SSE but has not yet applied it. Confirmation arrives
		// only via ConfirmBundleApplied (peers.bundle_version +
		// rule_bundles.applied_at, surfaced via AlertTypeBundleDeployed).
		// This path uses AlertTypeBundleNotified so Type-based consumers
		// (rules/digest/UI) never group or render an SSE notify as a
		// deployed/confirmed bundle.
		w.triggerAlert(jobCtx, &models.AlertEvent{
			Type:     models.AlertTypeBundleNotified,
			PeerID:   peer.PeerID,
			PeerName: peer.Hostname,
			Subject:  fmt.Sprintf("Bundle notified: %s", peer.Hostname),
			Message:  "Bundle notification sent via SSE; awaiting agent confirmation",
			Metadata: map[string]any{
				"hostname": peer.Hostname,
				"version":  bundle.Version,
				"job_id":   jobID,
			},
		})
	}

	// Finalize job with counts in a single atomic update. Uses a detached
	// context so the write succeeds even if the job context was canceled.
	// notified is stored in succeeded_count for backward compatibility; the
	// terminal status stays complete/completed_with_errors (notified counts),
	// never confirmed — confirmed is only via ConfirmBundleApplied.
	fctx, fcancel := finalizeCtx(ctx)
	if err := db.FinalizePushJobWithCounts(fctx, w.db, jobID, notified, failed); err != nil {
		runiclog.Error("failed to finalize push job with counts", "error", err)
	}
	fcancel()

	finalStatus := "completed"
	if failed > 0 {
		finalStatus = "completed_with_errors"
	}

	runiclog.Info("pushworker: job finished", "job_id", jobID, "status", finalStatus, "total", total, "notified", notified, "succeeded", notified, "failed", failed)

	w.notifyProgress(jobID, "complete", map[string]any{
		"status":      finalStatus,
		"total_peers": total,
		"total":       total,
		"notified":    notified,
		"succeeded":   notified,
		"success":     notified,
		"failed":      failed,
	})
}

func (w *PushWorker) notifyProgress(jobID, eventType string, payload any) {
	if w == nil || w.sseHub == nil {
		return
	}
	data, err := json.Marshal(payload)
	if err != nil {
		runiclog.Error("pushworker: failed to marshal progress payload", "error", err)
		return
	}
	w.sseHub.NotifyPushJobProgress(jobID, eventType, string(data))
}
