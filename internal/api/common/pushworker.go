package common

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"

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
		if _, ok := err.(prometheus.AlreadyRegisteredError); !ok {
			runiclog.Warn("Failed to register push queue depth metric", "error", err)
		}
	}
}

type PushWorker struct {
	db           *sql.DB
	compiler     *engine.Compiler
	alertService AlertTrigger
	sseHub       interface {
		NotifyBundleUpdated(hostID string, version string) bool
		NotifyPushJobProgress(jobID string, eventType string, payload string)
	}
	workCh    chan string
	done      chan struct{}
	startOnce sync.Once
	stopOnce  sync.Once
	started   atomic.Bool
	closed    atomic.Bool
	closeMu   sync.RWMutex
}

// finalizeCtx returns a detached context for final DB writes that must
// succeed even when the job context has been canceled (shutdown or timeout).
// The detached context carries values but not cancellation, bounded by a
// short timeout so shutdown cannot hang indefinitely.
func finalizeCtx(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(parent), 15*time.Second)
}

func NewPushWorker(database *sql.DB, compiler *engine.Compiler, alertService AlertTrigger, sseHub interface {
	NotifyBundleUpdated(hostID string, version string) bool
	NotifyPushJobProgress(jobID string, eventType string, payload string)
}) *PushWorker {
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
func (w *PushWorker) Start(ctx context.Context) {
	w.startOnce.Do(func() {
		w.started.Store(true)
		go func() {
			defer close(w.done)
			for {
				select {
				case <-ctx.Done():
					return
				case jobID, ok := <-w.workCh:
					if !ok {
						return // channel closed, exit cleanly
					}
					pushQueueDepth.Set(float64(len(w.workCh)))
					w.processJob(ctx, jobID)
				}
			}
		}()
	})
}

// QueueDepth reports the current number of jobs waiting in the work queue.
func (w *PushWorker) QueueDepth() int {
	if w == nil {
		return 0
	}
	return len(w.workCh)
}

// QueueCapacity reports the maximum number of jobs the work queue can hold.
func (w *PushWorker) QueueCapacity() int {
	if w == nil {
		return 0
	}
	return cap(w.workCh)
}

// Enqueue submits a job ID to the work queue. It is non-blocking: if the queue
// is full it returns an error so callers can signal backpressure instead of
// silently dropping the job. It never panics: sends are serialized against
// Stop's close via closeMu, guarded by the closed flag, with recover as a
// final guard against a send-on-closed race.
func (w *PushWorker) Enqueue(jobID string) (err error) {
	if w == nil {
		return fmt.Errorf("enqueue push job %s: %w", jobID, ErrPushQueueFull)
	}
	if w.closed.Load() {
		return fmt.Errorf("enqueue push job %s: push worker stopped: %w", jobID, ErrPushQueueFull)
	}
	w.closeMu.RLock()
	defer w.closeMu.RUnlock()
	defer func() {
		if recover() != nil {
			runiclog.Warn("PushWorker enqueue on closed channel, dropping job", "job_id", jobID)
			err = fmt.Errorf("enqueue push job %s: push worker stopped: %w", jobID, ErrPushQueueFull)
		}
	}()
	if w.closed.Load() {
		return fmt.Errorf("enqueue push job %s: push worker stopped: %w", jobID, ErrPushQueueFull)
	}
	select {
	case w.workCh <- jobID:
		pushQueueDepth.Set(float64(len(w.workCh)))
		return nil
	default:
		runiclog.Warn("PushWorker queue full, dropping job", "job_id", jobID)
		return fmt.Errorf("enqueue push job %s: %w", jobID, ErrPushQueueFull)
	}
}

func (w *PushWorker) Stop() {
	w.stopOnce.Do(func() {
		if !w.started.Load() {
			w.closed.Store(true)
			return
		}
		w.closeMu.Lock()
		w.closed.Store(true)
		close(w.workCh)
		w.closeMu.Unlock()
		timer := time.NewTimer(30 * time.Second)
		defer timer.Stop()
		select {
		case <-w.done:
		case <-timer.C:
			runiclog.Warn("PushWorker.Stop() timed out after 30s")
		}
	})
}

// triggerAlert is a helper that fires an alert through the alert service if one is configured.
// It handles the nil check and error logging in a single place, reducing call-site duplication.
func (w *PushWorker) triggerAlert(ctx context.Context, event *models.AlertEvent) {
	if w.alertService == nil {
		return
	}
	if err := w.alertService.TriggerAlert(ctx, event); err != nil {
		runiclog.Warn("failed to trigger alert", "error", err, "alert_type", event.Type)
	}
}

func (w *PushWorker) processJob(ctx context.Context, jobID string) {
	jobCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	job, peers, err := db.GetPushJobWithPeers(jobCtx, w.db, jobID)
	if err != nil {
		runiclog.Error("PushWorker: failed to load job", "job_id", jobID, "error", err)
		return
	}

	if err := db.UpdatePushJobStatus(jobCtx, w.db, jobID, "running"); err != nil {
		runiclog.Error("PushWorker: failed to update job status to running", "job_id", jobID, "error", err)
		// Continue processing - this is non-fatal
	}

	total := len(peers)
	if total == 0 {
		fctx, fcancel := finalizeCtx(ctx)
		ferr := db.FinalizePushJob(fctx, w.db, jobID)
		fcancel()
		if ferr != nil {
			runiclog.Error("Failed to finalize push job on complete", "error", ferr)
		}
		// total_peers is canonical; total is a deprecated alias kept for
		// backward compatibility.
		w.notifyProgress(jobID, "complete", map[string]interface{}{
			"status":      "completed",
			"total_peers": 0,
			"total":       0,
			"success":     0,
			"failed":      0,
		})
		return
	}

	runiclog.Info("PushWorker: processing job", "job_id", jobID, "initiated_by", job.InitiatedBy, "total_peers", total)

	succeeded := 0
	failed := 0

	for _, peer := range peers {
		// Check context before each peer — abort on shutdown
		select {
		case <-jobCtx.Done():
			runiclog.Warn("PushWorker: job context canceled, aborting",
				"job_id", jobID, "error", jobCtx.Err())
			fctx, fcancel := finalizeCtx(ctx)
			_ = db.FinalizePushJobWithCounts(fctx, w.db, jobID, succeeded, failed)
			fcancel()
			return
		default:
		}

		w.notifyProgress(jobID, "progress", map[string]interface{}{
			"peer_id":     peer.PeerID,
			"hostname":    peer.Hostname,
			"status":      "processing",
			"total_peers": total,
			"total":       total,
			"succeeded":   succeeded,
			"failed":      failed,
		})

		bundle, err := w.compiler.CompileAndStore(jobCtx, peer.PeerID)
		if err != nil {
			failed++
			if err := db.UpdatePushJobPeerStatus(jobCtx, w.db, jobID, peer.PeerID, "failed", err.Error()); err != nil {
				runiclog.Error("Failed to update push job peer status", "error", err)
			}
			runiclog.Error("PushWorker: failed to compile for peer", "peer_id", peer.PeerID, "hostname", peer.Hostname, "error", err)
			w.notifyProgress(jobID, "peer_failed", map[string]interface{}{
				"peer_id":     peer.PeerID,
				"hostname":    peer.Hostname,
				"error":       err.Error(),
				"total_peers": total,
				"total":       total,
				"succeeded":   succeeded,
				"failed":      failed,
			})

			w.triggerAlert(jobCtx, &models.AlertEvent{
				Type:     models.AlertTypeBundleFailed,
				PeerID:   peer.PeerID,
				PeerName: peer.Hostname,
				Subject:  fmt.Sprintf("Bundle deployment failed: %s", peer.Hostname),
				Message:  err.Error(),
				Metadata: map[string]interface{}{
					"hostname": peer.Hostname,
					"job_id":   jobID,
					"error":    err.Error(),
				},
			})

			continue
		}

		// Notify peer via SSE (reuse existing infrastructure)
		delivered := w.sseHub.NotifyBundleUpdated("host-"+peer.Hostname, bundle.Version)

		if !delivered {
			failed++
			if err := db.UpdatePushJobPeerStatus(jobCtx, w.db, jobID, peer.PeerID, "failed", "SSE delivery failed: agent not connected"); err != nil {
				runiclog.Error("Failed to update push job peer status", "error", err)
			}
			runiclog.Error("PushWorker: SSE delivery failed for peer", "peer_id", peer.PeerID, "hostname", peer.Hostname)
			w.notifyProgress(jobID, "peer_failed", map[string]interface{}{
				"peer_id":     peer.PeerID,
				"hostname":    peer.Hostname,
				"error":       "SSE delivery failed: agent not connected",
				"total_peers": total,
				"total":       total,
				"succeeded":   succeeded,
				"failed":      failed,
			})

			w.triggerAlert(jobCtx, &models.AlertEvent{
				Type:     models.AlertTypeBundleFailed,
				PeerID:   peer.PeerID,
				PeerName: peer.Hostname,
				Subject:  fmt.Sprintf("Bundle delivery failed: %s", peer.Hostname),
				Message:  "SSE delivery failed: agent not connected",
				Metadata: map[string]interface{}{
					"hostname": peer.Hostname,
					"version":  bundle.Version,
					"job_id":   jobID,
				},
			})

			continue
		}

		if err := db.UpdatePushJobPeerStatus(jobCtx, w.db, jobID, peer.PeerID, "notified", ""); err != nil {
			runiclog.Error("Failed to update push job peer status", "error", err)
		}

		succeeded++
		w.notifyProgress(jobID, "peer_success", map[string]interface{}{
			"peer_id":     peer.PeerID,
			"hostname":    peer.Hostname,
			"version":     bundle.Version,
			"total_peers": total,
			"total":       total,
			"succeeded":   succeeded,
			"failed":      failed,
		})

		w.triggerAlert(jobCtx, &models.AlertEvent{
			Type:     models.AlertTypeBundleDeployed,
			PeerID:   peer.PeerID,
			PeerName: peer.Hostname,
			Subject:  fmt.Sprintf("Bundle deployed: %s", peer.Hostname),
			Metadata: map[string]interface{}{
				"hostname": peer.Hostname,
				"version":  bundle.Version,
				"job_id":   jobID,
			},
		})
	}

	// Finalize job with counts in a single atomic update. Uses a detached
	// context so the write succeeds even if the job context was canceled.
	fctx, fcancel := finalizeCtx(ctx)
	if err := db.FinalizePushJobWithCounts(fctx, w.db, jobID, succeeded, failed); err != nil {
		runiclog.Error("Failed to finalize push job with counts", "error", err)
	}
	fcancel()

	finalStatus := "completed"
	if failed > 0 {
		finalStatus = "completed_with_errors"
	}

	runiclog.Info("PushWorker: job finished", "job_id", jobID, "status", finalStatus, "total", total, "succeeded", succeeded, "failed", failed)

	w.notifyProgress(jobID, "complete", map[string]interface{}{
		"status":      finalStatus,
		"total_peers": total,
		"total":       total,
		"succeeded":   succeeded,
		"failed":      failed,
	})
}

func (w *PushWorker) notifyProgress(jobID, eventType string, payload interface{}) {
	data, err := json.Marshal(payload)
	if err != nil {
		runiclog.Error("PushWorker: failed to marshal progress payload", "error", err)
		return
	}
	w.sseHub.NotifyPushJobProgress(jobID, eventType, string(data))
}
