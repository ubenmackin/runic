package common

import (
	"context"
	"database/sql"
	"encoding/json"
	"sync"
	"sync/atomic"
	"time"

	runiclog "runic/internal/common/log"
	"runic/internal/db"
	"runic/internal/engine"
)

// PushWorker processes push-all-rules jobs in a single background goroutine.
type PushWorker struct {
	db       *sql.DB
	compiler *engine.Compiler
	sseHub   interface {
		NotifyBundleUpdated(hostID string, version string)
		NotifyPushJobProgress(jobID string, eventType string, payload string)
	}
	workCh    chan string
	done      chan struct{}
	startOnce sync.Once
	stopOnce  sync.Once
	started   atomic.Bool
}

// NewPushWorker creates a new PushWorker.
func NewPushWorker(database *sql.DB, compiler *engine.Compiler, sseHub interface {
	NotifyBundleUpdated(hostID string, version string)
	NotifyPushJobProgress(jobID string, eventType string, payload string)
}) *PushWorker {
	return &PushWorker{
		db:       database,
		compiler: compiler,
		sseHub:   sseHub,
		workCh:   make(chan string, 10),
		done:     make(chan struct{}),
	}
}

// Start launches the background worker goroutine.
// Call once during application startup.
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
					w.processJob(ctx, jobID)
				}
			}
		}()
	})
}

// Enqueue submits a job ID to the worker for processing.
func (w *PushWorker) Enqueue(jobID string) {
	select {
	case w.workCh <- jobID:
	default:
		runiclog.Warn("PushWorker queue full, dropping job", "job_id", jobID)
	}
}

// Stop waits for the worker to finish processing.
func (w *PushWorker) Stop() {
	w.stopOnce.Do(func() {
		if !w.started.Load() {
			return
		}
		close(w.workCh)
		select {
		case <-w.done:
		case <-time.After(30 * time.Second):
			runiclog.Warn("PushWorker.Stop() timed out after 30s")
		}
	})
}

// pushJobPeer represents a peer associated with a push job.
type pushJobPeer struct {
	PeerID   int
	Hostname string
}

func (w *PushWorker) processJob(ctx context.Context, jobID string) {
	// Create a per-job context with timeout to prevent indefinite hangs
	jobCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	// Load job and peers
	job, peers, err := db.GetPushJobWithPeers(jobCtx, w.db, jobID)
	if err != nil {
		runiclog.Error("PushWorker: failed to load job", "job_id", jobID, "error", err)
		return
	}

	// Transition status to 'running'
	if err := db.UpdatePushJobStatus(jobCtx, w.db, jobID, "running"); err != nil {
		runiclog.Error("PushWorker: failed to update job status to running", "job_id", jobID, "error", err)
		// Continue processing - this is non-fatal
	}

	total := len(peers)
	if total == 0 {
		db.FinalizePushJob(jobCtx, w.db, jobID)
		w.notifyProgress(jobID, "complete", map[string]interface{}{
			"status":  "completed",
			"total":   0,
			"success": 0,
			"failed":  0,
		})
		return
	}

	runiclog.Info("PushWorker: processing job", "job_id", jobID, "initiated_by", job.InitiatedBy, "total_peers", total)

	succeeded := 0
	failed := 0

	for _, peer := range peers {
		// Send progress update
		w.notifyProgress(jobID, "progress", map[string]interface{}{
			"peer_id":   peer.PeerID,
			"hostname":  peer.Hostname,
			"status":    "processing",
			"total":     total,
			"succeeded": succeeded,
			"failed":    failed,
		})

		// Compile and store bundle
		bundle, err := w.compiler.CompileAndStore(jobCtx, peer.PeerID)
		if err != nil {
			failed++
			db.UpdatePushJobPeerStatus(jobCtx, w.db, jobID, peer.PeerID, "failed", err.Error())
			runiclog.Error("PushWorker: failed to compile for peer", "peer_id", peer.PeerID, "hostname", peer.Hostname, "error", err)
			w.notifyProgress(jobID, "peer_failed", map[string]interface{}{
				"peer_id":   peer.PeerID,
				"hostname":  peer.Hostname,
				"error":     err.Error(),
				"total":     total,
				"succeeded": succeeded,
				"failed":    failed,
			})
			continue
		}

		// Notify peer via SSE (reuse existing infrastructure)
		w.sseHub.NotifyBundleUpdated("host-"+peer.Hostname, bundle.Version)

		// Update peer status
		db.UpdatePushJobPeerStatus(jobCtx, w.db, jobID, peer.PeerID, "notified", "")

		succeeded++
		w.notifyProgress(jobID, "peer_success", map[string]interface{}{
			"peer_id":   peer.PeerID,
			"hostname":  peer.Hostname,
			"version":   bundle.Version,
			"total":     total,
			"succeeded": succeeded,
			"failed":    failed,
		})
	}

	// Finalize job with counts in a single atomic update
	db.FinalizePushJobWithCounts(jobCtx, w.db, jobID, succeeded, failed)

	finalStatus := "completed"
	if failed > 0 {
		finalStatus = "completed_with_errors"
	}

	runiclog.Info("PushWorker: job finished", "job_id", jobID, "status", finalStatus, "total", total, "succeeded", succeeded, "failed", failed)

	w.notifyProgress(jobID, "complete", map[string]interface{}{
		"status":    finalStatus,
		"total":     total,
		"succeeded": succeeded,
		"failed":    failed,
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
