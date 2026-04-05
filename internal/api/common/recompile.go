package common

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	runiclog "runic/internal/common/log"
	"runic/internal/db"
	"runic/internal/engine"
)

// ChangeWorker processes pending change queue operations in a single background goroutine.
type ChangeWorker struct {
	workCh    chan changeWork
	done      chan struct{}
	startOnce sync.Once
	stopOnce  sync.Once
	started   atomic.Bool
}

type changeWork struct {
	ctx          context.Context
	database     *sql.DB
	peerIDs      []int
	changeType   string
	changeAction string
	changeID     int
	summary      string
	isGroup      bool
	compiler     *engine.Compiler
	groupID      int
}

// NewChangeWorker creates a new ChangeWorker.
func NewChangeWorker() *ChangeWorker {
	return &ChangeWorker{
		workCh: make(chan changeWork, 100),
		done:   make(chan struct{}),
	}
}

// Start launches the background worker goroutine.
// Call once during application startup.
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
						w.processGroupChange(work)
					} else {
						w.processPeerChange(work)
					}
				}
			}
		}()
	})
}

// QueuePeerChange submits a peer change to the worker.
func (w *ChangeWorker) QueuePeerChange(ctx context.Context, database *sql.DB, peerIDs []int, changeType, changeAction string, changeID int, summary string) {
	select {
	case w.workCh <- changeWork{
		ctx: ctx, database: database, peerIDs: peerIDs,
		changeType: changeType, changeAction: changeAction, changeID: changeID, summary: summary,
	}:
	case <-ctx.Done():
	}
}

// QueueGroupChange submits a group change to the worker.
func (w *ChangeWorker) QueueGroupChange(ctx context.Context, database *sql.DB, compiler *engine.Compiler, groupID int, changeAction string, summary string) {
	select {
	case w.workCh <- changeWork{
		ctx: ctx, database: database, compiler: compiler, groupID: groupID,
		changeAction: changeAction, summary: summary, isGroup: true,
	}:
	case <-ctx.Done():
	}
}

// Stop waits for the worker to finish processing.
func (w *ChangeWorker) Stop() {
	w.stopOnce.Do(func() {
		if !w.started.Load() {
			return
		}
		close(w.workCh)
		select {
		case <-w.done:
		case <-time.After(10 * time.Second):
			runiclog.Warn("ChangeWorker.Stop() timed out after 10s")
		}
	})
}

func (w *ChangeWorker) processPeerChange(work changeWork) {
	for _, peerID := range work.peerIDs {
		if err := queueChangeForPeer(work.ctx, work.database, peerID, work.changeType, work.changeAction, work.changeID, work.summary); err != nil {
			runiclog.Error("failed to queue change", "peer_id", peerID, "error", err)
		}
	}
}

func (w *ChangeWorker) processGroupChange(work changeWork) {
	rows, err := work.database.QueryContext(work.ctx, `
		SELECT DISTINCT id FROM policies
		WHERE ((source_type = 'group' AND source_id = ?)
		   OR (target_type = 'group' AND target_id = ?))
		   AND enabled = 1
	`, work.groupID, work.groupID)
	if err != nil {
		runiclog.Error("failed to find policies for group", "group_id", work.groupID, "error", err)
		return
	}
	defer rows.Close()

	peerSet := make(map[int]bool)
	for rows.Next() {
		var policyID int
		if err := rows.Scan(&policyID); err != nil {
			continue
		}
		affectedPeers, _ := work.compiler.GetAffectedPeersByPolicy(work.ctx, policyID)
		for _, peerID := range affectedPeers {
			peerSet[peerID] = true
		}
	}
	if err := rows.Err(); err != nil {
		runiclog.Error("failed to iterate policies for group", "group_id", work.groupID, "error", err)
		return
	}

	for peerID := range peerSet {
		if err := db.AddPendingChange(work.ctx, work.database, peerID, "group", work.changeAction, work.groupID, work.summary); err != nil {
			runiclog.Error("failed to queue group change", "peer_id", peerID, "error", err)
		}
	}
}

// QueuePeerChanges queues pending changes for affected peers.
// Deprecated: Use ChangeWorker.QueuePeerChange instead.
// This function now processes synchronously to avoid launching bare goroutines.
func QueuePeerChanges(ctx context.Context, database *sql.DB, peerIDs []int, changeType, changeAction string, changeID int, summary string) {
	for _, peerID := range peerIDs {
		if err := queueChangeForPeer(ctx, database, peerID, changeType, changeAction, changeID, summary); err != nil {
			runiclog.Error("failed to queue change", "peer_id", peerID, "error", err)
		}
	}
}

func queueChangeForPeer(ctx context.Context, database *sql.DB, peerID int, changeType, changeAction string, changeID int, summary string) error {
	// Check if this exact change is already queued (avoid duplicates)
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

// QueueGroupChanges queues changes for all peers affected by a group change.
// Deprecated: Use ChangeWorker.QueueGroupChange instead.
// This function now processes synchronously to avoid launching bare goroutines.
func QueueGroupChanges(ctx context.Context, database *sql.DB, compiler *engine.Compiler, groupID int, changeAction string, summary string) {
	rows, err := database.QueryContext(ctx, `
		SELECT DISTINCT id FROM policies
		WHERE ((source_type = 'group' AND source_id = ?)
		   OR (target_type = 'group' AND target_id = ?))
		   AND enabled = 1
	`, groupID, groupID)
	if err != nil {
		runiclog.Error("failed to find policies for group", "group_id", groupID, "error", err)
		return
	}
	defer rows.Close()

	peerSet := make(map[int]bool)
	for rows.Next() {
		var policyID int
		if err := rows.Scan(&policyID); err != nil {
			continue
		}
		affectedPeers, _ := compiler.GetAffectedPeersByPolicy(ctx, policyID)
		for _, peerID := range affectedPeers {
			peerSet[peerID] = true
		}
	}
	if err := rows.Err(); err != nil {
		runiclog.Error("failed to iterate policies for group", "group_id", groupID, "error", err)
		return
	}

	for peerID := range peerSet {
		if err := db.AddPendingChange(ctx, database, peerID, "group", changeAction, groupID, summary); err != nil {
			runiclog.Error("failed to queue group change", "peer_id", peerID, "error", err)
		}
	}
}
