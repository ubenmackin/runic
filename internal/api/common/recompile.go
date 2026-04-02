package common

import (
	"context"
	"database/sql"
	"fmt"

	runiclog "runic/internal/common/log"
	"runic/internal/db"
	"runic/internal/engine"
)

// QueuePeerChanges queues pending changes for affected peers.
// Replaces AsyncRecompilePeers.
func QueuePeerChanges(database *sql.DB, peerIDs []int, changeType, changeAction string, changeID int, summary string) {
	go func() {
		ctx := context.Background()
		for _, peerID := range peerIDs {
			if err := queueChangeForPeer(ctx, database, peerID, changeType, changeAction, changeID, summary); err != nil {
				runiclog.Error("failed to queue change", "peer_id", peerID, "error", err)
			}
		}
	}()
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
// Replaces AsyncRecompileGroup.
func QueueGroupChanges(database *sql.DB, compiler *engine.Compiler, groupID int, changeAction string, summary string) {
	go func() {
		ctx := context.Background()

		// Find policies using this group
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
			// Get affected peers for this policy
			affectedPeers, _ := compiler.GetAffectedPeersByPolicy(ctx, policyID)
			for _, peerID := range affectedPeers {
				peerSet[peerID] = true
			}
		}
		if err := rows.Err(); err != nil {
			runiclog.Error("failed to iterate policies for group", "group_id", groupID, "error", err)
			return
		}

		// Queue change for each affected peer
		for peerID := range peerSet {
			if err := db.AddPendingChange(ctx, database, peerID, "group", changeAction, groupID, summary); err != nil {
				runiclog.Error("failed to queue group change", "peer_id", peerID, "error", err)
			}
		}
	}()
}
