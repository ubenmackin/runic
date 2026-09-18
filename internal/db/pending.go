package db

import (
	"context"
	"fmt"

	"runic/internal/common/log"
	"runic/internal/models"
)

func AddPendingChange(ctx context.Context, database Querier, peerID int, changeType, changeAction string, changeID int, summary string) error {
	// Single-source idempotent enqueue: a single INSERT ... WHERE NOT EXISTS
	// so concurrent callers cannot create duplicate pending rows. The dedup
	// predicate (peer_id, change_type, change_id, change_action) lives here;
	// internal/change delegates via queueChangeForPeer instead of
	// duplicating the SQL.
	_, err := database.ExecContext(ctx,
		`INSERT INTO pending_changes (peer_id, change_type, change_id, change_action, change_summary)
		SELECT ?, ?, ?, ?, ?
		WHERE NOT EXISTS (
			SELECT 1 FROM pending_changes
			WHERE peer_id = ? AND change_type = ? AND change_id = ? AND change_action = ?
		)`,
		peerID, changeType, changeID, changeAction, summary, peerID, changeType, changeID, changeAction)
	return err
}

func GetPendingChangesForPeer(ctx context.Context, database Querier, peerID int) ([]models.PendingChange, error) {
	rows, err := database.QueryContext(ctx,
		`SELECT id, peer_id, change_type, change_id, change_action, change_summary, created_at
		FROM pending_changes WHERE peer_id = ? ORDER BY created_at ASC
		`, peerID)
	if err != nil {
		return nil, err
	}
	defer func() {
		if cerr := rows.Close(); cerr != nil {
			log.WarnContext(ctx, "failed to close rows", "error", cerr)
		}
	}()

	var changes []models.PendingChange
	for rows.Next() {
		var c models.PendingChange
		if err := rows.Scan(&c.ID, &c.PeerID, &c.ChangeType, &c.ChangeID, &c.ChangeAction, &c.ChangeSummary, &c.CreatedAt); err != nil {
			return nil, err
		}
		changes = append(changes, c)
	}
	return changes, rows.Err()
}

func ClearPendingChangesForPeer(ctx context.Context, database Querier, peerID int) error {
	_, err := database.ExecContext(ctx, "DELETE FROM pending_changes WHERE peer_id = ?", peerID)
	return err
}

// GetPeersWithPendingChanges returns IDs of peers with pending changes.
// Manual peers are included: pending rows are queued for every affected peer
// (including manual peers) and the Peers UI surfaces pending counts for manual
// servers so policy edits targeting them stay visible. Push delivery stays
// agent-only (see ListAgentBasedPeers and PushCurrentRules, which keep the
// is_manual=0 filter); this listing intentionally has no is_manual filter.
// The JOIN on peers excludes orphan pending rows whose peer was removed
// without cleanup, so callers only see peers that still exist.
func GetPeersWithPendingChanges(ctx context.Context, database Querier) ([]int, error) {
	rows, err := database.QueryContext(ctx, "SELECT DISTINCT pc.peer_id FROM pending_changes pc JOIN peers p ON pc.peer_id = p.id ORDER BY pc.peer_id ASC")
	if err != nil {
		return nil, err
	}
	defer func() {
		if cerr := rows.Close(); cerr != nil {
			log.WarnContext(ctx, "failed to close rows", "error", cerr)
		}
	}()

	var ids []int
	for rows.Next() {
		var id int
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan peer ID from pending_changes: %w", err)
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func SavePendingBundlePreview(ctx context.Context, database Querier, peerID int, rulesContent, diffContent, versionHash string) error {
	_, err := database.ExecContext(ctx,
		`INSERT INTO pending_bundle_previews (peer_id, rules_content, diff_content, version_hash)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(peer_id) DO UPDATE SET
		rules_content = excluded.rules_content,
		diff_content = excluded.diff_content,
		version_hash = excluded.version_hash,
		created_at = CURRENT_TIMESTAMP
		`, peerID, rulesContent, diffContent, versionHash)
	return err
}

func DeletePendingBundlePreview(ctx context.Context, database Querier, peerID int) error {
	_, err := database.ExecContext(ctx, "DELETE FROM pending_bundle_previews WHERE peer_id = ?", peerID)
	return err
}

func DeletePendingChangeForEntity(ctx context.Context, database Querier, peerID int, changeType string, changeID int) error {
	_, err := database.ExecContext(ctx, "DELETE FROM pending_changes WHERE peer_id = ? AND change_type = ? AND change_id = ?", peerID, changeType, changeID)
	return err
}

func CountPendingChangesForPeer(ctx context.Context, database Querier, peerID int) (int, error) {
	var count int
	err := database.QueryRowContext(ctx, "SELECT COUNT(*) FROM pending_changes WHERE peer_id = ?", peerID).Scan(&count)
	if err != nil {
		return 0, err
	}
	return count, nil
}

func DeleteAllPendingBundlePreviews(ctx context.Context, database Querier) error {
	_, err := database.ExecContext(ctx, "DELETE FROM pending_bundle_previews")
	if err != nil {
		return fmt.Errorf("delete all pending bundle previews: %w", err)
	}
	return nil
}
