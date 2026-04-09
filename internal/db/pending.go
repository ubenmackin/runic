package db

import (
	"context"
	"database/sql"
	"fmt"

	"runic/internal/common/log"
	"runic/internal/models"
)

// AddPendingChange records a change that affects a peer.
func AddPendingChange(ctx context.Context, database Querier, peerID int, changeType, changeAction string, changeID int, summary string) error {
	_, err := database.ExecContext(ctx,
		`INSERT INTO pending_changes (peer_id, change_type, change_id, change_action, change_summary)
		VALUES (?, ?, ?, ?, ?)`,
		peerID, changeType, changeID, changeAction, summary)
	return err
}

// GetPendingChangesForPeer returns all pending changes for a peer.
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

// ClearPendingChangesForPeer removes all pending changes for a peer.
func ClearPendingChangesForPeer(ctx context.Context, database Querier, peerID int) error {
	_, err := database.ExecContext(ctx, "DELETE FROM pending_changes WHERE peer_id = ?", peerID)
	return err
}

// GetPeersWithPendingChanges returns all peer IDs that have pending changes.
func GetPeersWithPendingChanges(ctx context.Context, database Querier) ([]int, error) {
	rows, err := database.QueryContext(ctx, "SELECT DISTINCT peer_id FROM pending_changes")
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
			log.WarnContext(ctx, "failed to scan peer ID", "error", err)
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// SavePendingBundlePreview stores a compiled bundle preview.
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

// GetPendingBundlePreview retrieves the pending bundle for a peer.
func GetPendingBundlePreview(ctx context.Context, database Querier, peerID int) (*models.PendingBundlePreview, error) {
	var p models.PendingBundlePreview
	err := database.QueryRowContext(ctx,
		`SELECT id, peer_id, rules_content, diff_content, version_hash, created_at
		FROM pending_bundle_previews WHERE peer_id = ?
		`, peerID).Scan(&p.ID, &p.PeerID, &p.RulesContent, &p.DiffContent, &p.VersionHash, &p.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// DeletePendingBundlePreview removes the pending bundle for a peer.
func DeletePendingBundlePreview(ctx context.Context, database Querier, peerID int) error {
	_, err := database.ExecContext(ctx, "DELETE FROM pending_bundle_previews WHERE peer_id = ?", peerID)
	return err
}

// SaveBundleTx is the transaction-based version for internal use.
// This is kept separate because SaveBundle needs transactions.
func SaveBundleTx(ctx context.Context, database *sql.DB, params models.CreateBundleParams) (models.RuleBundleRow, error) {
	tx, err := database.BeginTx(ctx, nil)
	if err != nil {
		return models.RuleBundleRow{}, err
	}
	committed := false
	defer func() {
		if !committed {
			if rErr := tx.Rollback(); rErr != nil {
				fmt.Printf("rollback failed: %v", rErr)
			}
		}
	}()

	result, err := tx.ExecContext(ctx,
		`INSERT INTO rule_bundles (peer_id, version, version_number, rules_content, hmac) VALUES (?, ?, ?, ?, ?)`,
		params.PeerID, params.Version, params.VersionNumber, params.RulesContent, params.HMAC)
	if err != nil {
		return models.RuleBundleRow{}, err
	}

	bundleID, err := result.LastInsertId()
	if err != nil {
		return models.RuleBundleRow{}, fmt.Errorf("get last insert id: %w", err)
	}

	_, err = tx.ExecContext(ctx, `UPDATE peers SET bundle_version = ? WHERE id = ?`, params.Version, params.PeerID)
	if err != nil {
		return models.RuleBundleRow{}, err
	}

	if err := tx.Commit(); err != nil {
		return models.RuleBundleRow{}, err
	}
	committed = true

	return models.RuleBundleRow{
		ID:            int(bundleID),
		PeerID:        params.PeerID,
		Version:       params.Version,
		VersionNumber: params.VersionNumber,
		RulesContent:  params.RulesContent,
		HMAC:          params.HMAC,
	}, nil
}

// DeleteAllPendingBundlePreviews removes all pending bundle previews.
func DeleteAllPendingBundlePreviews(ctx context.Context, database Querier) error {
	_, err := database.ExecContext(ctx, "DELETE FROM rule_bundles_pending")
	if err != nil {
		return fmt.Errorf("delete all pending bundle previews: %w", err)
	}
	return nil
}
