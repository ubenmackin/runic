package store

import (
	"context"
	"database/sql"
	"fmt"

	ic "runic/internal/common"
	"runic/internal/db"
	"runic/internal/models"
)

// ErrConstraintViolation indicates a rollback was blocked by a constraint violation.
var ErrConstraintViolation = db.ErrConstraintViolation

// PushJob represents a push job record.
type PushJob = db.PushJob

// PushJobPeer represents a peer within a push job.
type PushJobPeer = db.PushJobPeer

// PendingStore provides data access methods for pending changes, snapshots, rollback, and push jobs.
type PendingStore struct {
	db db.DB
}

// NewPendingStore creates a new PendingStore.
func NewPendingStore(database db.DB) *PendingStore {
	return &PendingStore{db: database}
}

// GetPeersWithPendingChanges returns IDs of peers with pending changes.
// Excludes manual peers (is_manual = 1) since they cannot receive rule bundles.
func (s *PendingStore) GetPeersWithPendingChanges(ctx context.Context) ([]int, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT DISTINCT pc.peer_id FROM pending_changes pc JOIN peers p ON pc.peer_id = p.id WHERE p.is_manual = 0")
	if err != nil {
		return nil, fmt.Errorf("query peers with pending changes: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var ids []int
	for rows.Next() {
		var id int
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan peer id: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows error: %w", err)
	}
	return ic.EnsureSlice(ids), nil
}

// GetPendingChangesForPeer returns pending changes for a specific peer.
func (s *PendingStore) GetPendingChangesForPeer(ctx context.Context, peerID int) ([]models.PendingChange, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, peer_id, change_type, change_id, change_action, change_summary, created_at
		FROM pending_changes WHERE peer_id = ? ORDER BY created_at ASC`, peerID)
	if err != nil {
		return nil, fmt.Errorf("query pending changes for peer: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var changes []models.PendingChange
	for rows.Next() {
		var c models.PendingChange
		if err := rows.Scan(&c.ID, &c.PeerID, &c.ChangeType, &c.ChangeID, &c.ChangeAction, &c.ChangeSummary, &c.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan pending change: %w", err)
		}
		changes = append(changes, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows error: %w", err)
	}
	return ic.EnsureSlice(changes), nil
}

// ClearPendingChangesForPeer deletes all pending changes for a peer.
func (s *PendingStore) ClearPendingChangesForPeer(ctx context.Context, peerID int) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM pending_changes WHERE peer_id = ?", peerID)
	if err != nil {
		return fmt.Errorf("clear pending changes for peer: %w", err)
	}
	return nil
}

// SavePendingBundlePreview upserts a pending bundle preview for a peer.
func (s *PendingStore) SavePendingBundlePreview(ctx context.Context, peerID int, rulesContent, diffContent, versionHash string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO pending_bundle_previews (peer_id, rules_content, diff_content, version_hash)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(peer_id) DO UPDATE SET
		rules_content = excluded.rules_content,
		diff_content = excluded.diff_content,
		version_hash = excluded.version_hash,
		created_at = CURRENT_TIMESTAMP
		`, peerID, rulesContent, diffContent, versionHash)
	if err != nil {
		return fmt.Errorf("save pending bundle preview: %w", err)
	}
	return nil
}

// DeletePendingBundlePreview deletes the pending bundle preview for a peer.
func (s *PendingStore) DeletePendingBundlePreview(ctx context.Context, peerID int) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM pending_bundle_previews WHERE peer_id = ?", peerID)
	if err != nil {
		return fmt.Errorf("delete pending bundle preview: %w", err)
	}
	return nil
}

// DeleteAllPendingBundlePreviews deletes all pending bundle previews.
func (s *PendingStore) DeleteAllPendingBundlePreviews(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM pending_bundle_previews")
	if err != nil {
		return fmt.Errorf("delete all pending bundle previews: %w", err)
	}
	return nil
}

// DeletePendingChangeForEntity deletes a specific pending change for a peer and entity.
func (s *PendingStore) DeletePendingChangeForEntity(ctx context.Context, peerID int64, changeType string, changeID int) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM pending_changes WHERE peer_id = ? AND change_type = ? AND change_id = ?", peerID, changeType, changeID)
	if err != nil {
		return fmt.Errorf("delete pending change for entity: %w", err)
	}
	return nil
}

// CountPendingChangesForPeer counts remaining pending changes for a peer.
func (s *PendingStore) CountPendingChangesForPeer(ctx context.Context, peerID int64) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM pending_changes WHERE peer_id = ?", peerID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count pending changes for peer: %w", err)
	}
	return count, nil
}

// DeleteSnapshot deletes a change snapshot for a specific entity.
func (s *PendingStore) DeleteSnapshot(ctx context.Context, entityType string, entityID int) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM change_snapshots WHERE entity_type = ? AND entity_id = ?", entityType, entityID)
	if err != nil {
		return fmt.Errorf("delete snapshot: %w", err)
	}
	return nil
}

// ClearPendingChangesForPeerTx deletes all pending changes for a peer within a transaction.
func (s *PendingStore) ClearPendingChangesForPeerTx(ctx context.Context, tx *sql.Tx, peerID int) error {
	_, err := tx.ExecContext(ctx, "DELETE FROM pending_changes WHERE peer_id = ?", peerID)
	if err != nil {
		return fmt.Errorf("clear pending changes for peer: %w", err)
	}
	return nil
}

// DeletePendingBundlePreviewTx deletes the pending bundle preview for a peer within a transaction.
func (s *PendingStore) DeletePendingBundlePreviewTx(ctx context.Context, tx *sql.Tx, peerID int) error {
	_, err := tx.ExecContext(ctx, "DELETE FROM pending_bundle_previews WHERE peer_id = ?", peerID)
	if err != nil {
		return fmt.Errorf("delete pending bundle preview: %w", err)
	}
	return nil
}

// SavePendingBundlePreviewTx upserts a pending bundle preview for a peer within a transaction.
func (s *PendingStore) SavePendingBundlePreviewTx(ctx context.Context, tx *sql.Tx, peerID int, rulesContent, diffContent, versionHash string) error {
	_, err := tx.ExecContext(ctx,
		`INSERT INTO pending_bundle_previews (peer_id, rules_content, diff_content, version_hash)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(peer_id) DO UPDATE SET
		rules_content = excluded.rules_content,
		diff_content = excluded.diff_content,
		version_hash = excluded.version_hash,
		created_at = CURRENT_TIMESTAMP
		`, peerID, rulesContent, diffContent, versionHash)
	if err != nil {
		return fmt.Errorf("save pending bundle preview: %w", err)
	}
	return nil
}

// DeleteSnapshotTx deletes a change snapshot for a specific entity within a transaction.
func (s *PendingStore) DeleteSnapshotTx(ctx context.Context, tx *sql.Tx, entityType string, entityID int) error {
	_, err := tx.ExecContext(ctx, "DELETE FROM change_snapshots WHERE entity_type = ? AND entity_id = ?", entityType, entityID)
	if err != nil {
		return fmt.Errorf("delete snapshot: %w", err)
	}
	return nil
}

// DeletePendingChangeForEntityTx deletes a specific pending change for a peer and entity within a transaction.
func (s *PendingStore) DeletePendingChangeForEntityTx(ctx context.Context, tx *sql.Tx, peerID int64, changeType string, changeID int) error {
	_, err := tx.ExecContext(ctx, "DELETE FROM pending_changes WHERE peer_id = ? AND change_type = ? AND change_id = ?", peerID, changeType, changeID)
	if err != nil {
		return fmt.Errorf("delete pending change for entity: %w", err)
	}
	return nil
}

// CountPendingChangesForPeerTx counts remaining pending changes for a peer within a transaction.
func (s *PendingStore) CountPendingChangesForPeerTx(ctx context.Context, tx *sql.Tx, peerID int64) (int, error) {
	var count int
	err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM pending_changes WHERE peer_id = ?", peerID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count pending changes for peer: %w", err)
	}
	return count, nil
}

// RollbackSnapshots is a thin delegation to db.RollbackSnapshots.
func (s *PendingStore) RollbackSnapshots(ctx context.Context) error {
	return db.RollbackSnapshots(ctx, s.db)
}

// RollbackEntitySnapshot is a thin delegation to db.RollbackEntitySnapshot.
// Returns ErrConstraintViolation if the rollback would violate referential integrity.
func (s *PendingStore) RollbackEntitySnapshot(ctx context.Context, entityType string, entityID int) error {
	return db.RollbackEntitySnapshot(ctx, s.db, entityType, entityID)
}

// CleanupIfComplete checks if no pending changes remain and, if so, performs cleanup
// (hard deletes of soft-deleted entities and snapshot removal).
func (s *PendingStore) CleanupIfComplete(ctx context.Context) error {
	var count int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM pending_changes").Scan(&count); err != nil {
		return fmt.Errorf("count pending changes: %w", err)
	}
	if count > 0 {
		return nil
	}
	return s.cleanupAfterApplyAll(ctx)
}

// CreatePushJob creates a new push job record.
func (s *PendingStore) CreatePushJob(ctx context.Context, jobID, initiatedBy string, totalPeers int) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO push_jobs (id, initiated_by, total_peers, succeeded_count, failed_count, status)
		VALUES (?, ?, ?, 0, 0, 'pending')
	`, jobID, initiatedBy, totalPeers)
	if err != nil {
		return fmt.Errorf("create push job %s: %w", jobID, err)
	}
	return nil
}

// CreatePushJobPeers creates push job peer records within a transaction.
func (s *PendingStore) CreatePushJobPeers(ctx context.Context, jobID string, peers []struct {
	ID       int
	Hostname string
}) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin push job peers tx: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO push_job_peers (job_id, peer_id, peer_hostname, status)
		VALUES (?, ?, ?, 'pending')
	`)
	if err != nil {
		return fmt.Errorf("prepare push job peers stmt: %w", err)
	}
	defer func() { _ = stmt.Close() }()

	for _, p := range peers {
		if _, err := stmt.ExecContext(ctx, jobID, p.ID, p.Hostname); err != nil {
			return fmt.Errorf("insert push job peer %d: %w", p.ID, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit push job peers tx: %w", err)
	}
	committed = true
	return nil
}

// GetPushJob retrieves a push job by ID.
func (s *PendingStore) GetPushJob(ctx context.Context, jobID string) (PushJob, error) {
	var job PushJob
	err := s.db.QueryRowContext(ctx, `
		SELECT id, initiated_by, total_peers, succeeded_count, failed_count, status,
		COALESCE(created_at, ''), COALESCE(completed_at, '')
		FROM push_jobs WHERE id = ?
	`, jobID).Scan(&job.ID, &job.InitiatedBy, &job.TotalPeers, &job.Succeeded, &job.Failed,
		&job.Status, &job.CreatedAt, &job.CompletedAt)
	if err != nil {
		return PushJob{}, fmt.Errorf("get push job %s: %w", jobID, err)
	}
	return job, nil
}

// GetPushJobWithPeers retrieves a push job along with its peer records.
func (s *PendingStore) GetPushJobWithPeers(ctx context.Context, jobID string) (PushJob, []PushJobPeer, error) {
	job, err := s.GetPushJob(ctx, jobID)
	if err != nil {
		return PushJob{}, nil, err
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT peer_id, peer_hostname, status, COALESCE(error_message, '')
		FROM push_job_peers WHERE job_id = ?
	`, jobID)
	if err != nil {
		return PushJob{}, nil, fmt.Errorf("query push job peers for %s: %w", jobID, err)
	}
	defer func() { _ = rows.Close() }()

	var peers []PushJobPeer
	for rows.Next() {
		var p PushJobPeer
		if err := rows.Scan(&p.PeerID, &p.Hostname, &p.Status, &p.ErrorMessage); err != nil {
			return PushJob{}, nil, fmt.Errorf("scan push job peer: %w", err)
		}
		peers = append(peers, p)
	}
	if err := rows.Err(); err != nil {
		return PushJob{}, nil, fmt.Errorf("iterate push job peers: %w", err)
	}

	return job, ic.EnsureSlice(peers), nil
}

// cleanupAfterApplyAll hard deletes soft-deleted entities and clears change snapshots.
func (s *PendingStore) cleanupAfterApplyAll(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	_, err = tx.ExecContext(ctx, "DELETE FROM group_members WHERE group_id IN (SELECT id FROM groups WHERE is_pending_delete = 1)")
	if err != nil {
		return fmt.Errorf("delete soft-deleted group members: %w", err)
	}
	_, err = tx.ExecContext(ctx, "DELETE FROM groups WHERE is_pending_delete = 1")
	if err != nil {
		return fmt.Errorf("delete soft-deleted groups: %w", err)
	}
	_, err = tx.ExecContext(ctx, "DELETE FROM policies WHERE is_pending_delete = 1")
	if err != nil {
		return fmt.Errorf("delete soft-deleted policies: %w", err)
	}
	_, err = tx.ExecContext(ctx, "DELETE FROM services WHERE is_pending_delete = 1")
	if err != nil {
		return fmt.Errorf("delete soft-deleted services: %w", err)
	}

	_, err = tx.ExecContext(ctx, "DELETE FROM change_snapshots")
	if err != nil {
		return fmt.Errorf("delete snapshots: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit cleanup: %w", err)
	}
	return nil
}
