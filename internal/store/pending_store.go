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
// It delegates to db.GetPeersWithPendingChanges so the pending-peers query
// lives in exactly one place. Manual peers are included (see the db helper
// for the orphan-exclusion and is_manual rationale); push delivery stays
// agent-only (see ListAgentBasedPeers and PushCurrentRules).
func (s *PendingStore) GetPeersWithPendingChanges(ctx context.Context) ([]int, error) {
	ids, err := db.GetPeersWithPendingChanges(ctx, s.db)
	if err != nil {
		return nil, fmt.Errorf("query peers with pending changes: %w", err)
	}
	return ic.EnsureSlice(ids), nil
}

// GetPendingChangesForPeer returns pending changes for a specific peer.
// It delegates to db.GetPendingChangesForPeer so the pending-changes query
// lives in exactly one place.
func (s *PendingStore) GetPendingChangesForPeer(ctx context.Context, peerID int) ([]models.PendingChange, error) {
	changes, err := db.GetPendingChangesForPeer(ctx, s.db, peerID)
	if err != nil {
		return nil, fmt.Errorf("query pending changes for peer: %w", err)
	}
	return ic.EnsureSlice(changes), nil
}

// ClearPendingChangesForPeer deletes all pending changes for a peer.
// It delegates to db.ClearPendingChangesForPeer so the delete lives in
// exactly one place.
func (s *PendingStore) ClearPendingChangesForPeer(ctx context.Context, peerID int) error {
	if err := db.ClearPendingChangesForPeer(ctx, s.db, peerID); err != nil {
		return fmt.Errorf("clear pending changes for peer: %w", err)
	}
	return nil
}

// SavePendingBundlePreview upserts a pending bundle preview for a peer.
// It delegates to db.SavePendingBundlePreview so the upsert lives in
// exactly one place.
func (s *PendingStore) SavePendingBundlePreview(ctx context.Context, peerID int, rulesContent, diffContent, versionHash string) error {
	if err := db.SavePendingBundlePreview(ctx, s.db, peerID, rulesContent, diffContent, versionHash); err != nil {
		return fmt.Errorf("save pending bundle preview: %w", err)
	}
	return nil
}

// DeletePendingBundlePreview deletes the pending bundle preview for a peer.
// It delegates to db.DeletePendingBundlePreview so the delete lives in
// exactly one place.
func (s *PendingStore) DeletePendingBundlePreview(ctx context.Context, peerID int) error {
	if err := db.DeletePendingBundlePreview(ctx, s.db, peerID); err != nil {
		return fmt.Errorf("delete pending bundle preview: %w", err)
	}
	return nil
}

// DeleteAllPendingBundlePreviews deletes all pending bundle previews.
// It delegates to db.DeleteAllPendingBundlePreviews so the delete lives in
// exactly one place.
func (s *PendingStore) DeleteAllPendingBundlePreviews(ctx context.Context) error {
	if err := db.DeleteAllPendingBundlePreviews(ctx, s.db); err != nil {
		return fmt.Errorf("delete all pending bundle previews: %w", err)
	}
	return nil
}

// DeletePendingChangeForEntity deletes a specific pending change for a peer and entity.
// It delegates to db.DeletePendingChangeForEntity so the delete lives in
// exactly one place.
func (s *PendingStore) DeletePendingChangeForEntity(ctx context.Context, peerID int64, changeType string, changeID int) error {
	if err := db.DeletePendingChangeForEntity(ctx, s.db, int(peerID), changeType, changeID); err != nil {
		return fmt.Errorf("delete pending change for entity: %w", err)
	}
	return nil
}

// CountPendingChangesForPeer counts remaining pending changes for a peer.
// It delegates to db.CountPendingChangesForPeer so the count query lives in
// exactly one place.
func (s *PendingStore) CountPendingChangesForPeer(ctx context.Context, peerID int64) (int, error) {
	count, err := db.CountPendingChangesForPeer(ctx, s.db, int(peerID))
	if err != nil {
		return 0, fmt.Errorf("count pending changes for peer: %w", err)
	}
	return count, nil
}

// DeleteSnapshot deletes a change snapshot for a specific entity.
// It delegates to db.DeleteSnapshot so the delete lives in exactly one place.
func (s *PendingStore) DeleteSnapshot(ctx context.Context, entityType string, entityID int) error {
	if err := db.DeleteSnapshot(ctx, s.db, entityType, entityID); err != nil {
		return fmt.Errorf("delete snapshot: %w", err)
	}
	return nil
}

// ClearPendingChangesForPeerTx deletes all pending changes for a peer within a transaction.
// It delegates to db.ClearPendingChangesForPeer so the delete lives in
// exactly one place (*sql.Tx satisfies db.Querier).
func (s *PendingStore) ClearPendingChangesForPeerTx(ctx context.Context, tx *sql.Tx, peerID int) error {
	if err := db.ClearPendingChangesForPeer(ctx, tx, peerID); err != nil {
		return fmt.Errorf("clear pending changes for peer: %w", err)
	}
	return nil
}

// DeletePendingBundlePreviewTx deletes the pending bundle preview for a peer within a transaction.
// It delegates to db.DeletePendingBundlePreview so the delete lives in
// exactly one place (*sql.Tx satisfies db.Querier).
func (s *PendingStore) DeletePendingBundlePreviewTx(ctx context.Context, tx *sql.Tx, peerID int) error {
	if err := db.DeletePendingBundlePreview(ctx, tx, peerID); err != nil {
		return fmt.Errorf("delete pending bundle preview: %w", err)
	}
	return nil
}

// SavePendingBundlePreviewTx upserts a pending bundle preview for a peer within a transaction.
// It delegates to db.SavePendingBundlePreview so the upsert lives in
// exactly one place (*sql.Tx satisfies db.Querier).
func (s *PendingStore) SavePendingBundlePreviewTx(ctx context.Context, tx *sql.Tx, peerID int, rulesContent, diffContent, versionHash string) error {
	if err := db.SavePendingBundlePreview(ctx, tx, peerID, rulesContent, diffContent, versionHash); err != nil {
		return fmt.Errorf("save pending bundle preview: %w", err)
	}
	return nil
}

// DeleteSnapshotTx deletes a change snapshot for a specific entity within a transaction.
// It delegates to db.DeleteSnapshot so the delete lives in exactly one
// place (*sql.Tx satisfies db.Querier).
func (s *PendingStore) DeleteSnapshotTx(ctx context.Context, tx *sql.Tx, entityType string, entityID int) error {
	if err := db.DeleteSnapshot(ctx, tx, entityType, entityID); err != nil {
		return fmt.Errorf("delete snapshot: %w", err)
	}
	return nil
}

// DeletePendingChangeForEntityTx deletes a specific pending change for a peer and entity within a transaction.
// It delegates to db.DeletePendingChangeForEntity so the delete lives in
// exactly one place (*sql.Tx satisfies db.Querier).
func (s *PendingStore) DeletePendingChangeForEntityTx(ctx context.Context, tx *sql.Tx, peerID int64, changeType string, changeID int) error {
	if err := db.DeletePendingChangeForEntity(ctx, tx, int(peerID), changeType, changeID); err != nil {
		return fmt.Errorf("delete pending change for entity: %w", err)
	}
	return nil
}

// CountPendingChangesForPeerTx counts remaining pending changes for a peer within a transaction.
// It delegates to db.CountPendingChangesForPeer so the count query lives in
// exactly one place (*sql.Tx satisfies db.Querier).
func (s *PendingStore) CountPendingChangesForPeerTx(ctx context.Context, tx *sql.Tx, peerID int64) (int, error) {
	count, err := db.CountPendingChangesForPeer(ctx, tx, int(peerID))
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
// (hard deletes of soft-deleted entities and snapshot removal). The COUNT
// check and the conditional deletes run atomically inside a single
// transaction so a concurrent soft-delete cannot slip between the check
// and the hard-delete and lose its pending signal.
func (s *PendingStore) CleanupIfComplete(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var count int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM pending_changes").Scan(&count); err != nil {
		return fmt.Errorf("count pending changes: %w", err)
	}
	if count > 0 {
		return nil
	}

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

// CreatePushJob creates a new push job record.
// It delegates to db.CreatePushJob so the insert lives in exactly one place.
func (s *PendingStore) CreatePushJob(ctx context.Context, jobID, initiatedBy string, totalPeers int) error {
	return db.CreatePushJob(ctx, s.db, jobID, initiatedBy, totalPeers)
}

// CreatePushJobPeers creates push job peer records within a transaction.
// It delegates to db.CreatePushJobPeersT so the bulk insert and statement
// lifecycle live in exactly one place.
func (s *PendingStore) CreatePushJobPeers(ctx context.Context, jobID string, peers []struct {
	ID       int
	Hostname string
}) error {
	return db.CreatePushJobPeersT(ctx, s.db, jobID, peers)
}

// GetPushJob retrieves a push job by ID.
// It delegates to db.GetPushJob so the query lives in exactly one place.
func (s *PendingStore) GetPushJob(ctx context.Context, jobID string) (PushJob, error) {
	return db.GetPushJob(ctx, s.db, jobID)
}

// GetPushJobWithPeers retrieves a push job along with its peer records.
// It delegates to db.GetPushJobWithPeers so the query and rows lifecycle
// live in exactly one place.
func (s *PendingStore) GetPushJobWithPeers(ctx context.Context, jobID string) (PushJob, []PushJobPeer, error) {
	job, peers, err := db.GetPushJobWithPeers(ctx, s.db, jobID)
	if err != nil {
		return PushJob{}, nil, err
	}
	return job, ic.EnsureSlice(peers), nil
}

// UpdatePushJobPeerStatus marks a peer's delivery status within a push job.
// It delegates to the shared db helper so bulk fan-out handlers outside the
// pending package can record per-peer outcomes against the same audit rows.
func (s *PendingStore) UpdatePushJobPeerStatus(ctx context.Context, jobID string, peerID int, status string, errMsg string) error {
	return db.UpdatePushJobPeerStatus(ctx, s.db, jobID, peerID, status, errMsg)
}

// FinalizePushJobWithCounts marks a push job completed with explicit
// success/failure counts. It delegates to the shared db helper so bulk
// fan-out handlers outside the pending package close the audit rows they
// opened with CreatePushJob.
func (s *PendingStore) FinalizePushJobWithCounts(ctx context.Context, jobID string, succeeded, failed int) error {
	return db.FinalizePushJobWithCounts(ctx, s.db, jobID, succeeded, failed)
}
