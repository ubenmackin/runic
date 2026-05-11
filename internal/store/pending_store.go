package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
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
	_, err := s.db.ExecContext(ctx, "DELETE FROM rule_bundles_pending")
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

// RollbackSnapshots rolls back all pending changes by restoring snapshots and deleting them.
func (s *PendingStore) RollbackSnapshots(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	rows, err := tx.QueryContext(ctx, "SELECT id, entity_type, entity_id, action, snapshot_data FROM change_snapshots ORDER BY id DESC")
	if err != nil {
		return fmt.Errorf("query snapshots: %w", err)
	}

	var snapshots []models.ChangeSnapshot
	for rows.Next() {
		var s models.ChangeSnapshot
		var data sql.NullString
		if err := rows.Scan(&s.ID, &s.EntityType, &s.EntityID, &s.Action, &data); err != nil {
			_ = rows.Close()
			return fmt.Errorf("scan snapshot: %w", err)
		}
		if data.Valid {
			s.SnapshotData = data.String
		}
		snapshots = append(snapshots, s)
	}
	_ = rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("rows error: %w", err)
	}

	for _, s := range snapshots {
		if s.Action == "create" {
			switch s.EntityType {
			case "group":
				_, err = tx.ExecContext(ctx, "DELETE FROM group_members WHERE group_id = ?", s.EntityID)
				if err != nil {
					return fmt.Errorf("rollback create group members: %w", err)
				}
				_, err = tx.ExecContext(ctx, "DELETE FROM groups WHERE id = ?", s.EntityID)
			case "service":
				_, err = tx.ExecContext(ctx, "DELETE FROM services WHERE id = ?", s.EntityID)
			case "policy":
				_, err = tx.ExecContext(ctx, "DELETE FROM policies WHERE id = ?", s.EntityID)
			case "peer":
				_, err = tx.ExecContext(ctx, "DELETE FROM peer_ips WHERE peer_id = ?", s.EntityID)
				if err != nil {
					return fmt.Errorf("rollback create peer IPs: %w", err)
				}
				_, err = tx.ExecContext(ctx, "DELETE FROM peers WHERE id = ?", s.EntityID)
			}
			if err != nil {
				return fmt.Errorf("rollback create %s %d: %w", s.EntityType, s.EntityID, err)
			}
		} else {
			switch s.EntityType {
			case "group":
				var data struct {
					Group   models.GroupRow         `json:"group"`
					Members []models.GroupMemberRow `json:"members"`
				}
				if err := json.Unmarshal([]byte(s.SnapshotData), &data); err != nil {
					return fmt.Errorf("unmarshal group snapshot: %w", err)
				}
				_, err = tx.ExecContext(ctx, "UPDATE groups SET name=?, description=?, is_pending_delete=0 WHERE id=?",
					data.Group.Name, data.Group.Description, s.EntityID)
				if err != nil {
					return fmt.Errorf("rollback group update: %w", err)
				}

				_, err = tx.ExecContext(ctx, "DELETE FROM group_members WHERE group_id = ?", s.EntityID)
				if err != nil {
					return fmt.Errorf("rollback group members delete: %w", err)
				}

				for _, m := range data.Members {
					_, err = tx.ExecContext(ctx, "INSERT INTO group_members (id, group_id, peer_id, added_at) VALUES (?, ?, ?, ?)",
						m.ID, m.GroupID, m.PeerID, m.AddedAt)
					if err != nil {
						return fmt.Errorf("rollback group member insert: %w", err)
					}
				}
			case "service":
				var svc models.ServiceRow
				if err := json.Unmarshal([]byte(s.SnapshotData), &svc); err != nil {
					return fmt.Errorf("unmarshal service snapshot: %w", err)
				}
				_, err = tx.ExecContext(ctx, "UPDATE services SET name=?, ports=?, source_ports=?, protocol=?, description=?, direction_hint=?, is_system=?, is_pending_delete=0 WHERE id=?",
					svc.Name, svc.Ports, svc.SourcePorts, svc.Protocol, svc.Description, svc.DirectionHint, svc.IsSystem, s.EntityID)
				if err != nil {
					return fmt.Errorf("rollback service update: %w", err)
				}
			case "policy":
				var p models.PolicyRow
				if err := json.Unmarshal([]byte(s.SnapshotData), &p); err != nil {
					return fmt.Errorf("unmarshal policy snapshot: %w", err)
				}
				_, err = tx.ExecContext(ctx, "UPDATE policies SET name=?, description=?, source_id=?, source_type=?, service_id=?, target_id=?, target_type=?, source_ip=?, target_ip=?, action=?, priority=?, enabled=?, target_scope=?, direction=?, is_pending_delete=0 WHERE id=?",
					p.Name, p.Description, p.SourceID, p.SourceType, p.ServiceID, p.TargetID, p.TargetType, p.SourceIP, p.TargetIP, p.Action, p.Priority, p.Enabled, p.TargetScope, p.Direction, s.EntityID)
				if err != nil {
					return fmt.Errorf("rollback policy update: %w", err)
				}
			case "peer":
				return fmt.Errorf("peer update/delete rollback not yet implemented")
			}
		}
	}

	_, err = tx.ExecContext(ctx, "DELETE FROM change_snapshots")
	if err != nil {
		return fmt.Errorf("delete snapshots: %w", err)
	}
	_, err = tx.ExecContext(ctx, "DELETE FROM pending_changes")
	if err != nil {
		return fmt.Errorf("delete pending changes: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit rollback: %w", err)
	}
	return nil
}

// RollbackEntitySnapshot restores an entity from its snapshot.
// Returns ErrConstraintViolation if the rollback would violate referential integrity.
func (s *PendingStore) RollbackEntitySnapshot(ctx context.Context, entityType string, entityID int) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var snapshotID int
	var action string
	var snapshotData sql.NullString
	err = tx.QueryRowContext(ctx, "SELECT id, action, snapshot_data FROM change_snapshots WHERE entity_type = ? AND entity_id = ?", entityType, entityID).Scan(&snapshotID, &action, &snapshotData)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("snapshot not found for %s %d", entityType, entityID)
		}
		return fmt.Errorf("query snapshot: %w", err)
	}

	// Security check for create rollbacks
	if action == "create" {
		if err := checkCreateRollbackConstraints(ctx, tx, entityType, entityID); err != nil {
			return err
		}
	}

	// Execute rollback based on action
	switch action {
	case "create":
		if err := rollbackCreateEntity(ctx, tx, entityType, entityID); err != nil {
			return err
		}
	case "update", "delete":
		if !snapshotData.Valid {
			return fmt.Errorf("missing snapshot data for %s %d", entityType, entityID)
		}
		if err := rollbackUpdateDeleteEntity(ctx, tx, entityType, entityID, action, snapshotData.String); err != nil {
			return err
		}
	}

	// Clear pending changes for this entity
	_, err = tx.ExecContext(ctx, "DELETE FROM pending_changes WHERE change_type = ? AND change_id = ?", entityType, entityID)
	if err != nil {
		return fmt.Errorf("clear pending changes: %w", err)
	}

	_, err = tx.ExecContext(ctx, "DELETE FROM change_snapshots WHERE entity_type = ? AND entity_id = ?", entityType, entityID)
	if err != nil {
		return fmt.Errorf("delete snapshot: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit entity rollback: %w", err)
	}
	return nil
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
	defer func() { _ = tx.Rollback() }()

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

// checkCreateRollbackConstraints verifies that rolling back a "create" action won't violate referential integrity.
func checkCreateRollbackConstraints(ctx context.Context, tx db.Querier, entityType string, entityID int) error {
	switch entityType {
	case "group":
		var policyCount int
		err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM policies WHERE (source_id = ? AND source_type = 'group') OR (target_id = ? AND target_type = 'group')", entityID, entityID).Scan(&policyCount)
		if err != nil {
			return fmt.Errorf("check policy constraints: %w", err)
		}
		if policyCount > 0 {
			return fmt.Errorf("%w: group %d is referenced by %d policy(s)", ErrConstraintViolation, entityID, policyCount)
		}
	case "service":
		var policyCount int
		err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM policies WHERE service_id = ?", entityID).Scan(&policyCount)
		if err != nil {
			return fmt.Errorf("check policy constraints: %w", err)
		}
		if policyCount > 0 {
			return fmt.Errorf("%w: service %d is referenced by %d policy(s)", ErrConstraintViolation, entityID, policyCount)
		}
	case "peer":
		var groupMemberCount int
		err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM group_members WHERE peer_id = ?", entityID).Scan(&groupMemberCount)
		if err != nil {
			return fmt.Errorf("check group member constraints: %w", err)
		}
		var policyCount int
		err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM policies WHERE (source_id = ? AND source_type = 'peer') OR (target_id = ? AND target_type = 'peer')", entityID, entityID).Scan(&policyCount)
		if err != nil {
			return fmt.Errorf("check policy constraints: %w", err)
		}
		if groupMemberCount > 0 || policyCount > 0 {
			return fmt.Errorf("%w: cannot rollback peer creation: peer is referenced by %d group members and %d policies", ErrConstraintViolation, groupMemberCount, policyCount)
		}
	}
	return nil
}

// rollbackCreateEntity deletes an entity that was created (undoing a "create" action).
func rollbackCreateEntity(ctx context.Context, tx db.Querier, entityType string, entityID int) error {
	switch entityType {
	case "group":
		_, err := tx.ExecContext(ctx, "DELETE FROM group_members WHERE group_id = ?", entityID)
		if err != nil {
			return fmt.Errorf("delete group members: %w", err)
		}
		_, err = tx.ExecContext(ctx, "DELETE FROM groups WHERE id = ?", entityID)
		return err
	case "service":
		_, err := tx.ExecContext(ctx, "DELETE FROM services WHERE id = ?", entityID)
		return err
	case "policy":
		_, err := tx.ExecContext(ctx, "DELETE FROM policies WHERE id = ?", entityID)
		return err
	case "peer":
		_, err := tx.ExecContext(ctx, "DELETE FROM peer_ips WHERE peer_id = ?", entityID)
		if err != nil {
			return fmt.Errorf("delete peer IPs: %w", err)
		}
		_, err = tx.ExecContext(ctx, "DELETE FROM peers WHERE id = ?", entityID)
		return err
	}
	return fmt.Errorf("unknown entity type: %s", entityType)
}

// rollbackUpdateDeleteEntity restores an entity from its snapshot data (undoing "update" or "delete").
func rollbackUpdateDeleteEntity(ctx context.Context, tx db.Querier, entityType string, entityID int, action, snapshotData string) error {
	switch entityType {
	case "group":
		var data struct {
			Group   models.GroupRow         `json:"group"`
			Members []models.GroupMemberRow `json:"members"`
		}
		if err := json.Unmarshal([]byte(snapshotData), &data); err != nil {
			return fmt.Errorf("unmarshal group snapshot: %w", err)
		}
		_, err := tx.ExecContext(ctx, "UPDATE groups SET name=?, description=?, is_pending_delete=0 WHERE id=?", data.Group.Name, data.Group.Description, entityID)
		if err != nil {
			return fmt.Errorf("restore group: %w", err)
		}
		_, err = tx.ExecContext(ctx, "DELETE FROM group_members WHERE group_id = ?", entityID)
		if err != nil {
			return fmt.Errorf("delete group members for restore: %w", err)
		}
		for _, m := range data.Members {
			_, err = tx.ExecContext(ctx, "INSERT INTO group_members (id, group_id, peer_id, added_at) VALUES (?, ?, ?, ?)", m.ID, m.GroupID, m.PeerID, m.AddedAt)
			if err != nil {
				return fmt.Errorf("restore group member: %w", err)
			}
		}
		return nil
	case "service":
		var svc models.ServiceRow
		if err := json.Unmarshal([]byte(snapshotData), &svc); err != nil {
			return fmt.Errorf("unmarshal service snapshot: %w", err)
		}
		_, err := tx.ExecContext(ctx, "UPDATE services SET name=?, ports=?, source_ports=?, protocol=?, description=?, direction_hint=?, is_system=?, is_pending_delete=0 WHERE id=?", svc.Name, svc.Ports, svc.SourcePorts, svc.Protocol, svc.Description, svc.DirectionHint, svc.IsSystem, entityID)
		return err
	case "policy":
		var p models.PolicyRow
		if err := json.Unmarshal([]byte(snapshotData), &p); err != nil {
			return fmt.Errorf("unmarshal policy snapshot: %w", err)
		}
		_, err := tx.ExecContext(ctx, "UPDATE policies SET name=?, description=?, source_id=?, source_type=?, service_id=?, target_id=?, target_type=?, source_ip=?, target_ip=?, action=?, priority=?, enabled=?, target_scope=?, direction=?, is_pending_delete=0 WHERE id=?", p.Name, p.Description, p.SourceID, p.SourceType, p.ServiceID, p.TargetID, p.TargetType, p.SourceIP, p.TargetIP, p.Action, p.Priority, p.Enabled, p.TargetScope, p.Direction, entityID)
		return err
	case "peer":
		return fmt.Errorf("peer update/delete rollback not yet supported: entityID %d", entityID)
	}
	return fmt.Errorf("unknown entity type: %s", entityType)
}
