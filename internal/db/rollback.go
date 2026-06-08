package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"runic/internal/common/log"
	"runic/internal/models"
)

var ErrConstraintViolation = errors.New("rollback blocked by constraint violation")

func RollbackSnapshots(ctx context.Context, database DB) error {
	return withTx(ctx, database, func(ctx context.Context, tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, "SELECT id, entity_type, entity_id, action, snapshot_data FROM change_snapshots ORDER BY id DESC")
		if err != nil {
			return fmt.Errorf("query snapshots: %w", err)
		}
		defer func() {
			if cerr := rows.Close(); cerr != nil {
				log.WarnContext(ctx, "failed to close rows", "error", cerr)
			}
		}()

		var snapshots []models.ChangeSnapshot
		for rows.Next() {
			var s models.ChangeSnapshot
			var data sql.NullString
			if err := rows.Scan(&s.ID, &s.EntityType, &s.EntityID, &s.Action, &data); err != nil {
				return fmt.Errorf("scan snapshot: %w", err)
			}
			if data.Valid {
				s.SnapshotData = data.String
			}
			snapshots = append(snapshots, s)
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("rows error: %w", err)
		}

		for _, s := range snapshots {
			// CRITICAL: For "create" rollbacks, verify that the entity can be
			// safely removed before deletion. If a peer was added to a group,
			// or a group is referenced by a policy, the rollback would violate
			// referential integrity. Aborting here leaves the snapshot in place
			// and prevents cascading data loss.
			if s.Action == "create" {
				if err := checkCreateRollbackConstraints(ctx, tx, s.EntityType, s.EntityID); err != nil {
					return fmt.Errorf("rollback %s %s %d: %w", s.Action, s.EntityType, s.EntityID, err)
				}
			}

			var rollbackErr error
			if s.Action == "create" {
				rollbackErr = rollbackCreateEntity(ctx, tx, s.EntityType, s.EntityID)
			} else {
				// update / delete — snapshot data is required
				if s.SnapshotData == "" {
					return fmt.Errorf("missing snapshot data for %s %d", s.EntityType, s.EntityID)
				}
				rollbackErr = rollbackUpdateDeleteEntity(ctx, tx, s.EntityType, s.EntityID, s.Action, s.SnapshotData)
			}
			if rollbackErr != nil {
				return fmt.Errorf("rollback %s %s %d: %w", s.Action, s.EntityType, s.EntityID, rollbackErr)
			}
		}

		_, err = tx.ExecContext(ctx, "DELETE FROM change_snapshots")
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, "DELETE FROM pending_changes")
		if err != nil {
			return err
		}

		return nil
	})
}

// RollbackEntitySnapshot restores an entity from its snapshot. Returns ErrConstraintViolation if the rollback would violate referential integrity.
func RollbackEntitySnapshot(ctx context.Context, database DB, entityType string, entityID int) error {
	return withTx(ctx, database, func(ctx context.Context, tx *sql.Tx) error {
		var snapshotID int
		var action string
		var snapshotData sql.NullString
		err := tx.QueryRowContext(ctx, "SELECT id, action, snapshot_data FROM change_snapshots WHERE entity_type = ? AND entity_id = ?", entityType, entityID).Scan(&snapshotID, &action, &snapshotData)
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
		default:
			return fmt.Errorf("unknown snapshot action %q for %s %d", action, entityType, entityID)
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

		return nil
	})
}

func checkCreateRollbackConstraints(ctx context.Context, tx Querier, entityType string, entityID int) error {
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

func rollbackCreateEntity(ctx context.Context, tx Querier, entityType string, entityID int) error {
	switch entityType {
	case "group":
		_, err := tx.ExecContext(ctx, "DELETE FROM group_members WHERE group_id = ?", entityID)
		if err != nil {
			return err
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
			return err
		}
		_, err = tx.ExecContext(ctx, "DELETE FROM peers WHERE id = ?", entityID)
		return err
	}
	return fmt.Errorf("unknown entity type: %s", entityType)
}

func rollbackUpdateDeleteEntity(ctx context.Context, tx Querier, entityType string, entityID int, action, snapshotData string) error {
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
			return err
		}
		_, err = tx.ExecContext(ctx, "DELETE FROM group_members WHERE group_id = ?", entityID)
		if err != nil {
			return err
		}
		for _, m := range data.Members {
			_, err = tx.ExecContext(ctx, "INSERT INTO group_members (id, group_id, peer_id, added_at) VALUES (?, ?, ?, ?)", m.ID, m.GroupID, m.PeerID, m.AddedAt)
			if err != nil {
				return err
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

func CleanupAfterApplyAll(ctx context.Context, database DB) error {
	return withTx(ctx, database, func(ctx context.Context, tx *sql.Tx) error {
		// Hard delete soft deleted entities
		_, err := tx.ExecContext(ctx, "DELETE FROM group_members WHERE group_id IN (SELECT id FROM groups WHERE is_pending_delete = 1)")
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, "DELETE FROM groups WHERE is_pending_delete = 1")
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, "DELETE FROM policies WHERE is_pending_delete = 1")
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, "DELETE FROM services WHERE is_pending_delete = 1")
		if err != nil {
			return err
		}

		_, err = tx.ExecContext(ctx, "DELETE FROM change_snapshots")
		if err != nil {
			return err
		}

		return nil
	})
}

func CleanupIfComplete(ctx context.Context, database DB) error {
	var count int
	if err := database.QueryRowContext(ctx, "SELECT COUNT(*) FROM pending_changes").Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return nil
	}
	return CleanupAfterApplyAll(ctx, database)
}
