package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"runic/internal/models"
)

// ErrConstraintViolation is returned when rollback is blocked by foreign key constraints
var ErrConstraintViolation = errors.New("rollback blocked by constraint violation")

// RollbackSnapshots iterates over all snapshots in reverse chronological order and restores entities.
func RollbackSnapshots(ctx context.Context, database DB) error {
	tx, err := database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()

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
					return err
				}
				_, err = tx.ExecContext(ctx, "DELETE FROM groups WHERE id = ?", s.EntityID)
			case "service":
				_, err = tx.ExecContext(ctx, "DELETE FROM services WHERE id = ?", s.EntityID)
			case "policy":
				_, err = tx.ExecContext(ctx, "DELETE FROM policies WHERE id = ?", s.EntityID)
			}
			if err != nil {
				return fmt.Errorf("rollback create %s %d: %w", s.EntityType, s.EntityID, err)
			}
		} else {
			// Update or delete actions -> restore state
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
					return err
				}

				_, err = tx.ExecContext(ctx, "DELETE FROM group_members WHERE group_id = ?", s.EntityID)
				if err != nil {
					return err
				}

				for _, m := range data.Members {
					_, err = tx.ExecContext(ctx, "INSERT INTO group_members (id, group_id, peer_id, added_at) VALUES (?, ?, ?, ?)",
						m.ID, m.GroupID, m.PeerID, m.AddedAt)
					if err != nil {
						return err
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
					return err
				}
			case "policy":
				var p models.PolicyRow
				if err := json.Unmarshal([]byte(s.SnapshotData), &p); err != nil {
					return fmt.Errorf("unmarshal policy snapshot: %w", err)
				}
				_, err = tx.ExecContext(ctx, "UPDATE policies SET name=?, description=?, source_id=?, source_type=?, service_id=?, target_id=?, target_type=?, source_ip=?, target_ip=?, action=?, priority=?, enabled=?, target_scope=?, direction=?, is_pending_delete=0 WHERE id=?",
					p.Name, p.Description, p.SourceID, p.SourceType, p.ServiceID, p.TargetID, p.TargetType, p.SourceIP, p.TargetIP, p.Action, p.Priority, p.Enabled, p.TargetScope, p.Direction, s.EntityID)
				if err != nil {
					return err
				}
			}
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

	return tx.Commit()
}

// RollbackEntitySnapshot rolls back a single entity by its type and ID.
// Returns ErrConstraintViolation if the rollback would violate referential integrity.
func RollbackEntitySnapshot(ctx context.Context, database DB, entityType string, entityID int) error {
	tx, err := database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()

	// Get the snapshot for this entity
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

	// Delete the snapshot
	_, err = tx.ExecContext(ctx, "DELETE FROM change_snapshots WHERE entity_type = ? AND entity_id = ?", entityType, entityID)
	if err != nil {
		return fmt.Errorf("delete snapshot: %w", err)
	}

	return tx.Commit()
}

// checkCreateRollbackConstraints checks if a create rollback would violate foreign key constraints
func checkCreateRollbackConstraints(ctx context.Context, tx Querier, entityType string, entityID int) error {
	switch entityType {
	case "group":
		// Check if any policies reference this group
		var policyCount int
		err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM policies WHERE (source_id = ? AND source_type = 'group') OR (target_id = ? AND target_type = 'group')", entityID, entityID).Scan(&policyCount)
		if err != nil {
			return fmt.Errorf("check policy constraints: %w", err)
		}
		if policyCount > 0 {
			return fmt.Errorf("%w: group %d is referenced by %d policy(s)", ErrConstraintViolation, entityID, policyCount)
		}
	case "service":
		// Check if any policies reference this service
		var policyCount int
		err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM policies WHERE service_id = ?", entityID).Scan(&policyCount)
		if err != nil {
			return fmt.Errorf("check policy constraints: %w", err)
		}
		if policyCount > 0 {
			return fmt.Errorf("%w: service %d is referenced by %d policy(s)", ErrConstraintViolation, entityID, policyCount)
		}
	}
	return nil
}

// rollbackCreateEntity handles rollback of a create action
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
	}
	return fmt.Errorf("unknown entity type: %s", entityType)
}

// rollbackUpdateDeleteEntity handles rollback of update or delete actions
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
	}
	return fmt.Errorf("unknown entity type: %s", entityType)
}

func CleanupAfterApplyAll(ctx context.Context, database DB) error {
	tx, err := database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()

	// Hard delete soft deleted entities
	_, err = tx.ExecContext(ctx, "DELETE FROM group_members WHERE group_id IN (SELECT id FROM groups WHERE is_pending_delete = 1)")
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

	return tx.Commit()
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
