package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"runic/internal/models"
)

// RollbackSnapshots iterates over all snapshots in reverse chronological order and restores entities.
func RollbackSnapshots(ctx context.Context, database DB) error {
	tx, err := database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() {
		_ = tx.Rollback() //nolint:errcheck
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
			_ = rows.Close() //nolint:errcheck
			return fmt.Errorf("scan snapshot: %w", err)
		}
		if data.Valid {
			s.SnapshotData = data.String
		}
		snapshots = append(snapshots, s)
	}
	_ = rows.Close() //nolint:errcheck
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
				_, err = tx.ExecContext(ctx, "UPDATE policies SET name=?, description=?, source_id=?, source_type=?, service_id=?, target_id=?, target_type=?, action=?, priority=?, enabled=?, target_scope=?, direction=?, is_pending_delete=0 WHERE id=?",
					p.Name, p.Description, p.SourceID, p.SourceType, p.ServiceID, p.TargetID, p.TargetType, p.Action, p.Priority, p.Enabled, p.TargetScope, p.Direction, s.EntityID)
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

func CleanupAfterApplyAll(ctx context.Context, database DB) error {
	tx, err := database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() {
		_ = tx.Rollback() //nolint:errcheck
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
