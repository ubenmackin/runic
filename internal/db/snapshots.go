package db

import (
	"context"
	"database/sql"
	"fmt"

	"runic/internal/common/log"
	"runic/internal/models"
)

// CreateSnapshot creates a snapshot if one doesn't already exist for this entity.
// It is idempotent to ensure all-or-nothing rollback (only the first change is snapshotted).
func CreateSnapshot(ctx context.Context, database Querier, entityType string, entityID int, action, snapshotData string) error {
	// Check if a snapshot already exists
	var exists bool
	err := database.QueryRowContext(ctx,
		"SELECT COUNT(*) > 0 FROM change_snapshots WHERE entity_type = ? AND entity_id = ?",
		entityType, entityID,
	).Scan(&exists)
	if err != nil {
		return fmt.Errorf("check existing snapshot: %w", err)
	}

	if exists {
		// Snapshot already exists, preserve the original state
		return nil
	}

	// Insert new snapshot
	var data sql.NullString
	if snapshotData != "" {
		data.String = snapshotData
		data.Valid = true
	}

	_, err = database.ExecContext(ctx,
		"INSERT INTO change_snapshots (entity_type, entity_id, action, snapshot_data) VALUES (?, ?, ?, ?)",
		entityType, entityID, action, data,
	)
	if err != nil {
		return fmt.Errorf("insert snapshot: %w", err)
	}
	return nil
}

// GetSnapshot returns the snapshot for an entity, or sql.ErrNoRows if not found.
func GetSnapshot(ctx context.Context, database Querier, entityType string, entityID int) (*models.ChangeSnapshot, error) {
	row := database.QueryRowContext(ctx,
		"SELECT id, entity_type, entity_id, action, snapshot_data, created_at FROM change_snapshots WHERE entity_type = ? AND entity_id = ?",
		entityType, entityID,
	)

	var s models.ChangeSnapshot
	var snapshotData sql.NullString
	err := row.Scan(&s.ID, &s.EntityType, &s.EntityID, &s.Action, &snapshotData, &s.CreatedAt)
	if err != nil {
		return nil, err
	}

	if snapshotData.Valid {
		s.SnapshotData = snapshotData.String
	}

	return &s, nil
}

// GetAllSnapshots returns all active snapshots.
func GetAllSnapshots(ctx context.Context, database Querier) ([]models.ChangeSnapshot, error) {
	rows, err := database.QueryContext(ctx,
		"SELECT id, entity_type, entity_id, action, snapshot_data, created_at FROM change_snapshots ORDER BY created_at DESC",
	)
	if err != nil {
		return nil, fmt.Errorf("query snapshots: %w", err)
	}
	defer func() {
		if cerr := rows.Close(); cerr != nil {
			log.WarnContext(ctx, "failed to close rows", "error", cerr)
		}
	}()

	var snapshots []models.ChangeSnapshot
	for rows.Next() {
		var s models.ChangeSnapshot
		var snapshotData sql.NullString
		if err := rows.Scan(&s.ID, &s.EntityType, &s.EntityID, &s.Action, &snapshotData, &s.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan snapshot: %w", err)
		}
		if snapshotData.Valid {
			s.SnapshotData = snapshotData.String
		}
		snapshots = append(snapshots, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows error: %w", err)
	}

	return snapshots, nil
}

// DeleteSnapshot removes a snapshot, typically after apply or rollback.
func DeleteSnapshot(ctx context.Context, database Querier, entityType string, entityID int) error {
	_, err := database.ExecContext(ctx,
		"DELETE FROM change_snapshots WHERE entity_type = ? AND entity_id = ?",
		entityType, entityID,
	)
	if err != nil {
		return fmt.Errorf("delete snapshot: %w", err)
	}
	return nil
}

// DeleteAllSnapshots clears all snapshots after apply-all.
func DeleteAllSnapshots(ctx context.Context, database Querier) error {
	_, err := database.ExecContext(ctx, "DELETE FROM change_snapshots")
	if err != nil {
		return fmt.Errorf("delete all snapshots: %w", err)
	}
	return nil
}

// ClearPendingChangesByEntity deletes all pending_changes rows matching the entity.
func ClearPendingChangesByEntity(ctx context.Context, database Querier, entityType string, entityID int) error {
	_, err := database.ExecContext(ctx,
		"DELETE FROM pending_changes WHERE change_type = ? AND change_id = ?",
		entityType, entityID,
	)
	if err != nil {
		return fmt.Errorf("clear pending changes: %w", err)
	}
	return nil
}
