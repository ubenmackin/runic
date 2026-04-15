package db

import (
	"context"
	"database/sql"
	"fmt"
)

// CreateSnapshot creates a snapshot if one doesn't already exist for this entity.
// It is idempotent to ensure all-or-nothing rollback (only the first change is snapshotted).
// Uses INSERT OR IGNORE for atomic idempotency - if a snapshot already exists, the operation
// silently succeeds without modifying the existing snapshot.
func CreateSnapshot(ctx context.Context, database Querier, entityType string, entityID int, action, snapshotData string) error {
	var data sql.NullString
	if snapshotData != "" {
		data.String = snapshotData
		data.Valid = true
	}

	// Use INSERT OR IGNORE for atomic idempotency
	// If a snapshot already exists for this entity, the insert is silently ignored
	_, err := database.ExecContext(ctx,
		"INSERT OR IGNORE INTO change_snapshots (entity_type, entity_id, action, snapshot_data) VALUES (?, ?, ?, ?)",
		entityType, entityID, action, data,
	)
	if err != nil {
		return fmt.Errorf("insert snapshot: %w", err)
	}
	return nil
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
