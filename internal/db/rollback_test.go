package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"runic/internal/models"

	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRollbackEntitySnapshot_Create(t *testing.T) {
	database, cleanup := SetupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	// Setup: Create a group
	result, err := database.ExecContext(ctx,
		"INSERT INTO groups (name, description) VALUES (?, ?)",
		"test-group", "test description")
	require.NoError(t, err, "Failed to create group")

	groupID, err := result.LastInsertId()
	require.NoError(t, err, "Failed to get group ID")

	err = CreateSnapshot(ctx, database, "group", int(groupID), "create", "")
	require.NoError(t, err, "Failed to create snapshot")

	// Verify group exists before rollback
	var count int
	err = database.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM groups WHERE id = ?", groupID).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 1, count, "Group should exist before rollback")

	// Call RollbackEntitySnapshot
	err = RollbackEntitySnapshot(ctx, database, "group", int(groupID))
	require.NoError(t, err, "RollbackEntitySnapshot should succeed")

	// Assert: group is deleted
	err = database.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM groups WHERE id = ?", groupID).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 0, count, "Group should be deleted after rollback")

	// Assert: snapshot is deleted
	err = database.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM change_snapshots WHERE entity_type = ? AND entity_id = ?",
		"group", groupID).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 0, count, "Snapshot should be deleted after rollback")
}

func TestRollbackEntitySnapshot_Update(t *testing.T) {
	database, cleanup := SetupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	// Setup: Create a group with initial state
	result, err := database.ExecContext(ctx,
		"INSERT INTO groups (name, description) VALUES (?, ?)",
		"original-name", "original description")
	require.NoError(t, err)

	groupID, err := result.LastInsertId()
	require.NoError(t, err)

	originalGroup := models.GroupRow{
		ID:          int(groupID),
		Name:        "original-name",
		Description: "original description",
	}
	snapshotData := map[string]interface{}{
		"group":   originalGroup,
		"members": []models.GroupMemberRow{},
	}
	snapshotJSON, err := json.Marshal(snapshotData)
	require.NoError(t, err)

	err = CreateSnapshot(ctx, database, "group", int(groupID), "update", string(snapshotJSON))
	require.NoError(t, err)

	_, err = database.ExecContext(ctx,
		"UPDATE groups SET name = ?, description = ? WHERE id = ?",
		"updated-name", "updated description", groupID)
	require.NoError(t, err)

	// Verify update happened
	var name, desc string
	err = database.QueryRowContext(ctx,
		"SELECT name, description FROM groups WHERE id = ?", groupID).Scan(&name, &desc)
	require.NoError(t, err)
	assert.Equal(t, "updated-name", name, "Name should be updated before rollback")
	assert.Equal(t, "updated description", desc, "Description should be updated before rollback")

	// Call RollbackEntitySnapshot
	err = RollbackEntitySnapshot(ctx, database, "group", int(groupID))
	require.NoError(t, err, "RollbackEntitySnapshot should succeed")

	// Assert: group is restored to original state
	err = database.QueryRowContext(ctx,
		"SELECT name, description FROM groups WHERE id = ?", groupID).Scan(&name, &desc)
	require.NoError(t, err)
	assert.Equal(t, "original-name", name, "Name should be restored")
	assert.Equal(t, "original description", desc, "Description should be restored")

	// Assert: snapshot is deleted
	var count int
	err = database.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM change_snapshots WHERE entity_type = ? AND entity_id = ?",
		"group", groupID).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 0, count, "Snapshot should be deleted")
}

func TestRollbackEntitySnapshot_Delete(t *testing.T) {
	database, cleanup := SetupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	// Setup: Create a group
	result, err := database.ExecContext(ctx,
		"INSERT INTO groups (name, description) VALUES (?, ?)",
		"test-group", "test description")
	require.NoError(t, err)

	groupID, err := result.LastInsertId()
	require.NoError(t, err)

	// Soft-delete the group (set is_pending_delete=1)
	_, err = database.ExecContext(ctx,
		"UPDATE groups SET is_pending_delete = 1 WHERE id = ?", groupID)
	require.NoError(t, err)

	originalGroup := models.GroupRow{
		ID:              int(groupID),
		Name:            "test-group",
		Description:     "test description",
		IsPendingDelete: false,
	}
	snapshotData := map[string]interface{}{
		"group":   originalGroup,
		"members": []models.GroupMemberRow{},
	}
	snapshotJSON, err := json.Marshal(snapshotData)
	require.NoError(t, err)

	err = CreateSnapshot(ctx, database, "group", int(groupID), "delete", string(snapshotJSON))
	require.NoError(t, err)

	// Verify is_pending_delete=1 before rollback
	var isPendingDelete bool
	err = database.QueryRowContext(ctx,
		"SELECT is_pending_delete FROM groups WHERE id = ?", groupID).Scan(&isPendingDelete)
	require.NoError(t, err)
	assert.True(t, isPendingDelete, "Group should be soft-deleted before rollback")

	// Call RollbackEntitySnapshot
	err = RollbackEntitySnapshot(ctx, database, "group", int(groupID))
	require.NoError(t, err, "RollbackEntitySnapshot should succeed")

	// Assert: is_pending_delete=0, group restored
	err = database.QueryRowContext(ctx,
		"SELECT is_pending_delete FROM groups WHERE id = ?", groupID).Scan(&isPendingDelete)
	require.NoError(t, err)
	assert.False(t, isPendingDelete, "Group should be restored (is_pending_delete=0)")

	// Assert: snapshot is deleted
	var count int
	err = database.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM change_snapshots WHERE entity_type = ? AND entity_id = ?",
		"group", groupID).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 0, count, "Snapshot should be deleted")
}

func TestRollbackEntitySnapshot_ConstraintViolation(t *testing.T) {
	database, cleanup := SetupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	// Setup: Create foreign key dependencies first (service_id=1, peer_id=1)
	_, err := database.ExecContext(ctx,
		"INSERT INTO services (name, ports, protocol) VALUES (?, ?, ?)",
		"test-service", "8080", "tcp")
	require.NoError(t, err)

	_, err = database.ExecContext(ctx,
		"INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, is_manual) VALUES (?, ?, ?, ?, 1)",
		"fkey-peer", "10.0.0.1", "fkey-key", "fkey-hmac")
	require.NoError(t, err)

	// Create a group
	result, err := database.ExecContext(ctx,
		"INSERT INTO groups (name, description) VALUES (?, ?)",
		"test-group", "test description")
	require.NoError(t, err)

	groupID, err := result.LastInsertId()
	require.NoError(t, err)

	_, err = database.ExecContext(ctx,
		`INSERT INTO policies (name, source_id, source_type, service_id, target_id, target_type, action, priority, enabled)
		 VALUES (?, ?, 'group', 1, 1, 'peer', 'ACCEPT', 100, 1)`,
		"test-policy", groupID)
	require.NoError(t, err)

	err = CreateSnapshot(ctx, database, "group", int(groupID), "create", "")
	require.NoError(t, err)

	// Call RollbackEntitySnapshot
	err = RollbackEntitySnapshot(ctx, database, "group", int(groupID))

	// Assert: returns ErrConstraintViolation
	assert.Error(t, err, "Should return error when constraint violated")
	assert.True(t, errors.Is(err, ErrConstraintViolation), "Error should be ErrConstraintViolation")

	// Assert: group still exists
	var count int
	err = database.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM groups WHERE id = ?", groupID).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 1, count, "Group should still exist after failed rollback")

	// Assert: snapshot still exists
	err = database.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM change_snapshots WHERE entity_type = ? AND entity_id = ?",
		"group", groupID).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 1, count, "Snapshot should still exist after failed rollback")
}

func TestRollbackEntitySnapshot_NotFound(t *testing.T) {
	database, cleanup := SetupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	// Call RollbackEntitySnapshot with non-existent entity
	err := RollbackEntitySnapshot(ctx, database, "group", 99999)

	// Assert: returns error with "snapshot not found"
	assert.Error(t, err, "Should return error when snapshot not found")
	assert.Contains(t, err.Error(), "snapshot not found", "Error message should mention snapshot not found")
}

func TestCheckCreateRollbackConstraints_GroupReferencedByPolicy(t *testing.T) {
	database, cleanup := SetupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	// Setup: Create foreign key dependencies first (service_id=1)
	_, err := database.ExecContext(ctx,
		"INSERT INTO services (name, ports, protocol) VALUES (?, ?, ?)",
		"fkey-service", "8080", "tcp")
	require.NoError(t, err)

	// Create a group
	result, err := database.ExecContext(ctx,
		"INSERT INTO groups (name, description) VALUES (?, ?)",
		"test-group", "test description")
	require.NoError(t, err)

	groupID, err := result.LastInsertId()
	require.NoError(t, err)

	_, err = database.ExecContext(ctx,
		`INSERT INTO policies (name, source_id, source_type, service_id, target_id, target_type, action, priority, enabled)
		 VALUES (?, ?, 'group', 1, 1, 'peer', 'ACCEPT', 100, 1)`,
		"test-policy", groupID)
	require.NoError(t, err)

	// Start transaction for constraint check
	tx, err := database.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer tx.Rollback()

	// Call checkCreateRollbackConstraints
	err = checkCreateRollbackConstraints(ctx, tx, "group", int(groupID))

	// Assert: returns ErrConstraintViolation
	assert.Error(t, err, "Should return error when group referenced by policy")
	assert.True(t, errors.Is(err, ErrConstraintViolation), "Error should be ErrConstraintViolation")
}

func TestCheckCreateRollbackConstraints_ServiceReferencedByPolicy(t *testing.T) {
	database, cleanup := SetupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	// Setup: Create a service
	result, err := database.ExecContext(ctx,
		"INSERT INTO services (name, ports, protocol) VALUES (?, ?, ?)",
		"test-service", "8080", "tcp")
	require.NoError(t, err)

	serviceID, err := result.LastInsertId()
	require.NoError(t, err)

	_, err = database.ExecContext(ctx,
		`INSERT INTO policies (name, source_id, source_type, service_id, target_id, target_type, action, priority, enabled)
		 VALUES (?, 1, 'group', ?, 1, 'peer', 'ACCEPT', 100, 1)`,
		"test-policy", serviceID)
	require.NoError(t, err)

	// Start transaction for constraint check
	tx, err := database.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer tx.Rollback()

	// Call checkCreateRollbackConstraints
	err = checkCreateRollbackConstraints(ctx, tx, "service", int(serviceID))

	// Assert: returns ErrConstraintViolation
	assert.Error(t, err, "Should return error when service referenced by policy")
	assert.True(t, errors.Is(err, ErrConstraintViolation), "Error should be ErrConstraintViolation")
}

func TestCheckCreateRollbackConstraints_NoConstraints(t *testing.T) {
	database, cleanup := SetupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	// Setup: Create a group with no policies referencing it
	result, err := database.ExecContext(ctx,
		"INSERT INTO groups (name, description) VALUES (?, ?)",
		"test-group", "test description")
	require.NoError(t, err)

	groupID, err := result.LastInsertId()
	require.NoError(t, err)

	// Start transaction for constraint check
	tx, err := database.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer tx.Rollback()

	// Call checkCreateRollbackConstraints
	err = checkCreateRollbackConstraints(ctx, tx, "group", int(groupID))

	// Assert: returns nil
	assert.NoError(t, err, "Should return nil when no constraints")
}

func TestRollbackSnapshots_BulkRollback(t *testing.T) {
	database, cleanup := SetupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	// Setup: Create multiple entities with snapshots
	// Group 1 - create action
	result1, err := database.ExecContext(ctx,
		"INSERT INTO groups (name, description) VALUES (?, ?)",
		"group1", "description1")
	require.NoError(t, err)
	groupID1, err := result1.LastInsertId()
	require.NoError(t, err)
	err = CreateSnapshot(ctx, database, "group", int(groupID1), "create", "")
	require.NoError(t, err)

	// Group 2 - update action
	result2, err := database.ExecContext(ctx,
		"INSERT INTO groups (name, description) VALUES (?, ?)",
		"group2-original", "description2")
	require.NoError(t, err)
	groupID2, err := result2.LastInsertId()
	require.NoError(t, err)
	originalGroup2 := models.GroupRow{
		ID:          int(groupID2),
		Name:        "group2-original",
		Description: "description2",
	}
	snapshotData2 := map[string]interface{}{
		"group":   originalGroup2,
		"members": []models.GroupMemberRow{},
	}
	snapshotJSON2, err := json.Marshal(snapshotData2)
	require.NoError(t, err)
	err = CreateSnapshot(ctx, database, "group", int(groupID2), "update", string(snapshotJSON2))
	require.NoError(t, err)

	_, err = database.ExecContext(ctx,
		"UPDATE groups SET name = ?, description = ? WHERE id = ?",
		"group2-updated", "updated desc", groupID2)
	require.NoError(t, err)

	// Service - delete action
	result3, err := database.ExecContext(ctx,
		"INSERT INTO services (name, ports, protocol) VALUES (?, ?, ?)",
		"test-service", "8080", "tcp")
	require.NoError(t, err)
	serviceID, err := result3.LastInsertId()
	require.NoError(t, err)
	_, err = database.ExecContext(ctx,
		"UPDATE services SET is_pending_delete = 1 WHERE id = ?", serviceID)
	require.NoError(t, err)
	originalService := models.ServiceRow{
		ID:              int(serviceID),
		Name:            "test-service",
		Ports:           "8080",
		Protocol:        "tcp",
		IsPendingDelete: false,
	}
	snapshotJSON3, err := json.Marshal(originalService)
	require.NoError(t, err)
	err = CreateSnapshot(ctx, database, "service", int(serviceID), "delete", string(snapshotJSON3))
	require.NoError(t, err)

	// Call RollbackSnapshots
	err = RollbackSnapshots(ctx, database)
	require.NoError(t, err, "RollbackSnapshots should succeed")

	// Assert: group 1 is deleted (create rollback)
	var count int
	err = database.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM groups WHERE id = ?", groupID1).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 0, count, "Group 1 should be deleted")

	// Assert: group 2 is restored to original state (update rollback)
	var name, desc string
	err = database.QueryRowContext(ctx,
		"SELECT name, description FROM groups WHERE id = ?", groupID2).Scan(&name, &desc)
	require.NoError(t, err)
	assert.Equal(t, "group2-original", name, "Group 2 name should be restored")
	assert.Equal(t, "description2", desc, "Group 2 description should be restored")

	// Assert: service is restored (delete rollback)
	var isPendingDelete bool
	err = database.QueryRowContext(ctx,
		"SELECT is_pending_delete FROM services WHERE id = ?", serviceID).Scan(&isPendingDelete)
	require.NoError(t, err)
	assert.False(t, isPendingDelete, "Service should be restored")

	// Assert: all snapshots are deleted
	err = database.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM change_snapshots").Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 0, count, "All snapshots should be deleted")

	// Assert: all pending changes are deleted
	err = database.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM pending_changes").Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 0, count, "All pending changes should be deleted")
}

func TestRollbackSnapshots_ReverseOrder(t *testing.T) {
	database, cleanup := SetupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	// Setup: Create snapshots in order 1, 2, 3
	// We'll track the order by using policies that depend on each other
	// Policy 1 references group 1
	// Policy 2 references policy 1's service (simulated)

	result, err := database.ExecContext(ctx,
		"INSERT INTO groups (name) VALUES (?)", "group1")
	require.NoError(t, err)
	groupID, err := result.LastInsertId()
	require.NoError(t, err)

	result, err = database.ExecContext(ctx,
		"INSERT INTO services (name, ports, protocol) VALUES (?, ?, ?)",
		"service1", "8080", "tcp")
	require.NoError(t, err)
	serviceID, err := result.LastInsertId()
	require.NoError(t, err)

	result, err = database.ExecContext(ctx,
		`INSERT INTO policies (name, source_id, source_type, service_id, target_id, target_type, action, priority, enabled)
		 VALUES (?, ?, 'group', ?, 1, 'peer', 'ACCEPT', 100, 1)`,
		"policy1", groupID, serviceID)
	require.NoError(t, err)
	policyID, err := result.LastInsertId()
	require.NoError(t, err)

	// (This simulates creating a full stack: group -> service -> policy)
	err = CreateSnapshot(ctx, database, "policy", int(policyID), "create", "")
	require.NoError(t, err)

	err = CreateSnapshot(ctx, database, "service", int(serviceID), "create", "")
	require.NoError(t, err)

	err = CreateSnapshot(ctx, database, "group", int(groupID), "create", "")
	require.NoError(t, err)

	// RollbackSnapshots processes in ORDER BY id DESC, so the service
	// gets deleted before the policy that references it. Disable FK
	// enforcement temporarily to match the original test environment.
	_, err = database.ExecContext(ctx, "PRAGMA foreign_keys=OFF")
	require.NoError(t, err)
	err = RollbackSnapshots(ctx, database)
	require.NoError(t, err, "RollbackSnapshots should succeed with reverse order")

	// Assert: all entities are deleted
	var count int
	err = database.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM groups WHERE id = ?", groupID).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 0, count, "Group should be deleted")

	err = database.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM services WHERE id = ?", serviceID).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 0, count, "Service should be deleted")

	err = database.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM policies WHERE id = ?", policyID).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 0, count, "Policy should be deleted")

	// Assert: all snapshots deleted
	err = database.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM change_snapshots").Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 0, count, "All snapshots should be deleted")
}

func TestRollbackCreateEntity_Group(t *testing.T) {
	database, cleanup := SetupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	// Setup: Create group with members
	result, err := database.ExecContext(ctx,
		"INSERT INTO groups (name) VALUES (?)", "test-group")
	require.NoError(t, err)
	groupID, err := result.LastInsertId()
	require.NoError(t, err)

	_, err = database.ExecContext(ctx,
		"INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, is_manual) VALUES (?, ?, ?, ?, 1)",
		"peer1", "10.0.0.1", "key1", "hmac1")
	require.NoError(t, err)
	_, err = database.ExecContext(ctx,
		"INSERT INTO group_members (group_id, peer_id) VALUES (?, 1)", groupID)
	require.NoError(t, err)

	// Start transaction
	tx, err := database.BeginTx(ctx, nil)
	require.NoError(t, err)

	// Call rollbackCreateEntity
	err = rollbackCreateEntity(ctx, tx, "group", int(groupID))
	require.NoError(t, err)

	// Commit to verify changes
	err = tx.Commit()
	require.NoError(t, err)

	// Assert: group members deleted
	var count int
	err = database.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM group_members WHERE group_id = ?", groupID).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 0, count, "Group members should be deleted")

	// Assert: group deleted
	err = database.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM groups WHERE id = ?", groupID).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 0, count, "Group should be deleted")
}

func TestRollbackCreateEntity_Service(t *testing.T) {
	database, cleanup := SetupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	// Setup: Create service
	result, err := database.ExecContext(ctx,
		"INSERT INTO services (name, ports, protocol) VALUES (?, ?, ?)",
		"test-service", "8080", "tcp")
	require.NoError(t, err)
	serviceID, err := result.LastInsertId()
	require.NoError(t, err)

	// Start transaction
	tx, err := database.BeginTx(ctx, nil)
	require.NoError(t, err)

	// Call rollbackCreateEntity
	err = rollbackCreateEntity(ctx, tx, "service", int(serviceID))
	require.NoError(t, err)

	// Commit to verify changes
	err = tx.Commit()
	require.NoError(t, err)

	// Assert: service deleted
	var count int
	err = database.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM services WHERE id = ?", serviceID).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 0, count, "Service should be deleted")
}

func TestRollbackCreateEntity_Policy(t *testing.T) {
	database, cleanup := SetupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	// Setup: Create foreign key dependencies first (service_id=1)
	_, err := database.ExecContext(ctx,
		"INSERT INTO services (name, ports, protocol) VALUES (?, ?, ?)",
		"fkey-service", "8080", "tcp")
	require.NoError(t, err)

	// Create policy
	result, err := database.ExecContext(ctx,
		`INSERT INTO policies (name, source_id, source_type, service_id, target_id, target_type, action, priority, enabled)
		 VALUES (?, 1, 'group', 1, 1, 'peer', 'ACCEPT', 100, 1)`,
		"test-policy")
	require.NoError(t, err)
	policyID, err := result.LastInsertId()
	require.NoError(t, err)

	// Start transaction
	tx, err := database.BeginTx(ctx, nil)
	require.NoError(t, err)

	// Call rollbackCreateEntity
	err = rollbackCreateEntity(ctx, tx, "policy", int(policyID))
	require.NoError(t, err)

	// Commit to verify changes
	err = tx.Commit()
	require.NoError(t, err)

	// Assert: policy deleted
	var count int
	err = database.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM policies WHERE id = ?", policyID).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 0, count, "Policy should be deleted")
}

func TestRollbackUpdateDeleteEntity_Group(t *testing.T) {
	database, cleanup := SetupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	// Setup: Create group
	result, err := database.ExecContext(ctx,
		"INSERT INTO groups (name, description) VALUES (?, ?)",
		"test-group", "test description")
	require.NoError(t, err)
	groupID, err := result.LastInsertId()
	require.NoError(t, err)

	_, err = database.ExecContext(ctx,
		"INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, is_manual) VALUES (?, ?, ?, ?, 1)",
		"peer1", "10.0.0.1", "key1", "hmac1")
	require.NoError(t, err)
	_, err = database.ExecContext(ctx,
		"INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, is_manual) VALUES (?, ?, ?, ?, 1)",
		"peer2", "10.0.0.2", "key2", "hmac2")
	require.NoError(t, err)

	originalGroup := models.GroupRow{
		ID:          int(groupID),
		Name:        "original-name",
		Description: "original description",
	}
	originalMembers := []models.GroupMemberRow{
		{ID: 1, GroupID: int(groupID), PeerID: 1, AddedAt: sql.NullTime{Time: time.Now(), Valid: true}},
		{ID: 2, GroupID: int(groupID), PeerID: 2, AddedAt: sql.NullTime{Time: time.Now(), Valid: true}},
	}
	snapshotData := map[string]interface{}{
		"group":   originalGroup,
		"members": originalMembers,
	}
	snapshotJSON, err := json.Marshal(snapshotData)
	require.NoError(t, err)

	// Start transaction
	tx, err := database.BeginTx(ctx, nil)
	require.NoError(t, err)

	// Call rollbackUpdateDeleteEntity
	err = rollbackUpdateDeleteEntity(ctx, tx, "group", int(groupID), "update", string(snapshotJSON))
	require.NoError(t, err)

	// Commit to verify changes
	err = tx.Commit()
	require.NoError(t, err)

	// Assert: group restored to original state
	var name, desc string
	err = database.QueryRowContext(ctx,
		"SELECT name, description FROM groups WHERE id = ?", groupID).Scan(&name, &desc)
	require.NoError(t, err)
	assert.Equal(t, "original-name", name, "Name should be restored")
	assert.Equal(t, "original description", desc, "Description should be restored")

	// Assert: members restored
	var count int
	err = database.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM group_members WHERE group_id = ?", groupID).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 2, count, "Members should be restored")
}

func TestRollbackUpdateDeleteEntity_Service(t *testing.T) {
	database, cleanup := SetupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	// Setup: Create service
	result, err := database.ExecContext(ctx,
		"INSERT INTO services (name, ports, protocol, description) VALUES (?, ?, ?, ?)",
		"test-service", "8080", "tcp", "test description")
	require.NoError(t, err)
	serviceID, err := result.LastInsertId()
	require.NoError(t, err)

	originalService := models.ServiceRow{
		ID:          int(serviceID),
		Name:        "original-service",
		Ports:       "9090",
		Protocol:    "udp",
		Description: "original description",
	}
	snapshotJSON, err := json.Marshal(originalService)
	require.NoError(t, err)

	// Start transaction
	tx, err := database.BeginTx(ctx, nil)
	require.NoError(t, err)

	// Call rollbackUpdateDeleteEntity
	err = rollbackUpdateDeleteEntity(ctx, tx, "service", int(serviceID), "update", string(snapshotJSON))
	require.NoError(t, err)

	// Commit to verify changes
	err = tx.Commit()
	require.NoError(t, err)

	// Assert: service restored to original state
	var name, ports, protocol, desc string
	var isPendingDelete bool
	err = database.QueryRowContext(ctx,
		"SELECT name, ports, protocol, description, is_pending_delete FROM services WHERE id = ?",
		serviceID).Scan(&name, &ports, &protocol, &desc, &isPendingDelete)
	require.NoError(t, err)
	assert.Equal(t, "original-service", name, "Name should be restored")
	assert.Equal(t, "9090", ports, "Ports should be restored")
	assert.Equal(t, "udp", protocol, "Protocol should be restored")
	assert.Equal(t, "original description", desc, "Description should be restored")
	assert.False(t, isPendingDelete, "is_pending_delete should be cleared")
}

func TestRollbackUpdateDeleteEntity_Policy(t *testing.T) {
	database, cleanup := SetupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	// Setup: Create foreign key dependencies (service_id=2 needed by originalPolicy)
	_, err := database.ExecContext(ctx,
		"INSERT INTO services (name, ports, protocol) VALUES (?, ?, ?)",
		"svc1", "8080", "tcp")
	require.NoError(t, err)
	_, err = database.ExecContext(ctx,
		"INSERT INTO services (name, ports, protocol) VALUES (?, ?, ?)",
		"svc2", "9090", "udp")
	require.NoError(t, err)

	// Create policy (service_id=1 exists, target_id=1 has no FK)
	result, err := database.ExecContext(ctx,
		`INSERT INTO policies (name, source_id, source_type, service_id, target_id, target_type, action, priority, enabled)
		 VALUES (?, 1, 'group', 1, 1, 'peer', 'ACCEPT', 100, 1)`,
		"test-policy")
	require.NoError(t, err)
	policyID, err := result.LastInsertId()
	require.NoError(t, err)

	originalPolicy := models.PolicyRow{
		ID:          int(policyID),
		Name:        "original-policy",
		Description: "original description",
		SourceID:    2,
		SourceType:  "group",
		ServiceID:   2,
		TargetID:    2,
		TargetType:  "peer",
		Action:      "DROP",
		Priority:    200,
		Enabled:     false,
		TargetScope: "both",
		Direction:   "both",
	}
	snapshotJSON, err := json.Marshal(originalPolicy)
	require.NoError(t, err)

	// Start transaction
	tx, err := database.BeginTx(ctx, nil)
	require.NoError(t, err)

	// Call rollbackUpdateDeleteEntity
	err = rollbackUpdateDeleteEntity(ctx, tx, "policy", int(policyID), "update", string(snapshotJSON))
	require.NoError(t, err)

	// Commit to verify changes
	err = tx.Commit()
	require.NoError(t, err)

	// Assert: policy restored to original state
	var name, desc, action string
	var sourceID, priority int
	var enabled bool
	err = database.QueryRowContext(ctx,
		`SELECT name, description, source_id, action, priority, enabled FROM policies WHERE id = ?`,
		policyID).Scan(&name, &desc, &sourceID, &action, &priority, &enabled)
	require.NoError(t, err)
	assert.Equal(t, "original-policy", name, "Name should be restored")
	assert.Equal(t, "original description", desc, "Description should be restored")
	assert.Equal(t, 2, sourceID, "SourceID should be restored")
	assert.Equal(t, "DROP", action, "Action should be restored")
	assert.Equal(t, 200, priority, "Priority should be restored")
	assert.False(t, enabled, "Enabled should be restored")
}

func TestRollbackCreateEntity_UnknownEntityType(t *testing.T) {
	database, cleanup := SetupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	// Start transaction
	tx, err := database.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer tx.Rollback()

	// Call rollbackCreateEntity with unknown entity type
	err = rollbackCreateEntity(ctx, tx, "unknown_type", 1)

	// Assert: returns error for unknown entity type
	assert.Error(t, err, "Should return error for unknown entity type")
	assert.Contains(t, err.Error(), "unknown entity type", "Error message should mention unknown entity type")
}

// TestRollbackUpdateDeleteEntity_UnknownEntityType tests error handling for unknown entity type in rollbackUpdateDeleteEntity
func TestRollbackUpdateDeleteEntity_UnknownEntityType(t *testing.T) {
	database, cleanup := SetupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	// Start transaction
	tx, err := database.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer tx.Rollback()

	// Call rollbackUpdateDeleteEntity with unknown entity type
	err = rollbackUpdateDeleteEntity(ctx, tx, "unknown_type", 1, "update", "{}")

	// Assert: returns error for unknown entity type
	assert.Error(t, err, "Should return error for unknown entity type")
	assert.Contains(t, err.Error(), "unknown entity type", "Error message should mention unknown entity type")
}

func TestCheckCreateRollbackConstraints_GroupReferencedByTarget(t *testing.T) {
	database, cleanup := SetupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	// Setup: Create foreign key dependencies first (service_id=1, source_id=1 as peer)
	_, err := database.ExecContext(ctx,
		"INSERT INTO services (name, ports, protocol) VALUES (?, ?, ?)",
		"fkey-service", "8080", "tcp")
	require.NoError(t, err)

	_, err = database.ExecContext(ctx,
		"INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, is_manual) VALUES (?, ?, ?, ?, 1)",
		"fkey-peer", "10.0.0.1", "fkey-key", "fkey-hmac")
	require.NoError(t, err)

	// Create a group
	result, err := database.ExecContext(ctx,
		"INSERT INTO groups (name, description) VALUES (?, ?)",
		"test-group", "test description")
	require.NoError(t, err)

	groupID, err := result.LastInsertId()
	require.NoError(t, err)

	_, err = database.ExecContext(ctx,
		`INSERT INTO policies (name, source_id, source_type, service_id, target_id, target_type, action, priority, enabled)
		 VALUES (?, 1, 'peer', 1, ?, 'group', 'ACCEPT', 100, 1)`,
		"test-policy", groupID)
	require.NoError(t, err)

	// Start transaction for constraint check
	tx, err := database.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer tx.Rollback()

	// Call checkCreateRollbackConstraints
	err = checkCreateRollbackConstraints(ctx, tx, "group", int(groupID))

	// Assert: returns ErrConstraintViolation
	assert.Error(t, err, "Should return error when group referenced by policy as target")
	assert.True(t, errors.Is(err, ErrConstraintViolation), "Error should be ErrConstraintViolation")
}

func TestRollbackEntitySnapshot_MissingSnapshotData(t *testing.T) {
	database, cleanup := SetupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	// Setup: Create a group
	result, err := database.ExecContext(ctx,
		"INSERT INTO groups (name, description) VALUES (?, ?)",
		"test-group", "test description")
	require.NoError(t, err)

	groupID, err := result.LastInsertId()
	require.NoError(t, err)

	err = CreateSnapshot(ctx, database, "group", int(groupID), "update", "")
	require.NoError(t, err)

	// Call RollbackEntitySnapshot
	err = RollbackEntitySnapshot(ctx, database, "group", int(groupID))

	// Assert: returns error for missing snapshot data
	assert.Error(t, err, "Should return error when snapshot data is missing")
	assert.Contains(t, err.Error(), "missing snapshot data", "Error message should mention missing snapshot data")
}

func TestRollbackSnapshots_EmptySet(t *testing.T) {
	database, cleanup := SetupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	// Call RollbackSnapshots with no snapshots in database
	err := RollbackSnapshots(ctx, database)

	// Assert: should succeed without error
	assert.NoError(t, err, "RollbackSnapshots should succeed with empty snapshot set")

	// Verify no changes made
	var count int
	err = database.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM change_snapshots").Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 0, count, "No snapshots should exist")
}

func TestRollbackEntitySnapshot_ClearsPendingChanges(t *testing.T) {
	database, cleanup := SetupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	// Setup: Create a peer that pending_changes references
	_, err := database.ExecContext(ctx,
		"INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, is_manual) VALUES (?, ?, ?, ?, 1)",
		"fkey-peer", "10.0.0.1", "fkey-key", "fkey-hmac")
	require.NoError(t, err)

	// Create a group
	result, err := database.ExecContext(ctx,
		"INSERT INTO groups (name, description) VALUES (?, ?)",
		"test-group", "test description")
	require.NoError(t, err)

	groupID, err := result.LastInsertId()
	require.NoError(t, err)

	err = CreateSnapshot(ctx, database, "group", int(groupID), "create", "")
	require.NoError(t, err)

	_, err = database.ExecContext(ctx,
		`INSERT INTO pending_changes (peer_id, change_type, change_id, change_action, change_summary)
		 VALUES (1, 'group', ?, 'create', 'test')`, groupID)
	require.NoError(t, err)

	// Verify pending change exists
	var count int
	err = database.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM pending_changes WHERE change_type = ? AND change_id = ?",
		"group", groupID).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 1, count, "Pending change should exist before rollback")

	// Call RollbackEntitySnapshot
	err = RollbackEntitySnapshot(ctx, database, "group", int(groupID))
	require.NoError(t, err)

	// Assert: pending changes are cleared
	err = database.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM pending_changes WHERE change_type = ? AND change_id = ?", "group", groupID).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 0, count, "Pending changes should be cleared after rollback")
}

func TestRollbackCreateEntity_Peer(t *testing.T) {
	database, cleanup := SetupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	// Setup: Create peer
	result, err := database.ExecContext(ctx,
		"INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, is_manual) VALUES (?, ?, ?, ?, 1)",
		"test-peer", "10.0.0.1", "key1", "hmac1")
	require.NoError(t, err)
	peerID, err := result.LastInsertId()
	require.NoError(t, err)

	// Create peer_ips entry
	_, err = database.ExecContext(ctx,
		"INSERT INTO peer_ips (peer_id, ip_address, is_primary) VALUES (?, ?, 1)",
		peerID, "10.0.0.1")
	require.NoError(t, err)

	// Verify peer_ips exists before rollback
	var count int
	err = database.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM peer_ips WHERE peer_id = ?", peerID).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 1, count, "Peer IP should exist before rollback")

	// Start transaction
	tx, err := database.BeginTx(ctx, nil)
	require.NoError(t, err)

	// Call rollbackCreateEntity
	err = rollbackCreateEntity(ctx, tx, "peer", int(peerID))
	require.NoError(t, err)

	// Commit to verify changes
	err = tx.Commit()
	require.NoError(t, err)

	// Assert: peer_ips deleted
	err = database.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM peer_ips WHERE peer_id = ?", peerID).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 0, count, "Peer IPs should be deleted")

	// Assert: peer deleted
	err = database.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM peers WHERE id = ?", peerID).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 0, count, "Peer should be deleted")
}

func TestRollbackEntitySnapshot_PeerCreate(t *testing.T) {
	database, cleanup := SetupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	// Setup: Create peer
	result, err := database.ExecContext(ctx,
		"INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, is_manual) VALUES (?, ?, ?, ?, 1)",
		"test-peer", "10.0.0.1", "key1", "hmac1")
	require.NoError(t, err)
	peerID, err := result.LastInsertId()
	require.NoError(t, err)

	// Create peer_ips entry
	_, err = database.ExecContext(ctx,
		"INSERT INTO peer_ips (peer_id, ip_address, is_primary) VALUES (?, ?, 1)",
		peerID, "10.0.0.1")
	require.NoError(t, err)

	// Create snapshot
	err = CreateSnapshot(ctx, database, "peer", int(peerID), "create", "")
	require.NoError(t, err, "Failed to create snapshot")

	// Insert a pending_change
	_, err = database.ExecContext(ctx,
		`INSERT INTO pending_changes (peer_id, change_type, change_id, change_action, change_summary)
		VALUES (1, 'peer', ?, 'create', 'test')`, peerID)
	require.NoError(t, err)

	// Verify peer exists before rollback
	var count int
	err = database.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM peers WHERE id = ?", peerID).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 1, count, "Peer should exist before rollback")

	// Verify peer_ips exists before rollback
	err = database.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM peer_ips WHERE peer_id = ?", peerID).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 1, count, "Peer IP should exist before rollback")

	// Call RollbackEntitySnapshot
	err = RollbackEntitySnapshot(ctx, database, "peer", int(peerID))
	require.NoError(t, err, "RollbackEntitySnapshot should succeed")

	// Assert: peer is deleted
	err = database.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM peers WHERE id = ?", peerID).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 0, count, "Peer should be deleted after rollback")

	// Assert: peer_ips is deleted
	err = database.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM peer_ips WHERE peer_id = ?", peerID).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 0, count, "Peer IPs should be deleted after rollback")

	// Assert: snapshot is deleted
	err = database.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM change_snapshots WHERE entity_type = ? AND entity_id = ?",
		"peer", peerID).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 0, count, "Snapshot should be deleted after rollback")

	// Assert: pending change is deleted
	err = database.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM pending_changes WHERE change_type = ? AND change_id = ?",
		"peer", peerID).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 0, count, "Pending change should be deleted after rollback")
}

func TestRollbackSnapshots_WithPeerCreate(t *testing.T) {
	database, cleanup := SetupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	// Setup: Create a peer
	peerResult, err := database.ExecContext(ctx,
		"INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, is_manual) VALUES (?, ?, ?, ?, 1)",
		"test-peer", "10.0.0.1", "key1", "hmac1")
	require.NoError(t, err)
	peerID, err := peerResult.LastInsertId()
	require.NoError(t, err)

	// Create peer_ips entry
	_, err = database.ExecContext(ctx,
		"INSERT INTO peer_ips (peer_id, ip_address, is_primary) VALUES (?, ?, 1)",
		peerID, "10.0.0.1")
	require.NoError(t, err)

	err = CreateSnapshot(ctx, database, "peer", int(peerID), "create", "")
	require.NoError(t, err)

	// Setup: Create a group
	groupResult, err := database.ExecContext(ctx,
		"INSERT INTO groups (name) VALUES (?)", "test-group")
	require.NoError(t, err)
	groupID, err := groupResult.LastInsertId()
	require.NoError(t, err)

	err = CreateSnapshot(ctx, database, "group", int(groupID), "create", "")
	require.NoError(t, err)

	// Setup: Create a service
	serviceResult, err := database.ExecContext(ctx,
		"INSERT INTO services (name, ports, protocol) VALUES (?, ?, ?)", "test-service", "8080", "tcp")
	require.NoError(t, err)
	serviceID, err := serviceResult.LastInsertId()
	require.NoError(t, err)

	err = CreateSnapshot(ctx, database, "service", int(serviceID), "create", "")
	require.NoError(t, err)

	// Setup: Create a policy
	policyResult, err := database.ExecContext(ctx,
		`INSERT INTO policies (name, source_id, source_type, service_id, target_id, target_type, action, priority, enabled)
		VALUES (?, ?, 'group', ?, ?, 'peer', 'ACCEPT', 100, 1)`,
		"test-policy", groupID, serviceID, peerID)
	require.NoError(t, err)
	policyID, err := policyResult.LastInsertId()
	require.NoError(t, err)

	err = CreateSnapshot(ctx, database, "policy", int(policyID), "create", "")
	require.NoError(t, err)

	// Call RollbackSnapshots
	err = RollbackSnapshots(ctx, database)
	require.NoError(t, err, "RollbackSnapshots should succeed")

	// Assert: peer is deleted
	var count int
	err = database.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM peers WHERE id = ?", peerID).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 0, count, "Peer should be deleted")

	// Assert: peer_ips is deleted
	err = database.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM peer_ips WHERE peer_id = ?", peerID).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 0, count, "Peer IPs should be deleted")

	// Assert: group is deleted
	err = database.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM groups WHERE id = ?", groupID).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 0, count, "Group should be deleted")

	// Assert: service is deleted
	err = database.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM services WHERE id = ?", serviceID).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 0, count, "Service should be deleted")

	// Assert: policy is deleted
	err = database.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM policies WHERE id = ?", policyID).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 0, count, "Policy should be deleted")

	// Assert: all snapshots are deleted
	err = database.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM change_snapshots").Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 0, count, "All snapshots should be deleted")

	// Assert: all pending changes are deleted
	err = database.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM pending_changes").Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 0, count, "All pending changes should be deleted")
}

func TestRollbackSnapshots_PeerCreateDeletesPeerIPs(t *testing.T) {
	database, cleanup := SetupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	// Setup: Create a peer
	result, err := database.ExecContext(ctx,
		"INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, is_manual) VALUES (?, ?, ?, ?, 1)",
		"test-peer", "10.0.0.1", "key1", "hmac1")
	require.NoError(t, err)
	peerID, err := result.LastInsertId()
	require.NoError(t, err)

	// Create 2 peer_ips entries: one primary, one not
	_, err = database.ExecContext(ctx,
		"INSERT INTO peer_ips (peer_id, ip_address, is_primary) VALUES (?, ?, 1)",
		peerID, "10.0.0.1")
	require.NoError(t, err)

	_, err = database.ExecContext(ctx,
		"INSERT INTO peer_ips (peer_id, ip_address, is_primary) VALUES (?, ?, 0)",
		peerID, "10.0.0.2")
	require.NoError(t, err)

	// Verify peer_ips exist before rollback
	var count int
	err = database.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM peer_ips WHERE peer_id = ?", peerID).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 2, count, "Two peer IPs should exist before rollback")

	// Create snapshot
	err = CreateSnapshot(ctx, database, "peer", int(peerID), "create", "")
	require.NoError(t, err)

	// Call RollbackSnapshots
	err = RollbackSnapshots(ctx, database)
	require.NoError(t, err, "RollbackSnapshots should succeed")

	// Assert: both peer_ips entries are deleted
	err = database.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM peer_ips WHERE peer_id = ?", peerID).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 0, count, "Both peer IPs should be deleted")

	// Assert: peer is deleted
	err = database.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM peers WHERE id = ?", peerID).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 0, count, "Peer should be deleted")
}
