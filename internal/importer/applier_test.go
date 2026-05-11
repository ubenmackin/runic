package importer

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"runic/internal/api/common"
	"runic/internal/db"
	"runic/internal/testutil"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupImportSession creates a test import session with all required staging data:
// - An importing peer (referenced by import_sessions.peer_id)
// - An import session in 'reviewing' status
// - A staging peer mapping (new peer to be created)
// - A staging group mapping (new group to be created)
// - A staging service mapping (new service to be created)
// - An approved import_rule referencing all staging entities
// Returns the session ID, the importing peer ID, and the staging entity IDs.
func setupImportSession(t *testing.T, database *sql.DB) (sessionID int64, peerID int64, stagingPeerID int64, stagingGroupID int64, stagingServiceID int64) {
	t.Helper()
	ctx := context.Background()

	// Create the importing peer (must exist before import_session references it)
	res, err := database.ExecContext(ctx,
		"INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)",
		"importing-peer", "10.0.0.1", "key1", "hmac1")
	require.NoError(t, err)
	peerID, err = res.LastInsertId()
	require.NoError(t, err)

	// Insert peer_ips for the importing peer
	_, err = database.ExecContext(ctx,
		"INSERT INTO peer_ips (peer_id, ip_address, is_primary) VALUES (?, ?, 1)",
		peerID, "10.0.0.1")
	require.NoError(t, err)

	// Create import session in 'reviewing' status
	res, err = database.ExecContext(ctx,
		"INSERT INTO import_sessions (peer_id, status, raw_backup, raw_ipsets) VALUES (?, 'reviewing', 'backup', '')",
		peerID)
	require.NoError(t, err)
	sessionID, err = res.LastInsertId()
	require.NoError(t, err)

	// Create staging peer mapping (existing_peer_id IS NULL → new peer)
	res, err = database.ExecContext(ctx,
		"INSERT INTO import_peer_mappings (session_id, ip_address, hostname, status) VALUES (?, ?, ?, 'approved')",
		sessionID, "192.168.1.100", "imported-peer")
	require.NoError(t, err)
	stagingPeerID, err = res.LastInsertId()
	require.NoError(t, err)

	// Create staging group mapping (existing_group_id IS NULL → new group)
	res, err = database.ExecContext(ctx,
		"INSERT INTO import_group_mappings (session_id, group_name, member_ips, member_peer_ids, member_staging_peer_ids, status) VALUES (?, ?, ?, ?, ?, 'approved')",
		sessionID, "imported-group", "[\"192.168.1.100\"]", "[]", "[]")
	require.NoError(t, err)
	stagingGroupID, err = res.LastInsertId()
	require.NoError(t, err)

	// Create staging service mapping (existing_service_id IS NULL → new service)
	res, err = database.ExecContext(ctx,
		"INSERT INTO import_service_mappings (session_id, name, ports, source_ports, protocol, direction_hint, status) VALUES (?, ?, ?, ?, ?, ?, 'approved')",
		sessionID, "imported-service", "443", "", "tcp", "inbound")
	require.NoError(t, err)
	stagingServiceID, err = res.LastInsertId()
	require.NoError(t, err)

	// Create an approved import_rule referencing the staging entities
	_, err = database.ExecContext(ctx,
		`INSERT INTO import_rules (session_id, chain, rule_order, raw_rule, status,
			source_type, source_staging_id, target_type, target_staging_id,
			service_staging_id, action, priority, direction, target_scope, policy_name, enabled)
		VALUES (?, 'INPUT', 1, '-A INPUT ...', 'approved',
			'peer', ?, 'group', ?,
			?, 'ACCEPT', 100, 'both', 'both', 'test-policy', 1)`,
		sessionID, stagingPeerID, stagingGroupID, stagingServiceID)
	require.NoError(t, err)

	return sessionID, peerID, stagingPeerID, stagingGroupID, stagingServiceID
}

func TestApplySession_CreatesSnapshots(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()
	database.Exec("PRAGMA foreign_keys=OFF")

	sessionID, _, _, _, _ := setupImportSession(t, database)

	ctx := context.Background()
	result, err := ApplySession(ctx, database, sessionID, nil)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Verify that the result reports the correct counts
	assert.Equal(t, 1, result.PeersCreated, "should create 1 peer")
	assert.Equal(t, 1, result.GroupsCreated, "should create 1 group")
	assert.Equal(t, 1, result.ServicesCreated, "should create 1 service")
	assert.Equal(t, 1, result.PoliciesCreated, "should create 1 policy")

	// Verify change_snapshots contains rows for all created entities
	rows, err := database.QueryContext(ctx,
		"SELECT entity_type, entity_id, action FROM change_snapshots ORDER BY entity_type, entity_id")
	require.NoError(t, err)
	defer rows.Close()

	snapshots := make(map[string][]int)
	for rows.Next() {
		var entityType, action string
		var entityID int
		require.NoError(t, rows.Scan(&entityType, &entityID, &action))
		assert.Equal(t, "create", action, "snapshot action should be 'create'")
		snapshots[entityType] = append(snapshots[entityType], entityID)
	}

	assert.Len(t, snapshots["peer"], 1, "should have 1 peer snapshot")
	assert.Len(t, snapshots["group"], 1, "should have 1 group snapshot")
	assert.Len(t, snapshots["service"], 1, "should have 1 service snapshot")
	assert.Len(t, snapshots["policy"], 1, "should have 1 policy snapshot")

	// Verify session status changed to 'applied'
	var status string
	err = database.QueryRowContext(ctx,
		"SELECT status FROM import_sessions WHERE id = ?", sessionID).Scan(&status)
	require.NoError(t, err)
	assert.Equal(t, "applied", status, "session status should be 'applied'")
}

func TestApplySession_PendingChangesWithRealEntityIDs(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()
	database.Exec("PRAGMA foreign_keys=OFF")

	sessionID, _, _, _, _ := setupImportSession(t, database)

	// Create and start a real ChangeWorker
	changeWorker := common.NewChangeWorker(nil, database)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	changeWorker.Start(ctx)
	defer changeWorker.Stop()

	result, err := ApplySession(ctx, database, sessionID, changeWorker)
	require.NoError(t, err)
	require.NotNil(t, result)
	_ = result

	// Give the async worker time to process
	time.Sleep(200 * time.Millisecond)

	// Verify pending_changes contains rows with real change_id values (not 0)
	rows, err := database.QueryContext(ctx,
		"SELECT peer_id, change_type, change_id, change_action FROM pending_changes ORDER BY id")
	require.NoError(t, err)
	defer rows.Close()

	var count int
	for rows.Next() {
		var peerID, changeID int
		var changeType, changeAction string
		require.NoError(t, rows.Scan(&peerID, &changeType, &changeID, &changeAction))
		count++

		// Verify the change_id is a real entity ID (not 0)
		assert.NotZero(t, changeID, "change_id should be a real entity ID, not 0 (type=%s)", changeType)
		assert.Equal(t, "create", changeAction, "change_action should be 'create'")
	}
	assert.Equal(t, 4, count, "should have 4 pending changes (peer, group, service, policy)")
}

func TestApplySession_PeerIPsCreated(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()
	database.Exec("PRAGMA foreign_keys=OFF")

	sessionID, _, _, _, _ := setupImportSession(t, database)

	ctx := context.Background()
	result, err := ApplySession(ctx, database, sessionID, nil)
	require.NoError(t, err)
	assert.Equal(t, 1, result.PeersCreated, "should create 1 peer")

	// Find the created manual peer
	var createdPeerID int64
	err = database.QueryRowContext(ctx,
		"SELECT id FROM peers WHERE hostname = ?", "imported-peer").Scan(&createdPeerID)
	require.NoError(t, err, "imported peer should exist in peers table")

	// Verify peer_ips contains an entry with the correct IP and is_primary=1
	var ipCount int
	err = database.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM peer_ips WHERE peer_id = ? AND ip_address = ? AND is_primary = 1",
		createdPeerID, "192.168.1.100").Scan(&ipCount)
	require.NoError(t, err)
	assert.Equal(t, 1, ipCount, "should have 1 peer_ip entry with is_primary=1 for the created peer")

	// Verify the peer is marked as manual
	var isManual bool
	err = database.QueryRowContext(ctx,
		"SELECT is_manual FROM peers WHERE id = ?", createdPeerID).Scan(&isManual)
	require.NoError(t, err)
	assert.True(t, isManual, "imported peer should be manual")
}

func TestApplySession_RollbackDeletesImportedEntities(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()
	database.Exec("PRAGMA foreign_keys=OFF")

	sessionID, _, _, _, _ := setupImportSession(t, database)

	ctx := context.Background()
	result, err := ApplySession(ctx, database, sessionID, nil)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, 1, result.PeersCreated)
	assert.Equal(t, 1, result.GroupsCreated)
	assert.Equal(t, 1, result.ServicesCreated)
	assert.Equal(t, 1, result.PoliciesCreated)

	// Verify entities exist before rollback
	var peerCount, groupCount, serviceCount, policyCount int
	require.NoError(t, database.QueryRowContext(ctx, "SELECT COUNT(*) FROM peers WHERE is_manual = 1").Scan(&peerCount))
	require.NoError(t, database.QueryRowContext(ctx, "SELECT COUNT(*) FROM groups WHERE name = 'imported-group'").Scan(&groupCount))
	require.NoError(t, database.QueryRowContext(ctx, "SELECT COUNT(*) FROM services WHERE name = 'imported-service'").Scan(&serviceCount))
	require.NoError(t, database.QueryRowContext(ctx, "SELECT COUNT(*) FROM policies WHERE name = 'test-policy'").Scan(&policyCount))
	assert.Equal(t, 1, peerCount, "manual peer should exist before rollback")
	assert.Equal(t, 1, groupCount, "imported group should exist before rollback")
	assert.Equal(t, 1, serviceCount, "imported service should exist before rollback")
	assert.Equal(t, 1, policyCount, "imported policy should exist before rollback")

	// Rollback all snapshots
	err = db.RollbackSnapshots(ctx, database)
	require.NoError(t, err, "RollbackSnapshots should succeed")

	// Verify all imported entities are deleted
	require.NoError(t, database.QueryRowContext(ctx, "SELECT COUNT(*) FROM peers WHERE is_manual = 1").Scan(&peerCount))
	require.NoError(t, database.QueryRowContext(ctx, "SELECT COUNT(*) FROM groups WHERE name = 'imported-group'").Scan(&groupCount))
	require.NoError(t, database.QueryRowContext(ctx, "SELECT COUNT(*) FROM services WHERE name = 'imported-service'").Scan(&serviceCount))
	require.NoError(t, database.QueryRowContext(ctx, "SELECT COUNT(*) FROM policies WHERE name = 'test-policy'").Scan(&policyCount))
	assert.Equal(t, 0, peerCount, "manual peer should be deleted after rollback")
	assert.Equal(t, 0, groupCount, "imported group should be deleted after rollback")
	assert.Equal(t, 0, serviceCount, "imported service should be deleted after rollback")
	assert.Equal(t, 0, policyCount, "imported policy should be deleted after rollback")

	// Verify peer_ips for the imported peer are also deleted
	var peerIPCount int
	require.NoError(t, database.QueryRowContext(ctx, "SELECT COUNT(*) FROM peer_ips WHERE ip_address = '192.168.1.100'").Scan(&peerIPCount))
	assert.Equal(t, 0, peerIPCount, "peer_ips for imported peer should be deleted after rollback")

	// Verify snapshots and pending changes are cleared
	var snapshotCount, pendingCount int
	require.NoError(t, database.QueryRowContext(ctx, "SELECT COUNT(*) FROM change_snapshots").Scan(&snapshotCount))
	require.NoError(t, database.QueryRowContext(ctx, "SELECT COUNT(*) FROM pending_changes").Scan(&pendingCount))
	assert.Equal(t, 0, snapshotCount, "all snapshots should be deleted after rollback")
	assert.Equal(t, 0, pendingCount, "all pending changes should be deleted after rollback")
}

func TestApplySession_RollbackEntitySnapshotForPolicy(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()
	database.Exec("PRAGMA foreign_keys=OFF")

	sessionID, importingPeerID, _, _, _ := setupImportSession(t, database)

	// Use a real ChangeWorker so pending_changes are created
	changeWorker := common.NewChangeWorker(nil, database)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	changeWorker.Start(ctx)
	defer changeWorker.Stop()

	result, err := ApplySession(ctx, database, sessionID, changeWorker)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, 1, result.PoliciesCreated)

	// Give the async worker time to process
	time.Sleep(200 * time.Millisecond)

	// Find the created policy ID
	var policyID int
	err = database.QueryRowContext(ctx,
		"SELECT id FROM policies WHERE name = 'test-policy'").Scan(&policyID)
	require.NoError(t, err, "imported policy should exist")

	// Verify the policy's pending change exists
	var pendingCount int
	err = database.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM pending_changes WHERE change_type = 'policy' AND change_id = ?",
		policyID).Scan(&pendingCount)
	require.NoError(t, err)
	assert.Equal(t, 1, pendingCount, "pending change for the policy should exist")

	// Verify the policy's snapshot exists
	var snapshotCount int
	err = database.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM change_snapshots WHERE entity_type = 'policy' AND entity_id = ?",
		policyID).Scan(&snapshotCount)
	require.NoError(t, err)
	assert.Equal(t, 1, snapshotCount, "snapshot for the policy should exist")

	// Rollback just the policy entity
	err = db.RollbackEntitySnapshot(ctx, database, "policy", policyID)
	require.NoError(t, err, "RollbackEntitySnapshot for policy should succeed")

	// Verify the policy is deleted
	var policyCount int
	err = database.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM policies WHERE id = ?", policyID).Scan(&policyCount)
	require.NoError(t, err)
	assert.Equal(t, 0, policyCount, "policy should be deleted after entity rollback")

	// Verify the policy's pending change is removed
	err = database.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM pending_changes WHERE change_type = 'policy' AND change_id = ?",
		policyID).Scan(&pendingCount)
	require.NoError(t, err)
	assert.Equal(t, 0, pendingCount, "pending change for the policy should be removed after entity rollback")

	// Verify the policy's snapshot is removed
	err = database.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM change_snapshots WHERE entity_type = 'policy' AND entity_id = ?",
		policyID).Scan(&snapshotCount)
	require.NoError(t, err)
	assert.Equal(t, 0, snapshotCount, "snapshot for the policy should be removed after entity rollback")

	// Verify other entities (peer, group, service) still exist
	var otherCount int
	require.NoError(t, database.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM peers WHERE is_manual = 1").Scan(&otherCount))
	assert.Equal(t, 1, otherCount, "imported peer should still exist after policy-only rollback")

	require.NoError(t, database.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM groups WHERE name = 'imported-group'").Scan(&otherCount))
	assert.Equal(t, 1, otherCount, "imported group should still exist after policy-only rollback")

	require.NoError(t, database.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM services WHERE name = 'imported-service'").Scan(&otherCount))
	assert.Equal(t, 1, otherCount, "imported service should still exist after policy-only rollback")

	// Verify the importing peer was not affected
	var importingPeerExists int
	require.NoError(t, database.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM peers WHERE id = ?", importingPeerID).Scan(&importingPeerExists))
	assert.Equal(t, 1, importingPeerExists, "importing peer should not be affected by policy rollback")
}
