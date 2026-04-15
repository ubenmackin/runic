package db

import (
	"context"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

// TestAddPendingChange tests the AddPendingChange function.
func TestAddPendingChange(t *testing.T) {
	db, cleanup := SetupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	// Insert required peer for foreign key
	_, err := db.Exec(`INSERT INTO peers (id, hostname, ip_address, agent_key, hmac_key, status) VALUES (1, 'peer1', '10.0.0.1', 'key1', 'hmac1', 'online')`)
	if err != nil {
		t.Fatalf("Failed to insert peer: %v", err)
	}

	// Test successful add
	err = AddPendingChange(ctx, db, 1, "policy", "create", 100, "Added policy rule")
	if err != nil {
		t.Fatalf("AddPendingChange failed: %v", err)
	}

	// Verify the pending change was inserted
	var count int
	err = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM pending_changes WHERE peer_id = 1").Scan(&count)
	if err != nil {
		t.Fatalf("Failed to query pending changes: %v", err)
	}
	if count != 1 {
		t.Fatalf("Expected 1 pending change, got %d", count)
	}

	// Test database failure (use a closed database)
	err = AddPendingChange(ctx, db, 1, "policy", "update", 101, "Updated policy")
	if err != nil {
		t.Fatalf("AddPendingChange should not fail on valid input: %v", err)
	}
}

// TestAddPendingChange_DBError tests AddPendingChange with a closed database.
func TestAddPendingChange_DBError(t *testing.T) {
	db, cleanup := SetupTestDB(t)

	// Close the database to simulate failure
	db.Close()
	cleanup()

	ctx := context.Background()
	err := AddPendingChange(ctx, db, 1, "policy", "create", 100, "Added policy rule")
	if err == nil {
		t.Fatal("Expected error when database is closed")
	}
}

// TestGetPendingChangesForPeer tests the GetPendingChangesForPeer function.
func TestGetPendingChangesForPeer(t *testing.T) {
	db, cleanup := SetupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	// Insert required peers for foreign key
	_, err := db.Exec(`INSERT INTO peers (id, hostname, ip_address, agent_key, hmac_key, status) VALUES (1, 'peer1', '10.0.0.1', 'key1', 'hmac1', 'online'), (2, 'peer2', '10.0.0.2', 'key2', 'hmac2', 'online')`)
	if err != nil {
		t.Fatalf("Failed to insert peers: %v", err)
	}

	// Add multiple pending changes
	err = AddPendingChange(ctx, db, 1, "policy", "create", 100, "Policy create 1")
	if err != nil {
		t.Fatalf("AddPendingChange failed: %v", err)
	}
	err = AddPendingChange(ctx, db, 1, "group", "update", 101, "Group update 1")
	if err != nil {
		t.Fatalf("AddPendingChange failed: %v", err)
	}
	err = AddPendingChange(ctx, db, 1, "service", "delete", 102, "Service delete 1")
	if err != nil {
		t.Fatalf("AddPendingChange failed: %v", err)
	}

	// Add changes for another peer
	err = AddPendingChange(ctx, db, 2, "policy", "create", 200, "Policy create 2")
	if err != nil {
		t.Fatalf("AddPendingChange failed: %v", err)
	}

	// Test getting pending changes for peer 1
	changes, err := GetPendingChangesForPeer(ctx, db, 1)
	if err != nil {
		t.Fatalf("GetPendingChangesForPeer failed: %v", err)
	}

	if len(changes) != 3 {
		t.Fatalf("Expected 3 pending changes for peer 1, got %d", len(changes))
	}

	// Verify ordering (created_at ASC)
	if changes[0].ChangeID != 100 {
		t.Errorf("Expected first change ID to be 100, got %d", changes[0].ChangeID)
	}
	if changes[1].ChangeID != 101 {
		t.Errorf("Expected second change ID to be 101, got %d", changes[1].ChangeID)
	}
	if changes[2].ChangeID != 102 {
		t.Errorf("Expected third change ID to be 102, got %d", changes[2].ChangeID)
	}

	// Test getting pending changes for peer 2
	changes2, err := GetPendingChangesForPeer(ctx, db, 2)
	if err != nil {
		t.Fatalf("GetPendingChangesForPeer failed: %v", err)
	}
	if len(changes2) != 1 {
		t.Fatalf("Expected 1 pending change for peer 2, got %d", len(changes2))
	}

	// Test getting pending changes for peer with no changes
	changesEmpty, err := GetPendingChangesForPeer(ctx, db, 999)
	if err != nil {
		t.Fatalf("GetPendingChangesForPeer failed: %v", err)
	}
	if len(changesEmpty) != 0 {
		t.Fatalf("Expected 0 pending changes for non-existent peer, got %d", len(changesEmpty))
	}
}

// TestGetPendingChangesForPeer_DBError tests GetPendingChangesForPeer with a closed database.
func TestGetPendingChangesForPeer_DBError(t *testing.T) {
	db, cleanup := SetupTestDB(t)
	db.Close()
	cleanup()

	ctx := context.Background()
	_, err := GetPendingChangesForPeer(ctx, db, 1)
	if err == nil {
		t.Fatal("Expected error when database is closed")
	}
}

// TestClearPendingChangesForPeer tests the ClearPendingChangesForPeer function.
func TestClearPendingChangesForPeer(t *testing.T) {
	db, cleanup := SetupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	// Insert required peers for foreign key
	_, err := db.Exec(`INSERT INTO peers (id, hostname, ip_address, agent_key, hmac_key, status) VALUES (1, 'peer1', '10.0.0.1', 'key1', 'hmac1', 'online'), (2, 'peer2', '10.0.0.2', 'key2', 'hmac2', 'online')`)
	if err != nil {
		t.Fatalf("Failed to insert peers: %v", err)
	}

	// Add pending changes
	err = AddPendingChange(ctx, db, 1, "policy", "create", 100, "Policy 1")
	if err != nil {
		t.Fatalf("AddPendingChange failed: %v", err)
	}
	err = AddPendingChange(ctx, db, 1, "group", "update", 101, "Group 1")
	if err != nil {
		t.Fatalf("AddPendingChange failed: %v", err)
	}
	err = AddPendingChange(ctx, db, 2, "policy", "create", 200, "Policy 2")
	if err != nil {
		t.Fatalf("AddPendingChange failed: %v", err)
	}

	// Clear pending changes for peer 1
	err = ClearPendingChangesForPeer(ctx, db, 1)
	if err != nil {
		t.Fatalf("ClearPendingChangesForPeer failed: %v", err)
	}

	// Verify peer 1 has no pending changes
	changes, err := GetPendingChangesForPeer(ctx, db, 1)
	if err != nil {
		t.Fatalf("GetPendingChangesForPeer failed: %v", err)
	}
	if len(changes) != 0 {
		t.Fatalf("Expected 0 pending changes for peer 1, got %d", len(changes))
	}

	// Verify peer 2 still has pending changes
	changes2, err := GetPendingChangesForPeer(ctx, db, 2)
	if err != nil {
		t.Fatalf("GetPendingChangesForPeer failed: %v", err)
	}
	if len(changes2) != 1 {
		t.Fatalf("Expected 1 pending change for peer 2, got %d", len(changes2))
	}

	// Clear pending changes for non-existent peer (should not error)
	err = ClearPendingChangesForPeer(ctx, db, 999)
	if err != nil {
		t.Fatalf("ClearPendingChangesForPeer should not fail for non-existent peer: %v", err)
	}
}

// TestClearPendingChangesForPeer_DBError tests ClearPendingChangesForPeer with a closed database.
func TestClearPendingChangesForPeer_DBError(t *testing.T) {
	db, cleanup := SetupTestDB(t)
	db.Close()
	cleanup()

	ctx := context.Background()
	err := ClearPendingChangesForPeer(ctx, db, 1)
	if err == nil {
		t.Fatal("Expected error when database is closed")
	}
}

// TestGetPeersWithPendingChanges tests the GetPeersWithPendingChanges function.
func TestGetPeersWithPendingChanges(t *testing.T) {
	db, cleanup := SetupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	// Insert required peers for foreign key
	_, err := db.Exec(`INSERT INTO peers (id, hostname, ip_address, agent_key, hmac_key, status) VALUES (1, 'peer1', '10.0.0.1', 'key1', 'hmac1', 'online'), (2, 'peer2', '10.0.0.2', 'key2', 'hmac2', 'online'), (3, 'peer3', '10.0.0.3', 'key3', 'hmac3', 'online')`)
	if err != nil {
		t.Fatalf("Failed to insert peers: %v", err)
	}

	// Add pending changes for multiple peers
	err = AddPendingChange(ctx, db, 1, "policy", "create", 100, "Policy 1")
	if err != nil {
		t.Fatalf("AddPendingChange failed: %v", err)
	}
	err = AddPendingChange(ctx, db, 1, "group", "update", 101, "Group 1")
	if err != nil {
		t.Fatalf("AddPendingChange failed: %v", err)
	}
	err = AddPendingChange(ctx, db, 2, "policy", "create", 200, "Policy 2")
	if err != nil {
		t.Fatalf("AddPendingChange failed: %v", err)
	}
	err = AddPendingChange(ctx, db, 3, "service", "delete", 300, "Service 3")
	if err != nil {
		t.Fatalf("AddPendingChange failed: %v", err)
	}

	// Test getting peers with pending changes
	peers, err := GetPeersWithPendingChanges(ctx, db)
	if err != nil {
		t.Fatalf("GetPeersWithPendingChanges failed: %v", err)
	}

	if len(peers) != 3 {
		t.Fatalf("Expected 3 peers with pending changes, got %d", len(peers))
	}

	// Verify they're distinct
	peerSet := make(map[int]bool)
	for _, p := range peers {
		peerSet[p] = true
	}
	if len(peerSet) != 3 {
		t.Fatalf("Expected 3 distinct peers, got %d", len(peerSet))
	}

	// Clear all pending changes and verify empty result
	err = ClearPendingChangesForPeer(ctx, db, 1)
	if err != nil {
		t.Fatalf("ClearPendingChangesForPeer failed: %v", err)
	}
	err = ClearPendingChangesForPeer(ctx, db, 2)
	if err != nil {
		t.Fatalf("ClearPendingChangesForPeer failed: %v", err)
	}
	err = ClearPendingChangesForPeer(ctx, db, 3)
	if err != nil {
		t.Fatalf("ClearPendingChangesForPeer failed: %v", err)
	}

	peersEmpty, err := GetPeersWithPendingChanges(ctx, db)
	if err != nil {
		t.Fatalf("GetPeersWithPendingChanges failed: %v", err)
	}
	if len(peersEmpty) != 0 {
		t.Fatalf("Expected 0 peers with pending changes, got %d", len(peersEmpty))
	}
}

// TestGetPeersWithPendingChanges_DBError tests GetPeersWithPendingChanges with a closed database.
func TestGetPeersWithPendingChanges_DBError(t *testing.T) {
	db, cleanup := SetupTestDB(t)
	db.Close()
	cleanup()

	ctx := context.Background()
	_, err := GetPeersWithPendingChanges(ctx, db)
	if err == nil {
		t.Fatal("Expected error when database is closed")
	}
}

// TestSavePendingBundlePreview tests the SavePendingBundlePreview function.
func TestSavePendingBundlePreview(t *testing.T) {
	db, cleanup := SetupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	// Insert required peer for foreign key
	_, err := db.Exec(`INSERT INTO peers (id, hostname, ip_address, agent_key, hmac_key, status) VALUES (1, 'peer1', '10.0.0.1', 'key1', 'hmac1', 'online')`)
	if err != nil {
		t.Fatalf("Failed to insert peer: %v", err)
	}

	// Test insert
	err = SavePendingBundlePreview(ctx, db, 1, "rules content", "diff content", "version-hash-1")
	if err != nil {
		t.Fatalf("SavePendingBundlePreview (insert) failed: %v", err)
	}

	// Verify the bundle preview was inserted
	var peerID int
	var rulesContent, diffContent, versionHash string
	err = db.QueryRowContext(ctx, "SELECT peer_id, rules_content, diff_content, version_hash FROM pending_bundle_previews WHERE peer_id = 1").Scan(&peerID, &rulesContent, &diffContent, &versionHash)
	if err != nil {
		t.Fatalf("Failed to query bundle preview: %v", err)
	}
	if peerID != 1 {
		t.Errorf("Expected peer ID 1, got %d", peerID)
	}
	if rulesContent != "rules content" {
		t.Errorf("Expected rules content, got %s", rulesContent)
	}
	if diffContent != "diff content" {
		t.Errorf("Expected diff content, got %s", diffContent)
	}
	if versionHash != "version-hash-1" {
		t.Errorf("Expected version hash, got %s", versionHash)
	}

	// Test update (upsert)
	err = SavePendingBundlePreview(ctx, db, 1, "updated rules", "updated diff", "version-hash-2")
	if err != nil {
		t.Fatalf("SavePendingBundlePreview (update) failed: %v", err)
	}

	// Verify the bundle preview was updated
	err = db.QueryRowContext(ctx, "SELECT peer_id, rules_content, diff_content, version_hash FROM pending_bundle_previews WHERE peer_id = 1").Scan(&peerID, &rulesContent, &diffContent, &versionHash)
	if err != nil {
		t.Fatalf("Failed to query bundle preview: %v", err)
	}
	if rulesContent != "updated rules" {
		t.Errorf("Expected updated rules content, got %s", rulesContent)
	}
	if versionHash != "version-hash-2" {
		t.Errorf("Expected updated version hash, got %s", versionHash)
	}
}

// TestSavePendingBundlePreview_DBError tests SavePendingBundlePreview with a closed database.
func TestSavePendingBundlePreview_DBError(t *testing.T) {
	db, cleanup := SetupTestDB(t)
	db.Close()
	cleanup()

	ctx := context.Background()
	err := SavePendingBundlePreview(ctx, db, 1, "rules", "diff", "hash")
	if err == nil {
		t.Fatal("Expected error when database is closed")
	}
}

// TestDeletePendingBundlePreview tests the DeletePendingBundlePreview function.
func TestDeletePendingBundlePreview(t *testing.T) {
	db, cleanup := SetupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	// Insert required peer for foreign key
	_, err := db.Exec(`INSERT INTO peers (id, hostname, ip_address, agent_key, hmac_key, status) VALUES (1, 'peer1', '10.0.0.1', 'key1', 'hmac1', 'online')`)
	if err != nil {
		t.Fatalf("Failed to insert peer: %v", err)
	}

	// Add a bundle preview
	err = SavePendingBundlePreview(ctx, db, 1, "rules content", "diff content", "version-hash-1")
	if err != nil {
		t.Fatalf("SavePendingBundlePreview failed: %v", err)
	}

	// Delete the bundle preview
	err = DeletePendingBundlePreview(ctx, db, 1)
	if err != nil {
		t.Fatalf("DeletePendingBundlePreview failed: %v", err)
	}

	// Verify it's deleted
	var count int
	err = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM pending_bundle_previews WHERE peer_id = 1").Scan(&count)
	if err != nil {
		t.Fatalf("Failed to count pending_bundle_previews: %v", err)
	}
	if count != 0 {
		t.Fatalf("Expected 0 pending bundle previews after deletion, got %d", count)
	}

	// Delete non-existent peer (should not error)
	err = DeletePendingBundlePreview(ctx, db, 999)
	if err != nil {
		t.Fatalf("DeletePendingBundlePreview should not fail for non-existent peer: %v", err)
	}
}

// TestDeletePendingBundlePreview_DBError tests DeletePendingBundlePreview with a closed database.
func TestDeletePendingBundlePreview_DBError(t *testing.T) {
	db, cleanup := SetupTestDB(t)
	db.Close()
	cleanup()

	ctx := context.Background()
	err := DeletePendingBundlePreview(ctx, db, 1)
	if err == nil {
		t.Fatal("Expected error when database is closed")
	}
}
