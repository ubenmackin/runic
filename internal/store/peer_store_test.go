package store

import (
	"context"
	"database/sql"
	"os"
	"testing"

	"runic/internal/db"

	_ "github.com/mattn/go-sqlite3"
)

func setupTestDB(t *testing.T) (*PeerStore, func()) {
	t.Helper()
	f, err := os.CreateTemp("", "runic-store-test-*.db")
	if err != nil {
		t.Fatal(err)
	}
	dbPath := f.Name()
	if cErr := f.Close(); cErr != nil {
		t.Logf("Failed to close temp file: %v", cErr)
	}

	database, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		os.Remove(dbPath)
		t.Fatal(err)
	}

	if _, err := database.Exec("PRAGMA foreign_keys=ON"); err != nil {
		database.Close()
		os.Remove(dbPath)
		t.Fatal(err)
	}

	if _, err := database.Exec(db.Schema()); err != nil {
		database.Close()
		os.Remove(dbPath)
		t.Fatal(err)
	}

	store := NewPeerStore(db.New(database))
	cleanup := func() {
		database.Close()
		os.Remove(dbPath)
	}
	return store, cleanup
}

func getSyncStatus(t *testing.T, store *PeerStore, ctx context.Context, peerID int) string {
	t.Helper()
	peers, err := store.ListPeers(ctx)
	if err != nil {
		t.Fatalf("ListPeers failed: %v", err)
	}
	for _, p := range peers {
		if p.ID == peerID {
			return p.SyncStatus
		}
	}
	t.Fatalf("peer %d not found in ListPeers results", peerID)
	return ""
}

func TestListPeersSyncStatus(t *testing.T) {
	store, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	d := store.db

	// Step 1: Create a peer with no bundles → synced
	var peerID int
	t.Run("no bundles is synced", func(t *testing.T) {
		result, err := d.ExecContext(ctx,
			`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, is_manual) VALUES (?, ?, ?, ?, 0)`,
			"testhost", "10.0.0.1", "agent-key-1", "hmac-key-1")
		if err != nil {
			t.Fatalf("insert peer: %v", err)
		}
		id, err := result.LastInsertId()
		if err != nil {
			t.Fatalf("last insert id: %v", err)
		}
		peerID = int(id)

		status := getSyncStatus(t, store, ctx, peerID)
		if status != "synced" {
			t.Errorf("expected sync_status='synced', got '%s'", status)
		}
	})

	// Step 2: Insert pending_changes → pending
	t.Run("pending changes is pending", func(t *testing.T) {
		_, err := d.ExecContext(ctx,
			`INSERT INTO pending_changes (peer_id, change_type, change_id, change_action, change_summary) VALUES (?, ?, ?, ?, ?)`,
			peerID, "policy", 1, "create", "test change")
		if err != nil {
			t.Fatalf("insert pending change: %v", err)
		}

		status := getSyncStatus(t, store, ctx, peerID)
		if status != "pending" {
			t.Errorf("expected sync_status='pending', got '%s'", status)
		}
	})

	// Step 3: Clear pending_changes, compile a bundle (insert rule_bundle, do NOT set bundle_version) → pending_sync (applied_at is NULL)
	t.Run("bundle without applied_at is pending_sync", func(t *testing.T) {
		_, err := d.ExecContext(ctx, "DELETE FROM pending_changes WHERE peer_id = ?", peerID)
		if err != nil {
			t.Fatalf("clear pending changes: %v", err)
		}

		_, err = d.ExecContext(ctx,
			`INSERT INTO rule_bundles (peer_id, version, version_number, rules_content, hmac, created_at) VALUES (?, ?, ?, ?, ?, '2026-01-01 00:00:00')`,
			peerID, "v1-hash", 1, "rules-content-v1", "hmac-v1")
		if err != nil {
			t.Fatalf("insert rule bundle: %v", err)
		}

		status := getSyncStatus(t, store, ctx, peerID)
		if status != "pending_sync" {
			t.Errorf("expected sync_status='pending_sync', got '%s'", status)
		}
	})

	// Step 4: Simulate heartbeat (set peers.bundle_version to the old version) → still pending_sync (version mismatch)
	t.Run("heartbeat with old bundle_version is pending_sync", func(t *testing.T) {
		_, err := d.ExecContext(ctx,
			`UPDATE peers SET bundle_version = 'v0-old', last_heartbeat = CURRENT_TIMESTAMP, status = 'online' WHERE id = ?`,
			peerID)
		if err != nil {
			t.Fatalf("update peer heartbeat: %v", err)
		}

		status := getSyncStatus(t, store, ctx, peerID)
		if status != "pending_sync" {
			t.Errorf("expected sync_status='pending_sync', got '%s'", status)
		}
	})

	// Step 5: Simulate confirmation (set applied_at AND set peers.bundle_version to the new version) → synced
	t.Run("applied bundle with matching version is synced", func(t *testing.T) {
		_, err := d.ExecContext(ctx,
			`UPDATE rule_bundles SET applied_at = CURRENT_TIMESTAMP, first_applied_at = CURRENT_TIMESTAMP WHERE peer_id = ? AND version = ?`,
			peerID, "v1-hash")
		if err != nil {
			t.Fatalf("set applied_at on bundle: %v", err)
		}

		_, err = d.ExecContext(ctx,
			`UPDATE peers SET bundle_version = ? WHERE id = ?`,
			"v1-hash", peerID)
		if err != nil {
			t.Fatalf("update peer bundle_version: %v", err)
		}

		status := getSyncStatus(t, store, ctx, peerID)
		if status != "synced" {
			t.Errorf("expected sync_status='synced', got '%s'", status)
		}
	})

	// Step 6: Compile a new bundle (insert new rule_bundle) → back to pending_sync
	t.Run("new bundle makes it pending_sync again", func(t *testing.T) {
		// Use a later created_at to ensure deterministic ORDER BY created_at DESC ordering
		_, err := d.ExecContext(ctx,
			`INSERT INTO rule_bundles (peer_id, version, version_number, rules_content, hmac, created_at) VALUES (?, ?, ?, ?, ?, '2026-01-02 00:00:00')`,
			peerID, "v2-hash", 2, "rules-content-v2", "hmac-v2")
		if err != nil {
			t.Fatalf("insert new rule bundle: %v", err)
		}

		status := getSyncStatus(t, store, ctx, peerID)
		if status != "pending_sync" {
			t.Errorf("expected sync_status='pending_sync', got '%s'", status)
		}
	})

	// Step 7: Simulate agent that heartbeats but never confirms (set bundle_version to old version, applied_at remains NULL for new bundle) → pending_sync
	t.Run("agent heartbeats with old version never confirms is pending_sync", func(t *testing.T) {
		_, err := d.ExecContext(ctx,
			`UPDATE peers SET bundle_version = 'v1-hash', last_heartbeat = CURRENT_TIMESTAMP WHERE id = ?`,
			peerID)
		if err != nil {
			t.Fatalf("update peer bundle_version to old: %v", err)
		}

		status := getSyncStatus(t, store, ctx, peerID)
		if status != "pending_sync" {
			t.Errorf("expected sync_status='pending_sync' (agent heartbeats but never confirms new bundle), got '%s'", status)
		}
	})
}
