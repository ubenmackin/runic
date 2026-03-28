package peers

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
	_ "github.com/mattn/go-sqlite3"

	"runic/internal/db"
)

// setupTestDB creates an in-memory SQLite database for testing.
func setupTestDB(t *testing.T) (*sql.DB, func()) {
	t.Helper()

	// Create in-memory database with unique name
	dsn := fmt.Sprintf("file:testdb%d?mode=memory&cache=shared", time.Now().UnixNano())
	database, err := sql.Open("sqlite3", dsn)
	if err != nil {
		t.Fatalf("failed to open test db: %v", err)
	}

	// Initialize database schema
	if _, err := database.Exec(db.Schema()); err != nil {
		t.Fatalf("failed to create schema: %v", err)
	}

	// Set global DB
	db.DB = db.New(database)

	// Cleanup function
	cleanup := func() {
		db.DB = nil
		database.Close()
	}

	return database, cleanup
}

// muxVars is a helper to mock gorilla/mux vars
func muxVars(r *http.Request, vars map[string]string) *http.Request {
	return mux.SetURLVars(r, vars)
}

// TestDeletePeer tests the DELETE /peers/{id} endpoint with constraint checks.
func TestDeletePeer(t *testing.T) {
	tests := []struct {
		name         string
		peerID       string
		setup        func(t *testing.T, db *sql.DB)
		wantCode     int
		wantErr      string
		wantMessage  string
		verifyDelete func(t *testing.T, db *sql.DB)
	}{
		{
			name:   "delete peer that is target_peer_id in policy",
			peerID: "1",
			setup: func(t *testing.T, database *sql.DB) {
				// Insert peer
				database.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, has_docker) VALUES (?, ?, ?, ?, ?)`,
					"test-peer", "10.0.0.1", "test-key", "test-hmac", 0)
				// Insert group
				database.Exec(`INSERT INTO groups (name) VALUES (?)`, "test-group")
				// Insert service (required for policy)
				database.Exec(`INSERT INTO services (name, ports, protocol) VALUES (?, ?, ?)`, "ssh", "22", "tcp")
				// Insert policy with peer as target_peer_id
				database.Exec(`INSERT INTO policies (name, source_group_id, service_id, target_peer_id, action, priority, enabled) VALUES (?, ?, ?, ?, ?, ?, ?)`,
					"test-policy", 1, 1, 1, "ACCEPT", 100, 1)
			},
			wantCode: http.StatusConflict,
			wantErr:  "Cannot delete peer — it is the target of policy 'test-policy'",
		},
		{
			name:   "delete peer that is in group used by policy",
			peerID: "1",
			setup: func(t *testing.T, database *sql.DB) {
				// Insert peer
				database.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, has_docker) VALUES (?, ?, ?, ?, ?)`,
					"test-peer", "10.0.0.1", "test-key", "test-hmac", 0)
				// Insert group
				database.Exec(`INSERT INTO groups (name) VALUES (?)`, "test-group")
				// Add peer to group
				database.Exec(`INSERT INTO group_members (group_id, peer_id) VALUES (?, ?)`, 1, 1)
				// Insert service (required for policy)
				database.Exec(`INSERT INTO services (name, ports, protocol) VALUES (?, ?, ?)`, "ssh", "22", "tcp")
				// Insert another peer as target_peer_id (peer 1 is in source group)
				database.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, has_docker) VALUES (?, ?, ?, ?, ?)`,
					"target-peer", "10.0.0.2", "target-key", "target-hmac", 0)
				// Insert policy using group 1 as source_group_id
				database.Exec(`INSERT INTO policies (name, source_group_id, service_id, target_peer_id, action, priority, enabled) VALUES (?, ?, ?, ?, ?, ?, ?)`,
					"test-policy", 1, 1, 2, "ACCEPT", 100, 1)
			},
			wantCode: http.StatusConflict,
			wantErr:  "Cannot delete peer — it is in group used by policy 'test-policy'",
		},
		{
			name:   "successful delete - peer not used anywhere",
			peerID: "1",
			setup: func(t *testing.T, database *sql.DB) {
				// Insert peer
				database.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, has_docker) VALUES (?, ?, ?, ?, ?)`,
					"test-peer", "10.0.0.1", "test-key", "test-hmac", 0)
				// Insert group
				database.Exec(`INSERT INTO groups (name) VALUES (?)`, "test-group")
				// Add peer to group (will be cleaned up)
				database.Exec(`INSERT INTO group_members (group_id, peer_id) VALUES (?, ?)`, 1, 1)
			},
			wantCode:    http.StatusOK,
			wantMessage: "Peer deleted",
			verifyDelete: func(t *testing.T, database *sql.DB) {
				// Verify peer was deleted
				var peerCount int
				err := database.QueryRow("SELECT COUNT(*) FROM peers WHERE id = 1").Scan(&peerCount)
				if err != nil {
					t.Fatalf("failed to query peers: %v", err)
				}
				if peerCount != 0 {
					t.Error("expected peer to be deleted")
				}

				// Verify group_members was cleaned up
				var memberCount int
				err = database.QueryRow("SELECT COUNT(*) FROM group_members WHERE peer_id = 1").Scan(&memberCount)
				if err != nil {
					t.Fatalf("failed to query group_members: %v", err)
				}
				if memberCount != 0 {
					t.Error("expected group_members to be cleaned up when peer is deleted")
				}
			},
		},
		{
			name:   "delete non-existent peer",
			peerID: "999",
			setup: func(t *testing.T, database *sql.DB) {
				// No setup needed - peer doesn't exist
			},
			wantCode: http.StatusNotFound,
			wantErr:  "Peer not found",
		},
		{
			name:   "invalid peer ID",
			peerID: "invalid",
			setup: func(t *testing.T, database *sql.DB) {
				// Insert peer (won't be used due to invalid ID)
				database.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, has_docker) VALUES (?, ?, ?, ?, ?)`,
					"test-peer", "10.0.0.1", "test-key", "test-hmac", 0)
			},
			wantCode: http.StatusBadRequest,
			wantErr:  "invalid peer ID",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			database, cleanup := setupTestDB(t)
			defer cleanup()

			if tt.setup != nil {
				tt.setup(t, database)
			}

			req := httptest.NewRequest("DELETE", "/api/v1/peers/"+tt.peerID, nil)
			w := httptest.NewRecorder()

			// Mock gorilla/mux vars
			req = muxVars(req, map[string]string{"id": tt.peerID})

			DeletePeer(w, req)

			if w.Code != tt.wantCode {
				t.Errorf("expected status %d, got %d: %s", tt.wantCode, w.Code, w.Body.String())
			}

			if tt.wantErr != "" {
				var resp map[string]string
				if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
					t.Fatalf("failed to decode error response: %v", err)
				}
				if !strings.Contains(resp["error"], tt.wantErr) {
					t.Errorf("expected error containing %q, got %q", tt.wantErr, resp["error"])
				}
			}

			if tt.wantMessage != "" {
				var resp map[string]string
				if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
					t.Fatalf("failed to decode response: %v", err)
				}
				if resp["message"] != tt.wantMessage {
					t.Errorf("expected message %q, got %q", tt.wantMessage, resp["message"])
				}
			}

			if tt.verifyDelete != nil {
				tt.verifyDelete(t, database)
			}
		})
	}
}

// TestDeletePeer_GroupMembersCleanup verifies that group_members entries are removed
// when a peer is deleted, even if the peer was in multiple groups.
func TestDeletePeer_GroupMembersCleanup(t *testing.T) {
	database, cleanup := setupTestDB(t)
	defer cleanup()

	// Insert peer
	database.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, has_docker) VALUES (?, ?, ?, ?, ?)`,
		"test-peer", "10.0.0.1", "test-key", "test-hmac", 0)

	// Insert multiple groups
	database.Exec(`INSERT INTO groups (name) VALUES (?)`, "group1")
	database.Exec(`INSERT INTO groups (name) VALUES (?)`, "group2")
	database.Exec(`INSERT INTO groups (name) VALUES (?)`, "group3")

	// Add peer to all groups
	database.Exec(`INSERT INTO group_members (group_id, peer_id) VALUES (?, ?)`, 1, 1)
	database.Exec(`INSERT INTO group_members (group_id, peer_id) VALUES (?, ?)`, 2, 1)
	database.Exec(`INSERT INTO group_members (group_id, peer_id) VALUES (?, ?)`, 3, 1)

	// Verify setup: peer should be in 3 groups
	var initialCount int
	err := database.QueryRow("SELECT COUNT(*) FROM group_members WHERE peer_id = 1").Scan(&initialCount)
	if err != nil {
		t.Fatalf("failed to query initial group_members: %v", err)
	}
	if initialCount != 3 {
		t.Fatalf("expected 3 group_members entries, got %d", initialCount)
	}

	// Delete the peer
	req := httptest.NewRequest("DELETE", "/api/v1/peers/1", nil)
	w := httptest.NewRecorder()
	req = muxVars(req, map[string]string{"id": "1"})

	DeletePeer(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d: %s", http.StatusOK, w.Code, w.Body.String())
	}

	// Verify all group_members entries were removed
	var finalCount int
	err = database.QueryRow("SELECT COUNT(*) FROM group_members WHERE peer_id = 1").Scan(&finalCount)
	if err != nil {
		t.Fatalf("failed to query final group_members: %v", err)
	}
	if finalCount != 0 {
		t.Errorf("expected 0 group_members entries after peer deletion, got %d", finalCount)
	}

	// Verify groups still exist (they should not be deleted)
	var groupCount int
	err = database.QueryRow("SELECT COUNT(*) FROM groups").Scan(&groupCount)
	if err != nil {
		t.Fatalf("failed to query groups: %v", err)
	}
	if groupCount != 3 {
		t.Errorf("expected 3 groups to remain, got %d", groupCount)
	}
}

// TestDeletePeer_WithRuleBundlesAndLogs verifies that related data is cleaned up.
func TestDeletePeer_WithRuleBundlesAndLogs(t *testing.T) {
	database, cleanup := setupTestDB(t)
	defer cleanup()

	// Insert peer
	database.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, has_docker) VALUES (?, ?, ?, ?, ?)`,
		"test-peer", "10.0.0.1", "test-key", "test-hmac", 0)

	// Insert rule_bundle
	database.Exec(`INSERT INTO rule_bundles (peer_id, version, rules_content, hmac) VALUES (?, ?, ?, ?)`,
		1, "v1", "test-rules", "test-hmac")

	// Insert firewall_logs
	database.Exec(`INSERT INTO firewall_logs (peer_id, timestamp, direction, src_ip, dst_ip, protocol, action) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		1, "2024-01-01 00:00:00", "inbound", "10.0.0.100", "10.0.0.1", "tcp", "ACCEPT")

	// Verify setup
	var bundleCount, logCount int
	database.QueryRow("SELECT COUNT(*) FROM rule_bundles WHERE peer_id = 1").Scan(&bundleCount)
	database.QueryRow("SELECT COUNT(*) FROM firewall_logs WHERE peer_id = 1").Scan(&logCount)
	if bundleCount != 1 || logCount != 1 {
		t.Fatalf("setup failed: expected 1 bundle and 1 log, got %d bundles, %d logs", bundleCount, logCount)
	}

	// Delete the peer
	req := httptest.NewRequest("DELETE", "/api/v1/peers/1", nil)
	w := httptest.NewRecorder()
	req = muxVars(req, map[string]string{"id": "1"})

	DeletePeer(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d: %s", http.StatusOK, w.Code, w.Body.String())
	}

	// Verify rule_bundles was deleted (cascade)
	database.QueryRow("SELECT COUNT(*) FROM rule_bundles WHERE peer_id = 1").Scan(&bundleCount)
	if bundleCount != 0 {
		t.Errorf("expected 0 rule_bundles after peer deletion, got %d", bundleCount)
	}

	// Verify firewall_logs was deleted
	database.QueryRow("SELECT COUNT(*) FROM firewall_logs WHERE peer_id = 1").Scan(&logCount)
	if logCount != 0 {
		t.Errorf("expected 0 firewall_logs after peer deletion, got %d", logCount)
	}
}
