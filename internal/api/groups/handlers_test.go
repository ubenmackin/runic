package groups

import (
	"database/sql"
	"encoding/json"
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

	// Create in-memory database with unique name to avoid conflicts
	dsn := "file:testdb_groups_" + time.Now().Format("20060102150405.999999999") + "?mode=memory&cache=shared"
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
		database.Close()
	}

	return database, cleanup
}

// muxVars is a helper to mock gorilla/mux vars
func muxVars(r *http.Request, vars map[string]string) *http.Request {
	return mux.SetURLVars(r, vars)
}

// =============================================================================
// ListGroups Tests
// =============================================================================

func TestListGroups(t *testing.T) {
	database, cleanup := setupTestDB(t)
	defer cleanup()

	// Insert test groups
	database.Exec(`INSERT INTO groups (name, description) VALUES (?, ?)`, "alpha-group", "First group")
	database.Exec(`INSERT INTO groups (name, description) VALUES (?, ?)`, "beta-group", "Second group")

	// Insert peers and add to groups
	database.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, os_type, is_manual) VALUES (?, ?, ?, ?, ?, ?)`,
		"peer1", "10.0.0.1", "key1", "hmac1", "linux", 0)
	database.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, os_type, is_manual) VALUES (?, ?, ?, ?, ?, ?)`,
		"peer2", "10.0.0.2", "key2", "hmac2", "linux", 1)

	// Add peer1 to alpha-group (id=1)
	database.Exec(`INSERT INTO group_members (group_id, peer_id) VALUES (?, ?)`, 1, 1)
	// Add peer2 to alpha-group
	database.Exec(`INSERT INTO group_members (group_id, peer_id) VALUES (?, ?)`, 1, 2)

	// Create a service and policy to test policy_count
	database.Exec(`INSERT INTO services (name, ports, protocol) VALUES (?, ?, ?)`, "ssh", "22", "tcp")
	database.Exec(`INSERT INTO policies (name, source_group_id, service_id, target_peer_id, action, priority, enabled) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		"ssh-policy", 1, 1, 1, "ACCEPT", 100, 1)

	tests := []struct {
		name           string
		wantCode       int
		validateResult func(*testing.T, []GroupWithCounts)
	}{
		{
			name:     "list all groups with counts",
			wantCode: http.StatusOK,
			validateResult: func(t *testing.T, groups []GroupWithCounts) {
				if len(groups) < 2 {
					t.Errorf("expected at least 2 groups, got %d", len(groups))
					return
				}

				// Find alpha-group
				var alphaGroup *GroupWithCounts
				for i := range groups {
					if groups[i].Name == "alpha-group" {
						alphaGroup = &groups[i]
						break
					}
				}

				if alphaGroup == nil {
					t.Error("expected to find alpha-group")
					return
				}

				// Verify peer_count
				if alphaGroup.PeerCount != 2 {
					t.Errorf("expected alpha-group to have 2 peers, got %d", alphaGroup.PeerCount)
				}

				// Verify policy_count
				if alphaGroup.PolicyCount != 1 {
					t.Errorf("expected alpha-group to have 1 policy, got %d", alphaGroup.PolicyCount)
				}

				// Verify is_system is false for regular groups
				if alphaGroup.IsSystem {
					t.Error("expected alpha-group to NOT be a system group")
				}

				// Verify ordering (alphabetical by name)
				for i := 1; i < len(groups); i++ {
					if groups[i-1].Name > groups[i].Name {
						t.Errorf("groups not sorted alphabetically: %s should come before %s", groups[i-1].Name, groups[i].Name)
					}
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/api/v1/groups", nil)
			w := httptest.NewRecorder()

			ListGroups(w, req)

			if w.Code != tt.wantCode {
				t.Errorf("expected status %d, got %d: %s", tt.wantCode, w.Code, w.Body.String())
			}

			if tt.validateResult != nil && w.Code == http.StatusOK {
				var groups []GroupWithCounts
				if err := json.NewDecoder(w.Body).Decode(&groups); err != nil {
					t.Fatalf("failed to decode response: %v", err)
				}
				tt.validateResult(t, groups)
			}
		})
	}
}

func TestListGroups_SystemGroup(t *testing.T) {
	database, cleanup := setupTestDB(t)
	defer cleanup()

	// Insert the "any" system group with is_system=1
	database.Exec(`INSERT INTO groups (name, description, is_system) VALUES (?, ?, 1)`, "any", "System group representing all peers")

	// Insert a regular group for comparison
	database.Exec(`INSERT INTO groups (name, description) VALUES (?, ?)`, "regular-group", "A regular group")

	req := httptest.NewRequest("GET", "/api/v1/groups", nil)
	w := httptest.NewRecorder()

	ListGroups(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d: %s", http.StatusOK, w.Code, w.Body.String())
	}

	var groups []GroupWithCounts
	if err := json.NewDecoder(w.Body).Decode(&groups); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	// Find the "any" group
	var anyGroup *GroupWithCounts
	for i := range groups {
		if groups[i].Name == "any" {
			anyGroup = &groups[i]
			break
		}
	}

	if anyGroup == nil {
		t.Fatal("expected to find 'any' group")
	}

	// Verify is_system is true for "any" group
	if !anyGroup.IsSystem {
		t.Error("expected 'any' group to have is_system=true")
	}

	// Verify description is set
	if anyGroup.Description == "" {
		t.Error("expected 'any' group to have a description")
	}
}

func TestListGroups_EmptyResult(t *testing.T) {
	_, cleanup := setupTestDB(t)
	defer cleanup()

	req := httptest.NewRequest("GET", "/api/v1/groups", nil)
	w := httptest.NewRecorder()

	ListGroups(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var groups []GroupWithCounts
	if err := json.NewDecoder(w.Body).Decode(&groups); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	// Should return empty array, not null
	if groups == nil {
		t.Error("expected empty array, got nil")
	}
	if len(groups) != 0 {
		t.Errorf("expected 0 groups, got %d", len(groups))
	}
}

// =============================================================================
// DeleteGroup Tests
// =============================================================================

func TestDeleteGroup_SystemGroup(t *testing.T) {
	database, cleanup := setupTestDB(t)
	defer cleanup()

	// Insert the "any" system group with is_system=1
	database.Exec(`INSERT INTO groups (name, description, is_system) VALUES (?, ?, 1)`, "any", "System group")

	req := httptest.NewRequest("DELETE", "/api/v1/groups/1", nil)
	w := httptest.NewRecorder()

	// Mock gorilla/mux vars
	req = muxVars(req, map[string]string{"id": "1"})

	DeleteGroup(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected status %d, got %d: %s", http.StatusForbidden, w.Code, w.Body.String())
	}

	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}
	if !strings.Contains(resp["error"], "Cannot delete system group") {
		t.Errorf("expected error containing %q, got %q", "Cannot delete system group", resp["error"])
	}
}

func TestDeleteGroup_UsedByPolicy(t *testing.T) {
	database, cleanup := setupTestDB(t)
	defer cleanup()

	// Insert test data
	database.Exec(`INSERT INTO groups (name, description) VALUES (?, ?)`, "web-servers", "Web server group")
	database.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)`,
		"web-01", "10.0.0.1", "key1", "hmac1")
	database.Exec(`INSERT INTO services (name, ports, protocol) VALUES (?, ?, ?)`, "http", "80", "tcp")
	database.Exec(`INSERT INTO policies (name, source_group_id, service_id, target_peer_id, action, priority, enabled) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		"allow-http", 1, 1, 1, "ACCEPT", 100, 1)

	req := httptest.NewRequest("DELETE", "/api/v1/groups/1", nil)
	w := httptest.NewRecorder()

	req = muxVars(req, map[string]string{"id": "1"})

	DeleteGroup(w, req)

	if w.Code != http.StatusConflict {
		t.Errorf("expected status %d, got %d: %s", http.StatusConflict, w.Code, w.Body.String())
	}

	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}

	// Should include policy name in error
	if !strings.Contains(resp["error"], "allow-http") {
		t.Errorf("expected error to contain policy name 'allow-http', got %q", resp["error"])
	}
}

func TestDeleteGroup_Success(t *testing.T) {
	database, cleanup := setupTestDB(t)
	defer cleanup()

	// Insert a group without policies
	database.Exec(`INSERT INTO groups (name, description) VALUES (?, ?)`, "unused-group", "Group not used by any policy")

	// Insert a peer and add to the group
	database.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)`,
		"peer1", "10.0.0.1", "key1", "hmac1")
	database.Exec(`INSERT INTO group_members (group_id, peer_id) VALUES (?, ?)`, 1, 1)

	req := httptest.NewRequest("DELETE", "/api/v1/groups/1", nil)
	w := httptest.NewRecorder()

	req = muxVars(req, map[string]string{"id": "1"})

	DeleteGroup(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("expected status %d, got %d: %s", http.StatusNoContent, w.Code, w.Body.String())
	}

	// Verify group was deleted
	var count int
	err := database.QueryRow("SELECT COUNT(*) FROM groups WHERE id = 1").Scan(&count)
	if err != nil {
		t.Fatalf("failed to check group deletion: %v", err)
	}
	if count != 0 {
		t.Error("expected group to be deleted")
	}

	// Verify group_members were also deleted (cascade)
	err = database.QueryRow("SELECT COUNT(*) FROM group_members WHERE group_id = 1").Scan(&count)
	if err != nil {
		t.Fatalf("failed to check group_members deletion: %v", err)
	}
	if count != 0 {
		t.Error("expected group_members to be deleted")
	}
}

func TestDeleteGroup_NotFound(t *testing.T) {
	_, cleanup := setupTestDB(t)
	defer cleanup()

	req := httptest.NewRequest("DELETE", "/api/v1/groups/999", nil)
	w := httptest.NewRecorder()

	req = muxVars(req, map[string]string{"id": "999"})

	DeleteGroup(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status %d, got %d: %s", http.StatusNotFound, w.Code, w.Body.String())
	}
}

func TestDeleteGroup_InvalidID(t *testing.T) {
	_, cleanup := setupTestDB(t)
	defer cleanup()

	req := httptest.NewRequest("DELETE", "/api/v1/groups/invalid", nil)
	w := httptest.NewRecorder()

	req = muxVars(req, map[string]string{"id": "invalid"})

	DeleteGroup(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d: %s", http.StatusBadRequest, w.Code, w.Body.String())
	}
}

// =============================================================================
// AddGroupMember Tests
// =============================================================================

func TestAddGroupMember(t *testing.T) {
	database, cleanup := setupTestDB(t)
	defer cleanup()

	// Insert test data
	database.Exec(`INSERT INTO groups (name) VALUES (?)`, "test-group")
	database.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, os_type, is_manual) VALUES (?, ?, ?, ?, ?, ?)`,
		"peer1", "10.0.0.1", "key1", "hmac1", "linux", 0)

	tests := []struct {
		name     string
		groupID  string
		body     string
		wantCode int
		wantErr  string
		validate func(*testing.T)
	}{
		{
			name:     "add peer to group successfully",
			groupID:  "1",
			body:     `{"peer_id": 1}`,
			wantCode: http.StatusCreated,
			validate: func(t *testing.T) {
				var count int
				err := database.QueryRow("SELECT COUNT(*) FROM group_members WHERE group_id = 1 AND peer_id = 1").Scan(&count)
				if err != nil {
					t.Fatalf("failed to check group_members: %v", err)
				}
				if count != 1 {
					t.Error("expected peer to be added to group")
				}
			},
		},
		{
			name:     "missing peer_id",
			groupID:  "1",
			body:     `{}`,
			wantCode: http.StatusBadRequest,
			wantErr:  "peer_id is required",
		},
		{
			name:     "invalid JSON",
			groupID:  "1",
			body:     `{"invalid json}`,
			wantCode: http.StatusBadRequest,
			wantErr:  "invalid JSON",
		},
		{
			name:     "invalid group ID",
			groupID:  "invalid",
			body:     `{"peer_id": 1}`,
			wantCode: http.StatusBadRequest,
			wantErr:  "invalid group ID",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/api/v1/groups/"+tt.groupID+"/members", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			req = muxVars(req, map[string]string{"id": tt.groupID})

			// Pass nil for compiler since async recompile doesn't affect test result
			handler := MakeAddGroupMemberHandler(nil)
			handler(w, req)

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

			if tt.validate != nil {
				tt.validate(t)
			}
		})
	}
}

func TestAddGroupMember_Duplicate(t *testing.T) {
	database, cleanup := setupTestDB(t)
	defer cleanup()

	// Insert test data
	database.Exec(`INSERT INTO groups (name) VALUES (?)`, "test-group")
	database.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)`,
		"peer1", "10.0.0.1", "key1", "hmac1")
	database.Exec(`INSERT INTO group_members (group_id, peer_id) VALUES (?, ?)`, 1, 1)

	// Try to add the same peer again (should succeed due to INSERT OR IGNORE)
	req := httptest.NewRequest("POST", "/api/v1/groups/1/members", strings.NewReader(`{"peer_id": 1}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	req = muxVars(req, map[string]string{"id": "1"})

	handler := MakeAddGroupMemberHandler(nil)
	handler(w, req)

	// Should return Created (201) due to INSERT OR IGNORE
	if w.Code != http.StatusCreated {
		t.Errorf("expected status %d, got %d: %s", http.StatusCreated, w.Code, w.Body.String())
	}

	// Verify only one entry exists
	var count int
	err := database.QueryRow("SELECT COUNT(*) FROM group_members WHERE group_id = 1 AND peer_id = 1").Scan(&count)
	if err != nil {
		t.Fatalf("failed to check group_members: %v", err)
	}
	if count != 1 {
		t.Errorf("expected exactly 1 group_member entry, got %d", count)
	}
}

// =============================================================================
// RemoveGroupMember Tests
// =============================================================================

func TestRemoveGroupMember(t *testing.T) {
	database, cleanup := setupTestDB(t)
	defer cleanup()

	// Insert test data
	database.Exec(`INSERT INTO groups (name) VALUES (?)`, "test-group")
	database.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)`,
		"peer1", "10.0.0.1", "key1", "hmac1")
	database.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)`,
		"peer2", "10.0.0.2", "key2", "hmac2")
	database.Exec(`INSERT INTO group_members (group_id, peer_id) VALUES (?, ?)`, 1, 1)
	database.Exec(`INSERT INTO group_members (group_id, peer_id) VALUES (?, ?)`, 1, 2)

	tests := []struct {
		name     string
		groupID  string
		peerID   string
		wantCode int
		validate func(*testing.T)
	}{
		{
			name:     "remove peer from group successfully",
			groupID:  "1",
			peerID:   "1",
			wantCode: http.StatusNoContent,
			validate: func(t *testing.T) {
				var count int
				err := database.QueryRow("SELECT COUNT(*) FROM group_members WHERE group_id = 1 AND peer_id = 1").Scan(&count)
				if err != nil {
					t.Fatalf("failed to check group_members: %v", err)
				}
				if count != 0 {
					t.Error("expected peer to be removed from group")
				}
				// Verify peer2 is still in group
				err = database.QueryRow("SELECT COUNT(*) FROM group_members WHERE group_id = 1 AND peer_id = 2").Scan(&count)
				if err != nil {
					t.Fatalf("failed to check group_members: %v", err)
				}
				if count != 1 {
					t.Error("expected peer2 to still be in group")
				}
			},
		},
		{
			name:     "remove non-existent peer from group",
			groupID:  "1",
			peerID:   "999",
			wantCode: http.StatusNoContent, // DELETE is idempotent
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("DELETE", "/api/v1/groups/"+tt.groupID+"/members/"+tt.peerID, nil)
			w := httptest.NewRecorder()

			// Note: route uses groupId and peerId params (not id and memberId)
			req = muxVars(req, map[string]string{"groupId": tt.groupID, "peerId": tt.peerID})

			handler := MakeDeleteGroupMemberHandler(nil)
			handler(w, req)

			if w.Code != tt.wantCode {
				t.Errorf("expected status %d, got %d: %s", tt.wantCode, w.Code, w.Body.String())
			}

			if tt.validate != nil {
				tt.validate(t)
			}
		})
	}
}

func TestRemoveGroupMember_InvalidIDs(t *testing.T) {
	_, cleanup := setupTestDB(t)
	defer cleanup()

	tests := []struct {
		name     string
		groupID  string
		peerID   string
		wantCode int
		wantErr  string
	}{
		{
			name:     "invalid group ID",
			groupID:  "invalid",
			peerID:   "1",
			wantCode: http.StatusBadRequest,
			wantErr:  "invalid group ID",
		},
		{
			name:     "invalid peer ID",
			groupID:  "1",
			peerID:   "invalid",
			wantCode: http.StatusBadRequest,
			wantErr:  "invalid peer ID",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("DELETE", "/api/v1/groups/"+tt.groupID+"/members/"+tt.peerID, nil)
			w := httptest.NewRecorder()

			req = muxVars(req, map[string]string{"groupId": tt.groupID, "peerId": tt.peerID})

			handler := MakeDeleteGroupMemberHandler(nil)
			handler(w, req)

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
		})
	}
}

// =============================================================================
// GetGroupMembers Tests
// =============================================================================

func TestGetGroupMembers(t *testing.T) {
	database, cleanup := setupTestDB(t)
	defer cleanup()

	// Insert test data
	database.Exec(`INSERT INTO groups (name) VALUES (?)`, "test-group")
	database.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, os_type, is_manual) VALUES (?, ?, ?, ?, ?, ?)`,
		"alpha-peer", "10.0.0.1", "key1", "hmac1", "linux", 0)
	database.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, os_type, is_manual) VALUES (?, ?, ?, ?, ?, ?)`,
		"beta-peer", "10.0.0.2", "key2", "hmac2", "windows", 1)
	database.Exec(`INSERT INTO group_members (group_id, peer_id) VALUES (?, ?)`, 1, 1)
	database.Exec(`INSERT INTO group_members (group_id, peer_id) VALUES (?, ?)`, 1, 2)

	req := httptest.NewRequest("GET", "/api/v1/groups/1/members", nil)
	w := httptest.NewRecorder()

	req = muxVars(req, map[string]string{"id": "1"})

	ListGroupMembers(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d: %s", http.StatusOK, w.Code, w.Body.String())
	}

	var peers []PeerInGroup
	if err := json.NewDecoder(w.Body).Decode(&peers); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(peers) != 2 {
		t.Fatalf("expected 2 peers, got %d", len(peers))
	}

	// Verify ordering (alphabetical by hostname)
	if peers[0].Hostname != "alpha-peer" {
		t.Errorf("expected first peer to be 'alpha-peer', got %s", peers[0].Hostname)
	}
	if peers[1].Hostname != "beta-peer" {
		t.Errorf("expected second peer to be 'beta-peer', got %s", peers[1].Hostname)
	}

	// Verify peer details
	if peers[0].IPAddress != "10.0.0.1" {
		t.Errorf("expected IP '10.0.0.1', got %s", peers[0].IPAddress)
	}
	if peers[0].OSType != "linux" {
		t.Errorf("expected os_type 'linux', got %s", peers[0].OSType)
	}
	if peers[0].IsManual {
		t.Error("expected alpha-peer to NOT be manual")
	}

	// Verify second peer details
	if peers[1].IsManual != true {
		t.Error("expected beta-peer to be manual")
	}
}

func TestGetGroupMembers_EmptyGroup(t *testing.T) {
	_, cleanup := setupTestDB(t)
	defer cleanup()

	// Insert an empty group
	database, _ := sql.Open("sqlite3", "file:testdb_empty_group?mode=memory&cache=shared")
	defer database.Close()
	database.Exec(db.Schema())
	db.DB = db.New(database)

	db.DB.Exec(`INSERT INTO groups (name) VALUES (?)`, "empty-group")

	req := httptest.NewRequest("GET", "/api/v1/groups/1/members", nil)
	w := httptest.NewRecorder()

	req = muxVars(req, map[string]string{"id": "1"})

	ListGroupMembers(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d: %s", http.StatusOK, w.Code, w.Body.String())
	}

	var peers []PeerInGroup
	if err := json.NewDecoder(w.Body).Decode(&peers); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if peers == nil {
		t.Error("expected empty array, got nil")
	}
	if len(peers) != 0 {
		t.Errorf("expected 0 peers, got %d", len(peers))
	}
}

func TestGetGroupMembers_InvalidGroupID(t *testing.T) {
	_, cleanup := setupTestDB(t)
	defer cleanup()

	req := httptest.NewRequest("GET", "/api/v1/groups/invalid/members", nil)
	w := httptest.NewRecorder()

	req = muxVars(req, map[string]string{"id": "invalid"})

	ListGroupMembers(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d: %s", http.StatusBadRequest, w.Code, w.Body.String())
	}
}

// =============================================================================
// CreateGroup Tests
// =============================================================================

func TestCreateGroup(t *testing.T) {
	_, cleanup := setupTestDB(t)
	defer cleanup()

	tests := []struct {
		name     string
		body     string
		wantCode int
		wantErr  string
		validate func(*testing.T, map[string]int64)
	}{
		{
			name:     "create group successfully",
			body:     `{"name": "new-group", "description": "A new group"}`,
			wantCode: http.StatusCreated,
			validate: func(t *testing.T, r map[string]int64) {
				if r["id"] == 0 {
					t.Error("expected non-zero group ID")
				}
			},
		},
		{
			name:     "create group without description",
			body:     `{"name": "minimal-group"}`,
			wantCode: http.StatusCreated,
		},
		{
			name:     "missing name",
			body:     `{"description": "test"}`,
			wantCode: http.StatusBadRequest,
			wantErr:  "name is required",
		},
		{
			name:     "invalid JSON",
			body:     `{"invalid json}`,
			wantCode: http.StatusBadRequest,
			wantErr:  "invalid JSON",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/api/v1/groups", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			CreateGroup(w, req)

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

			if tt.validate != nil && w.Code == http.StatusCreated {
				var result map[string]int64
				if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
					t.Fatalf("failed to decode result: %v", err)
				}
				tt.validate(t, result)
			}
		})
	}
}

// =============================================================================
// GetGroup Tests
// =============================================================================

func TestGetGroup(t *testing.T) {
	database, cleanup := setupTestDB(t)
	defer cleanup()

	// Insert test data
	database.Exec(`INSERT INTO groups (name, description) VALUES (?, ?)`, "test-group", "Test description")

	tests := []struct {
		name     string
		groupID  string
		wantCode int
		wantErr  string
	}{
		{
			name:     "get group successfully",
			groupID:  "1",
			wantCode: http.StatusOK,
		},
		{
			name:     "group not found",
			groupID:  "999",
			wantCode: http.StatusNotFound,
			wantErr:  "group not found",
		},
		{
			name:     "invalid group ID",
			groupID:  "invalid",
			wantCode: http.StatusBadRequest,
			wantErr:  "invalid group ID",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/api/v1/groups/"+tt.groupID, nil)
			w := httptest.NewRecorder()

			req = muxVars(req, map[string]string{"id": tt.groupID})

			GetGroup(w, req)

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
		})
	}
}

// =============================================================================
// UpdateGroup Tests
// =============================================================================

func TestUpdateGroup(t *testing.T) {
	database, cleanup := setupTestDB(t)
	defer cleanup()

	// Insert test data
	database.Exec(`INSERT INTO groups (name, description) VALUES (?, ?)`, "test-group", "Original description")

	tests := []struct {
		name     string
		groupID  string
		body     string
		wantCode int
		wantErr  string
	}{
		{
			name:     "update group successfully",
			groupID:  "1",
			body:     `{"name": "updated-group", "description": "Updated description"}`,
			wantCode: http.StatusOK,
		},
		{
			name:     "invalid group ID",
			groupID:  "invalid",
			body:     `{"name": "test"}`,
			wantCode: http.StatusBadRequest,
			wantErr:  "invalid group ID",
		},
		{
			name:     "invalid JSON",
			groupID:  "1",
			body:     `{"invalid json}`,
			wantCode: http.StatusBadRequest,
			wantErr:  "invalid JSON",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("PUT", "/api/v1/groups/"+tt.groupID, strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			req = muxVars(req, map[string]string{"id": tt.groupID})

			UpdateGroup(w, req)

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
		})
	}
}
