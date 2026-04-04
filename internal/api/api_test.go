package api

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
	_ "github.com/mattn/go-sqlite3"

	"runic/internal/api/common"
	"runic/internal/api/groups"
	"runic/internal/api/peers"
	"runic/internal/api/policies"
	"runic/internal/api/services"
	"runic/internal/db"
	"runic/internal/engine"
)

// setupTestAPI creates a test API instance with an in-memory database
func setupTestAPI(t *testing.T) (*API, *sql.DB, func()) {
	t.Helper()

	// Create in-memory database
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

	// Create compiler
	compiler := engine.NewCompiler(database)

	// Create API instance
	api := NewAPI(compiler)

	// Cleanup function
	cleanup := func() {
		database.Close()
	}

	return api, database, cleanup
}

// TestGetPeers tests the GET /peers endpoint
func TestGetPeers(t *testing.T) {
	_, database, cleanup := setupTestAPI(t)
	defer cleanup()

	// Insert test peers (hmac_key is required in schema)
	database.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, has_docker) VALUES (?, ?, ?, ?, ?)`,
		"peer1", "10.0.0.1", "key1", "test-hmac-1", true)
	database.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, has_docker) VALUES (?, ?, ?, ?, ?)`,
		"peer2", "10.0.0.2", "key2", "test-hmac-2", false)

	req := httptest.NewRequest("GET", "/api/v1/peers", nil)
	w := httptest.NewRecorder()

	peers.GetPeers(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var prs []peers.Peer
	if err := json.NewDecoder(w.Body).Decode(&prs); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(prs) != 2 {
		t.Errorf("expected 2 peers, got %d", len(prs))
	}

	if prs[0].Hostname != "peer1" {
		t.Errorf("expected peer1, got %v", prs[0].Hostname)
	}

	if prs[1].Hostname != "peer2" {
		t.Error("expected HasDocker to be true")
	}
}

// TestCreatePeer tests the POST /peers endpoint
func TestCreatePeer(t *testing.T) {
	tests := []struct {
		name           string
		body           string
		wantCode       int
		wantErr        string
		validateResult func(*testing.T, map[string]int64)
	}{
		{
			name:     "valid peer",
			body:     `{"hostname": "test-peer", "ip_address": "10.0.1.1", "agent_key": "test-key", "has_docker": true}`,
			wantCode: http.StatusCreated,
			validateResult: func(t *testing.T, r map[string]int64) {
				if r["id"] == 0 {
					t.Error("expected non-zero peer ID")
				}
			},
		},
		{
			name:     "valid peer without docker",
			body:     `{"hostname": "test-peer2", "ip_address": "10.0.1.2", "agent_key": "test-key", "has_docker": false}`,
			wantCode: http.StatusCreated,
		},
		{
			name:     "missing hostname",
			body:     `{"ip_address": "10.0.1.1", "agent_key": "test-key"}`,
			wantCode: http.StatusBadRequest,
			wantErr:  "hostname",
		},
		{
			name:     "missing ip_address",
			body:     `{"hostname": "test-peer", "agent_key": "test-key"}`,
			wantCode: http.StatusBadRequest,
			wantErr:  "ip_address",
		},
		{
			name:     "missing agent_key",
			body:     `{"hostname": "test-peer", "ip_address": "10.0.1.1"}`,
			wantCode: http.StatusBadRequest,
			wantErr:  "agent_key",
		},
		{
			name:     "invalid JSON",
			body:     `{"invalid json}`,
			wantCode: http.StatusBadRequest,
			wantErr:  "invalid JSON",
		},
		{
			name:     "empty body",
			body:     ``,
			wantCode: http.StatusBadRequest,
			wantErr:  "invalid JSON",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			api, _, cleanup := setupTestAPI(t)
			defer cleanup()

			req := httptest.NewRequest("POST", "/api/v1/peers", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			// Set up context with API instance
			ctx := context.WithValue(req.Context(), apiContextKey, api)
			req = req.WithContext(ctx)

			handler := http.HandlerFunc(peers.CreatePeer)
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

			if tt.validateResult != nil && w.Code == http.StatusCreated {
				var result map[string]int64
				if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
					t.Fatalf("failed to decode result: %v", err)
				}
				tt.validateResult(t, result)
			}
		})
	}
}

// TestCompilePeer tests the POST /peers/{id}/compile endpoint
func TestCompilePeer(t *testing.T) {
	api, database, cleanup := setupTestAPI(t)
	defer cleanup()

	// Insert test peer with required data
	database.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, has_docker) VALUES (?, ?, ?, ?, ?)`,
		"test-peer", "10.0.0.1", "test-key", "test-hmac-key", true)
	database.Exec(`INSERT INTO groups (name) VALUES (?)`, "test-group")
	// Insert manual peer for group member (new schema: groups contain peers, not IP/CIDR)
	database.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, is_manual) VALUES (?, ?, ?, ?, 1)`,
		"manual-peer", "192.168.1.0/24", "manual-key", "manual-hmac")
	database.Exec(`INSERT INTO group_members (group_id, peer_id) VALUES (?, ?)`, 1, 2)
	database.Exec(`INSERT INTO services (name, ports, protocol) VALUES (?, ?, ?)`,
		"ssh", "22", "tcp")
	database.Exec(`INSERT INTO policies (name, source_id, source_type, service_id, target_id, target_type, action, priority, enabled) VALUES (?, ?, "group", ?, ?, "peer", ?, ?, ?)`,
		"test-policy", 1, 1, 1, "ACCEPT", 100, 1)

	tests := []struct {
		name     string
		peerID   string
		wantCode int
		wantErr  string
	}{
		{
			name:     "valid peer",
			peerID:   "1",
			wantCode: http.StatusOK,
		},
		{
			name:     "non-existent peer",
			peerID:   "999",
			wantCode: http.StatusInternalServerError,
			wantErr:  "compilation failed",
		},
		{
			name:     "invalid peer ID",
			peerID:   "invalid",
			wantCode: http.StatusBadRequest,
			wantErr:  "invalid peer ID",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/api/v1/peers/"+tt.peerID+"/compile", nil)
			w := httptest.NewRecorder()

			// Mock gorilla/mux vars
			req = muxVars(req, map[string]string{"id": tt.peerID})

			// Set up context with API instance
			ctx := context.WithValue(req.Context(), apiContextKey, api)
			req = req.WithContext(ctx)

			handler := peers.MakeCompilePeerHandler(api.Compiler)
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

			if tt.wantCode == http.StatusOK {
				var result map[string]interface{}
				if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
					t.Fatalf("failed to decode result: %v", err)
				}
				if _, ok := result["version"]; !ok {
					t.Error("expected version in response")
				}
				if _, ok := result["hmac"]; !ok {
					t.Error("expected hmac in response")
				}
				if _, ok := result["size"]; !ok {
					t.Error("expected size in response")
				}
			}
		})
	}
}

// TestListPolicies tests the GET /policies endpoint
func TestListPolicies(t *testing.T) {
	_, database, cleanup := setupTestAPI(t)
	defer cleanup()

	// Insert test data
	database.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, has_docker) VALUES (?, ?, ?, ?, ?)`,
		"test-peer", "10.0.0.1", "test-key", false)
	database.Exec(`INSERT INTO groups (name) VALUES (?)`, "test-group")
	database.Exec(`INSERT INTO services (name, ports, protocol) VALUES (?, ?, ?)`,
		"ssh", "22", "tcp")
	database.Exec(`INSERT INTO policies (name, description, source_id, source_type, service_id, target_id, target_type, action, priority, enabled) VALUES (?, ?, ?, 'group', ?, ?, 'peer', ?, ?, ?)`,
		"policy1", "test policy 1", 1, 1, 1, "ACCEPT", 100, 1)
	database.Exec(`INSERT INTO policies (name, description, source_id, source_type, service_id, target_id, target_type, action, priority, enabled) VALUES (?, ?, ?, 'group', ?, ?, 'peer', ?, ?, ?)`,
		"policy2", "test policy 2", 1, 1, 1, "DROP", 200, 0)

	req := httptest.NewRequest("GET", "/api/v1/policies", nil)
	w := httptest.NewRecorder()

	policies.ListPolicies(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d: %s", http.StatusOK, w.Code, w.Body.String())
	}

	var policies []struct {
		ID          int    `json:"id"`
		Name        string `json:"name"`
		Description string `json:"description"`
		SourceID    int    `json:"source_id"`
		SourceType  string `json:"source_type"`
		ServiceID   int    `json:"service_id"`
		TargetID    int    `json:"target_id"`
		TargetType  string `json:"target_type"`
		Action      string `json:"action"`
		Priority    int    `json:"priority"`
		Enabled     bool   `json:"enabled"`
	}
	if err := json.NewDecoder(w.Body).Decode(&policies); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(policies) != 2 {
		t.Errorf("expected 2 policies, got %d", len(policies))
	}

	// Check ordering (by priority ASC)
	if policies[0].Priority != 100 {
		t.Errorf("expected first policy priority 100, got %d", policies[0].Priority)
	}
	if policies[1].Priority != 200 {
		t.Errorf("expected second policy priority 200, got %d", policies[1].Priority)
	}

	if !policies[0].Enabled {
		t.Error("expected first policy to be enabled")
	}
	if policies[1].Enabled {
		t.Error("expected second policy to be disabled")
	}
}

// TestCreatePolicy tests the POST /policies endpoint
func TestCreatePolicy(t *testing.T) {
	tests := []struct {
		name           string
		body           string
		wantCode       int
		wantErr        string
		setup          func(*testing.T, *sql.DB)
		validateResult func(*testing.T, map[string]int64)
	}{
		{
			name: "valid policy",
			setup: func(t *testing.T, db *sql.DB) {
				db.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, has_docker) VALUES (?, ?, ?, ?, ?)`,
					"test-peer", "10.0.0.1", "test-key", false)
				db.Exec(`INSERT INTO groups (name) VALUES (?)`, "test-group")
				db.Exec(`INSERT INTO services (name, ports, protocol) VALUES (?, ?, ?)`,
					"ssh", "22", "tcp")
			},
			body:     `{"name": "new-policy", "description": "test", "source_id": 1, "source_type": "group", "service_id": 1, "target_id": 1, "target_type": "peer", "action": "ACCEPT", "priority": 100, "enabled": true}`,
			wantCode: http.StatusCreated,
			validateResult: func(t *testing.T, r map[string]int64) {
				if r["id"] == 0 {
					t.Error("expected non-zero policy ID")
				}
			},
		},
		{
			name:     "missing required fields",
			body:     `{"name": "test"}`,
			wantCode: http.StatusBadRequest,
			wantErr:  "source_id",
			setup: func(t *testing.T, db *sql.DB) {
				db.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, has_docker) VALUES (?, ?, ?, ?, ?)`,
					"test-peer", "10.0.0.1", "test-key", false)
			},
		},
		{
			name: "defaults applied",
			setup: func(t *testing.T, db *sql.DB) {
				db.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, has_docker) VALUES (?, ?, ?, ?, ?)`,
					"test-peer", "10.0.0.1", "test-key", false)
				db.Exec(`INSERT INTO groups (name) VALUES (?)`, "test-group")
				db.Exec(`INSERT INTO services (name, ports, protocol) VALUES (?, ?, ?)`,
					"ssh", "22", "tcp")
			},
			body:     `{"name": "default-policy", "source_id": 1, "source_type": "group", "service_id": 1, "target_id": 1, "target_type": "peer"}`,
			wantCode: http.StatusCreated,
		},
		{
			name:     "invalid JSON",
			body:     `{"invalid json}`,
			wantCode: http.StatusBadRequest,
			wantErr:  "invalid JSON",
			setup:    func(t *testing.T, db *sql.DB) {},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			api, database, cleanup := setupTestAPI(t)
			defer cleanup()

			if tt.setup != nil {
				tt.setup(t, database)
			}

			req := httptest.NewRequest("POST", "/api/v1/policies", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			// Set up context with API instance
			ctx := context.WithValue(req.Context(), apiContextKey, api)
			req = req.WithContext(ctx)

			handler := policies.MakeCreatePolicyHandler(api.Compiler)
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

			if tt.validateResult != nil && w.Code == http.StatusCreated {
				var result map[string]int64
				if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
					t.Fatalf("failed to decode result: %v", err)
				}
				tt.validateResult(t, result)
			}
		})
	}
}

// TestGetPolicy tests the GET /policies/{id} endpoint
func TestGetPolicy(t *testing.T) {
	_, database, cleanup := setupTestAPI(t)
	defer cleanup()

	// Insert test data
	database.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, has_docker) VALUES (?, ?, ?, ?, ?)`,
		"test-peer", "10.0.0.1", "test-key", false)
	database.Exec(`INSERT INTO groups (name) VALUES (?)`, "test-group")
	database.Exec(`INSERT INTO services (name, ports, protocol) VALUES (?, ?, ?)`,
		"ssh", "22", "tcp")
	database.Exec(`INSERT INTO policies (name, description, source_id, source_type, service_id, target_id, target_type, action, priority, enabled) VALUES (?, ?, ?, 'group', ?, ?, 'peer', ?, ?, ?)`,
		"test-policy", "test description", 1, 1, 1, "ACCEPT", 100, 1)

	tests := []struct {
		name     string
		policyID string
		wantCode int
		wantErr  string
	}{
		{
			name:     "valid policy",
			policyID: "1",
			wantCode: http.StatusOK,
		},
		{
			name:     "non-existent policy",
			policyID: "999",
			wantCode: http.StatusNotFound,
			wantErr:  "policy not found",
		},
		{
			name:     "invalid policy ID",
			policyID: "invalid",
			wantCode: http.StatusBadRequest,
			wantErr:  "invalid policy ID",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/api/v1/policies/"+tt.policyID, nil)
			w := httptest.NewRecorder()

			// Mock gorilla/mux vars
			req = muxVars(req, map[string]string{"id": tt.policyID})

			policies.GetPolicy(w, req)

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

			if tt.wantCode == http.StatusOK {
				var policy struct {
					ID          int    `json:"id"`
					Name        string `json:"name"`
					Description string `json:"description"`
					SourceID    int    `json:"source_id"`
					SourceType  string `json:"source_type"`
					ServiceID   int    `json:"service_id"`
					TargetID    int    `json:"target_id"`
					TargetType  string `json:"target_type"`
					Action      string `json:"action"`
					Priority    int    `json:"priority"`
					Enabled     bool   `json:"enabled"`
				}
				if err := json.NewDecoder(w.Body).Decode(&policy); err != nil {
					t.Fatalf("failed to decode policy: %v", err)
				}
				if policy.Name != "test-policy" {
					t.Errorf("expected name %q, got %q", "test-policy", policy.Name)
				}
				if !policy.Enabled {
					t.Error("expected policy to be enabled")
				}
			}
		})
	}
}

// TestUpdatePolicy tests the PUT /policies/{id} endpoint
func TestUpdatePolicy(t *testing.T) {
	api, database, cleanup := setupTestAPI(t)
	defer cleanup()

	// Insert test data
	database.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, has_docker) VALUES (?, ?, ?, ?, ?)`,
		"test-peer", "10.0.0.1", "test-key", false)
	database.Exec(`INSERT INTO groups (name) VALUES (?)`, "test-group")
	database.Exec(`INSERT INTO services (name, ports, protocol) VALUES (?, ?, ?)`,
		"ssh", "22", "tcp")
	database.Exec(`INSERT INTO policies (name, source_id, source_type, service_id, target_id, target_type, action, priority, enabled) VALUES (?, ?, 'group', ?, ?, 'peer', ?, ?, ?)`,
		"test-policy", 1, 1, 1, "ACCEPT", 100, 1)

	tests := []struct {
		name     string
		policyID string
		body     string
		wantCode int
		wantErr  string
	}{
		{
			name:     "valid update",
			policyID: "1",
			body:     `{"name": "updated-policy", "action": "DROP", "priority": 200, "enabled": false}`,
			wantCode: http.StatusOK,
		},
		{
			name:     "non-existent policy",
			policyID: "999",
			body:     `{"name": "test"}`,
			wantCode: http.StatusNotFound,
		},
		{
			name:     "invalid JSON",
			policyID: "1",
			body:     `{"invalid json}`,
			wantCode: http.StatusBadRequest,
			wantErr:  "invalid JSON",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("PUT", "/api/v1/policies/"+tt.policyID, strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			// Mock gorilla/mux vars
			req = muxVars(req, map[string]string{"id": tt.policyID})

			// Set up context with API instance
			ctx := context.WithValue(req.Context(), apiContextKey, api)
			req = req.WithContext(ctx)

			handler := policies.MakeUpdatePolicyHandler(api.Compiler)
			handler(w, req)

			if w.Code != tt.wantCode {
				t.Errorf("expected status %d, got %d: %s", tt.wantCode, w.Code, w.Body.String())
			}
		})
	}
}

// TestDeletePolicy tests the DELETE /policies/{id} endpoint
func TestDeletePolicy(t *testing.T) {
	api, database, cleanup := setupTestAPI(t)
	defer cleanup()

	// Insert test data
	database.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, has_docker) VALUES (?, ?, ?, ?, ?)`,
		"test-peer", "10.0.0.1", "test-key", false)
	database.Exec(`INSERT INTO groups (name) VALUES (?)`, "test-group")
	database.Exec(`INSERT INTO services (name, ports, protocol) VALUES (?, ?, ?)`,
		"ssh", "22", "tcp")
	database.Exec(`INSERT INTO policies (name, source_id, source_type, service_id, target_id, target_type, action, priority, enabled) VALUES (?, ?, 'group', ?, ?, 'peer', ?, ?, ?)`,
		"test-policy", 1, 1, 1, "ACCEPT", 100, 1)

	tests := []struct {
		name     string
		policyID string
		wantCode int
		wantErr  string
	}{
		{
			name:     "valid delete",
			policyID: "1",
			wantCode: http.StatusNoContent,
		},
		{
			name:     "non-existent policy",
			policyID: "999",
			wantCode: http.StatusNotFound,
			wantErr:  "policy not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("DELETE", "/api/v1/policies/"+tt.policyID, nil)
			w := httptest.NewRecorder()

			// Mock gorilla/mux vars
			req = muxVars(req, map[string]string{"id": tt.policyID})

			handler := policies.MakeDeletePolicyHandler(api.Compiler)
			handler(w, req)

			if w.Code != tt.wantCode {
				t.Errorf("expected status %d, got %d: %s", tt.wantCode, w.Code, w.Body.String())
			}

			if tt.wantCode == http.StatusNoContent {
				// Verify policy was deleted
				var count int
				err := database.QueryRow("SELECT COUNT(*) FROM policies WHERE id = ?", tt.policyID).Scan(&count)
				if err != nil {
					t.Fatalf("failed to check policy deletion: %v", err)
				}
				if count != 0 {
					t.Error("expected policy to be deleted")
				}
			}
		})
	}
}

// TestListGroups tests the GET /groups endpoint
func TestListGroups(t *testing.T) {
	_, database, cleanup := setupTestAPI(t)
	defer cleanup()

	// Insert test groups
	database.Exec(`INSERT INTO groups (name, description) VALUES (?, ?)`, "group1", "test group 1")
	database.Exec(`INSERT INTO groups (name, description) VALUES (?, ?)`, "group2", "test group 2")

	req := httptest.NewRequest("GET", "/api/v1/groups", nil)
	w := httptest.NewRecorder()

	groups.ListGroups(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var groups []struct {
		ID          int    `json:"id"`
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(w.Body).Decode(&groups); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(groups) != 2 {
		t.Errorf("expected 2 groups, got %d", len(groups))
	}
}

// TestCreateGroup tests the POST /groups endpoint
func TestCreateGroup(t *testing.T) {
	tests := []struct {
		name           string
		body           string
		wantCode       int
		wantErr        string
		validateResult func(*testing.T, map[string]int64)
	}{
		{
			name:     "valid group",
			body:     `{"name": "test-group", "description": "test description"}`,
			wantCode: http.StatusCreated,
			validateResult: func(t *testing.T, r map[string]int64) {
				if r["id"] == 0 {
					t.Error("expected non-zero group ID")
				}
			},
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
			_, _, cleanup := setupTestAPI(t)
			defer cleanup()

			req := httptest.NewRequest("POST", "/api/v1/groups", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			groups.CreateGroup(w, req)

			if w.Code != tt.wantCode {
				t.Errorf("expected status %d, got %d: %s", tt.wantCode, w.Code, w.Body.String())
			}

			if tt.validateResult != nil && w.Code == http.StatusCreated {
				var result map[string]int64
				if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
					t.Fatalf("failed to decode result: %v", err)
				}
				tt.validateResult(t, result)
			}
		})
	}
}

// TestListServices tests the GET /services endpoint
func TestListServices(t *testing.T) {
	_, database, cleanup := setupTestAPI(t)
	defer cleanup()

	// Insert test services
	database.Exec(`INSERT INTO services (name, ports, protocol, description) VALUES (?, ?, ?, ?)`, "http", "80", "tcp", "HTTP web server")
	database.Exec(`INSERT INTO services (name, ports, protocol, description) VALUES (?, ?, ?, ?)`, "ssh", "22", "tcp", "SSH access")

	req := httptest.NewRequest("GET", "/api/v1/services", nil)
	w := httptest.NewRecorder()

	services.ListServices(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var services []struct {
		ID          int    `json:"id"`
		Name        string `json:"name"`
		Ports       string `json:"ports"`
		Protocol    string `json:"protocol"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(w.Body).Decode(&services); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(services) != 2 {
		t.Errorf("expected 2 services, got %d", len(services))
	}
}

// TestCreateService tests the POST /services endpoint
func TestCreateService(t *testing.T) {
	tests := []struct {
		name           string
		body           string
		wantCode       int
		wantErr        string
		validateResult func(*testing.T, map[string]int64)
	}{
		{
			name:     "valid service",
			body:     `{"name": "test-service", "ports": "60443", "protocol": "tcp", "description": "test"}`,
			wantCode: http.StatusCreated,
			validateResult: func(t *testing.T, r map[string]int64) {
				if r["id"] == 0 {
					t.Error("expected non-zero service ID")
				}
			},
		},
		{
			name:     "multiport service",
			body:     `{"name": "web", "ports": "80,443", "protocol": "tcp"}`,
			wantCode: http.StatusCreated,
		},
		{
			name:     "port range service",
			body:     `{"name": "highports", "ports": "8000:9000", "protocol": "tcp"}`,
			wantCode: http.StatusCreated,
		},
		{
			name:     "missing name",
			body:     `{"ports": "80", "protocol": "tcp"}`,
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
			api, _, cleanup := setupTestAPI(t)
			defer cleanup()

			req := httptest.NewRequest("POST", "/api/v1/services", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			services.MakeCreateServiceHandler(api.Compiler)(w, req)

			if w.Code != tt.wantCode {
				t.Errorf("expected status %d, got %d: %s", tt.wantCode, w.Code, w.Body.String())
			}

			if tt.validateResult != nil && w.Code == http.StatusCreated {
				var result map[string]int64
				if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
					t.Fatalf("failed to decode result: %v", err)
				}
				tt.validateResult(t, result)
			}
		})
	}
}

// TestGroupMembers tests group member operations
func TestGroupMembers(t *testing.T) {
	api, database, cleanup := setupTestAPI(t)
	defer cleanup()

	// Insert test group
	database.Exec(`INSERT INTO groups (name) VALUES (?)`, "test-group")

	// Insert test peers to add to group
	// Note: SQLite auto-increment starts at 1, so these will be IDs 1 and 2
	database.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, is_manual) VALUES (?, ?, ?, ?, 1)`,
		"peer1", "192.168.1.100", "key1", "hmac1")
	database.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, is_manual) VALUES (?, ?, ?, ?, 1)`,
		"peer2", "10.0.0.0/24", "key2", "hmac2")

	// Add peer 1 to group 1
	req1 := httptest.NewRequest("POST", "/api/v1/groups/1/members", strings.NewReader(`{"peer_id": 1}`))
	req1.Header.Set("Content-Type", "application/json")
	w1 := httptest.NewRecorder()
	req1 = muxVars(req1, map[string]string{"id": "1"})
	groups.MakeAddGroupMemberHandler(api.Compiler)(w1, req1)
	if w1.Code != http.StatusCreated {
		t.Errorf("expected status %d, got %d: %s", http.StatusCreated, w1.Code, w1.Body.String())
	}

	// Add peer 2 to group 1
	req2 := httptest.NewRequest("POST", "/api/v1/groups/1/members", strings.NewReader(`{"peer_id": 2}`))
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	req2 = muxVars(req2, map[string]string{"id": "1"})
	groups.MakeAddGroupMemberHandler(api.Compiler)(w2, req2)
	if w2.Code != http.StatusCreated {
		t.Errorf("expected status %d, got %d: %s", http.StatusCreated, w2.Code, w2.Body.String())
	}

	// Test listing members
	req := httptest.NewRequest("GET", "/api/v1/groups/1/members", nil)
	w := httptest.NewRecorder()
	req = muxVars(req, map[string]string{"id": "1"})
	groups.ListGroupMembers(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	// New schema returns peer objects, not member objects
	var members []struct {
		ID        int    `json:"id"`
		Hostname  string `json:"hostname"`
		IPAddress string `json:"ip_address"`
		IsManual  bool   `json:"is_manual"`
	}
	if err := json.NewDecoder(w.Body).Decode(&members); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(members) != 2 {
		t.Errorf("expected 2 members, got %d", len(members))
	}
}

// TestHelpers tests helper functions
func TestHelpers(t *testing.T) {
	t.Run("RespondJSON", func(t *testing.T) {
		w := httptest.NewRecorder()
		data := map[string]string{"test": "value"}

		common.RespondJSON(w, http.StatusOK, data)

		if w.Code != http.StatusOK {
			t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
		}

		if w.Header().Get("Content-Type") != "application/json" {
			t.Errorf("expected Content-Type application/json, got %s", w.Header().Get("Content-Type"))
		}

		var resp map[string]string
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		if resp["test"] != "value" {
			t.Errorf("expected test value, got %s", resp["test"])
		}
	})

	t.Run("RespondError", func(t *testing.T) {
		w := httptest.NewRecorder()
		msg := "test error"

		common.RespondError(w, http.StatusBadRequest, msg)

		if w.Code != http.StatusBadRequest {
			t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
		}

		var resp map[string]string
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		if resp["error"] != msg {
			t.Errorf("expected error %q, got %q", msg, resp["error"])
		}
	})

	t.Run("ParseIDParam", func(t *testing.T) {
		// This would require mocking gorilla/mux, so we'll skip it for now
		// In a real test, you'd use gorilla/mux's NewRoute with vars
	})
}

// muxVars is a helper to mock gorilla/mux vars
func muxVars(r *http.Request, vars map[string]string) *http.Request {
	// Use gorilla/mux's SetURLVars to properly set route variables
	return mux.SetURLVars(r, vars)
}

// TestJSONDecoding tests JSON decoding edge cases
func TestJSONDecoding(t *testing.T) {
	api, _, _ := setupTestAPI(t)

	tests := []struct {
		name     string
		body     io.Reader
		wantCode int
	}{
		{
			name:     "nil body",
			body:     nil,
			wantCode: http.StatusBadRequest,
		},
		{
			name:     "empty body",
			body:     bytes.NewReader([]byte("")),
			wantCode: http.StatusBadRequest,
		},
		{
			name:     "whitespace body",
			body:     bytes.NewReader([]byte(" ")),
			wantCode: http.StatusBadRequest,
		},
		{
			name:     "malformed JSON",
			body:     bytes.NewReader([]byte("{ broken json")),
			wantCode: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/api/v1/peers", tt.body)
			if tt.body != nil {
				req.Header.Set("Content-Type", "application/json")
			}
			w := httptest.NewRecorder()

			// Set up context with API instance
			ctx := context.WithValue(req.Context(), apiContextKey, api)
			req = req.WithContext(ctx)

			peers.CreatePeer(w, req)

			if w.Code != tt.wantCode {
				t.Errorf("expected status %d, got %d", tt.wantCode, w.Code)
			}
		})
	}
}

// TestDatabaseConnectionFailures tests database failure scenarios
func TestDatabaseConnectionFailures(t *testing.T) {
	// This test is conceptual - in a real test, you would:
	// 1. Mock the database connection
	// 2. Simulate connection errors
	// 3. Verify proper error handling
	t.Skip("skipping - requires database mocking")
}

// TestConcurrentRequests tests concurrent API requests
func TestConcurrentRequests(t *testing.T) {
	_, database, cleanup := setupTestAPI(t)
	defer cleanup()

	// Insert test data
	database.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, has_docker) VALUES (?, ?, ?, ?, ?)`,
		"peer1", "10.0.0.1", "key1", "hmac1", true)
	database.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, has_docker) VALUES (?, ?, ?, ?, ?)`,
		"peer2", "10.0.0.2", "key2", "hmac2", false)

	// Make concurrent requests
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func() {
			req := httptest.NewRequest("GET", "/api/v1/peers", nil)
			w := httptest.NewRecorder()
			peers.GetPeers(w, req)
			done <- true
		}()
	}

	// Wait for all requests to complete
	for i := 0; i < 10; i++ {
		<-done
	}
}

// TestResponseHeaders tests response headers
func TestResponseHeaders(t *testing.T) {
	_, _, cleanup := setupTestAPI(t)
	defer cleanup()

	req := httptest.NewRequest("GET", "/api/v1/peers", nil)
	w := httptest.NewRecorder()

	peers.GetPeers(w, req)

	if w.Header().Get("Content-Type") != "application/json" {
		t.Errorf("expected Content-Type application/json, got %s", w.Header().Get("Content-Type"))
	}
}
