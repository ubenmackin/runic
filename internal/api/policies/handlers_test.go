package policies

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"runic/internal/api/common"
	"runic/internal/engine"
	"runic/internal/testutil"
)

// Helper to set up test DB with required data
func setupTestDBWithData(t *testing.T) (*sql.DB, func()) {
	db, cleanup := testutil.SetupTestDBWithTestData(t)

	// Insert special target
	_, err := db.Exec(
		"INSERT INTO special_targets (name, display_name, description, address) VALUES (?, ?, ?, ?)",
		"dns", "DNS", "DNS service", "8.8.8.8",
	)
	if err != nil {
		cleanup()
		t.Fatalf("failed to insert special target: %v", err)
	}

	return db, cleanup
}

// Helper to set up handler with real compiler (required for write operations)
func setupHandlerWithCompiler(db *sql.DB) *Handler {
	compiler := engine.NewCompiler(db)
	changeWorker := common.NewChangeWorker(nil) // nil sseHub for tests
	// Start the worker with a cancelled context so it doesn't process anything
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately
	changeWorker.Start(ctx)
	return NewHandler(db, compiler, changeWorker)
}

// Helper to set up handler for read-only operations
func setupHandler(db *sql.DB) *Handler {
	return NewHandler(db, nil, nil)
}

// Helper to create mux request with vars
var muxVars = testutil.MuxVars

// =============================================================================
// Test ListPolicies
// =============================================================================

func TestListPolicies(t *testing.T) {
	tests := []struct {
		name           string
		setupDB        func(t *testing.T, db *sql.DB)
		wantStatusCode int
		wantCount      int
	}{
		{
			name:           "empty table returns empty array",
			setupDB:        nil,
			wantStatusCode: http.StatusOK,
			wantCount:      0,
		},
		{
			name: "multiple policies returns all",
			setupDB: func(t *testing.T, db *sql.DB) {
				db.Exec(`
					INSERT INTO policies (name, source_id, source_type, service_id, target_id, target_type, action, priority, enabled)
					VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?),
					       (?, ?, ?, ?, ?, ?, ?, ?, ?),
					       (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
					"policy-1", 1, "peer", 1, 1, "peer", "ACCEPT", 100, true,
					"policy-2", 1, "group", 1, 1, "group", "DROP", 200, true,
					"policy-3", 1, "special", 1, 1, "special", "ACCEPT", 300, false,
				)
			},
			wantStatusCode: http.StatusOK,
			wantCount:      3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, cleanup := testutil.SetupTestDB(t)
			defer cleanup()

			if tt.setupDB != nil {
				tt.setupDB(t, db)
			}

			handler := setupHandler(db)

			req := httptest.NewRequest("GET", "/policies", nil)
			w := httptest.NewRecorder()

			handler.ListPolicies(w, req)

			if w.Code != tt.wantStatusCode {
				t.Errorf("expected status %d, got %d: %s", tt.wantStatusCode, w.Code, w.Body.String())
			}

			if tt.wantCount > 0 {
				var policies []map[string]interface{}
				if err := json.Unmarshal(w.Body.Bytes(), &policies); err != nil {
					t.Fatalf("failed to unmarshal response: %v", err)
				}
				if len(policies) != tt.wantCount {
					t.Errorf("expected %d policies, got %d", tt.wantCount, len(policies))
				}
			}
		})
	}
}

// =============================================================================
// Test CreatePolicy
// =============================================================================

func TestCreatePolicy(t *testing.T) {
	tests := []struct {
		name           string
		body           string
		setupDB        func(t *testing.T, db *sql.DB)
		wantStatusCode int
		wantID         bool
	}{
		{
			name:           "invalid JSON returns 400",
			body:           "{invalid json}",
			setupDB:        nil,
			wantStatusCode: http.StatusBadRequest,
		},
		{
			name: "missing required fields returns 400",
			body: `{"name": "test"}`,
			setupDB: func(t *testing.T, db *sql.DB) {
				db.Exec("INSERT INTO services (name, ports, protocol) VALUES (?, ?, ?)", "test-service", "8080", "tcp")
				db.Exec("INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)", "test-peer", "10.0.0.1", "key", "hmac")
			},
			wantStatusCode: http.StatusBadRequest,
		},
		{
			name: "name too long returns 400",
			body: `{"name": "` + strings.Repeat("a", 256) + `", "source_id": 1, "source_type": "peer", "service_id": 1, "target_id": 1, "target_type": "peer"}`,
			setupDB: func(t *testing.T, db *sql.DB) {
				db.Exec("INSERT INTO services (name, ports, protocol) VALUES (?, ?, ?)", "test-service", "8080", "tcp")
				db.Exec("INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)", "test-peer", "10.0.0.1", "key", "hmac")
			},
			wantStatusCode: http.StatusBadRequest,
		},
		{
			name: "invalid source_type returns 400",
			body: `{"name": "test", "source_id": 1, "source_type": "invalid", "service_id": 1, "target_id": 1, "target_type": "peer"}`,
			setupDB: func(t *testing.T, db *sql.DB) {
				db.Exec("INSERT INTO services (name, ports, protocol) VALUES (?, ?, ?)", "test-service", "8080", "tcp")
				db.Exec("INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)", "test-peer", "10.0.0.1", "key", "hmac")
			},
			wantStatusCode: http.StatusBadRequest,
		},
		{
			name: "invalid target_type returns 400",
			body: `{"name": "test", "source_id": 1, "source_type": "peer", "service_id": 1, "target_id": 1, "target_type": "invalid"}`,
			setupDB: func(t *testing.T, db *sql.DB) {
				db.Exec("INSERT INTO services (name, ports, protocol) VALUES (?, ?, ?)", "test-service", "8080", "tcp")
				db.Exec("INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)", "test-peer", "10.0.0.1", "key", "hmac")
			},
			wantStatusCode: http.StatusBadRequest,
		},
		{
			name: "invalid direction returns 400",
			body: `{"name": "test", "source_id": 1, "source_type": "peer", "service_id": 1, "target_id": 1, "target_type": "peer", "direction": "invalid"}`,
			setupDB: func(t *testing.T, db *sql.DB) {
				db.Exec("INSERT INTO services (name, ports, protocol) VALUES (?, ?, ?)", "test-service", "8080", "tcp")
				db.Exec("INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)", "test-peer", "10.0.0.1", "key", "hmac")
			},
			wantStatusCode: http.StatusBadRequest,
		},
		{
			name: "invalid target_scope returns 400",
			body: `{"name": "test", "source_id": 1, "source_type": "peer", "service_id": 1, "target_id": 1, "target_type": "peer", "target_scope": "invalid"}`,
			setupDB: func(t *testing.T, db *sql.DB) {
				db.Exec("INSERT INTO services (name, ports, protocol) VALUES (?, ?, ?)", "test-service", "8080", "tcp")
				db.Exec("INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)", "test-peer", "10.0.0.1", "key", "hmac")
			},
			wantStatusCode: http.StatusBadRequest,
		},
		{
			name: "valid creation returns 201",
			body: `{"name": "test-policy", "source_id": 1, "source_type": "peer", "service_id": 1, "target_id": 1, "target_type": "peer"}`,
			setupDB: func(t *testing.T, db *sql.DB) {
				db.Exec("INSERT INTO services (name, ports, protocol) VALUES (?, ?, ?)", "test-service", "8080", "tcp")
				db.Exec("INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)", "test-peer", "10.0.0.1", "key", "hmac")
			},
			wantStatusCode: http.StatusCreated,
			wantID:         true,
		},
		{
			name: "valid creation with all fields returns 201",
			body: `{"name": "full-policy", "description": "full description", "source_id": 1, "source_type": "group", "service_id": 1, "target_id": 1, "target_type": "special", "action": "DROP", "priority": 50, "enabled": false, "target_scope": "host", "direction": "forward"}`,
			setupDB: func(t *testing.T, db *sql.DB) {
				db.Exec("INSERT INTO services (name, ports, protocol) VALUES (?, ?, ?)", "test-service", "8080", "tcp")
				db.Exec("INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)", "test-peer", "10.0.0.1", "key", "hmac")
				db.Exec("INSERT INTO groups (name, description) VALUES (?, ?)", "test-group", "desc")
				db.Exec("INSERT INTO special_targets (name, display_name, description, address) VALUES (?, ?, ?, ?)", "dns", "DNS", "DNS", "8.8.8.8")
			},
			wantStatusCode: http.StatusCreated,
			wantID:         true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, cleanup := testutil.SetupTestDB(t)
			defer cleanup()

			if tt.setupDB != nil {
				tt.setupDB(t, db)
			}

			handler := setupHandlerWithCompiler(db)

			req := httptest.NewRequest("POST", "/policies", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			handler.CreatePolicy(w, req)

			if w.Code != tt.wantStatusCode {
				t.Errorf("expected status %d, got %d: %s", tt.wantStatusCode, w.Code, w.Body.String())
			}

			if tt.wantID {
				var resp map[string]int64
				if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
					t.Fatalf("failed to unmarshal response: %v", err)
				}
				if resp["id"] == 0 {
					t.Error("expected non-zero id in response")
				}
			}
		})
	}
}

// =============================================================================
// Test GetPolicy
// =============================================================================

func TestGetPolicy(t *testing.T) {
	tests := []struct {
		name           string
		policyID       string
		setupDB        func(t *testing.T, db *sql.DB)
		wantStatusCode int
	}{
		{
			name:           "invalid ID returns 400",
			policyID:       "invalid",
			setupDB:        nil,
			wantStatusCode: http.StatusBadRequest,
		},
		{
			name:     "not found returns 404",
			policyID: "999",
			setupDB: func(t *testing.T, db *sql.DB) {
				db.Exec("INSERT INTO services (name, ports, protocol) VALUES (?, ?, ?)", "test-service", "8080", "tcp")
				db.Exec("INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)", "test-peer", "10.0.0.1", "key", "hmac")
			},
			wantStatusCode: http.StatusNotFound,
		},
		{
			name:     "found returns 200",
			policyID: "1",
			setupDB: func(t *testing.T, db *sql.DB) {
				db.Exec("INSERT INTO services (name, ports, protocol) VALUES (?, ?, ?)", "test-service", "8080", "tcp")
				db.Exec("INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)", "test-peer", "10.0.0.1", "key", "hmac")
				db.Exec(`
					INSERT INTO policies (name, source_id, source_type, service_id, target_id, target_type, action, priority, enabled)
					VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
					"test-policy", 1, "peer", 1, 1, "peer", "ACCEPT", 100, true,
				)
			},
			wantStatusCode: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, cleanup := testutil.SetupTestDB(t)
			defer cleanup()

			if tt.setupDB != nil {
				tt.setupDB(t, db)
			}

			handler := setupHandler(db)

			req := httptest.NewRequest("GET", "/policies/"+tt.policyID, nil)
			req = muxVars(req, map[string]string{"id": tt.policyID})
			w := httptest.NewRecorder()

			handler.GetPolicy(w, req)

			if w.Code != tt.wantStatusCode {
				t.Errorf("expected status %d, got %d: %s", tt.wantStatusCode, w.Code, w.Body.String())
			}
		})
	}
}

// =============================================================================
// Test UpdatePolicy
// =============================================================================

func TestUpdatePolicy(t *testing.T) {
	tests := []struct {
		name           string
		policyID       string
		body           string
		setupDB        func(t *testing.T, db *sql.DB)
		wantStatusCode int
	}{
		{
			name:           "invalid ID returns 400",
			policyID:       "invalid",
			body:           `{"name": "updated"}`,
			setupDB:        nil,
			wantStatusCode: http.StatusBadRequest,
		},
		{
			name:     "invalid JSON returns 400",
			policyID: "1",
			body:     "{invalid json}",
			setupDB: func(t *testing.T, db *sql.DB) {
				db.Exec("INSERT INTO services (name, ports, protocol) VALUES (?, ?, ?)", "test-service", "8080", "tcp")
				db.Exec("INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)", "test-peer", "10.0.0.1", "key", "hmac")
			},
			wantStatusCode: http.StatusBadRequest,
		},
		{
			name:     "missing name returns 400",
			policyID: "1",
			body:     `{"source_id": 1}`,
			setupDB: func(t *testing.T, db *sql.DB) {
				db.Exec("INSERT INTO services (name, ports, protocol) VALUES (?, ?, ?)", "test-service", "8080", "tcp")
				db.Exec("INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)", "test-peer", "10.0.0.1", "key", "hmac")
			},
			wantStatusCode: http.StatusBadRequest,
		},
		{
			name:     "not found returns 404",
			policyID: "999",
			body:     `{"name": "updated"}`,
			setupDB: func(t *testing.T, db *sql.DB) {
				db.Exec("INSERT INTO services (name, ports, protocol) VALUES (?, ?, ?)", "test-service", "8080", "tcp")
				db.Exec("INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)", "test-peer", "10.0.0.1", "key", "hmac")
			},
			wantStatusCode: http.StatusNotFound,
		},
		{
			name:     "valid update returns 200",
			policyID: "1",
			body:     `{"name": "updated-policy", "source_id": 1, "source_type": "peer", "service_id": 1, "target_id": 1, "target_type": "peer", "action": "ACCEPT"}`,
			setupDB: func(t *testing.T, db *sql.DB) {
				db.Exec("INSERT INTO services (name, ports, protocol) VALUES (?, ?, ?)", "test-service", "8080", "tcp")
				db.Exec("INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)", "test-peer", "10.0.0.1", "key", "hmac")
				db.Exec(`
					INSERT INTO policies (name, source_id, source_type, service_id, target_id, target_type, action, priority, enabled)
					VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
					"test-policy", 1, "peer", 1, 1, "peer", "ACCEPT", 100, true,
				)
			},
			wantStatusCode: http.StatusOK,
		},
		{
			name:     "name too long returns 400",
			policyID: "1",
			body:     `{"name": "` + strings.Repeat("a", 256) + `", "source_id": 1, "source_type": "peer", "service_id": 1, "target_id": 1, "target_type": "peer"}`,
			setupDB: func(t *testing.T, db *sql.DB) {
				db.Exec("INSERT INTO services (name, ports, protocol) VALUES (?, ?, ?)", "test-service", "8080", "tcp")
				db.Exec("INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)", "test-peer", "10.0.0.1", "key", "hmac")
			},
			wantStatusCode: http.StatusBadRequest,
		},
		{
			name:     "invalid direction returns 400",
			policyID: "1",
			body:     `{"name": "updated", "direction": "invalid", "source_id": 1, "source_type": "peer", "service_id": 1, "target_id": 1, "target_type": "peer"}`,
			setupDB: func(t *testing.T, db *sql.DB) {
				db.Exec("INSERT INTO services (name, ports, protocol) VALUES (?, ?, ?)", "test-service", "8080", "tcp")
				db.Exec("INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)", "test-peer", "10.0.0.1", "key", "hmac")
			},
			wantStatusCode: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, cleanup := testutil.SetupTestDB(t)
			defer cleanup()

			if tt.setupDB != nil {
				tt.setupDB(t, db)
			}

			handler := setupHandlerWithCompiler(db)

			req := httptest.NewRequest("PUT", "/policies/"+tt.policyID, strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			req = muxVars(req, map[string]string{"id": tt.policyID})
			w := httptest.NewRecorder()

			handler.UpdatePolicy(w, req)

			if w.Code != tt.wantStatusCode {
				t.Errorf("expected status %d, got %d: %s", tt.wantStatusCode, w.Code, w.Body.String())
			}
		})
	}
}

// =============================================================================
// Test DeletePolicy
// =============================================================================

func TestDeletePolicy(t *testing.T) {
	tests := []struct {
		name           string
		policyID       string
		setupDB        func(t *testing.T, db *sql.DB)
		wantStatusCode int
	}{
		{
			name:           "invalid ID returns 400",
			policyID:       "invalid",
			setupDB:        nil,
			wantStatusCode: http.StatusBadRequest,
		},
		{
			name:     "not found returns 404",
			policyID: "999",
			setupDB: func(t *testing.T, db *sql.DB) {
				db.Exec("INSERT INTO services (name, ports, protocol) VALUES (?, ?, ?)", "test-service", "8080", "tcp")
				db.Exec("INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)", "test-peer", "10.0.0.1", "key", "hmac")
			},
			wantStatusCode: http.StatusNotFound,
		},
		{
			name:     "valid delete returns 204",
			policyID: "1",
			setupDB: func(t *testing.T, db *sql.DB) {
				db.Exec("INSERT INTO services (name, ports, protocol) VALUES (?, ?, ?)", "test-service", "8080", "tcp")
				db.Exec("INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)", "test-peer", "10.0.0.1", "key", "hmac")
				db.Exec(`
					INSERT INTO policies (name, source_id, source_type, service_id, target_id, target_type, action, priority, enabled)
					VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
					"test-policy", 1, "peer", 1, 1, "peer", "ACCEPT", 100, true,
				)
			},
			wantStatusCode: http.StatusNoContent,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, cleanup := testutil.SetupTestDB(t)
			defer cleanup()

			if tt.setupDB != nil {
				tt.setupDB(t, db)
			}

			handler := setupHandlerWithCompiler(db)

			req := httptest.NewRequest("DELETE", "/policies/"+tt.policyID, nil)
			req = muxVars(req, map[string]string{"id": tt.policyID})
			w := httptest.NewRecorder()

			handler.DeletePolicy(w, req)

			if w.Code != tt.wantStatusCode {
				t.Errorf("expected status %d, got %d: %s", tt.wantStatusCode, w.Code, w.Body.String())
			}
		})
	}
}

// =============================================================================
// Test PatchPolicy
// =============================================================================

func TestPatchPolicy(t *testing.T) {
	tests := []struct {
		name           string
		policyID       string
		body           string
		setupDB        func(t *testing.T, db *sql.DB)
		wantStatusCode int
	}{
		{
			name:           "invalid ID returns 400",
			policyID:       "invalid",
			body:           `{"enabled": true}`,
			setupDB:        nil,
			wantStatusCode: http.StatusBadRequest,
		},
		{
			name:     "invalid JSON returns 400",
			policyID: "1",
			body:     "{invalid",
			setupDB: func(t *testing.T, db *sql.DB) {
				db.Exec("INSERT INTO services (name, ports, protocol) VALUES (?, ?, ?)", "test-service", "8080", "tcp")
				db.Exec("INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)", "test-peer", "10.0.0.1", "key", "hmac")
			},
			wantStatusCode: http.StatusBadRequest,
		},
		{
			name:     "missing enabled field returns 400",
			policyID: "1",
			body:     `{"other": "field"}`,
			setupDB: func(t *testing.T, db *sql.DB) {
				db.Exec("INSERT INTO services (name, ports, protocol) VALUES (?, ?, ?)", "test-service", "8080", "tcp")
				db.Exec("INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)", "test-peer", "10.0.0.1", "key", "hmac")
			},
			wantStatusCode: http.StatusBadRequest,
		},
		{
			name:     "not found returns 404",
			policyID: "999",
			body:     `{"enabled": true}`,
			setupDB: func(t *testing.T, db *sql.DB) {
				db.Exec("INSERT INTO services (name, ports, protocol) VALUES (?, ?, ?)", "test-service", "8080", "tcp")
				db.Exec("INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)", "test-peer", "10.0.0.1", "key", "hmac")
			},
			wantStatusCode: http.StatusNotFound,
		},
		{
			name:     "enable policy returns 200",
			policyID: "1",
			body:     `{"enabled": true}`,
			setupDB: func(t *testing.T, db *sql.DB) {
				db.Exec("INSERT INTO services (name, ports, protocol) VALUES (?, ?, ?)", "test-service", "8080", "tcp")
				db.Exec("INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)", "test-peer", "10.0.0.1", "key", "hmac")
				db.Exec(`
					INSERT INTO policies (name, source_id, source_type, service_id, target_id, target_type, action, priority, enabled)
					VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
					"test-policy", 1, "peer", 1, 1, "peer", "ACCEPT", 100, true,
				)
			},
			wantStatusCode: http.StatusOK,
		},
		{
			name:     "disable policy returns 200",
			policyID: "1",
			body:     `{"enabled": false}`,
			setupDB: func(t *testing.T, db *sql.DB) {
				db.Exec("INSERT INTO services (name, ports, protocol) VALUES (?, ?, ?)", "test-service", "8080", "tcp")
				db.Exec("INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)", "test-peer", "10.0.0.1", "key", "hmac")
				db.Exec(`
					INSERT INTO policies (name, source_id, source_type, service_id, target_id, target_type, action, priority, enabled)
					VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
					"test-policy", 1, "peer", 1, 1, "peer", "ACCEPT", 100, true,
				)
			},
			wantStatusCode: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, cleanup := testutil.SetupTestDB(t)
			defer cleanup()

			if tt.setupDB != nil {
				tt.setupDB(t, db)
			}

			handler := setupHandlerWithCompiler(db)

			req := httptest.NewRequest("PATCH", "/policies/"+tt.policyID, strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			req = muxVars(req, map[string]string{"id": tt.policyID})
			w := httptest.NewRecorder()

			handler.PatchPolicy(w, req)

			if w.Code != tt.wantStatusCode {
				t.Errorf("expected status %d, got %d: %s", tt.wantStatusCode, w.Code, w.Body.String())
			}
		})
	}
}

// =============================================================================
// Test PolicyPreview
// =============================================================================

func TestPolicyPreview(t *testing.T) {
	tests := []struct {
		name           string
		body           string
		setupDB        func(t *testing.T, db *sql.DB)
		wantStatusCode int
	}{
		{
			name:           "invalid JSON returns 400",
			body:           "{invalid",
			setupDB:        nil,
			wantStatusCode: http.StatusBadRequest,
		},
		{
			name: "valid request returns 200",
			body: `{"source_id": 1, "source_type": "peer", "target_id": 1, "target_type": "peer", "service_id": 1, "peer_id": 1, "direction": "both", "target_scope": "both"}`,
			setupDB: func(t *testing.T, db *sql.DB) {
				db.Exec("INSERT INTO services (name, ports, protocol) VALUES (?, ?, ?)", "test-service", "8080", "tcp")
				db.Exec("INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)", "test-peer", "10.0.0.1", "key", "hmac")
			},
			wantStatusCode: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, cleanup := testutil.SetupTestDB(t)
			defer cleanup()

			if tt.setupDB != nil {
				tt.setupDB(t, db)
			}

			handler := setupHandlerWithCompiler(db)

			req := httptest.NewRequest("POST", "/policies/preview", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			handler.PolicyPreview(w, req)

			if w.Code != tt.wantStatusCode {
				t.Errorf("expected status %d, got %d: %s", tt.wantStatusCode, w.Code, w.Body.String())
			}
		})
	}
}

// =============================================================================
// Test ListSpecialTargets
// =============================================================================

func TestListSpecialTargets(t *testing.T) {
	tests := []struct {
		name           string
		setupDB        func(t *testing.T, db *sql.DB)
		wantStatusCode int
		wantCount      int
	}{
		{
			name:           "empty table returns empty array",
			setupDB:        nil,
			wantStatusCode: http.StatusOK,
			wantCount:      0,
		},
		{
			name: "multiple targets returns all",
			setupDB: func(t *testing.T, db *sql.DB) {
				// Schema now inserts 8 default special targets (added __igmpv3__)
				// Insert 3 more for a total of 11
				db.Exec("INSERT INTO special_targets (name, display_name, description, address) VALUES (?, ?, ?, ?)", "dns", "DNS", "DNS service", "8.8.8.8")
				db.Exec("INSERT INTO special_targets (name, display_name, description, address) VALUES (?, ?, ?, ?)", "gateway", "Gateway", "Gateway service", "10.0.0.1")
				db.Exec("INSERT INTO special_targets (name, display_name, description, address) VALUES (?, ?, ?, ?)", "mesh", "Mesh", "Mesh network", "10.0.0.2")
			},
			wantStatusCode: http.StatusOK,
			wantCount:      11, // 8 default + 3 inserted
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, cleanup := testutil.SetupTestDB(t)
			defer cleanup()

			if tt.setupDB != nil {
				tt.setupDB(t, db)
			}

			handler := setupHandler(db)

			req := httptest.NewRequest("GET", "/policies/special-targets", nil)
			w := httptest.NewRecorder()

			handler.ListSpecialTargets(w, req)

			if w.Code != tt.wantStatusCode {
				t.Errorf("expected status %d, got %d: %s", tt.wantStatusCode, w.Code, w.Body.String())
			}

			if tt.wantCount > 0 {
				var targets []map[string]interface{}
				if err := json.Unmarshal(w.Body.Bytes(), &targets); err != nil {
					t.Fatalf("failed to unmarshal response: %v", err)
				}
				if len(targets) != tt.wantCount {
					t.Errorf("expected %d targets, got %d", tt.wantCount, len(targets))
				}
			}
		})
	}
}
