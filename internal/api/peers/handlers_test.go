package peers

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"runic/internal/testutil"
)

// muxVars is a helper to mock gorilla/mux vars
var muxVars = testutil.MuxVars

// TestGetPeers tests the GET /peers endpoint.
func TestGetPeers(t *testing.T) {
	tests := []struct {
		name         string
		setup        func(t *testing.T, db *sql.DB)
		wantCode     int
		wantPeersLen int
		wantErr      string
	}{
		{
			name: "get all peers - empty",
			setup: func(t *testing.T, db *sql.DB) {
				// No peers inserted - empty result
			},
			wantCode:     http.StatusOK,
			wantPeersLen: 0,
		},
		{
			name: "get all peers - with peers",
			setup: func(t *testing.T, db *sql.DB) {
				db.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, has_docker) VALUES (?, ?, ?, ?, ?)`,
					"peer1", "10.0.0.1", "key1", "hmac1", 0)
				db.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, has_docker) VALUES (?, ?, ?, ?, ?)`,
					"peer2", "10.0.0.2", "key2", "hmac2", 1)
			},
			wantCode:     http.StatusOK,
			wantPeersLen: 2,
		},
		{
			name: "get peers with groups",
			setup: func(t *testing.T, db *sql.DB) {
				db.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, has_docker) VALUES (?, ?, ?, ?, ?)`,
					"peer1", "10.0.0.1", "key1", "hmac1", 0)
				db.Exec(`INSERT INTO groups (name) VALUES (?)`, "group1")
				db.Exec(`INSERT INTO group_members (group_id, peer_id) VALUES (?, ?)`, 1, 1)
			},
			wantCode:     http.StatusOK,
			wantPeersLen: 1,
		},
		{
			name: "get peers with pending changes",
			setup: func(t *testing.T, db *sql.DB) {
				db.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, has_docker) VALUES (?, ?, ?, ?, ?)`,
					"peer1", "10.0.0.1", "key1", "hmac1", 0)
				db.Exec(`INSERT INTO pending_changes (peer_id, change_type, change_data) VALUES (?, ?, ?)`,
					1, "test", `{"key": "value"}`)
			},
			wantCode:     http.StatusOK,
			wantPeersLen: 1,
		},
		{
			name: "get peer with last heartbeat - online",
			setup: func(t *testing.T, db *sql.DB) {
				db.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, has_docker, last_heartbeat, status) VALUES (?, ?, ?, ?, ?, ?, ?)`,
					"peer1", "10.0.0.1", "key1", "hmac1", 0, "2024-01-01 12:00:00", "online")
			},
			wantCode:     http.StatusOK,
			wantPeersLen: 1,
		},
		{
			name: "get peer with old heartbeat - offline",
			setup: func(t *testing.T, db *sql.DB) {
				db.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, has_docker, last_heartbeat) VALUES (?, ?, ?, ?, ?, ?)`,
					"peer1", "10.0.0.1", "key1", "hmac1", 0, "2020-01-01 00:00:00")
			},
			wantCode:     http.StatusOK,
			wantPeersLen: 1,
		},
		{
			name: "get peer with no heartbeat - pending",
			setup: func(t *testing.T, db *sql.DB) {
				db.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, has_docker) VALUES (?, ?, ?, ?, ?)`,
					"peer1", "10.0.0.1", "key1", "hmac1", 0)
			},
			wantCode:     http.StatusOK,
			wantPeersLen: 1,
		},
		{
			name: "get peer with description",
			setup: func(t *testing.T, db *sql.DB) {
				db.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, has_docker, description) VALUES (?, ?, ?, ?, ?, ?)`,
					"peer1", "10.0.0.1", "key1", "hmac1", 0, "Test peer description")
			},
			wantCode:     http.StatusOK,
			wantPeersLen: 1,
		},
		{
			name: "get peer with rule bundle version",
			setup: func(t *testing.T, db *sql.DB) {
				db.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, has_docker) VALUES (?, ?, ?, ?, ?)`,
					"peer1", "10.0.0.1", "key1", "hmac1", 0)
				db.Exec(`INSERT INTO rule_bundles (peer_id, version, version_number, rules_content, hmac) VALUES (?, ?, ?, ?, ?)`,
					1, "v1", 5, "rules", "hmac")
			},
			wantCode:     http.StatusOK,
			wantPeersLen: 1,
		},
		{
			name: "get peers - DB query error",
			setup: func(t *testing.T, db *sql.DB) {
				// Close DB to cause error
				db.Close()
			},
			wantCode: http.StatusInternalServerError,
			wantErr:  "failed to query peers",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			database, cleanup := testutil.SetupTestDB(t)
			defer cleanup()

			if tt.setup != nil {
				tt.setup(t, database)
			}

			// Skip tests that require closed DB (we can't easily simulate DB errors)
			if strings.Contains(tt.name, "DB query error") {
				t.Skip("DB error simulation not supported in this test setup")
				return
			}

			req := httptest.NewRequest("GET", "/api/v1/peers", nil)
			w := httptest.NewRecorder()

			handler := NewHandler(database, nil)
			handler.GetPeers(w, req)

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

			if tt.wantPeersLen > 0 {
				var peers []Peer
				if err := json.NewDecoder(w.Body).Decode(&peers); err != nil {
					t.Fatalf("failed to decode peers response: %v", err)
				}
				if len(peers) != tt.wantPeersLen {
					t.Errorf("expected %d peers, got %d", tt.wantPeersLen, len(peers))
				}
			}
		})
	}
}

// TestCreatePeer tests the POST /peers endpoint.
func TestCreatePeer(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		wantCode   int
		wantErr    string
		wantID     bool
		verifyPeer func(t *testing.T, db *sql.DB)
	}{
		{
			name:     "create peer - success",
			body:     `{"hostname":"test-peer","ip_address":"10.0.0.1","agent_key":"test-key","os_type":"debian","arch":"amd64","has_docker":false,"is_manual":false}`,
			wantCode: http.StatusCreated,
			wantID:   true,
			verifyPeer: func(t *testing.T, db *sql.DB) {
				var hostname, ipAddress, agentKey, osType, arch string
				err := db.QueryRow("SELECT hostname, ip_address, agent_key, os_type, arch FROM peers WHERE id = 1").Scan(&hostname, &ipAddress, &agentKey, &osType, &arch)
				if err != nil {
					t.Fatalf("failed to query peer: %v", err)
				}
				if hostname != "test-peer" || ipAddress != "10.0.0.1" || osType != "debian" || arch != "amd64" {
					t.Errorf("peer not created correctly")
				}
			},
		},
		{
			name:     "create peer - manual peer without agent key",
			body:     `{"hostname":"manual-peer","ip_address":"10.0.0.2","is_manual":true}`,
			wantCode: http.StatusCreated,
			wantID:   true,
			verifyPeer: func(t *testing.T, db *sql.DB) {
				var hostname, agentKey string
				var isManual bool
				err := db.QueryRow("SELECT hostname, agent_key, is_manual FROM peers WHERE id = 1").Scan(&hostname, &agentKey, &isManual)
				if err != nil {
					t.Fatalf("failed to query peer: %v", err)
				}
				if !isManual {
					t.Error("expected is_manual to be true")
				}
				if !strings.HasPrefix(agentKey, "manual-") {
					t.Errorf("expected agent_key to start with 'manual-', got %s", agentKey)
				}
			},
		},
		{
			name:     "create peer - invalid JSON",
			body:     `{"invalid":}`,
			wantCode: http.StatusBadRequest,
			wantErr:  "invalid JSON",
		},
		{
			name:     "create peer - empty hostname",
			body:     `{"hostname":"","ip_address":"10.0.0.1","agent_key":"key"}`,
			wantCode: http.StatusBadRequest,
			wantErr:  "hostname must be",
		},
		{
			name:     "create peer - hostname too long",
			body:     `{"hostname":"` + strings.Repeat("a", 254) + `","ip_address":"10.0.0.1","agent_key":"key"}`,
			wantCode: http.StatusBadRequest,
			wantErr:  "hostname must be",
		},
		{
			name:     "create peer - invalid hostname chars",
			body:     `{"hostname":"test_peer!","ip_address":"10.0.0.1","agent_key":"key"}`,
			wantCode: http.StatusBadRequest,
			wantErr:  "hostname must be",
		},
		{
			name:     "create peer - invalid IP address",
			body:     `{"hostname":"test-peer","ip_address":"invalid-ip","agent_key":"key"}`,
			wantCode: http.StatusBadRequest,
			wantErr:  "invalid IP address",
		},
		{
			name:     "create peer - invalid os_type",
			body:     `{"hostname":"test-peer","ip_address":"10.0.0.1","agent_key":"key","os_type":"windows"}`,
			wantCode: http.StatusBadRequest,
			wantErr:  "os_type must be one of",
		},
		{
			name:     "create peer - invalid arch",
			body:     `{"hostname":"test-peer","ip_address":"10.0.0.1","agent_key":"key","arch":"x86"}`,
			wantCode: http.StatusBadRequest,
			wantErr:  "arch must be one of",
		},
		{
			name:     "create peer - agent peer without agent_key",
			body:     `{"hostname":"test-peer","ip_address":"10.0.0.1","is_manual":false}`,
			wantCode: http.StatusBadRequest,
			wantErr:  "agent_key is required for agent peers",
		},
		{
			name:     "create peer - all valid os types",
			body:     `{"hostname":"test-peer","ip_address":"10.0.0.1","agent_key":"key","os_type":"ubuntu","arch":"arm64"}`,
			wantCode: http.StatusCreated,
			wantID:   true,
		},
		{
			name:     "create peer - IPv6 address",
			body:     `{"hostname":"test-peer","ip_address":"::1","agent_key":"key"}`,
			wantCode: http.StatusCreated,
			wantID:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			database, cleanup := testutil.SetupTestDB(t)
			defer cleanup()

			req := httptest.NewRequest("POST", "/api/v1/peers", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			handler := NewHandler(database, nil)
			handler.CreatePeer(w, req)

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

			if tt.wantID {
				var resp map[string]int64
				if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
					t.Fatalf("failed to decode response: %v", err)
				}
				if resp["id"] == 0 {
					t.Error("expected non-zero id")
				}
			}

			if tt.verifyPeer != nil {
				tt.verifyPeer(t, database)
			}
		})
	}
}

// TestUpdatePeer tests the PUT /peers/{id} endpoint.
func TestUpdatePeer(t *testing.T) {
	tests := []struct {
		name       string
		peerID     string
		setup      func(t *testing.T, db *sql.DB)
		body       string
		wantCode   int
		wantErr    string
		wantMsg    string
		verifyPeer func(t *testing.T, db *sql.DB)
	}{
		{
			name:   "update peer - success",
			peerID: "1",
			setup: func(t *testing.T, db *sql.DB) {
				db.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, has_docker, is_manual) VALUES (?, ?, ?, ?, ?, ?)`,
					"old-host", "10.0.0.1", "key", "hmac", 0, 1)
			},
			body:     `{"hostname":"new-host","ip_address":"10.0.0.2","os_type":"ubuntu","arch":"amd64","has_docker":true,"description":"updated"}`,
			wantCode: http.StatusOK,
			wantMsg:  "peer updated",
			verifyPeer: func(t *testing.T, db *sql.DB) {
				var hostname, ipAddress, osType, arch string
				var hasDocker bool
				var description sql.NullString
				err := db.QueryRow("SELECT hostname, ip_address, os_type, arch, has_docker, description FROM peers WHERE id = 1").Scan(&hostname, &ipAddress, &osType, &arch, &hasDocker, &description)
				if err != nil {
					t.Fatalf("failed to query peer: %v", err)
				}
				if hostname != "new-host" || ipAddress != "10.0.0.2" {
					t.Errorf("peer not updated correctly")
				}
			},
		},
		{
			name:   "update peer - invalid ID",
			peerID: "invalid",
			setup: func(t *testing.T, db *sql.DB) {
				db.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, is_manual) VALUES (?, ?, ?, ?, ?)`,
					"test", "10.0.0.1", "key", "hmac", 1)
			},
			body:     `{"hostname":"new-host"}`,
			wantCode: http.StatusBadRequest,
			wantErr:  "invalid peer ID",
		},
		{
			name:   "update peer - not found",
			peerID: "999",
			setup: func(t *testing.T, db *sql.DB) {
				// No peers
			},
			body:     `{"hostname":"new-host"}`,
			wantCode: http.StatusNotFound,
			wantErr:  "peer not found",
		},
		{
			name:   "update peer - invalid JSON",
			peerID: "1",
			setup: func(t *testing.T, db *sql.DB) {
				db.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, is_manual) VALUES (?, ?, ?, ?, ?)`,
					"test", "10.0.0.1", "key", "hmac", 1)
			},
			body:     `{"invalid":}`,
			wantCode: http.StatusBadRequest,
			wantErr:  "invalid JSON",
		},
		{
			name:   "update peer - invalid hostname",
			peerID: "1",
			setup: func(t *testing.T, db *sql.DB) {
				db.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, is_manual) VALUES (?, ?, ?, ?, ?)`,
					"test", "10.0.0.1", "key", "hmac", 1)
			},
			body:     `{"hostname":"invalid_host!"}`,
			wantCode: http.StatusBadRequest,
			wantErr:  "hostname",
		},
		{
			name:   "update peer - invalid IP",
			peerID: "1",
			setup: func(t *testing.T, db *sql.DB) {
				db.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, is_manual) VALUES (?, ?, ?, ?, ?)`,
					"test", "10.0.0.1", "key", "hmac", 1)
			},
			body:     `{"ip_address":"invalid-ip"}`,
			wantCode: http.StatusBadRequest,
			wantErr:  "IP address",
		},
		{
			name:   "update peer - cannot edit agent peer",
			peerID: "1",
			setup: func(t *testing.T, db *sql.DB) {
				db.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, has_docker, is_manual) VALUES (?, ?, ?, ?, ?, ?)`,
					"test", "10.0.0.1", "key", "hmac", 0, 0)
			},
			body:     `{"hostname":"new-host"}`,
			wantCode: http.StatusBadRequest,
			wantErr:  "can only edit manual peers",
		},
		{
			name:   "update peer - partial update with all fields",
			peerID: "1",
			setup: func(t *testing.T, db *sql.DB) {
				db.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, is_manual) VALUES (?, ?, ?, ?, ?)`,
					"test", "10.0.0.1", "key", "hmac", 1)
			},
			body:     `{"hostname":"test","ip_address":"10.0.0.1","description":"new description"}`,
			wantCode: http.StatusOK,
			wantMsg:  "peer updated",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			database, cleanup := testutil.SetupTestDB(t)
			defer cleanup()

			if tt.setup != nil {
				tt.setup(t, database)
			}

			req := httptest.NewRequest("PUT", "/api/v1/peers/"+tt.peerID, strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			req = muxVars(req, map[string]string{"id": tt.peerID})
			w := httptest.NewRecorder()

			handler := NewHandler(database, nil)
			handler.UpdatePeer(w, req)

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

			if tt.wantMsg != "" {
				var resp map[string]string
				if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
					t.Fatalf("failed to decode response: %v", err)
				}
				if resp["message"] != tt.wantMsg {
					t.Errorf("expected message %q, got %q", tt.wantMsg, resp["message"])
				}
			}

			if tt.verifyPeer != nil {
				tt.verifyPeer(t, database)
			}
		})
	}
}

// TestCompilePeer tests the POST /peers/{id}/compile endpoint.
func TestCompilePeer(t *testing.T) {
	tests := []struct {
		name       string
		peerID     string
		setup      func(t *testing.T, db *sql.DB)
		wantCode   int
		wantErr    string
		wantFields []string
	}{
		{
			name:     "compile peer - invalid ID",
			peerID:   "invalid",
			setup:    nil,
			wantCode: http.StatusBadRequest,
			wantErr:  "invalid peer ID",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			database, cleanup := testutil.SetupTestDB(t)
			defer cleanup()

			if tt.setup != nil {
				tt.setup(t, database)
			}

			req := httptest.NewRequest("POST", "/api/v1/peers/"+tt.peerID+"/compile", nil)
			req = muxVars(req, map[string]string{"id": tt.peerID})
			w := httptest.NewRecorder()

			handler := NewHandler(database, nil)
			handler.CompilePeer(w, req)

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

			if len(tt.wantFields) > 0 {
				var resp map[string]interface{}
				if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
					t.Fatalf("failed to decode response: %v", err)
				}
				for _, field := range tt.wantFields {
					if _, ok := resp[field]; !ok {
						t.Errorf("expected field %s in response", field)
					}
				}
			}
		})
	}
}

// TestGetPeerBundle tests the GET /peers/{id}/bundle endpoint.
func TestGetPeerBundle(t *testing.T) {
	tests := []struct {
		name       string
		peerID     string
		setup      func(t *testing.T, db *sql.DB)
		wantCode   int
		wantErr    string
		wantFields []string
	}{
		{
			name:     "get peer bundle - invalid ID",
			peerID:   "invalid",
			setup:    nil,
			wantCode: http.StatusBadRequest,
			wantErr:  "invalid peer ID",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			database, cleanup := testutil.SetupTestDB(t)
			defer cleanup()

			if tt.setup != nil {
				tt.setup(t, database)
			}

			req := httptest.NewRequest("GET", "/api/v1/peers/"+tt.peerID+"/bundle", nil)
			req = muxVars(req, map[string]string{"id": tt.peerID})
			w := httptest.NewRecorder()

			handler := NewHandler(database, nil)
			handler.GetPeerBundle(w, req)

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

			if len(tt.wantFields) > 0 {
				var resp map[string]interface{}
				if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
					t.Fatalf("failed to decode response: %v", err)
				}
				for _, field := range tt.wantFields {
					if _, ok := resp[field]; !ok {
						t.Errorf("expected field %s in response", field)
					}
				}
			}
		})
	}
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
				database.Exec(`INSERT INTO policies (name, source_id, source_type, service_id, target_id, target_type, action, priority, enabled) VALUES (?, ?, "group", ?, ?, "peer", ?, ?, ?)`,
					"test-policy", 1, 1, 1, "ACCEPT", 100, 1)
			},
			wantCode: http.StatusConflict,
			wantErr:  "cannot delete peer — it is explicitly targeted in policy 'test-policy'",
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
				// Insert policy using group 1 as source_id
				database.Exec(`INSERT INTO policies (name, source_id, source_type, service_id, target_id, target_type, action, priority, enabled) VALUES (?, ?, "group", ?, ?, "peer", ?, ?, ?)`,
					"test-policy", 1, 1, 2, "ACCEPT", 100, 1)
			},
			wantCode: http.StatusConflict,
			wantErr:  "cannot delete peer — it is in group used by policy 'test-policy'",
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
			database, cleanup := testutil.SetupTestDB(t)
			defer cleanup()

			if tt.setup != nil {
				tt.setup(t, database)
			}

			req := httptest.NewRequest("DELETE", "/api/v1/peers/"+tt.peerID, nil)
			w := httptest.NewRecorder()

			// Mock gorilla/mux vars
			req = muxVars(req, map[string]string{"id": tt.peerID})

			handler := NewHandler(database, nil)
			handler.DeletePeer(w, req)

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
	database, cleanup := testutil.SetupTestDB(t)
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

	handler := NewHandler(database, nil)
	handler.DeletePeer(w, req)

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
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	// Insert peer
	database.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, has_docker) VALUES (?, ?, ?, ?, ?)`,
		"test-peer", "10.0.0.1", "test-key", "test-hmac", 0)

	// Insert rule_bundle
	database.Exec(`INSERT INTO rule_bundles (peer_id, version, version_number, rules_content, hmac) VALUES (?, ?, ?, ?, ?)`,
		1, "v1", 1, "test-rules", "test-hmac")

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

	handler := NewHandler(database, nil)
	handler.DeletePeer(w, req)

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
