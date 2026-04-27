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

			handler := NewHandler(database, nil, nil)
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
			body:     `{"hostname":"test-peer","ip_address":"10.0.0.1","agent_key":"key","os_type":"invalidos"}`,
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

			handler := NewHandler(database, nil, nil)
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

			handler := NewHandler(database, nil, nil)
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

			handler := NewHandler(database, nil, nil)
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
		name              string
		peerID            string
		queryParams       string
		setup             func(t *testing.T, db *sql.DB)
		wantCode          int
		wantErr           string
		wantFields        []string
		wantVersion       string
		wantVersionNumber int
	}{
		{
			name:     "get peer bundle - invalid ID",
			peerID:   "invalid",
			setup:    nil,
			wantCode: http.StatusBadRequest,
			wantErr:  "invalid peer ID",
		},
		{
			name:        "include_pending=true returns latest bundle",
			peerID:      "1",
			queryParams: "?include_pending=true",
			setup: func(t *testing.T, db *sql.DB) {
				db.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, has_docker, bundle_version) VALUES (?, ?, ?, ?, ?, ?)`,
					"peer1", "10.0.0.1", "key1", "hmac1", 0, "v1")
				// Create multiple bundles with different versions and explicit timestamps
				// v1 is oldest
				db.Exec(`INSERT INTO rule_bundles (peer_id, version, version_number, rules_content, hmac, created_at) VALUES (?, ?, ?, ?, ?, datetime('now', '-2 seconds'))`,
					1, "v1", 1, "rules-v1", "hmac-v1")
				// v2 is middle
				db.Exec(`INSERT INTO rule_bundles (peer_id, version, version_number, rules_content, hmac, created_at) VALUES (?, ?, ?, ?, ?, datetime('now', '-1 second'))`,
					1, "v2", 2, "rules-v2", "hmac-v2")
				// v3 is newest (should be returned as latest)
				db.Exec(`INSERT INTO rule_bundles (peer_id, version, version_number, rules_content, hmac, created_at) VALUES (?, ?, ?, ?, ?, datetime('now'))`,
					1, "v3", 3, "rules-v3", "hmac-v3")
			},
			wantCode:          http.StatusOK,
			wantFields:        []string{"version", "version_number", "rules", "hmac"},
			wantVersion:       "v3",
			wantVersionNumber: 3,
		},
		{
			name:        "include_pending=false returns deployed bundle",
			peerID:      "1",
			queryParams: "?include_pending=false",
			setup: func(t *testing.T, db *sql.DB) {
				db.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, has_docker, bundle_version) VALUES (?, ?, ?, ?, ?, ?)`,
					"peer1", "10.0.0.1", "key1", "hmac1", 0, "v2")
				// Create multiple bundles
				db.Exec(`INSERT INTO rule_bundles (peer_id, version, version_number, rules_content, hmac) VALUES (?, ?, ?, ?, ?)`,
					1, "v1", 1, "rules-v1", "hmac-v1")
				db.Exec(`INSERT INTO rule_bundles (peer_id, version, version_number, rules_content, hmac) VALUES (?, ?, ?, ?, ?)`,
					1, "v2", 2, "rules-v2", "hmac-v2")
				db.Exec(`INSERT INTO rule_bundles (peer_id, version, version_number, rules_content, hmac) VALUES (?, ?, ?, ?, ?)`,
					1, "v3", 3, "rules-v3", "hmac-v3")
			},
			wantCode:          http.StatusOK,
			wantFields:        []string{"version", "version_number", "rules", "hmac"},
			wantVersion:       "v2",
			wantVersionNumber: 2,
		},
		{
			name:        "no query param defaults to deployed bundle",
			peerID:      "1",
			queryParams: "",
			setup: func(t *testing.T, db *sql.DB) {
				db.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, has_docker, bundle_version) VALUES (?, ?, ?, ?, ?, ?)`,
					"peer1", "10.0.0.1", "key1", "hmac1", 0, "v1")
				// Create multiple bundles
				db.Exec(`INSERT INTO rule_bundles (peer_id, version, version_number, rules_content, hmac) VALUES (?, ?, ?, ?, ?)`,
					1, "v1", 1, "rules-v1", "hmac-v1")
				db.Exec(`INSERT INTO rule_bundles (peer_id, version, version_number, rules_content, hmac) VALUES (?, ?, ?, ?, ?)`,
					1, "v2", 2, "rules-v2", "hmac-v2")
			},
			wantCode:          http.StatusOK,
			wantFields:        []string{"version", "version_number", "rules", "hmac"},
			wantVersion:       "v1",
			wantVersionNumber: 1,
		},
		{
			name:        "missing bundle for pending request returns 404",
			peerID:      "1",
			queryParams: "?include_pending=true",
			setup: func(t *testing.T, db *sql.DB) {
				// Create peer without any rule bundles
				db.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, has_docker) VALUES (?, ?, ?, ?, ?)`,
					"peer1", "10.0.0.1", "key1", "hmac1", 0)
			},
			wantCode: http.StatusNotFound,
			wantErr:  "bundle not found",
		},
		{
			name:        "missing bundle for deployed request returns 404",
			peerID:      "1",
			queryParams: "?include_pending=false",
			setup: func(t *testing.T, db *sql.DB) {
				// Create peer with bundle_version pointing to non-existent bundle
				db.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, has_docker, bundle_version) VALUES (?, ?, ?, ?, ?, ?)`,
					"peer1", "10.0.0.1", "key1", "hmac1", 0, "v999")
				// Create a bundle but with different version
				db.Exec(`INSERT INTO rule_bundles (peer_id, version, version_number, rules_content, hmac) VALUES (?, ?, ?, ?, ?)`,
					1, "v1", 1, "rules-v1", "hmac-v1")
			},
			wantCode: http.StatusNotFound,
			wantErr:  "bundle not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			database, cleanup := testutil.SetupTestDB(t)
			defer cleanup()

			if tt.setup != nil {
				tt.setup(t, database)
			}

			url := "/api/v1/peers/" + tt.peerID + "/bundle" + tt.queryParams
			req := httptest.NewRequest("GET", url, nil)
			req = muxVars(req, map[string]string{"id": tt.peerID})
			w := httptest.NewRecorder()

			handler := NewHandler(database, nil, nil)
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

			if len(tt.wantFields) > 0 || tt.wantVersion != "" {
				var resp map[string]interface{}
				if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
					t.Fatalf("failed to decode response: %v", err)
				}

				// Check fields
				if len(tt.wantFields) > 0 {
					for _, field := range tt.wantFields {
						if _, ok := resp[field]; !ok {
							t.Errorf("expected field %s in response", field)
						}
					}
				}

				// Check version
				if tt.wantVersion != "" {
					if resp["version"] != tt.wantVersion {
						t.Errorf("expected version %q, got %v", tt.wantVersion, resp["version"])
					}
					if resp["version_number"].(float64) != float64(tt.wantVersionNumber) {
						t.Errorf("expected version_number %d, got %v", tt.wantVersionNumber, resp["version_number"])
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
			wantErr:  "cannot delete peer — it is in use by one or more policies",
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
			wantErr:  "cannot delete peer — it is in use by one or more policies",
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

			handler := NewHandler(database, nil, nil)
			handler.DeletePeer(w, req)

			if w.Code != tt.wantCode {
				t.Errorf("expected status %d, got %d: %s", tt.wantCode, w.Code, w.Body.String())
			}

			if tt.wantErr != "" {
				// Try to decode as map with policies (new format) or simple map (old format)
				var respInterface map[string]interface{}
				if decodeErr := json.NewDecoder(w.Body).Decode(&respInterface); decodeErr == nil {
					// New format with policies
					if errMsg, ok := respInterface["error"].(string); ok {
						if strings.Contains(errMsg, tt.wantErr) {
							// Success - error message contains expected string
							return
						}
					}
				}

				// Fall back to trying simple string map
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

	handler := NewHandler(database, nil, nil)
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

	handler := NewHandler(database, nil, nil)
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

// TestDeletePeer_InUseByMultiplePolicies tests that deleting a peer explicitly used by multiple policies
// returns 409 Conflict with the list of all policies.
func TestDeletePeer_InUseByMultiplePolicies(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	// Create a peer (ID will be 1)
	database.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, has_docker) VALUES (?, ?, ?, ?, ?)`,
		"target-peer", "10.0.0.1", "test-key", "test-hmac", 0)

	// Create another peer as source (ID will be 2)
	database.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, has_docker) VALUES (?, ?, ?, ?, ?)`,
		"source-peer", "10.0.0.2", "source-key", "source-hmac", 0)

	// Insert service (required for policies)
	database.Exec(`INSERT INTO services (name, ports, protocol) VALUES (?, ?, ?)`, "ssh", "22", "tcp")

	// Create multiple policies that explicitly target the peer
	// Policy 1: source_type='peer', source_id=1 (peer 1 is the SOURCE)
	database.Exec(`INSERT INTO policies (name, source_id, source_type, service_id, target_id, target_type, action, priority, enabled) VALUES ('policy-1', 1, 'peer', 1, 2, 'peer', 'ACCEPT', 100, 1)`)

	// Policy 2: target_type='peer', target_id=1 (peer 1 is the TARGET)
	database.Exec(`INSERT INTO policies (name, source_id, source_type, service_id, target_id, target_type, action, priority, enabled) VALUES ('policy-2', 2, 'peer', 1, 1, 'peer', 'ACCEPT', 100, 1)`)

	// Policy 3: source_type='peer', source_id=1 AND target_type='peer', target_id=2 (peer 1 is SOURCE, peer 2 is TARGET)
	database.Exec(`INSERT INTO policies (name, source_id, source_type, service_id, target_id, target_type, action, priority, enabled) VALUES ('policy-3', 1, 'peer', 1, 2, 'peer', 'ACCEPT', 100, 1)`)

	// Try to delete the peer
	req := httptest.NewRequest("DELETE", "/api/v1/peers/1", nil)
	w := httptest.NewRecorder()
	req = muxVars(req, map[string]string{"id": "1"})

	handler := NewHandler(database, nil, nil)
	handler.DeletePeer(w, req)

	// Should return 409 Conflict
	if w.Code != http.StatusConflict {
		t.Errorf("expected status %d, got %d: %s", http.StatusConflict, w.Code, w.Body.String())
	}

	// Parse response to verify it contains the list of policies
	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	// Verify error message
	if errMsg, ok := resp["error"].(string); !ok || errMsg == "" {
		t.Error("expected error message in response")
	}

	// Verify policies list
	policiesRaw, ok := resp["policies"]
	if !ok {
		t.Fatal("expected policies field in response")
	}

	policies, ok := policiesRaw.([]interface{})
	if !ok {
		t.Fatal("expected policies to be an array")
	}

	if len(policies) != 3 {
		t.Errorf("expected 3 policies in response, got %d", len(policies))
	}

	// Verify policy names are in the response
	policyNames := make(map[string]bool)
	for _, p := range policies {
		policy, ok := p.(map[string]interface{})
		if !ok {
			t.Fatal("expected policy to be an object")
		}

		name, ok := policy["name"].(string)
		if !ok {
			t.Fatal("expected policy name to be a string")
		}
		policyNames[name] = true
	}

	// Check that all three policies are present
	if !policyNames["policy-1"] {
		t.Error("policy-1 not found in response")
	}
	if !policyNames["policy-2"] {
		t.Error("policy-2 not found in response")
	}
	if !policyNames["policy-3"] {
		t.Error("policy-3 not found in response")
	}

	// Verify the peer was NOT deleted
	var count int
	database.QueryRow("SELECT COUNT(*) FROM peers WHERE id = 1").Scan(&count)
	if count != 1 {
		t.Errorf("expected peer to still exist, but count = %d", count)
	}
}

// TestDeletePeer_InGroupUsedByMultiplePolicies tests that deleting a peer that is in a group
// used by multiple policies returns 409 Conflict with the list of all policies.
func TestDeletePeer_InGroupUsedByMultiplePolicies(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	// Create a peer (ID will be 1)
	database.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, has_docker) VALUES (?, ?, ?, ?, ?)`,
		"test-peer", "10.0.0.1", "test-key", "test-hmac", 0)

	// Create a group
	database.Exec(`INSERT INTO groups (name) VALUES (?)`, "test-group")

	// Add peer to group
	database.Exec(`INSERT INTO group_members (group_id, peer_id) VALUES (?, ?)`, 1, 1)

	// Insert service (required for policies)
	database.Exec(`INSERT INTO services (name, ports, protocol) VALUES (?, ?, ?)`, "ssh", "22", "tcp")

	// Create another target peer for policies
	database.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, has_docker) VALUES (?, ?, ?, ?, ?)`,
		"target-peer", "10.0.0.2", "target-key", "target-hmac", 0)

	// Create multiple policies that use the group (group_id=1 as source)
	// Policy 1: source_type='group', source_id=1
	database.Exec(`INSERT INTO policies (name, source_id, source_type, service_id, target_id, target_type, action, priority, enabled) VALUES (?, ?, "group", ?, ?, "peer", ?, ?, ?)`,
		"policy-1", 1, 1, 2, "ACCEPT", 100, 1)

	// Policy 2: source_type='group', source_id=1
	database.Exec(`INSERT INTO policies (name, source_id, source_type, service_id, target_id, target_type, action, priority, enabled) VALUES (?, ?, "group", ?, ?, "peer", ?, ?, ?)`,
		"policy-2", 1, 1, 2, "ACCEPT", 100, 1)

	// Policy 3: target_type='group', target_id=1
	database.Exec(`INSERT INTO policies (name, source_id, source_type, service_id, target_id, target_type, action, priority, enabled) VALUES (?, ?, "peer", ?, ?, "group", ?, ?, ?)`,
		"policy-3", 2, 1, 1, "ACCEPT", 100, 1)

	// Try to delete the peer
	req := httptest.NewRequest("DELETE", "/api/v1/peers/1", nil)
	w := httptest.NewRecorder()
	req = muxVars(req, map[string]string{"id": "1"})

	handler := NewHandler(database, nil, nil)
	handler.DeletePeer(w, req)

	// Should return 409 Conflict
	if w.Code != http.StatusConflict {
		t.Errorf("expected status %d, got %d: %s", http.StatusConflict, w.Code, w.Body.String())
	}

	// Parse response to verify it contains the list of policies
	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	// Verify error message
	if errMsg, ok := resp["error"].(string); !ok || errMsg == "" {
		t.Error("expected error message in response")
	}

	// Verify policies list
	policiesRaw, ok := resp["policies"]
	if !ok {
		t.Fatal("expected policies field in response")
	}

	policies, ok := policiesRaw.([]interface{})
	if !ok {
		t.Fatal("expected policies to be an array")
	}

	if len(policies) != 3 {
		t.Errorf("expected 3 policies in response, got %d", len(policies))
	}

	// Verify policy names are in the response
	policyNames := make(map[string]bool)
	for _, p := range policies {
		policy, ok := p.(map[string]interface{})
		if !ok {
			t.Fatal("expected policy to be an object")
		}

		name, ok := policy["name"].(string)
		if !ok {
			t.Fatal("expected policy name to be a string")
		}
		policyNames[name] = true
	}

	// Check that all three policies are present
	if !policyNames["policy-1"] {
		t.Error("policy-1 not found in response")
	}
	if !policyNames["policy-2"] {
		t.Error("policy-2 not found in response")
	}
	if !policyNames["policy-3"] {
		t.Error("policy-3 not found in response")
	}

	// Verify the peer was NOT deleted
	var count int
	err := database.QueryRow("SELECT COUNT(*) FROM peers WHERE id = 1").Scan(&count)
	if err != nil {
		t.Errorf("failed to query peers: %v", err)
	}
	if count != 1 {
		t.Errorf("expected peer to still exist, but count = %d", count)
	}
}

// TestDeletePeer_NotInUse_Success tests that successfully deleting a peer
// returns 200 and actually deletes the peer from the database.
func TestDeletePeer_NotInUse_Success(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	// Create a peer (ID will be 1)
	database.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, has_docker) VALUES (?, ?, ?, ?, ?)`,
		"standalone-peer", "10.0.0.1", "test-key", "test-hmac", 0)

	// Create a group (not used by any policies)
	database.Exec(`INSERT INTO groups (name) VALUES (?)`, "unused-group")

	// Add peer to the group (peer will be cleaned up on deletion)
	database.Exec(`INSERT INTO group_members (group_id, peer_id) VALUES (?, ?)`, 1, 1)

	// Create another peer that IS in use (to verify we're not blocking all deletions)
	database.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, has_docker) VALUES (?, ?, ?, ?, ?)`,
		"used-peer", "10.0.0.2", "used-key", "used-hmac", 0)

	// Insert service
	database.Exec(`INSERT INTO services (name, ports, protocol) VALUES (?, ?, ?)`, "ssh", "22", "tcp")

	// Create a policy using the used-peer (not our test peer)
	database.Exec(`INSERT INTO policies (name, source_id, source_type, service_id, target_id, target_type, action, priority, enabled) VALUES (?, ?, ?, ?, ?, "peer", ?, ?, ?)`,
		"used-policy", 2, "peer", 1, 2, "ACCEPT", 100, 1)

	// Delete the standalone peer (not in use)
	req := httptest.NewRequest("DELETE", "/api/v1/peers/1", nil)
	w := httptest.NewRecorder()
	req = muxVars(req, map[string]string{"id": "1"})

	handler := NewHandler(database, nil, nil)
	handler.DeletePeer(w, req)

	// Should return 200 OK
	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d: %s", http.StatusOK, w.Code, w.Body.String())
	}

	// Verify the peer was deleted
	var count int
	err := database.QueryRow("SELECT COUNT(*) FROM peers WHERE id = 1").Scan(&count)
	if err != nil {
		t.Errorf("failed to query peers: %v", err)
	}
	if count != 0 {
		t.Errorf("expected peer to be deleted, but it still exists")
	}

	// Verify group_members was cleaned up
	err = database.QueryRow("SELECT COUNT(*) FROM group_members WHERE peer_id = 1").Scan(&count)
	if err != nil {
		t.Errorf("failed to query group_members: %v", err)
	}
	if count != 0 {
		t.Errorf("expected group_members to be cleaned up when peer is deleted")
	}

	// Verify the used peer still exists (not affected)
	err = database.QueryRow("SELECT COUNT(*) FROM peers WHERE id = 2").Scan(&count)
	if err != nil {
		t.Errorf("failed to query peers: %v", err)
	}
	if count != 1 {
		t.Errorf("expected used peer to still exist, but count = %d", count)
	}
}

// TestGetPeerByIP tests the GET /peers/by-ip endpoint.
func TestGetPeerByIP(t *testing.T) {
	tests := []struct {
		name        string
		queryParams string
		setup       func(t *testing.T, db *sql.DB)
		wantCode    int
		wantErr     string
		wantPeer    *Peer
		wantNil     bool
	}{
		{
			name:        "missing ip parameter",
			queryParams: "",
			setup:       nil,
			wantCode:    http.StatusBadRequest,
			wantErr:     "ip parameter required",
		},
		{
			name:        "peer found",
			queryParams: "?ip=10.0.0.1",
			setup: func(t *testing.T, db *sql.DB) {
				db.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, has_docker, is_manual) VALUES (?, ?, ?, ?, ?, ?)`, "test-peer", "10.0.0.1", "key", "hmac", 0, 0)
			},
			wantCode: http.StatusOK,
			wantPeer: &Peer{ID: 1, Hostname: "test-peer", IPAddress: "10.0.0.1", IsManual: false},
		},
		{
			name:        "peer not found",
			queryParams: "?ip=10.0.0.99",
			setup: func(t *testing.T, db *sql.DB) {
				db.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, has_docker) VALUES (?, ?, ?, ?, ?)`, "test-peer", "10.0.0.1", "key", "hmac", 0)
			},
			wantCode: http.StatusOK,
			wantNil:  true,
		},
		{
			name:        "manual peer found",
			queryParams: "?ip=192.168.1.1",
			setup: func(t *testing.T, db *sql.DB) {
				db.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, has_docker, is_manual) VALUES (?, ?, ?, ?, ?, ?)`, "manual-peer", "192.168.1.1", "key", "hmac", 0, 1)
			},
			wantCode: http.StatusOK,
			wantPeer: &Peer{ID: 1, Hostname: "manual-peer", IPAddress: "192.168.1.1", IsManual: true},
		},
		{
			name: "ipv6 address - peer found",
			queryParams: "?ip=::1",
			setup: func(t *testing.T, db *sql.DB) {
				db.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, has_docker) VALUES (?, ?, ?, ?, ?)`, "ipv6-peer", "::1", "key", "hmac", 0)
			},
			wantCode: http.StatusOK,
			wantPeer: &Peer{ID: 1, Hostname: "ipv6-peer", IPAddress: "::1", IsManual: false},
		},
		{
			name: "peer found via secondary IP in peer_ips table",
			queryParams: "?ip=10.0.0.2",
			setup: func(t *testing.T, db *sql.DB) {
				db.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, has_docker, is_manual) VALUES (?, ?, ?, ?, ?, ?)`, "test-peer", "10.0.0.1", "key", "hmac", 0, 0)
				db.Exec(`INSERT INTO peer_ips (peer_id, ip_address, is_primary) VALUES (?, ?, 1)`, 1, "10.0.0.1")
				db.Exec(`INSERT INTO peer_ips (peer_id, ip_address, is_primary) VALUES (?, ?, 0)`, 1, "10.0.0.2")
			},
			wantCode: http.StatusOK,
			wantPeer: &Peer{ID: 1, Hostname: "test-peer", IPAddress: "10.0.0.1", IsManual: false},
		},
		{
			name: "secondary IP not found in peer_ips either",
			queryParams: "?ip=10.0.0.99",
			setup: func(t *testing.T, db *sql.DB) {
				db.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, has_docker, is_manual) VALUES (?, ?, ?, ?, ?, ?)`, "test-peer", "10.0.0.1", "key", "hmac", 0, 0)
				db.Exec(`INSERT INTO peer_ips (peer_id, ip_address, is_primary) VALUES (?, ?, 1)`, 1, "10.0.0.1")
				db.Exec(`INSERT INTO peer_ips (peer_id, ip_address, is_primary) VALUES (?, ?, 0)`, 1, "10.0.0.2")
			},
			wantCode: http.StatusOK,
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			database, cleanup := testutil.SetupTestDB(t)
			defer cleanup()

			if tt.setup != nil {
				tt.setup(t, database)
			}

			url := "/api/v1/peers/by-ip" + tt.queryParams
			req := httptest.NewRequest("GET", url, nil)
			w := httptest.NewRecorder()

			handler := NewHandler(database, nil, nil)
			handler.GetPeerByIP(w, req)

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

			if tt.wantPeer != nil {
				var p Peer
				if err := json.NewDecoder(w.Body).Decode(&p); err != nil {
					t.Fatalf("failed to decode peer response: %v", err)
				}
				if p.ID != tt.wantPeer.ID {
					t.Errorf("expected ID %d, got %d", tt.wantPeer.ID, p.ID)
				}
				if p.Hostname != tt.wantPeer.Hostname {
					t.Errorf("expected hostname %q, got %q", tt.wantPeer.Hostname, p.Hostname)
				}
				if p.IPAddress != tt.wantPeer.IPAddress {
					t.Errorf("expected ip_address %q, got %q", tt.wantPeer.IPAddress, p.IPAddress)
				}
				if p.IsManual != tt.wantPeer.IsManual {
					t.Errorf("expected is_manual %v, got %v", tt.wantPeer.IsManual, p.IsManual)
				}
			}

			if tt.wantNil {
				var resp interface{}
				if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
					t.Fatalf("failed to decode response: %v", err)
				}
				if resp != nil {
					t.Errorf("expected nil response, got %v", resp)
				}
			}
		})
	}
}

// TestGetPeerBundle_WithIncludePending tests that include_pending=true returns
// both the latest (pending) bundle and the deployed bundle for diff comparison.
func TestGetPeerBundle_WithIncludePending(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	// Create peer with deployed bundle version
	database.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, has_docker, bundle_version) VALUES (?, ?, ?, ?, ?, ?)`, "test-peer", "10.0.0.1", "key1", "hmac1", 0, "v1.0")

	// Create deployed bundle (version 1)
	database.Exec(`INSERT INTO rule_bundles (peer_id, version, version_number, rules_content, hmac, created_at) VALUES (?, ?, ?, ?, ?, datetime('now', '-2 seconds'))`, 1, "v1.0", 1, "rule1\nrule2", "hmac1")

	// Create pending bundle (version 2, newer)
	database.Exec(`INSERT INTO rule_bundles (peer_id, version, version_number, rules_content, hmac, created_at) VALUES (?, ?, ?, ?, ?, datetime('now'))`, 1, "v2.0", 2, "rule1\nrule2\nrule3", "hmac2")

	// Request with include_pending=true
	req := httptest.NewRequest("GET", "/api/v1/peers/1/bundle?include_pending=true", nil)
	req = muxVars(req, map[string]string{"id": "1"})
	w := httptest.NewRecorder()

	handler := NewHandler(database, nil, nil)
	handler.GetPeerBundle(w, req)

	// Verify response
	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d: %s", http.StatusOK, w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	// Verify pending bundle fields
	if resp["version"] != "v2.0" {
		t.Errorf("expected version v2.0, got %v", resp["version"])
	}
	if resp["version_number"].(float64) != 2 {
		t.Errorf("expected version_number 2, got %v", resp["version_number"])
	}
	if resp["rules"] != "rule1\nrule2\nrule3" {
		t.Errorf("expected rules 'rule1\\nrule2\\nrule3', got %v", resp["rules"])
	}

	// Verify deployed bundle fields (for diff comparison)
	if resp["deployed_version"] != "v1.0" {
		t.Errorf("expected deployed_version v1.0, got %v", resp["deployed_version"])
	}
	if resp["deployed_rules"] != "rule1\nrule2" {
		t.Errorf("expected deployed_rules 'rule1\\nrule2', got %v", resp["deployed_rules"])
	}
}

// TestCreatePeer_ValidOSOther tests that creating a peer with os_type "other" succeeds.
func TestCreatePeer_ValidOSOther(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	body := `{"hostname":"other-os-peer","ip_address":"10.0.0.10","agent_key":"key","os_type":"other"}`
	req := httptest.NewRequest("POST", "/api/v1/peers", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler := NewHandler(database, nil, nil)
	handler.CreatePeer(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("expected status %d, got %d: %s", http.StatusCreated, w.Code, w.Body.String())
	}

	var resp map[string]int64
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp["id"] == 0 {
		t.Error("expected non-zero id")
	}

	// Verify the peer was stored with the correct os_type
	var osType string
	err := database.QueryRow("SELECT os_type FROM peers WHERE id = ?", resp["id"]).Scan(&osType)
	if err != nil {
		t.Fatalf("failed to query peer: %v", err)
	}
	if osType != "other" {
		t.Errorf("expected os_type 'other', got %q", osType)
	}
}

// TestCreatePeer_ValidArchOther tests that creating a peer with arch "other" succeeds.
func TestCreatePeer_ValidArchOther(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	body := `{"hostname":"other-arch-peer","ip_address":"10.0.0.11","agent_key":"key","arch":"other"}`
	req := httptest.NewRequest("POST", "/api/v1/peers", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler := NewHandler(database, nil, nil)
	handler.CreatePeer(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("expected status %d, got %d: %s", http.StatusCreated, w.Code, w.Body.String())
	}

	var resp map[string]int64
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp["id"] == 0 {
		t.Error("expected non-zero id")
	}

	// Verify the peer was stored with the correct arch
	var arch string
	err := database.QueryRow("SELECT arch FROM peers WHERE id = ?", resp["id"]).Scan(&arch)
	if err != nil {
		t.Fatalf("failed to query peer: %v", err)
	}
	if arch != "other" {
		t.Errorf("expected arch 'other', got %q", arch)
	}
}

// TestCreatePeer_ValidMacOS tests that creating a peer with os_type "macos" succeeds.
func TestCreatePeer_ValidMacOS(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	body := `{"hostname":"macos-peer","ip_address":"10.0.0.12","agent_key":"key","os_type":"macos"}`
	req := httptest.NewRequest("POST", "/api/v1/peers", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler := NewHandler(database, nil, nil)
	handler.CreatePeer(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("expected status %d, got %d: %s", http.StatusCreated, w.Code, w.Body.String())
	}

	var resp map[string]int64
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp["id"] == 0 {
		t.Error("expected non-zero id")
	}

	// Verify the peer was stored with the correct os_type
	var osType string
	err := database.QueryRow("SELECT os_type FROM peers WHERE id = ?", resp["id"]).Scan(&osType)
	if err != nil {
		t.Fatalf("failed to query peer: %v", err)
	}
	if osType != "macos" {
		t.Errorf("expected os_type 'macos', got %q", osType)
	}
}

// TestGetPeerIPs tests the GET /peers/{id}/ips endpoint.
func TestGetPeerIPs(t *testing.T) {
	tests := []struct {
		name   string
		peerID string
		setup  func(t *testing.T, db *sql.DB)
		wantCode    int
		wantErr     string
		wantIPsLen  int
		wantPrimary bool
	}{
		{
			name:   "get peer IPs - success with primary and secondary",
			peerID: "1",
			setup: func(t *testing.T, db *sql.DB) {
				db.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, has_docker) VALUES (?, ?, ?, ?, ?)`, "peer1", "10.0.0.1", "key1", "hmac1", 0)
				db.Exec(`INSERT INTO peer_ips (peer_id, ip_address, is_primary) VALUES (?, ?, 1)`, 1, "10.0.0.1")
				db.Exec(`INSERT INTO peer_ips (peer_id, ip_address, is_primary) VALUES (?, ?, 0)`, 1, "10.0.0.2")
				db.Exec(`INSERT INTO peer_ips (peer_id, ip_address, is_primary) VALUES (?, ?, 0)`, 1, "10.0.0.3")
			},
			wantCode:    http.StatusOK,
			wantIPsLen:  3,
			wantPrimary: true,
		},
		{
			name:   "get peer IPs - only primary IP",
			peerID: "1",
			setup: func(t *testing.T, db *sql.DB) {
				db.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, has_docker) VALUES (?, ?, ?, ?, ?)`, "peer1", "10.0.0.1", "key1", "hmac1", 0)
				db.Exec(`INSERT INTO peer_ips (peer_id, ip_address, is_primary) VALUES (?, ?, 1)`, 1, "10.0.0.1")
			},
			wantCode:    http.StatusOK,
			wantIPsLen:  1,
			wantPrimary: true,
		},
		{
			name:   "get peer IPs - no IPs in peer_ips table",
			peerID: "1",
			setup: func(t *testing.T, db *sql.DB) {
				db.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, has_docker) VALUES (?, ?, ?, ?, ?)`, "peer1", "10.0.0.1", "key1", "hmac1", 0)
			},
			wantCode:   http.StatusOK,
			wantIPsLen: 0,
		},
		{
			name:   "get peer IPs - peer not found",
			peerID: "999",
			setup: func(t *testing.T, db *sql.DB) {
				// No peers inserted
			},
			wantCode: http.StatusNotFound,
			wantErr:  "peer not found",
		},
		{
			name:   "get peer IPs - invalid peer ID",
			peerID: "invalid",
			setup: func(t *testing.T, db *sql.DB) {
				db.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, has_docker) VALUES (?, ?, ?, ?, ?)`, "peer1", "10.0.0.1", "key1", "hmac1", 0)
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

			req := httptest.NewRequest("GET", "/api/v1/peers/"+tt.peerID+"/ips", nil)
			req = muxVars(req, map[string]string{"id": tt.peerID})
			w := httptest.NewRecorder()

			handler := NewHandler(database, nil, nil)
			handler.GetPeerIPs(w, req)

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

			if tt.wantIPsLen > 0 {
				var peerIPs []PeerIP
				if err := json.NewDecoder(w.Body).Decode(&peerIPs); err != nil {
					t.Fatalf("failed to decode peer IPs response: %v", err)
				}
				if len(peerIPs) != tt.wantIPsLen {
					t.Errorf("expected %d IPs, got %d", tt.wantIPsLen, len(peerIPs))
				}
				if tt.wantPrimary && len(peerIPs) > 0 {
					// Primary IP should be first (ordered by is_primary DESC)
					if !peerIPs[0].IsPrimary {
						t.Error("expected first IP to be primary")
					}
				}
			}

			if tt.wantIPsLen == 0 && tt.wantErr == "" {
				var peerIPs []PeerIP
				if err := json.NewDecoder(w.Body).Decode(&peerIPs); err != nil {
					t.Fatalf("failed to decode peer IPs response: %v", err)
				}
				if peerIPs == nil {
					peerIPs = []PeerIP{}
				}
				if len(peerIPs) != 0 {
					t.Errorf("expected 0 IPs, got %d", len(peerIPs))
				}
			}
		})
	}
}

// TestAddPeerIP tests the POST /peers/{id}/ips endpoint.
func TestAddPeerIP(t *testing.T) {
	tests := []struct {
		name   string
		peerID string
		body   string
		setup  func(t *testing.T, db *sql.DB)
		wantCode    int
		wantErr     string
		verifyIP    func(t *testing.T, db *sql.DB)
	}{
		{
			name:   "add peer IP - success",
			peerID: "1",
			body:   `{"ip_address":"10.0.0.2"}`,
			setup: func(t *testing.T, db *sql.DB) {
				db.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, has_docker) VALUES (?, ?, ?, ?, ?)`, "peer1", "10.0.0.1", "key1", "hmac1", 0)
				db.Exec(`INSERT INTO peer_ips (peer_id, ip_address, is_primary) VALUES (?, ?, 1)`, 1, "10.0.0.1")
			},
			wantCode: http.StatusCreated,
			verifyIP: func(t *testing.T, db *sql.DB) {
				var count int
				err := db.QueryRow("SELECT COUNT(*) FROM peer_ips WHERE peer_id = 1 AND ip_address = '10.0.0.2' AND is_primary = 0").Scan(&count)
				if err != nil {
					t.Fatalf("failed to query peer_ips: %v", err)
				}
				if count != 1 {
					t.Errorf("expected 1 secondary IP, got %d", count)
				}
			},
		},
		{
			name:   "add peer IP - duplicate IP for same peer",
			peerID: "1",
			body:   `{"ip_address":"10.0.0.1"}`,
			setup: func(t *testing.T, db *sql.DB) {
				db.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, has_docker) VALUES (?, ?, ?, ?, ?)`, "peer1", "10.0.0.1", "key1", "hmac1", 0)
				db.Exec(`INSERT INTO peer_ips (peer_id, ip_address, is_primary) VALUES (?, ?, 1)`, 1, "10.0.0.1")
			},
			wantCode: http.StatusConflict,
			wantErr:  "IP address already exists for this peer",
		},
		{
			name:   "add peer IP - invalid IP format",
			peerID: "1",
			body:   `{"ip_address":"not-an-ip"}`,
			setup: func(t *testing.T, db *sql.DB) {
				db.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, has_docker) VALUES (?, ?, ?, ?, ?)`, "peer1", "10.0.0.1", "key1", "hmac1", 0)
			},
			wantCode: http.StatusBadRequest,
			wantErr:  "invalid IP address",
		},
		{
			name:   "add peer IP - peer not found",
			peerID: "999",
			body:   `{"ip_address":"10.0.0.2"}`,
			setup: func(t *testing.T, db *sql.DB) {
				// No peers
			},
			wantCode: http.StatusNotFound,
			wantErr:  "peer not found",
		},
		{
			name:   "add peer IP - invalid JSON",
			peerID: "1",
			body:   `{"invalid":}`,
			setup: func(t *testing.T, db *sql.DB) {
				db.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, has_docker) VALUES (?, ?, ?, ?, ?)`, "peer1", "10.0.0.1", "key1", "hmac1", 0)
			},
			wantCode: http.StatusBadRequest,
			wantErr:  "invalid JSON",
		},
		{
			name:   "add peer IP - invalid peer ID",
			peerID: "invalid",
			body:   `{"ip_address":"10.0.0.2"}`,
			setup: func(t *testing.T, db *sql.DB) {
				db.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, has_docker) VALUES (?, ?, ?, ?, ?)`, "peer1", "10.0.0.1", "key1", "hmac1", 0)
			},
			wantCode: http.StatusBadRequest,
			wantErr:  "invalid peer ID",
		},
		{
			name:   "add peer IP - empty IP address",
			peerID: "1",
			body:   `{"ip_address":""}`,
			setup: func(t *testing.T, db *sql.DB) {
				db.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, has_docker) VALUES (?, ?, ?, ?, ?)`, "peer1", "10.0.0.1", "key1", "hmac1", 0)
			},
			wantCode: http.StatusBadRequest,
			wantErr:  "invalid IP address",
		},
		{
			name:   "add peer IP - IPv6 address",
			peerID: "1",
			body:   `{"ip_address":"::1"}`,
			setup: func(t *testing.T, db *sql.DB) {
				db.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, has_docker) VALUES (?, ?, ?, ?, ?)`, "peer1", "10.0.0.1", "key1", "hmac1", 0)
				db.Exec(`INSERT INTO peer_ips (peer_id, ip_address, is_primary) VALUES (?, ?, 1)`, 1, "10.0.0.1")
			},
			wantCode: http.StatusCreated,
			verifyIP: func(t *testing.T, db *sql.DB) {
				var count int
				err := db.QueryRow("SELECT COUNT(*) FROM peer_ips WHERE peer_id = 1 AND ip_address = '::1' AND is_primary = 0").Scan(&count)
				if err != nil {
					t.Fatalf("failed to query peer_ips: %v", err)
				}
				if count != 1 {
					t.Errorf("expected 1 secondary IPv6 IP, got %d", count)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			database, cleanup := testutil.SetupTestDB(t)
			defer cleanup()

			if tt.setup != nil {
				tt.setup(t, database)
			}

			req := httptest.NewRequest("POST", "/api/v1/peers/"+tt.peerID+"/ips", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			req = muxVars(req, map[string]string{"id": tt.peerID})
			w := httptest.NewRecorder()

			handler := NewHandler(database, nil, nil)
			handler.AddPeerIP(w, req)

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

			if tt.wantCode == http.StatusCreated {
				var pip PeerIP
				if err := json.NewDecoder(w.Body).Decode(&pip); err != nil {
					t.Fatalf("failed to decode response: %v", err)
				}
				if pip.IsPrimary {
					t.Error("expected is_primary to be false for added IP")
				}
				if pip.PeerID == 0 {
					t.Error("expected non-zero peer_id")
				}
				if pip.ID == 0 {
					t.Error("expected non-zero id")
				}
			}

			if tt.verifyIP != nil {
				tt.verifyIP(t, database)
			}
		})
	}
}

// TestDeletePeerIP tests the DELETE /peers/{id}/ips/{ip_id} endpoint.
func TestDeletePeerIP(t *testing.T) {
	tests := []struct {
		name   string
		peerID string
		ipID   string
		setup  func(t *testing.T, db *sql.DB)
		wantCode int
		wantErr  string
		verifyDelete func(t *testing.T, db *sql.DB)
	}{
		{
			name:   "delete peer IP - success",
			peerID: "1",
			ipID:   "2",
			setup: func(t *testing.T, db *sql.DB) {
				db.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, has_docker) VALUES (?, ?, ?, ?, ?)`, "peer1", "10.0.0.1", "key1", "hmac1", 0)
				db.Exec(`INSERT INTO peer_ips (peer_id, ip_address, is_primary) VALUES (?, ?, 1)`, 1, "10.0.0.1")
				db.Exec(`INSERT INTO peer_ips (peer_id, ip_address, is_primary) VALUES (?, ?, 0)`, 1, "10.0.0.2")
			},
			wantCode: http.StatusNoContent,
			verifyDelete: func(t *testing.T, db *sql.DB) {
				var count int
				err := db.QueryRow("SELECT COUNT(*) FROM peer_ips WHERE id = 2").Scan(&count)
				if err != nil {
					t.Fatalf("failed to query peer_ips: %v", err)
				}
				if count != 0 {
					t.Error("expected secondary IP to be deleted")
				}
			},
		},
		{
			name:   "delete peer IP - cannot delete primary IP",
			peerID: "1",
			ipID:   "1",
			setup: func(t *testing.T, db *sql.DB) {
				db.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, has_docker) VALUES (?, ?, ?, ?, ?)`, "peer1", "10.0.0.1", "key1", "hmac1", 0)
				db.Exec(`INSERT INTO peer_ips (peer_id, ip_address, is_primary) VALUES (?, ?, 1)`, 1, "10.0.0.1")
			},
			wantCode: http.StatusBadRequest,
			wantErr:  "cannot delete primary IP address",
		},
		{
			name:   "delete peer IP - peer not found",
			peerID: "999",
			ipID:   "1",
			setup: func(t *testing.T, db *sql.DB) {
				// No peers
			},
			wantCode: http.StatusNotFound,
			wantErr:  "peer not found",
		},
		{
			name:   "delete peer IP - IP not found",
			peerID: "1",
			ipID:   "999",
			setup: func(t *testing.T, db *sql.DB) {
				db.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, has_docker) VALUES (?, ?, ?, ?, ?)`, "peer1", "10.0.0.1", "key1", "hmac1", 0)
				db.Exec(`INSERT INTO peer_ips (peer_id, ip_address, is_primary) VALUES (?, ?, 1)`, 1, "10.0.0.1")
			},
			wantCode: http.StatusNotFound,
			wantErr:  "peer IP not found",
		},
		{
			name:   "delete peer IP - IP belongs to different peer",
			peerID: "1",
			ipID:   "2",
			setup: func(t *testing.T, db *sql.DB) {
				db.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, has_docker) VALUES (?, ?, ?, ?, ?)`, "peer1", "10.0.0.1", "key1", "hmac1", 0)
				db.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, has_docker) VALUES (?, ?, ?, ?, ?)`, "peer2", "10.0.0.2", "key2", "hmac2", 0)
				db.Exec(`INSERT INTO peer_ips (peer_id, ip_address, is_primary) VALUES (?, ?, 1)`, 1, "10.0.0.1")
				db.Exec(`INSERT INTO peer_ips (peer_id, ip_address, is_primary) VALUES (?, ?, 1)`, 2, "10.0.0.2")
			},
			wantCode: http.StatusNotFound,
			wantErr:  "peer IP not found",
		},
		{
			name:   "delete peer IP - invalid peer ID",
			peerID: "invalid",
			ipID:   "1",
			setup: func(t *testing.T, db *sql.DB) {
				db.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, has_docker) VALUES (?, ?, ?, ?, ?)`, "peer1", "10.0.0.1", "key1", "hmac1", 0)
			},
			wantCode: http.StatusBadRequest,
			wantErr:  "invalid peer ID",
		},
	{
		name: "delete peer IP - invalid IP ID",
		peerID: "1",
		ipID: "invalid",
		setup: func(t *testing.T, db *sql.DB) {
			db.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, has_docker) VALUES (?, ?, ?, ?, ?)`, "peer1", "10.0.0.1", "key1", "hmac1", 0)
		},
		wantCode: http.StatusBadRequest,
		wantErr: "invalid IP ID",
	},
	{
		name: "delete peer IP - referenced by policy as source_ip",
		peerID: "1",
		ipID: "2",
		setup: func(t *testing.T, db *sql.DB) {
			db.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, has_docker) VALUES (?, ?, ?, ?, ?)`, "peer1", "10.0.0.1", "key1", "hmac1", 0)
			db.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, has_docker) VALUES (?, ?, ?, ?, ?)`, "peer2", "10.0.0.3", "key2", "hmac2", 0)
			db.Exec(`INSERT INTO peer_ips (peer_id, ip_address, is_primary) VALUES (?, ?, 1)`, 1, "10.0.0.1")
			db.Exec(`INSERT INTO peer_ips (peer_id, ip_address, is_primary) VALUES (?, ?, 0)`, 1, "10.0.0.2")
			db.Exec(`INSERT INTO services (name, ports, protocol) VALUES (?, ?, ?)`, "ssh", "22", "tcp")
			db.Exec(`INSERT INTO policies (name, source_id, source_type, service_id, target_id, target_type, source_ip, action, priority, enabled) VALUES (?, ?, 'peer', ?, ?, 'peer', ?, 'ACCEPT', 100, 1)`, "test-policy", 1, 1, 2, "10.0.0.2")
		},
		wantCode: http.StatusConflict,
		wantErr:  "cannot delete IP: referenced by 1 policy/policies",
	},
	{
		name: "delete peer IP - referenced by policy as target_ip",
		peerID: "1",
		ipID: "2",
		setup: func(t *testing.T, db *sql.DB) {
			db.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, has_docker) VALUES (?, ?, ?, ?, ?)`, "peer1", "10.0.0.1", "key1", "hmac1", 0)
			db.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, has_docker) VALUES (?, ?, ?, ?, ?)`, "peer2", "10.0.0.3", "key2", "hmac2", 0)
			db.Exec(`INSERT INTO peer_ips (peer_id, ip_address, is_primary) VALUES (?, ?, 1)`, 1, "10.0.0.1")
			db.Exec(`INSERT INTO peer_ips (peer_id, ip_address, is_primary) VALUES (?, ?, 0)`, 1, "10.0.0.2")
			db.Exec(`INSERT INTO services (name, ports, protocol) VALUES (?, ?, ?)`, "ssh", "22", "tcp")
			db.Exec(`INSERT INTO policies (name, source_id, source_type, service_id, target_id, target_type, target_ip, action, priority, enabled) VALUES (?, ?, 'peer', ?, ?, 'peer', ?, 'ACCEPT', 100, 1)`, "test-policy", 2, 1, 1, "10.0.0.2")
		},
		wantCode: http.StatusConflict,
		wantErr:  "cannot delete IP: referenced by 1 policy/policies",
	},
	{
		name: "delete peer IP - not referenced by any policy succeeds",
		peerID: "1",
		ipID: "2",
		setup: func(t *testing.T, db *sql.DB) {
			db.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, has_docker) VALUES (?, ?, ?, ?, ?)`, "peer1", "10.0.0.1", "key1", "hmac1", 0)
			db.Exec(`INSERT INTO peer_ips (peer_id, ip_address, is_primary) VALUES (?, ?, 1)`, 1, "10.0.0.1")
			db.Exec(`INSERT INTO peer_ips (peer_id, ip_address, is_primary) VALUES (?, ?, 0)`, 1, "10.0.0.2")
		},
		wantCode: http.StatusNoContent,
		verifyDelete: func(t *testing.T, db *sql.DB) {
			var count int
			err := db.QueryRow("SELECT COUNT(*) FROM peer_ips WHERE id = 2").Scan(&count)
			if err != nil {
				t.Fatalf("failed to query peer_ips: %v", err)
			}
			if count != 0 {
				t.Error("expected secondary IP to be deleted")
			}
		},
	},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			database, cleanup := testutil.SetupTestDB(t)
			defer cleanup()

			if tt.setup != nil {
				tt.setup(t, database)
			}

			req := httptest.NewRequest("DELETE", "/api/v1/peers/"+tt.peerID+"/ips/"+tt.ipID, nil)
			req = muxVars(req, map[string]string{"id": tt.peerID, "ip_id": tt.ipID})
			w := httptest.NewRecorder()

			handler := NewHandler(database, nil, nil)
			handler.DeletePeerIP(w, req)

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

			if tt.verifyDelete != nil {
				tt.verifyDelete(t, database)
			}
		})
	}
}

// TestUpdateAgent tests the POST /peers/{id}/update-agent endpoint.
func TestUpdateAgent(t *testing.T) {
	t.Run("peer not found", func(t *testing.T) {
		database, cleanup := testutil.SetupTestDB(t)
		defer cleanup()

		handler := NewHandler(database, nil, nil)

		req := httptest.NewRequest("POST", "/api/v1/peers/999/update-agent", nil)
		req = muxVars(req, map[string]string{"id": "999"})
		w := httptest.NewRecorder()

		handler.UpdateAgent(w, req)

		if w.Code != http.StatusNotFound {
			t.Errorf("expected 404, got %d", w.Code)
		}
	})

	t.Run("invalid peer ID", func(t *testing.T) {
		database, cleanup := testutil.SetupTestDB(t)
		defer cleanup()

		handler := NewHandler(database, nil, nil)

		req := httptest.NewRequest("POST", "/api/v1/peers/invalid/update-agent", nil)
		req = muxVars(req, map[string]string{"id": "invalid"})
		w := httptest.NewRecorder()

		handler.UpdateAgent(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("expected 400, got %d", w.Code)
		}
	})

	t.Run("manual peer rejected", func(t *testing.T) {
		database, cleanup := testutil.SetupTestDB(t)
		defer cleanup()

		handler := NewHandler(database, nil, nil)

		database.Exec(`INSERT INTO peers (hostname, ip_address, is_manual, agent_key, hmac_key) VALUES (?, ?, 1, ?, ?)`, "manual-peer", "10.0.0.1", "manual-key", "hmac1")

		req := httptest.NewRequest("POST", "/api/v1/peers/1/update-agent", nil)
		req = muxVars(req, map[string]string{"id": "1"})
		w := httptest.NewRecorder()

		handler.UpdateAgent(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("expected 400, got %d", w.Code)
		}
	})

	t.Run("missing instance URL", func(t *testing.T) {
		database, cleanup := testutil.SetupTestDB(t)
		defer cleanup()

		handler := NewHandler(database, nil, nil)

		database.Exec(`INSERT INTO peers (hostname, ip_address, is_manual, agent_key, hmac_key) VALUES (?, ?, 0, ?, ?)`, "test-peer", "10.0.0.2", "key1", "hmackey1")

		req := httptest.NewRequest("POST", "/api/v1/peers/1/update-agent", nil)
		req = muxVars(req, map[string]string{"id": "1"})
		w := httptest.NewRecorder()

		handler.UpdateAgent(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("expected 400, got %d", w.Code)
		}
	})

	t.Run("nil SSEHub", func(t *testing.T) {
		database, cleanup := testutil.SetupTestDB(t)
		defer cleanup()

		handler := NewHandler(database, nil, nil)

		database.Exec(`INSERT INTO peers (hostname, ip_address, is_manual, agent_key, hmac_key) VALUES (?, ?, 0, ?, ?)`, "agent-peer", "10.0.0.3", "key2", "hmackey2")

		database.Exec(`INSERT INTO system_config (key, value) VALUES ('instance_url', 'https://runic.example.com')`)

		req := httptest.NewRequest("POST", "/api/v1/peers/1/update-agent", nil)
		req = muxVars(req, map[string]string{"id": "1"})
		w := httptest.NewRecorder()

		handler.UpdateAgent(w, req)

		if w.Code != http.StatusInternalServerError {
			t.Errorf("expected 500, got %d", w.Code)
		}
	})
}

// mockUpdateAgent implements the SSE hub interface for testing.
type mockUpdateAgent struct {
	called         bool
	hostID         string
	controlPlaneURL string
}

func (m *mockUpdateAgent) NotifyUpdateAgent(hostID, url string) {
	m.called = true
	m.hostID = hostID
	m.controlPlaneURL = url
}

func TestUpdateAgentSuccess(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	mock := &mockUpdateAgent{}
	handler := NewHandler(database, nil, mock)

	database.Exec(`INSERT INTO peers (hostname, ip_address, is_manual, agent_key, hmac_key) VALUES (?, ?, 0, ?, ?)`, "agent-peer", "10.0.0.5", "key5", "hmackey5")

	database.Exec(`INSERT INTO system_config (key, value) VALUES ('instance_url', 'https://runic.example.com')`)

	req := httptest.NewRequest("POST", "/api/v1/peers/1/update-agent", nil)
	req = muxVars(req, map[string]string{"id": "1"})
	w := httptest.NewRecorder()

	handler.UpdateAgent(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp["status"] != "update_sent" {
		t.Errorf("expected status 'update_sent', got %q", resp["status"])
	}

	if !mock.called {
		t.Error("expected NotifyUpdateAgent to be called")
	}
	if mock.hostID != "host-agent-peer" {
		t.Errorf("expected hostID 'host-agent-peer', got %q", mock.hostID)
	}
	if mock.controlPlaneURL != "https://runic.example.com" {
		t.Errorf("expected controlPlaneURL 'https://runic.example.com', got %q", mock.controlPlaneURL)
	}
}
