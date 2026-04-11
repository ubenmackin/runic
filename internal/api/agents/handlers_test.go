package agents

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"runic/internal/models"
	"runic/internal/testutil"
)

// generateValidAgentToken creates a valid JWT token for an agent
func generateValidAgentToken(t *testing.T, db *sql.DB, hostname string) string {
	secretStr := "test-secret-key-for-agent-jwt-256-bits!!"
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":  fmt.Sprintf("host-%s", hostname),
		"type": "agent",
		"iat":  time.Now().Unix(),
		"exp":  time.Now().Add(72 * time.Hour).Unix(),
	})
	tokenStr, err := token.SignedString([]byte(secretStr))
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}
	return tokenStr
}

// muxVars is a helper to mock gorilla/mux vars
var muxVars = testutil.MuxVars

// makeAuthRequest creates a request with valid auth for a given peer
func makeAuthRequest(t *testing.T, db *sql.DB, method, url string, body string, peerHostname string) *http.Request {
	req := httptest.NewRequest(method, url, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if peerHostname != "" {
		token := generateValidAgentToken(t, db, peerHostname)
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return req
}

// =============================================================================
// Test AgentAuthMiddleware
// =============================================================================

func TestAgentAuthMiddleware(t *testing.T) {
	tests := []struct {
		name       string
		setup      func(t *testing.T, db *sql.DB)
		authHeader string
		wantCode   int
	}{
		{
			name:       "missing Authorization header",
			setup:      nil,
			authHeader: "",
			wantCode:   http.StatusUnauthorized,
		},
		{
			name:       "empty Bearer token",
			setup:      nil,
			authHeader: "Bearer ",
			wantCode:   http.StatusUnauthorized,
		},
		{
			name:       "invalid Bearer format - no space",
			setup:      nil,
			authHeader: "BearerToken123",
			wantCode:   http.StatusUnauthorized,
		},
		{
			name: "expired JWT token",
			setup: func(t *testing.T, db *sql.DB) {
				db.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)`,
					"test-agent", "10.0.0.1", "agent-key-test", "test-hmac-key")
			},
			authHeader: "Bearer expired-token",
			wantCode:   http.StatusUnauthorized,
		},
		{
			name: "invalid JWT - wrong signature",
			setup: func(t *testing.T, db *sql.DB) {
				db.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)`,
					"test-agent", "10.0.0.1", "agent-key-test", "test-hmac-key")
			},
			authHeader: "Bearer wrong-signature-token",
			wantCode:   http.StatusUnauthorized,
		},
		{
			name: "valid JWT but wrong type claim",
			authHeader: func() string {
				secretStr := "test-secret-key-for-agent-jwt-256-bits!!"
				token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
					"sub":  "host-test-agent",
					"type": "not-agent", // wrong type
					"iat":  time.Now().Unix(),
					"exp":  time.Now().Add(72 * time.Hour).Unix(),
				})
				tokenStr, _ := token.SignedString([]byte(secretStr))
				return "Bearer " + tokenStr
			}(),
			wantCode: http.StatusUnauthorized,
		},
		{
			name: "valid JWT but missing sub claim",
			authHeader: func() string {
				secretStr := "test-secret-key-for-agent-jwt-256-bits!!"
				token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
					"type": "agent",
					"iat":  time.Now().Unix(),
					"exp":  time.Now().Add(72 * time.Hour).Unix(),
				})
				tokenStr, _ := token.SignedString([]byte(secretStr))
				return "Bearer " + tokenStr
			}(),
			wantCode: http.StatusUnauthorized,
		},
		{
			name: "valid JWT - passes through",
			setup: func(t *testing.T, db *sql.DB) {
				db.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)`,
					"test-agent", "10.0.0.1", "agent-key-test", "test-hmac-key")
			},
			authHeader: "Bearer valid-token",
			wantCode:   http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, cleanup := testutil.SetupTestDBWithSecret(t)
			defer cleanup()

			if tt.setup != nil {
				tt.setup(t, db)
			}

			authHeader := tt.authHeader
			// Special handling for valid JWT - generate actual token
			if tt.name == "valid JWT - passes through" {
				authHeader = "Bearer " + generateValidAgentToken(t, db, "test-agent")
			}

			req := httptest.NewRequest("GET", "/test", nil)
			if authHeader != "" {
				req.Header.Set("Authorization", authHeader)
			}
			w := httptest.NewRecorder()

			handler := NewHandler(db, db, nil)

			// Track if next handler was called
			nextCalled := false
			nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				nextCalled = true
				w.WriteHeader(http.StatusOK)
			})

			handler.AgentAuthMiddleware(nextHandler).ServeHTTP(w, req)

			if w.Code != tt.wantCode {
				t.Errorf("expected status %d, got %d: %s", tt.wantCode, w.Code, w.Body.String())
			}

			if tt.wantCode == http.StatusOK && !nextCalled {
				t.Error("expected next handler to be called")
			}
		})
	}
}

// =============================================================================
// Test RegisterAgent
// =============================================================================

func TestRegisterAgent(t *testing.T) {
	tests := []struct {
		name      string
		setup     func(t *testing.T, db *sql.DB)
		reqBody   string
		wantCode  int
		checkResp func(t *testing.T, w *httptest.ResponseRecorder)
	}{
		{
			name:     "empty hostname",
			setup:    nil,
			reqBody:  `{"hostname": ""}`,
			wantCode: http.StatusBadRequest,
		},
		{
			name:     "invalid JSON body",
			setup:    nil,
			reqBody:  `{invalid json}`,
			wantCode: http.StatusBadRequest,
		},
		{
			name:     "new server without registration token",
			setup:    nil,
			reqBody:  `{"hostname": "new-agent"}`,
			wantCode: http.StatusUnauthorized,
		},
		{
			name: "invalid registration token",
			setup: func(t *testing.T, db *sql.DB) {
				db.Exec(`INSERT INTO registration_tokens (token, description) VALUES (?, ?)`,
					"valid-token-123", "test token")
			},
			reqBody:  `{"hostname": "new-agent", "registration_token": "wrong-token"}`,
			wantCode: http.StatusUnauthorized,
		},
		{
			name: "valid registration token - new peer",
			setup: func(t *testing.T, db *sql.DB) {
				db.Exec(`INSERT INTO registration_tokens (token, description) VALUES (?, ?)`,
					"valid-registration-token-12345", "test token")
			},
			reqBody:  `{"hostname": "new-agent", "registration_token": "valid-registration-token-12345"}`,
			wantCode: http.StatusCreated,
			checkResp: func(t *testing.T, w *httptest.ResponseRecorder) {
				var resp map[string]interface{}
				if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
					t.Fatalf("failed to decode response: %v", err)
				}
				if resp["host_id"] != "host-new-agent" {
					t.Errorf("expected host_id 'host-new-agent', got %v", resp["host_id"])
				}
				if resp["token"] == nil || resp["token"] == "" {
					t.Error("expected non-empty token")
				}
				if resp["hmac_key"] == nil || resp["hmac_key"] == "" {
					t.Error("expected non-empty hmac_key")
				}
			},
		},
		{
			name: "existing peer re-registration - no token required",
			setup: func(t *testing.T, db *sql.DB) {
				db.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, status) VALUES (?, ?, ?, ?, ?)`,
					"existing-agent", "10.0.0.1", "existing-key", "existing-hmac", "offline")
			},
			reqBody:  `{"hostname": "existing-agent"}`,
			wantCode: http.StatusOK,
			checkResp: func(t *testing.T, w *httptest.ResponseRecorder) {
				var resp map[string]interface{}
				if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
					t.Fatalf("failed to decode response: %v", err)
				}
				if resp["host_id"] != "host-existing-agent" {
					t.Errorf("expected host_id 'host-existing-agent', got %v", resp["host_id"])
				}
				if resp["hmac_key"] != "existing-hmac" {
					t.Errorf("expected hmac_key 'existing-hmac', got %v", resp["hmac_key"])
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, cleanup := testutil.SetupTestDBWithSecret(t)
			defer cleanup()

			if tt.setup != nil {
				tt.setup(t, db)
			}

			req := httptest.NewRequest("POST", "/api/v1/agents/register", strings.NewReader(tt.reqBody))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			handler := NewHandler(db, db, nil)
			handler.RegisterAgent(w, req)

			if w.Code != tt.wantCode {
				t.Errorf("expected %d, got %d: %s", tt.wantCode, w.Code, w.Body.String())
			}

			if tt.checkResp != nil {
				tt.checkResp(t, w)
			}
		})
	}
}

// =============================================================================
// Test GetBundle
// =============================================================================

func TestGetBundle(t *testing.T) {
	tests := []struct {
		name      string
		setup     func(t *testing.T, db *sql.DB)
		peer      string
		etag      string
		wantCode  int
		wantETag  string
		checkResp func(t *testing.T, w *httptest.ResponseRecorder)
	}{
		{
			name:     "no bundle found",
			setup:    nil,
			peer:     "test-agent",
			wantCode: http.StatusNotFound,
		},
		{
			name: "bundle found with ETag match",
			setup: func(t *testing.T, db *sql.DB) {
				db.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)`,
					"test-agent", "10.0.0.1", "agent-key-test", "test-hmac")
				db.Exec(`INSERT INTO rule_bundles (peer_id, version, version_number, rules_content, hmac) VALUES (?, ?, ?, ?, ?)`,
					1, "v1.0.0", 1, "rules content", "bundle-hmac")
			},
			peer:     "test-agent",
			etag:     "v1.0.0",
			wantCode: http.StatusNotModified,
		},
		{
			name: "bundle found with different ETag",
			setup: func(t *testing.T, db *sql.DB) {
				db.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)`,
					"test-agent2", "10.0.0.2", "agent-key-test2", "test-hmac2")
				db.Exec(`INSERT INTO rule_bundles (peer_id, version, version_number, rules_content, hmac) VALUES (?, ?, ?, ?, ?)`,
					1, "v2.0.0", 2, "new rules content", "bundle-hmac2")
			},
			peer:     "test-agent2",
			etag:     "v1.0.0",
			wantCode: http.StatusOK,
			wantETag: "v2.0.0",
			checkResp: func(t *testing.T, w *httptest.ResponseRecorder) {
				var resp map[string]interface{}
				if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
					t.Fatalf("failed to decode response: %v", err)
				}
				if resp["version"] != "v2.0.0" {
					t.Errorf("expected version 'v2.0.0', got %v", resp["version"])
				}
				if resp["rules"] != "new rules content" {
					t.Errorf("expected rules 'new rules content', got %v", resp["rules"])
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, cleanup := testutil.SetupTestDBWithSecret(t)
			defer cleanup()

			if tt.setup != nil {
				tt.setup(t, db)
			}

			req := httptest.NewRequest("GET", "/api/v1/agents/bundle", nil)
			if tt.etag != "" {
				req.Header.Set("If-None-Match", tt.etag)
			}

			// Add auth header for peer lookup
			token := generateValidAgentToken(t, db, tt.peer)
			req.Header.Set("Authorization", "Bearer "+token)

			w := httptest.NewRecorder()

			handler := NewHandler(db, db, nil)

			handler.AgentAuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
				handler.GetBundle(w, r)
			}).ServeHTTP(w, req)

			if w.Code != tt.wantCode {
				t.Errorf("expected %d, got %d: %s", tt.wantCode, w.Code, w.Body.String())
			}

			if tt.wantETag != "" {
				gotETag := w.Header().Get("ETag")
				if gotETag != tt.wantETag {
					t.Errorf("expected ETag %s, got %s", tt.wantETag, gotETag)
				}
			}

			if tt.checkResp != nil {
				tt.checkResp(t, w)
			}
		})
	}
}

// =============================================================================
// Test Heartbeat
// =============================================================================

func TestHeartbeat(t *testing.T) {
	tests := []struct {
		name      string
		setup     func(t *testing.T, db *sql.DB)
		reqBody   string
		wantCode  int
		checkResp func(t *testing.T, w *httptest.ResponseRecorder)
	}{
		{
			name: "valid heartbeat",
			setup: func(t *testing.T, db *sql.DB) {
				db.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)`,
					"test-agent", "10.0.0.1", "agent-key-test", "test-hmac")
			},
			reqBody:  `{"bundle_version_applied": "v1.0.0", "uptime_seconds": 3600, "load_1m": 0.5, "agent_version": "1.0.0"}`,
			wantCode: http.StatusOK,
			checkResp: func(t *testing.T, w *httptest.ResponseRecorder) {
				var resp map[string]string
				if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
					t.Fatalf("failed to decode response: %v", err)
				}
				if resp["status"] != "ok" {
					t.Errorf("expected status 'ok', got %v", resp["status"])
				}
			},
		},
		{
			name: "invalid JSON - continues anyway",
			setup: func(t *testing.T, db *sql.DB) {
				db.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)`,
					"test-agent2", "10.0.0.2", "agent-key-test2", "test-hmac2")
			},
			reqBody:  `{invalid json}`,
			wantCode: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, cleanup := testutil.SetupTestDBWithSecret(t)
			defer cleanup()

			if tt.setup != nil {
				tt.setup(t, db)
			}

			peer := "test-agent"
			if strings.Contains(tt.name, "invalid JSON") {
				peer = "test-agent2"
			}

			req := makeAuthRequest(t, db, "POST", "/api/v1/agents/heartbeat", tt.reqBody, peer)
			w := httptest.NewRecorder()

			handler := NewHandler(db, db, nil)

			handler.AgentAuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
				handler.Heartbeat(w, r)
			}).ServeHTTP(w, req)

			if w.Code != tt.wantCode {
				t.Errorf("expected %d, got %d: %s", tt.wantCode, w.Code, w.Body.String())
			}

			if tt.checkResp != nil {
				tt.checkResp(t, w)
			}
		})
	}
}

// =============================================================================
// Test SubmitLogs
// =============================================================================

func TestSubmitLogs(t *testing.T) {
	tests := []struct {
		name      string
		setup     func(t *testing.T, db *sql.DB)
		reqBody   string
		wantCode  int
		checkResp func(t *testing.T, w *httptest.ResponseRecorder)
	}{
		{
			name: "valid logs",
			setup: func(t *testing.T, db *sql.DB) {
				db.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)`,
					"test-agent", "10.0.0.1", "agent-key-test", "test-hmac")
			},
			reqBody: `{"events": [
				{"timestamp": "2024-01-01T00:00:00Z", "direction": "IN", "src_ip": "192.168.1.1", "dst_ip": "10.0.0.1", "protocol": "tcp", "action": "ACCEPT", "src_port": 12345, "dst_port": 22}
			]}`,
			wantCode: http.StatusOK,
			checkResp: func(t *testing.T, w *httptest.ResponseRecorder) {
				var resp map[string]interface{}
				if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
					t.Fatalf("failed to decode response: %v", err)
				}
				if int(resp["accepted"].(float64)) != 1 {
					t.Errorf("expected accepted=1, got %v", resp["accepted"])
				}
				if int(resp["skipped"].(float64)) != 0 {
					t.Errorf("expected skipped=0, got %v", resp["skipped"])
				}
			},
		},
		{
			name: "invalid log event - bad src_ip",
			setup: func(t *testing.T, db *sql.DB) {
				db.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)`,
					"test-agent", "10.0.0.1", "agent-key-test", "test-hmac")
			},
			reqBody: `{"events": [
				{"timestamp": "2024-01-01T00:00:00Z", "direction": "IN", "src_ip": "invalid-ip", "dst_ip": "10.0.0.1", "protocol": "tcp", "action": "ACCEPT", "src_port": 12345, "dst_port": 22}
			]}`,
			wantCode: http.StatusOK,
			checkResp: func(t *testing.T, w *httptest.ResponseRecorder) {
				var resp map[string]interface{}
				if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
					t.Fatalf("failed to decode response: %v", err)
				}
				if int(resp["accepted"].(float64)) != 0 {
					t.Errorf("expected accepted=0, got %v", resp["accepted"])
				}
				if int(resp["skipped"].(float64)) != 1 {
					t.Errorf("expected skipped=1, got %v", resp["skipped"])
				}
			},
		},
		{
			name: "empty events array",
			setup: func(t *testing.T, db *sql.DB) {
				db.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)`,
					"test-agent", "10.0.0.1", "agent-key-test", "test-hmac")
			},
			reqBody:  `{"events": []}`,
			wantCode: http.StatusOK,
			checkResp: func(t *testing.T, w *httptest.ResponseRecorder) {
				var resp map[string]interface{}
				if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
					t.Fatalf("failed to decode response: %v", err)
				}
				if int(resp["accepted"].(float64)) != 0 {
					t.Errorf("expected accepted=0, got %v", resp["accepted"])
				}
				if int(resp["skipped"].(float64)) != 0 {
					t.Errorf("expected skipped=0, got %v", resp["skipped"])
				}
			},
		},
		{
			name: "invalid JSON",
			setup: func(t *testing.T, db *sql.DB) {
				db.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)`,
					"test-agent", "10.0.0.1", "agent-key-test", "test-hmac")
			},
			reqBody:  `{invalid json}`,
			wantCode: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, logsDB, cleanup := testutil.SetupTestDBWithSecretAndLogs(t)
			defer cleanup()

			if tt.setup != nil {
				tt.setup(t, db)
			}

			req := makeAuthRequest(t, db, "POST", "/api/v1/agents/logs", tt.reqBody, "test-agent")
			w := httptest.NewRecorder()

			handler := NewHandler(db, logsDB, nil)

			handler.AgentAuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
				handler.SubmitLogs(w, r)
			}).ServeHTTP(w, req)

			if w.Code != tt.wantCode {
				t.Errorf("expected %d, got %d: %s", tt.wantCode, w.Code, w.Body.String())
			}

			if tt.checkResp != nil {
				tt.checkResp(t, w)
			}
		})
	}
}

// =============================================================================
// Test ConfirmBundleApplied
// =============================================================================

func TestConfirmBundleApplied(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(t *testing.T, db *sql.DB)
		reqBody  string
		wantCode int
	}{
		{
			name: "valid confirmation",
			setup: func(t *testing.T, db *sql.DB) {
				db.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)`,
					"test-agent", "10.0.0.1", "agent-key-test", "test-hmac")
				db.Exec(`INSERT INTO rule_bundles (peer_id, version, version_number, rules_content, hmac) VALUES (?, ?, ?, ?, ?)`,
					1, "v1.0.0", 1, "rules content", "bundle-hmac")
			},
			reqBody:  `{"version": "v1.0.0", "applied_at": "2024-01-01T00:00:00Z"}`,
			wantCode: http.StatusOK,
		},
		{
			name: "invalid JSON",
			setup: func(t *testing.T, db *sql.DB) {
				db.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)`,
					"test-agent", "10.0.0.1", "agent-key-test", "test-hmac")
			},
			reqBody:  `{invalid json}`,
			wantCode: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, cleanup := testutil.SetupTestDBWithSecret(t)
			defer cleanup()

			if tt.setup != nil {
				tt.setup(t, db)
			}

			req := makeAuthRequest(t, db, "POST", "/api/v1/agents/confirm-bundle", tt.reqBody, "test-agent")
			w := httptest.NewRecorder()

			handler := NewHandler(db, db, nil)

			handler.AgentAuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
				handler.ConfirmBundleApplied(w, r)
			}).ServeHTTP(w, req)

			if w.Code != tt.wantCode {
				t.Errorf("expected %d, got %d: %s", tt.wantCode, w.Code, w.Body.String())
			}
		})
	}
}

// =============================================================================
// Test AgentCheckRotation
// =============================================================================

func TestAgentCheckRotation(t *testing.T) {
	tests := []struct {
		name      string
		setup     func(t *testing.T, db *sql.DB)
		wantCode  int
		checkResp func(t *testing.T, w *httptest.ResponseRecorder)
	}{
		{
			name:     "peer not found",
			setup:    nil,
			wantCode: http.StatusNotFound,
		},
		{
			name: "no rotation pending",
			setup: func(t *testing.T, db *sql.DB) {
				db.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)`,
					"test-agent", "10.0.0.1", "agent-key-test", "test-hmac")
			},
			wantCode: http.StatusNoContent,
		},
		{
			name: "rotation pending",
			setup: func(t *testing.T, db *sql.DB) {
				db.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, hmac_key_rotation_token) VALUES (?, ?, ?, ?, ?)`,
					"test-agent", "10.0.0.1", "agent-key-test", "test-hmac", "pending-rotation-token")
			},
			wantCode: http.StatusOK,
			checkResp: func(t *testing.T, w *httptest.ResponseRecorder) {
				var resp map[string]string
				if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
					t.Fatalf("failed to decode response: %v", err)
				}
				if resp["rotation_token"] != "pending-rotation-token" {
					t.Errorf("expected rotation_token 'pending-rotation-token', got %v", resp["rotation_token"])
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, cleanup := testutil.SetupTestDBWithSecret(t)
			defer cleanup()

			if tt.setup != nil {
				tt.setup(t, db)
			}

			peer := "test-agent"
			if tt.name == "peer not found" {
				peer = "nonexistent-peer"
			}

			req := makeAuthRequest(t, db, "GET", "/api/v1/agents/check-rotation", "", peer)
			w := httptest.NewRecorder()

			handler := NewHandler(db, db, nil)

			handler.AgentAuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
				handler.AgentCheckRotation(w, r)
			}).ServeHTTP(w, req)

			if w.Code != tt.wantCode {
				t.Errorf("expected %d, got %d: %s", tt.wantCode, w.Code, w.Body.String())
			}

			if tt.checkResp != nil {
				tt.checkResp(t, w)
			}
		})
	}
}

// =============================================================================
// Test AgentTestKey
// =============================================================================

func TestAgentTestKey(t *testing.T) {
	// Generate a valid signature for "test-message" with key "test-hmac"
	testHMACKey := "test-hmac"
	mac := hmac.New(sha256.New, []byte(testHMACKey))
	mac.Write([]byte("test-message"))
	validSignature := hex.EncodeToString(mac.Sum(nil))

	// Generate invalid signature
	invalidMAC := hmac.New(sha256.New, []byte("wrong-key"))
	invalidMAC.Write([]byte("test-message"))
	invalidSignature := hex.EncodeToString(invalidMAC.Sum(nil))

	tests := []struct {
		name     string
		setup    func(t *testing.T, db *sql.DB)
		reqBody  string
		wantCode int
	}{
		{
			name: "invalid JSON",
			setup: func(t *testing.T, db *sql.DB) {
				db.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)`,
					"test-agent", "10.0.0.1", "agent-key-test", testHMACKey)
			},
			reqBody:  `{invalid json}`,
			wantCode: http.StatusBadRequest,
		},
		{
			name:     "peer not found",
			setup:    nil,
			reqBody:  `{"message": "test-message", "signature": "` + validSignature + `"}`,
			wantCode: http.StatusNotFound,
		},
		{
			name: "invalid signature",
			setup: func(t *testing.T, db *sql.DB) {
				db.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)`,
					"test-agent", "10.0.0.1", "agent-key-test", testHMACKey)
			},
			reqBody:  `{"message": "test-message", "signature": "` + invalidSignature + `"}`,
			wantCode: http.StatusUnauthorized,
		},
		{
			name: "valid signature",
			setup: func(t *testing.T, db *sql.DB) {
				db.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)`,
					"test-agent", "10.0.0.1", "agent-key-test", testHMACKey)
			},
			reqBody:  `{"message": "test-message", "signature": "` + validSignature + `"}`,
			wantCode: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, cleanup := testutil.SetupTestDBWithSecret(t)
			defer cleanup()

			if tt.setup != nil {
				tt.setup(t, db)
			}

			peer := "test-agent"
			if tt.name == "peer not found" {
				peer = "nonexistent-peer"
			}

			req := makeAuthRequest(t, db, "POST", "/api/v1/agents/test-key", tt.reqBody, peer)
			w := httptest.NewRecorder()

			handler := NewHandler(db, db, nil)

			handler.AgentAuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
				handler.AgentTestKey(w, r)
			}).ServeHTTP(w, req)

			if w.Code != tt.wantCode {
				t.Errorf("expected %d, got %d: %s", tt.wantCode, w.Code, w.Body.String())
			}
		})
	}
}

// =============================================================================
// Test GenerateRegistrationToken
// =============================================================================

func TestGenerateRegistrationToken(t *testing.T) {
	tests := []struct {
		name      string
		reqBody   string
		wantCode  int
		checkResp func(t *testing.T, w *httptest.ResponseRecorder)
	}{
		{
			name:     "valid request with description",
			reqBody:  `{"description": "test token"}`,
			wantCode: http.StatusCreated,
			checkResp: func(t *testing.T, w *httptest.ResponseRecorder) {
				var resp map[string]interface{}
				if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
					t.Fatalf("failed to decode response: %v", err)
				}
				if resp["full_token"] == nil || resp["full_token"] == "" {
					t.Error("expected non-empty full_token")
				}
				if resp["description"] != "test token" {
					t.Errorf("expected description 'test token', got %v", resp["description"])
				}
				// Token should be 64 hex chars (32 bytes)
				token := resp["full_token"].(string)
				if len(token) != 64 {
					t.Errorf("expected token length 64, got %d", len(token))
				}
			},
		},
		{
			name:     "empty body - description optional",
			reqBody:  `{}`,
			wantCode: http.StatusCreated,
			checkResp: func(t *testing.T, w *httptest.ResponseRecorder) {
				var resp map[string]interface{}
				if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
					t.Fatalf("failed to decode response: %v", err)
				}
				if resp["full_token"] == nil || resp["full_token"] == "" {
					t.Error("expected non-empty full_token")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, cleanup := testutil.SetupTestDBWithSecret(t)
			defer cleanup()

			req := httptest.NewRequest("POST", "/api/v1/registration-tokens", strings.NewReader(tt.reqBody))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			handler := NewHandler(db, db, nil)
			handler.GenerateRegistrationToken(w, req)

			if w.Code != tt.wantCode {
				t.Errorf("expected %d, got %d: %s", tt.wantCode, w.Code, w.Body.String())
			}

			if tt.checkResp != nil {
				tt.checkResp(t, w)
			}
		})
	}
}

// =============================================================================
// Test ListRegistrationTokens
// =============================================================================

func TestListRegistrationTokens(t *testing.T) {
	tests := []struct {
		name      string
		setup     func(t *testing.T, db *sql.DB)
		wantCode  int
		checkResp func(t *testing.T, w *httptest.ResponseRecorder)
	}{
		{
			name:     "empty list",
			setup:    nil,
			wantCode: http.StatusOK,
			checkResp: func(t *testing.T, w *httptest.ResponseRecorder) {
				var resp []map[string]interface{}
				if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
					t.Fatalf("failed to decode response: %v", err)
				}
				if len(resp) != 0 {
					t.Errorf("expected 0 tokens, got %d", len(resp))
				}
			},
		},
		{
			name: "multiple tokens",
			setup: func(t *testing.T, db *sql.DB) {
				db.Exec(`INSERT INTO registration_tokens (token, description) VALUES (?, ?)`,
					"token1-11111111111111111111111111111111", "token 1")
				db.Exec(`INSERT INTO registration_tokens (token, description) VALUES (?, ?)`,
					"token2-22222222222222222222222222222222", "token 2")
			},
			wantCode: http.StatusOK,
			checkResp: func(t *testing.T, w *httptest.ResponseRecorder) {
				var resp []map[string]interface{}
				if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
					t.Fatalf("failed to decode response: %v", err)
				}
				if len(resp) != 2 {
					t.Errorf("expected 2 tokens, got %d", len(resp))
				}
				// Check masking - token should be masked
				for _, token := range resp {
					tokenStr := token["token"].(string)
					if !strings.Contains(tokenStr, "...") {
						t.Errorf("expected masked token, got %s", tokenStr)
					}
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, cleanup := testutil.SetupTestDBWithSecret(t)
			defer cleanup()

			if tt.setup != nil {
				tt.setup(t, db)
			}

			req := httptest.NewRequest("GET", "/api/v1/registration-tokens", nil)
			w := httptest.NewRecorder()

			handler := NewHandler(db, db, nil)
			handler.ListRegistrationTokens(w, req)

			if w.Code != tt.wantCode {
				t.Errorf("expected %d, got %d: %s", tt.wantCode, w.Code, w.Body.String())
			}

			if tt.checkResp != nil {
				tt.checkResp(t, w)
			}
		})
	}
}

// =============================================================================
// Test RevokeRegistrationToken
// =============================================================================

func TestRevokeRegistrationToken(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(t *testing.T, db *sql.DB)
		tokenID  string
		wantCode int
	}{
		{
			name:     "token not found",
			setup:    nil,
			tokenID:  "999",
			wantCode: http.StatusNotFound,
		},
		{
			name: "token already used",
			setup: func(t *testing.T, db *sql.DB) {
				db.Exec(`INSERT INTO registration_tokens (token, description, used_at) VALUES (?, ?, CURRENT_TIMESTAMP)`,
					"used-token-1111111111111111111111111111", "used token")
			},
			tokenID:  "1",
			wantCode: http.StatusNotFound,
		},
		{
			name: "valid revocation",
			setup: func(t *testing.T, db *sql.DB) {
				db.Exec(`INSERT INTO registration_tokens (token, description) VALUES (?, ?)`,
					"valid-token-2222222222222222222222222222", "valid token")
			},
			tokenID:  "1",
			wantCode: http.StatusNoContent,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, cleanup := testutil.SetupTestDBWithSecret(t)
			defer cleanup()

			if tt.setup != nil {
				tt.setup(t, db)
			}

			req := httptest.NewRequest("DELETE", "/api/v1/registration-tokens/"+tt.tokenID, nil)
			w := httptest.NewRecorder()
			req = muxVars(req, map[string]string{"id": tt.tokenID})

			handler := NewHandler(db, db, nil)
			handler.RevokeRegistrationToken(w, req)

			if w.Code != tt.wantCode {
				t.Errorf("expected %d, got %d: %s", tt.wantCode, w.Code, w.Body.String())
			}
		})
	}
}

// =============================================================================
// Test LogEvent.Validate
// =============================================================================

func TestLogEventValidate(t *testing.T) {
	tests := []struct {
		name   string
		event  LogEvent
		wantOk bool
	}{
		{
			name: "valid event",
			event: LogEvent{
				Timestamp: "2024-01-01T00:00:00Z",
				Direction: "IN",
				SrcIP:     "192.168.1.1",
				DstIP:     "10.0.0.1",
				Protocol:  "tcp",
				Action:    "ACCEPT",
				SrcPort:   12345,
				DstPort:   22,
			},
			wantOk: true,
		},
		{
			name: "invalid src_ip",
			event: LogEvent{
				SrcIP: "invalid-ip",
			},
			wantOk: false,
		},
		{
			name: "invalid dst_ip",
			event: LogEvent{
				DstIP: "invalid-ip",
			},
			wantOk: false,
		},
		{
			name: "src_port out of range - negative",
			event: LogEvent{
				SrcPort: -1,
			},
			wantOk: false,
		},
		{
			name: "src_port out of range - too high",
			event: LogEvent{
				SrcPort: 65536,
			},
			wantOk: false,
		},
		{
			name: "dst_port out of range - negative",
			event: LogEvent{
				DstPort: -1,
			},
			wantOk: false,
		},
		{
			name: "dst_port out of range - too high",
			event: LogEvent{
				DstPort: 65536,
			},
			wantOk: false,
		},
		{
			name: "invalid action",
			event: LogEvent{
				Action: "INVALID",
			},
			wantOk: false,
		},
		{
			name: "invalid direction",
			event: LogEvent{
				Direction: "INVALID",
			},
			wantOk: false,
		},
		{
			name: "valid action - DROP",
			event: LogEvent{
				Action: "DROP",
			},
			wantOk: true,
		},
		{
			name: "valid action - REJECT",
			event: LogEvent{
				Action: "REJECT",
			},
			wantOk: true,
		},
		{
			name: "valid direction - OUT",
			event: LogEvent{
				Direction: "OUT",
			},
			wantOk: true,
		},
		{
			name:   "empty optional fields - valid",
			event:  LogEvent{},
			wantOk: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ok, _ := tt.event.Validate()
			if ok != tt.wantOk {
				t.Errorf("expected ok=%v, got %v", tt.wantOk, ok)
			}
		})
	}
}

// =============================================================================
// Test GenerateHMACKey
// =============================================================================

func TestGenerateHMACKey(t *testing.T) {
	key, err := GenerateHMACKey()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Should be 64 hex chars (32 bytes)
	if len(key) != 64 {
		t.Errorf("expected key length 64, got %d", len(key))
	}

	// Should be valid hex
	_, err = hex.DecodeString(key)
	if err != nil {
		t.Errorf("expected valid hex string, got error: %v", err)
	}
}

// =============================================================================
// Test generateAgentKey
// =============================================================================

func TestGenerateAgentKey(t *testing.T) {
	key, err := generateAgentKey()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Should have "agent-key-" prefix
	if !strings.HasPrefix(key, "agent-key-") {
		t.Errorf("expected key to start with 'agent-key-', got %s", key)
	}

	// Should be 32 hex chars after prefix (16 bytes)
	hexPart := strings.TrimPrefix(key, "agent-key-")
	if len(hexPart) != 32 {
		t.Errorf("expected hex part length 32, got %d", len(hexPart))
	}

	// Should be valid hex
	_, err = hex.DecodeString(hexPart)
	if err != nil {
		t.Errorf("expected valid hex string, got error: %v", err)
	}
}

// =============================================================================
// Test maskToken
// =============================================================================

func TestMaskToken(t *testing.T) {
	tests := []struct {
		name  string
		token string
		want  string
	}{
		{
			name:  "normal token",
			token: "1234567890123456789012345678901234567890123456789012345678901234",
			want:  "12345678...1234",
		},
		{
			name:  "short token",
			token: "123456789012",
			want:  "****",
		},
		{
			name:  "exactly 12 chars",
			token: "123456789012",
			want:  "****",
		},
		{
			name:  "13 chars",
			token: "1234567890123",
			want:  "12345678...0123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := maskToken(tt.token)
			if got != tt.want {
				t.Errorf("expected %s, got %s", tt.want, got)
			}
		})
	}
}

// =============================================================================
// Test ConsumeRegistrationToken
// =============================================================================

func TestConsumeRegistrationToken(t *testing.T) {
	tests := []struct {
		name         string
		setup        func(t *testing.T, db *sql.DB)
		token        string
		hostname     string
		wantConsumed bool
	}{
		{
			name:         "token not found",
			setup:        nil,
			token:        "nonexistent-token",
			hostname:     "test-host",
			wantConsumed: false,
		},
		{
			name: "already used",
			setup: func(t *testing.T, db *sql.DB) {
				db.Exec(`INSERT INTO registration_tokens (token, description, used_at) VALUES (?, ?, CURRENT_TIMESTAMP)`,
					"used-token", "used token")
			},
			token:        "used-token",
			hostname:     "test-host",
			wantConsumed: false,
		},
		{
			name: "successfully consumed",
			setup: func(t *testing.T, db *sql.DB) {
				db.Exec(`INSERT INTO registration_tokens (token, description) VALUES (?, ?)`,
					"valid-token", "valid token")
			},
			token:        "valid-token",
			hostname:     "test-host",
			wantConsumed: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, cleanup := testutil.SetupTestDBWithSecret(t)
			defer cleanup()

			if tt.setup != nil {
				tt.setup(t, db)
			}

			handler := NewHandler(db, db, nil)
			consumed, err := handler.ConsumeRegistrationToken(tt.token, tt.hostname)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if consumed != tt.wantConsumed {
				t.Errorf("expected consumed=%v, got %v", tt.wantConsumed, consumed)
			}
		})
	}
}

// =============================================================================
// Test Helper Functions
// =============================================================================

func TestSSEHubFromContext(t *testing.T) {
	// Test with nil context
	ctx := context.Background()
	hub := SSEHubFromContext(ctx)
	if hub != nil {
		t.Error("expected nil hub for empty context")
	}

	// Test with mock hub
	mockHub := &mockSSEBroadcaster{}
	ctx = context.WithValue(ctx, sseHubKey, mockHub)
	hub = SSEHubFromContext(ctx)
	if hub == nil {
		t.Error("expected non-nil hub")
	}
}

func TestLogHubFromContext(t *testing.T) {
	// Test with nil context
	ctx := context.Background()
	hub := LogHubFromContext(ctx)
	if hub != nil {
		t.Error("expected nil hub for empty context")
	}
}

func TestWithHubs(t *testing.T) {
	ctx := context.Background()
	mockSSE := &mockSSEBroadcaster{}
	mockLog := &mockLogBroadcaster{}

	ctx = WithHubs(ctx, mockSSE, mockLog)

	sseHub := SSEHubFromContext(ctx)
	if sseHub == nil {
		t.Error("expected SSE hub")
	}

	logHub := LogHubFromContext(ctx)
	if logHub == nil {
		t.Error("expected log hub")
	}
}

// Mock implementations for interfaces
type mockSSEBroadcaster struct{}

func (m *mockSSEBroadcaster) Register(hostID string) chan string {
	return make(chan string)
}

func (m *mockSSEBroadcaster) Unregister(hostID string) {}

type mockLogBroadcaster struct{}

func (m *mockLogBroadcaster) Broadcast(event *models.LogEvent) {}
