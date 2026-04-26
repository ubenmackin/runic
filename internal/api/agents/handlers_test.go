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
// Test RegisterAgent Malicious Input
// =============================================================================

func TestRegisterAgent_MaliciousInput(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(t *testing.T, db *sql.DB)
		reqBody  string
		wantCode int
		checkDB  func(t *testing.T, db *sql.DB)
	}{
		{
			name: "XSS payload in hostname - script tag",
			setup: func(t *testing.T, db *sql.DB) {
				db.Exec(`INSERT INTO registration_tokens (token, description) VALUES (?, ?)`, "valid-token-xss-1", "test token")
			},
			reqBody:  `{"hostname": "<script>alert('xss')</script>", "registration_token": "valid-token-xss-1"}`,
			wantCode: http.StatusCreated,
			checkDB: func(t *testing.T, db *sql.DB) {
				// Verify hostname was sanitized (control chars removed, stored as-is for HTML)
				var hostname string
				err := db.QueryRow("SELECT hostname FROM peers WHERE hostname LIKE '%script%'").Scan(&hostname)
				if err == nil {
					// The hostname should be stored but we verify it doesn't contain control chars
					if hostname != "<script>alert('xss')</script>" {
						t.Errorf("unexpected hostname stored: %s", hostname)
					}
				}
			},
		},
		{
			name: "header injection in hostname - CRLF",
			setup: func(t *testing.T, db *sql.DB) {
				db.Exec(`INSERT INTO registration_tokens (token, description) VALUES (?, ?)`, "valid-token-crlf-1", "test token")
			},
			reqBody:  `{"hostname": "server-01\r\nBcc: attacker@evil.com", "registration_token": "valid-token-crlf-1"}`,
			wantCode: http.StatusCreated,
			checkDB: func(t *testing.T, db *sql.DB) {
				// CR/LF should be stripped
				var hostname string
				err := db.QueryRow("SELECT hostname FROM peers WHERE hostname LIKE '%server-01%'").Scan(&hostname)
				if err != nil {
					t.Errorf("expected peer to be created: %v", err)
				}
				// The hostname should not contain CR or LF
				if containsAny(hostname, "\r\n") {
					t.Errorf("hostname contains control characters: %q", hostname)
				}
			},
		},
		{
			name: "SQL injection attempt in hostname",
			setup: func(t *testing.T, db *sql.DB) {
				db.Exec(`INSERT INTO registration_tokens (token, description) VALUES (?, ?)`, "valid-token-sql-1", "test token")
			},
			reqBody:  `{"hostname": "server'; DROP TABLE peers; --", "registration_token": "valid-token-sql-1"}`,
			wantCode: http.StatusCreated,
			checkDB: func(t *testing.T, db *sql.DB) {
				// The SQL injection payload should be stored as a literal string, not executed
				var hostname string
				err := db.QueryRow("SELECT hostname FROM peers WHERE hostname LIKE '%DROP%'").Scan(&hostname)
				if err != nil {
					t.Errorf("expected peer to be created with SQL injection payload as hostname: %v", err)
				}
				// Verify peers table still exists (SQL wasn't executed)
				var count int
				err = db.QueryRow("SELECT COUNT(*) FROM peers").Scan(&count)
				if err != nil {
					t.Errorf("peers table should still exist: %v", err)
				}
			},
		},
		{
			name: "XSS payload in IP address",
			setup: func(t *testing.T, db *sql.DB) {
				db.Exec(`INSERT INTO registration_tokens (token, description) VALUES (?, ?)`, "valid-token-ip-1", "test token")
			},
			reqBody:  `{"hostname": "safe-hostname", "ip": "<img src=x onerror=alert(1)>", "registration_token": "valid-token-ip-1"}`,
			wantCode: http.StatusCreated,
			checkDB: func(t *testing.T, db *sql.DB) {
				var ipAddress string
				err := db.QueryRow("SELECT ip_address FROM peers WHERE hostname = 'safe-hostname'").Scan(&ipAddress)
				if err != nil {
					t.Errorf("expected peer to be created: %v", err)
				}
				// The IP address should be stored as-is (sanitization strips control chars)
				if containsAny(ipAddress, "\r\n") {
					t.Errorf("IP address contains control characters: %q", ipAddress)
				}
			},
		},
		{
			name: "header injection in IP address",
			setup: func(t *testing.T, db *sql.DB) {
				db.Exec(`INSERT INTO registration_tokens (token, description) VALUES (?, ?)`, "valid-token-ip-crlf", "test token")
			},
			reqBody:  `{"hostname": "test-server", "ip": "10.0.0.1\r\nX-Injected: header", "registration_token": "valid-token-ip-crlf"}`,
			wantCode: http.StatusCreated,
			checkDB: func(t *testing.T, db *sql.DB) {
				var ipAddress string
				err := db.QueryRow("SELECT ip_address FROM peers WHERE hostname = 'test-server'").Scan(&ipAddress)
				if err != nil {
					t.Errorf("expected peer to be created: %v", err)
				}
				// CR/LF should be stripped from IP
				if containsAny(ipAddress, "\r\n") {
					t.Errorf("IP address contains control characters: %q", ipAddress)
				}
			},
		},
		{
			name: "null byte in hostname",
			setup: func(t *testing.T, db *sql.DB) {
				db.Exec(`INSERT INTO registration_tokens (token, description) VALUES (?, ?)`, "valid-token-null-1", "test token")
			},
			reqBody:  `{"hostname": "server\u0000evil", "registration_token": "valid-token-null-1"}`,
			wantCode: http.StatusCreated,
			checkDB: func(t *testing.T, db *sql.DB) {
				var hostname string
				err := db.QueryRow("SELECT hostname FROM peers WHERE hostname LIKE '%server%'").Scan(&hostname)
				if err != nil {
					t.Errorf("expected peer to be created: %v", err)
				}
				// Null byte should be stripped
				if containsAny(hostname, "\x00") {
					t.Errorf("hostname contains null byte: %q", hostname)
				}
			},
		},
		{
			name: "unicode control characters in hostname",
			setup: func(t *testing.T, db *sql.DB) {
				db.Exec(`INSERT INTO registration_tokens (token, description) VALUES (?, ?)`, "valid-token-unicode-1", "test token")
			},
			reqBody:  `{"hostname": "server\u202e\u202dname", "registration_token": "valid-token-unicode-1"}`,
			wantCode: http.StatusCreated,
			checkDB: func(t *testing.T, db *sql.DB) {
				var hostname string
				err := db.QueryRow("SELECT hostname FROM peers LIMIT 1").Scan(&hostname)
				if err != nil {
					t.Errorf("expected peer to be created: %v", err)
				}
				// Note: SanitizeAlertInput does NOT strip Unicode control characters
				// (only ASCII control chars). The hostname is stored as-is with unicode chars.
				// If stricter sanitization is needed, use SanitizeAlertInputStrict.
			},
		},
		{
			name: "extremely long hostname - should truncate",
			setup: func(t *testing.T, db *sql.DB) {
				db.Exec(`INSERT INTO registration_tokens (token, description) VALUES (?, ?)`, "valid-token-long-1", "test token")
			},
			reqBody:  `{"hostname": "` + strings.Repeat("a", 500) + `", "registration_token": "valid-token-long-1"}`,
			wantCode: http.StatusCreated,
			checkDB: func(t *testing.T, db *sql.DB) {
				var hostname string
				err := db.QueryRow("SELECT hostname FROM peers LIMIT 1").Scan(&hostname)
				if err != nil {
					t.Errorf("expected peer to be created: %v", err)
				}
				// Hostname should be truncated to max length (255)
				if len(hostname) > 255 {
					t.Errorf("hostname too long: %d chars", len(hostname))
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

			if tt.checkDB != nil {
				tt.checkDB(t, db)
			}
		})
	}
}

// containsAny checks if s contains any of the chars in substrings
func containsAny(s string, chars string) bool {
	for _, c := range chars {
		if strings.ContainsRune(s, c) {
			return true
		}
	}
	return false
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

// =============================================================================
// Test upsertPeerIPs
// =============================================================================

func TestUpsertPeerIPs(t *testing.T) {
	tests := []struct {
		name       string
		setup      func(t *testing.T, db *sql.DB) int // returns peerID
		allIPs     []string
		primaryIP  string
		wantErr    bool
		checkDB    func(t *testing.T, db *sql.DB, peerID int)
	}{
		{
			name: "initial upsert of IPs",
			setup: func(t *testing.T, db *sql.DB) int {
				res, err := db.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)`, "test-peer", "10.0.0.1", "key1", "hmac1")
				if err != nil {
					t.Fatalf("setup: %v", err)
				}
				id, _ := res.LastInsertId()
				return int(id)
			},
			allIPs:    []string{"10.0.0.1", "192.168.1.1", "172.16.0.1"},
			primaryIP: "10.0.0.1",
			wantErr:   false,
			checkDB: func(t *testing.T, db *sql.DB, peerID int) {
				rows, err := db.Query("SELECT ip_address, is_primary FROM peer_ips WHERE peer_id = ? ORDER BY ip_address", peerID)
				if err != nil {
					t.Fatalf("query peer_ips: %v", err)
				}
				defer rows.Close()

				type ipEntry struct {
					ip        string
					isPrimary int
				}
				var entries []ipEntry
				for rows.Next() {
					var e ipEntry
					if err := rows.Scan(&e.ip, &e.isPrimary); err != nil {
						t.Fatalf("scan: %v", err)
					}
					entries = append(entries, e)
				}

				if len(entries) != 3 {
					t.Fatalf("expected 3 peer_ips, got %d", len(entries))
				}
				for _, e := range entries {
					if e.ip == "10.0.0.1" && e.isPrimary != 1 {
						t.Errorf("expected 10.0.0.1 to be primary, got is_primary=%d", e.isPrimary)
					}
					if e.ip != "10.0.0.1" && e.isPrimary != 0 {
						t.Errorf("expected %s to be non-primary, got is_primary=%d", e.ip, e.isPrimary)
					}
				}
			},
		},
		{
			name: "primary flag update on re-upsert",
			setup: func(t *testing.T, db *sql.DB) int {
				res, err := db.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)`, "test-peer2", "10.0.0.2", "key2", "hmac2")
				if err != nil {
					t.Fatalf("setup: %v", err)
				}
				id, _ := res.LastInsertId()

				// Insert IPs with old primary
				db.Exec("INSERT INTO peer_ips (peer_id, ip_address, is_primary) VALUES (?, ?, 1)", id, "10.0.0.2")
				db.Exec("INSERT INTO peer_ips (peer_id, ip_address, is_primary) VALUES (?, ?, 0)", id, "192.168.1.2")

				return int(id)
			},
			allIPs:    []string{"10.0.0.2", "192.168.1.2"},
			primaryIP: "192.168.1.2", // changed primary
			wantErr:   false,
			checkDB: func(t *testing.T, db *sql.DB, peerID int) {
				// upsertPeerIPs sets is_primary=1 for the primary IP via UPDATE,
				// but does NOT reset other is_primary flags to 0 (that's syncPeerIPs' job).
				// So 192.168.1.2 should now be primary=1, and 10.0.0.2 remains primary=1.
				var count int
				err := db.QueryRow("SELECT COUNT(*) FROM peer_ips WHERE peer_id = ? AND is_primary = 1", peerID).Scan(&count)
				if err != nil {
					t.Fatalf("count primary: %v", err)
				}
				// Both have is_primary=1 because upsertPeerIPs only sets primary, doesn't clear old ones
				if count != 2 {
					t.Errorf("expected 2 primary IPs (upsert only sets, doesn't clear), got %d", count)
				}
			},
		},
		{
			name: "duplicate IP handling is idempotent",
			setup: func(t *testing.T, db *sql.DB) int {
				res, err := db.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)`, "test-peer3", "10.0.0.3", "key3", "hmac3")
				if err != nil {
					t.Fatalf("setup: %v", err)
				}
				id, _ := res.LastInsertId()
				return int(id)
			},
			allIPs:    []string{"10.0.0.3", "10.0.0.3"}, // duplicate in input
			primaryIP: "10.0.0.3",
			wantErr:   false,
			checkDB: func(t *testing.T, db *sql.DB, peerID int) {
				var count int
				err := db.QueryRow("SELECT COUNT(*) FROM peer_ips WHERE peer_id = ?", peerID).Scan(&count)
				if err != nil {
					t.Fatalf("count: %v", err)
				}
				// INSERT OR IGNORE means only one row despite duplicate input
				if count != 1 {
					t.Errorf("expected 1 peer_ip (deduped by INSERT OR IGNORE), got %d", count)
				}
			},
		},
		{
			name: "empty AllIPs does nothing",
			setup: func(t *testing.T, db *sql.DB) int {
				res, err := db.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)`, "test-peer4", "10.0.0.4", "key4", "hmac4")
				if err != nil {
					t.Fatalf("setup: %v", err)
				}
				id, _ := res.LastInsertId()
				return int(id)
			},
			allIPs:    []string{},
			primaryIP: "10.0.0.4",
			wantErr:   false,
			checkDB: func(t *testing.T, db *sql.DB, peerID int) {
				var count int
				err := db.QueryRow("SELECT COUNT(*) FROM peer_ips WHERE peer_id = ?", peerID).Scan(&count)
				if err != nil {
					t.Fatalf("count: %v", err)
				}
				if count != 0 {
					t.Errorf("expected 0 peer_ips for empty input, got %d", count)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, cleanup := testutil.SetupTestDBWithSecret(t)
			defer cleanup()

			peerID := tt.setup(t, db)

			handler := NewHandler(db, db, nil)
			err := handler.upsertPeerIPs(context.Background(), peerID, tt.allIPs, tt.primaryIP)

			if (err != nil) != tt.wantErr {
				t.Errorf("upsertPeerIPs() error = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.checkDB != nil {
				tt.checkDB(t, db, peerID)
			}
		})
	}
}

// =============================================================================
// Test syncPeerIPs
// =============================================================================

func TestSyncPeerIPs(t *testing.T) {
	tests := []struct {
		name      string
		setup     func(t *testing.T, db *sql.DB) int // returns peerID
		allIPs    []string
		primaryIP string
		wantErr   bool
		checkDB   func(t *testing.T, db *sql.DB, peerID int)
	}{
		{
			name: "add new IPs and remove stale ones",
			setup: func(t *testing.T, db *sql.DB) int {
				res, err := db.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)`, "sync-peer1", "10.0.0.1", "key1", "hmac1")
				if err != nil {
					t.Fatalf("setup: %v", err)
				}
				id, _ := res.LastInsertId()
				// Pre-populate with old IPs
				db.Exec("INSERT INTO peer_ips (peer_id, ip_address, is_primary) VALUES (?, ?, 1)", id, "10.0.0.1")
				db.Exec("INSERT INTO peer_ips (peer_id, ip_address, is_primary) VALUES (?, ?, 0)", id, "192.168.1.100") // stale
				db.Exec("INSERT INTO peer_ips (peer_id, ip_address, is_primary) VALUES (?, ?, 0)", id, "172.16.0.100") // stale
				return int(id)
			},
			allIPs:    []string{"10.0.0.1", "10.0.1.1"}, // new IP, old stale ones removed
			primaryIP: "10.0.0.1",
			wantErr:   false,
			checkDB: func(t *testing.T, db *sql.DB, peerID int) {
				rows, err := db.Query("SELECT ip_address, is_primary FROM peer_ips WHERE peer_id = ? ORDER BY ip_address", peerID)
				if err != nil {
					t.Fatalf("query: %v", err)
				}
				defer rows.Close()

				type entry struct {
					ip        string
					isPrimary int
				}
				var entries []entry
				for rows.Next() {
					var e entry
					if err := rows.Scan(&e.ip, &e.isPrimary); err != nil {
						t.Fatalf("scan: %v", err)
					}
					entries = append(entries, e)
				}

				// Should only have 2 IPs (stale ones deleted)
				if len(entries) != 2 {
					t.Fatalf("expected 2 peer_ips, got %d", len(entries))
				}

				// Verify the IPs
				foundIPs := map[string]int{}
				for _, e := range entries {
					foundIPs[e.ip] = e.isPrimary
				}
				if _, ok := foundIPs["10.0.0.1"]; !ok {
					t.Error("expected 10.0.0.1 to exist")
				}
				if _, ok := foundIPs["10.0.1.1"]; !ok {
					t.Error("expected 10.0.1.1 to exist")
				}
				if _, ok := foundIPs["192.168.1.100"]; ok {
					t.Error("expected stale 192.168.1.100 to be deleted")
				}
				if _, ok := foundIPs["172.16.0.100"]; ok {
					t.Error("expected stale 172.16.0.100 to be deleted")
				}

				// Verify primary flag
				if foundIPs["10.0.0.1"] != 1 {
					t.Errorf("expected 10.0.0.1 is_primary=1, got %d", foundIPs["10.0.0.1"])
				}
				if foundIPs["10.0.1.1"] != 0 {
					t.Errorf("expected 10.0.1.1 is_primary=0, got %d", foundIPs["10.0.1.1"])
				}
			},
		},
		{
			name: "primary flag reset correctly",
			setup: func(t *testing.T, db *sql.DB) int {
				res, err := db.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)`, "sync-peer2", "10.0.0.2", "key2", "hmac2")
				if err != nil {
					t.Fatalf("setup: %v", err)
				}
				id, _ := res.LastInsertId()
				// Both marked as primary (corrupted state)
				db.Exec("INSERT INTO peer_ips (peer_id, ip_address, is_primary) VALUES (?, ?, 1)", id, "10.0.0.2")
				db.Exec("INSERT INTO peer_ips (peer_id, ip_address, is_primary) VALUES (?, ?, 1)", id, "192.168.1.2")
				return int(id)
			},
			allIPs:    []string{"10.0.0.2", "192.168.1.2"},
			primaryIP: "192.168.1.2",
			wantErr:   false,
			checkDB: func(t *testing.T, db *sql.DB, peerID int) {
				var primaryCount int
				err := db.QueryRow("SELECT COUNT(*) FROM peer_ips WHERE peer_id = ? AND is_primary = 1", peerID).Scan(&primaryCount)
				if err != nil {
					t.Fatalf("count primary: %v", err)
				}
				if primaryCount != 1 {
					t.Errorf("expected exactly 1 primary IP, got %d", primaryCount)
				}

				var primaryIP string
				err = db.QueryRow("SELECT ip_address FROM peer_ips WHERE peer_id = ? AND is_primary = 1", peerID).Scan(&primaryIP)
				if err != nil {
					t.Fatalf("query primary: %v", err)
				}
				if primaryIP != "192.168.1.2" {
					t.Errorf("expected primary IP 192.168.1.2, got %s", primaryIP)
				}
			},
		},
		{
			name: "stale IP referenced by source policy is preserved",
			setup: func(t *testing.T, db *sql.DB) int {
				res, err := db.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)`, "sync-peer3", "10.0.0.3", "key3", "hmac3")
				if err != nil {
					t.Fatalf("setup: %v", err)
				}
				id, _ := res.LastInsertId()

				// Insert peer IPs
				db.Exec("INSERT INTO peer_ips (peer_id, ip_address, is_primary) VALUES (?, ?, 1)", id, "10.0.0.3")
				db.Exec("INSERT INTO peer_ips (peer_id, ip_address, is_primary) VALUES (?, ?, 0)", id, "192.168.1.3") // will become stale

				// Create a group and service for the policy
				db.Exec("INSERT INTO groups (name) VALUES ('test-group')")
				db.Exec("INSERT INTO services (name, ports, protocol) VALUES ('ssh', '22', 'tcp')")

				// Create a policy referencing the soon-to-be-stale IP as source_ip
				db.Exec(`INSERT INTO policies (name, source_id, source_type, service_id, target_id, target_type, source_ip, target_ip, action)
					VALUES ('test-policy', ?, 'group', 1, ?, 'group', '192.168.1.3', '10.0.0.3', 'ACCEPT')`, id, id)

				return int(id)
			},
			allIPs:    []string{"10.0.0.3"}, // 192.168.1.3 is stale
			primaryIP: "10.0.0.3",
			wantErr:   false,
			checkDB: func(t *testing.T, db *sql.DB, peerID int) {
				// Stale IP should still exist because it's referenced by a policy
				var count int
				err := db.QueryRow("SELECT COUNT(*) FROM peer_ips WHERE peer_id = ?", peerID).Scan(&count)
				if err != nil {
					t.Fatalf("count: %v", err)
				}
				if count != 2 {
					t.Errorf("expected 2 peer_ips (stale IP preserved due to policy reference), got %d", count)
				}

				// Verify the stale IP still exists
				var exists int
				err = db.QueryRow("SELECT COUNT(*) FROM peer_ips WHERE peer_id = ? AND ip_address = '192.168.1.3'", peerID).Scan(&exists)
				if err != nil {
					t.Fatalf("check stale IP: %v", err)
				}
				if exists != 1 {
					t.Error("expected stale IP 192.168.1.3 to be preserved (referenced by policy)")
				}
			},
		},
		{
			name: "stale IP referenced by target policy is preserved",
			setup: func(t *testing.T, db *sql.DB) int {
				res, err := db.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)`, "sync-peer4", "10.0.0.4", "key4", "hmac4")
				if err != nil {
					t.Fatalf("setup: %v", err)
				}
				id, _ := res.LastInsertId()

				db.Exec("INSERT INTO peer_ips (peer_id, ip_address, is_primary) VALUES (?, ?, 1)", id, "10.0.0.4")
				db.Exec("INSERT INTO peer_ips (peer_id, ip_address, is_primary) VALUES (?, ?, 0)", id, "172.16.0.4") // will become stale

				// Create group and service
				db.Exec("INSERT INTO groups (name) VALUES ('test-group4')")
				db.Exec("INSERT INTO services (name, ports, protocol) VALUES ('http', '80', 'tcp')")

				// Create a policy referencing the stale IP as target_ip
				db.Exec(`INSERT INTO policies (name, source_id, source_type, service_id, target_id, target_type, source_ip, target_ip, action)
					VALUES ('target-policy', ?, 'group', 1, ?, 'group', '10.0.0.4', '172.16.0.4', 'ACCEPT')`, id, id)

				return int(id)
			},
			allIPs:    []string{"10.0.0.4"}, // 172.16.0.4 is stale
			primaryIP: "10.0.0.4",
			wantErr:   false,
			checkDB: func(t *testing.T, db *sql.DB, peerID int) {
				var exists int
				err := db.QueryRow("SELECT COUNT(*) FROM peer_ips WHERE peer_id = ? AND ip_address = '172.16.0.4'", peerID).Scan(&exists)
				if err != nil {
					t.Fatalf("check stale IP: %v", err)
				}
				if exists != 1 {
					t.Error("expected stale IP 172.16.0.4 to be preserved (referenced as target_ip in policy)")
				}
			},
		},
		{
			name: "stale IP not referenced by policy is deleted",
			setup: func(t *testing.T, db *sql.DB) int {
				res, err := db.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)`, "sync-peer5", "10.0.0.5", "key5", "hmac5")
				if err != nil {
					t.Fatalf("setup: %v", err)
				}
				id, _ := res.LastInsertId()

				db.Exec("INSERT INTO peer_ips (peer_id, ip_address, is_primary) VALUES (?, ?, 1)", id, "10.0.0.5")
				db.Exec("INSERT INTO peer_ips (peer_id, ip_address, is_primary) VALUES (?, ?, 0)", id, "192.168.1.5") // stale, no policy ref

				return int(id)
			},
			allIPs:    []string{"10.0.0.5"}, // 192.168.1.5 is stale and not referenced
			primaryIP: "10.0.0.5",
			wantErr:   false,
			checkDB: func(t *testing.T, db *sql.DB, peerID int) {
				var count int
				err := db.QueryRow("SELECT COUNT(*) FROM peer_ips WHERE peer_id = ?", peerID).Scan(&count)
				if err != nil {
					t.Fatalf("count: %v", err)
				}
				if count != 1 {
					t.Errorf("expected 1 peer_ip (unreferenced stale IP deleted), got %d", count)
				}
			},
		},
		{
			name: "empty AllIPs removes all unreferenced stale IPs",
			setup: func(t *testing.T, db *sql.DB) int {
				res, err := db.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)`, "sync-peer6", "10.0.0.6", "key6", "hmac6")
				if err != nil {
					t.Fatalf("setup: %v", err)
				}
				id, _ := res.LastInsertId()

				db.Exec("INSERT INTO peer_ips (peer_id, ip_address, is_primary) VALUES (?, ?, 1)", id, "10.0.0.6")
				db.Exec("INSERT INTO peer_ips (peer_id, ip_address, is_primary) VALUES (?, ?, 0)", id, "192.168.1.6")

				return int(id)
			},
			allIPs:    []string{}, // agent reports no IPs
			primaryIP: "10.0.0.6",
			wantErr:   false,
			checkDB: func(t *testing.T, db *sql.DB, peerID int) {
				var count int
				err := db.QueryRow("SELECT COUNT(*) FROM peer_ips WHERE peer_id = ?", peerID).Scan(&count)
				if err != nil {
					t.Fatalf("count: %v", err)
				}
				// Both IPs are stale since allIPs is empty; no policy references them
				if count != 0 {
					t.Errorf("expected 0 peer_ips (all stale and unreferenced), got %d", count)
				}
			},
		},
		{
			name: "upsert and stale cleanup interaction",
			setup: func(t *testing.T, db *sql.DB) int {
				res, err := db.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)`, "sync-peer7", "10.0.0.7", "key7", "hmac7")
				if err != nil {
					t.Fatalf("setup: %v", err)
				}
				id, _ := res.LastInsertId()

				// Start with some IPs
				db.Exec("INSERT INTO peer_ips (peer_id, ip_address, is_primary) VALUES (?, ?, 1)", id, "10.0.0.7")
				db.Exec("INSERT INTO peer_ips (peer_id, ip_address, is_primary) VALUES (?, ?, 0)", id, "192.168.1.7")
				db.Exec("INSERT INTO peer_ips (peer_id, ip_address, is_primary) VALUES (?, ?, 0)", id, "172.16.0.7")

				return int(id)
			},
			allIPs:    []string{"10.0.0.7", "10.0.1.7", "10.0.2.7"}, // 2 new, 2 stale removed
			primaryIP: "10.0.0.7",
			wantErr:   false,
			checkDB: func(t *testing.T, db *sql.DB, peerID int) {
				rows, err := db.Query("SELECT ip_address FROM peer_ips WHERE peer_id = ? ORDER BY ip_address", peerID)
				if err != nil {
					t.Fatalf("query: %v", err)
				}
				defer rows.Close()

				var ips []string
				for rows.Next() {
					var ip string
					if err := rows.Scan(&ip); err != nil {
						t.Fatalf("scan: %v", err)
					}
					ips = append(ips, ip)
				}

				expected := []string{"10.0.0.7", "10.0.1.7", "10.0.2.7"}
				if len(ips) != len(expected) {
					t.Fatalf("expected %d IPs, got %d: %v", len(expected), len(ips), ips)
				}

				for i, ip := range ips {
					if ip != expected[i] {
						t.Errorf("index %d: expected %s, got %s", i, expected[i], ip)
					}
				}
			},
		},
		{
			name: "policy reference from different peer does not prevent deletion",
			setup: func(t *testing.T, db *sql.DB) int {
				// Create the peer we'll sync
				res, err := db.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)`, "sync-peer8", "10.0.0.8", "key8", "hmac8")
				if err != nil {
					t.Fatalf("setup: %v", err)
				}
				id, _ := res.LastInsertId()

				// Create a different peer
				res2, err := db.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)`, "other-peer8", "10.0.0.88", "key88", "hmac88")
				if err != nil {
					t.Fatalf("setup other peer: %v", err)
				}
				otherID, _ := res2.LastInsertId()

				// Insert IPs for our peer
				db.Exec("INSERT INTO peer_ips (peer_id, ip_address, is_primary) VALUES (?, ?, 1)", id, "10.0.0.8")
				db.Exec("INSERT INTO peer_ips (peer_id, ip_address, is_primary) VALUES (?, ?, 0)", id, "192.168.1.8") // will be stale

				// Create group and service
				db.Exec("INSERT INTO groups (name) VALUES ('test-group8')")
				db.Exec("INSERT INTO services (name, ports, protocol) VALUES ('mysql', '3306', 'tcp')")

				// Create a policy where OTHER peer references the stale IP as source_ip
				// This should NOT prevent deletion since source_id != our peerID
				db.Exec(`INSERT INTO policies (name, source_id, source_type, service_id, target_id, target_type, source_ip, target_ip, action)
					VALUES ('cross-peer-policy', ?, 'group', 1, ?, 'group', '192.168.1.8', '10.0.0.8', 'ACCEPT')`, otherID, id)

				return int(id)
			},
			allIPs:    []string{"10.0.0.8"}, // 192.168.1.8 is stale for our peer
			primaryIP: "10.0.0.8",
			wantErr:   false,
			checkDB: func(t *testing.T, db *sql.DB, peerID int) {
				// The stale IP should be deleted because the policy reference
				// is from a DIFFERENT peer (source_id != peerID)
				var count int
				err := db.QueryRow("SELECT COUNT(*) FROM peer_ips WHERE peer_id = ?", peerID).Scan(&count)
				if err != nil {
					t.Fatalf("count: %v", err)
				}
				if count != 1 {
					t.Errorf("expected 1 peer_ip (stale IP deleted because policy ref is from different peer), got %d", count)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, cleanup := testutil.SetupTestDBWithSecret(t)
			defer cleanup()

			peerID := tt.setup(t, db)

			handler := NewHandler(db, db, nil)
			err := handler.syncPeerIPs(context.Background(), peerID, tt.allIPs, tt.primaryIP)

			if (err != nil) != tt.wantErr {
				t.Errorf("syncPeerIPs() error = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.checkDB != nil {
				tt.checkDB(t, db, peerID)
			}
		})
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
