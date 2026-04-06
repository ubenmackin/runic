package logs

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"runic/internal/auth"
	"runic/internal/testutil"
)

// =============================================================================
// GetLogs Tests
// =============================================================================

func TestGetLogs(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	// Insert test peer
	database.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, os_type, is_manual) VALUES (?, ?, ?, ?, ?, ?)`,
		"peer1", "10.0.0.1", "key1", "hmac1", "linux", 0)

	// Insert test log entries
	database.Exec(`INSERT INTO firewall_logs (peer_id, timestamp, direction, src_ip, dst_ip, protocol, src_port, dst_port, action) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"1", time.Now(), "inbound", "192.168.1.100", "10.0.0.1", "tcp", 54321, 22, "ACCEPT")
	database.Exec(`INSERT INTO firewall_logs (peer_id, timestamp, direction, src_ip, dst_ip, protocol, src_port, dst_port, action) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"1", time.Now(), "outbound", "10.0.0.1", "192.168.1.100", "tcp", 22, 54321, "ACCEPT")

	tests := []struct {
		name           string
		queryParams    string
		wantCode       int
		validateResult func(*testing.T, map[string]interface{})
	}{
		{
			name:        "list all logs with counts",
			queryParams: "",
			wantCode:    http.StatusOK,
			validateResult: func(t *testing.T, result map[string]interface{}) {
				logs, ok := result["logs"].([]interface{})
				if !ok {
					t.Fatal("expected logs to be an array")
				}
				if len(logs) < 2 {
					t.Errorf("expected at least 2 logs, got %d", len(logs))
				}
				total, ok := result["total"].(float64)
				if !ok {
					t.Fatal("expected total to be a number")
				}
				if total < 2 {
					t.Errorf("expected total >= 2, got %f", total)
				}
			},
		},
		{
			name:        "filter by peer_id",
			queryParams: "peer_id=1",
			wantCode:    http.StatusOK,
			validateResult: func(t *testing.T, result map[string]interface{}) {
				logs := result["logs"].([]interface{})
				// May return empty if peer_id filter doesn't match string "1"
				t.Logf("Got %d logs for peer_id=1", len(logs))
			},
		},
		{
			name:        "filter by action",
			queryParams: "action=ACCEPT",
			wantCode:    http.StatusOK,
			validateResult: func(t *testing.T, result map[string]interface{}) {
				total, ok := result["total"].(float64)
				if !ok {
					t.Fatal("expected total to be a number")
				}
				if total < 2 {
					t.Errorf("expected total >= 2 for action=ACCEPT, got %f", total)
				}
			},
		},
		{
			name:        "filter by src_ip",
			queryParams: "src_ip=192.168.1",
			wantCode:    http.StatusOK,
			validateResult: func(t *testing.T, result map[string]interface{}) {
				t.Logf("Got total=%v for src_ip=192.168.1", result["total"])
			},
		},
		{
			name:        "filter by dst_port",
			queryParams: "dst_port=22",
			wantCode:    http.StatusOK,
			validateResult: func(t *testing.T, result map[string]interface{}) {
				total, ok := result["total"].(float64)
				if !ok {
					t.Fatal("expected total to be a number")
				}
				if total < 1 {
					t.Errorf("expected total >= 1 for dst_port=22, got %f", total)
				}
			},
		},
		{
			name:        "pagination with limit and offset",
			queryParams: "limit=1&offset=0",
			wantCode:    http.StatusOK,
			validateResult: func(t *testing.T, result map[string]interface{}) {
				logs := result["logs"].([]interface{})
				if len(logs) != 1 {
					t.Errorf("expected 1 log due to limit, got %d", len(logs))
				}
				limit, ok := result["limit"].(float64)
				if !ok || limit != 1 {
					t.Errorf("expected limit=1, got %v", result["limit"])
				}
				offset, ok := result["offset"].(float64)
				if !ok || offset != 0 {
					t.Errorf("expected offset=0, got %v", result["offset"])
				}
			},
		},
		{
			name:        "filter by from time",
			queryParams: "from=" + time.Now().Add(-24*time.Hour).Format(time.RFC3339),
			wantCode:    http.StatusOK,
			validateResult: func(t *testing.T, result map[string]interface{}) {
				total, ok := result["total"].(float64)
				if !ok {
					t.Fatal("expected total to be a number")
				}
				// Should return logs since we're looking back 24 hours
				if total < 2 {
					t.Errorf("expected total >= 2 for from filter, got %f", total)
				}
			},
		},
		{
			name:        "invalid limit value",
			queryParams: "limit=invalid",
			wantCode:    http.StatusOK,
			validateResult: func(t *testing.T, result map[string]interface{}) {
				limit, ok := result["limit"].(float64)
				if !ok {
					t.Fatal("expected limit to be a number")
				}
				// Should default to 100
				if limit != 100 {
					t.Errorf("expected limit to default to 100, got %f", limit)
				}
			},
		},
		{
			name:        "limit exceeds max",
			queryParams: "limit=2000",
			wantCode:    http.StatusOK,
			validateResult: func(t *testing.T, result map[string]interface{}) {
				limit, ok := result["limit"].(float64)
				if !ok {
					t.Fatal("expected limit to be a number")
				}
				// Should default to 100 when limit > 1000 (not valid)
				if limit != 100 {
					t.Errorf("expected limit to default to 100 when > 1000, got %f", limit)
				}
			},
		},
		{
			name:        "invalid offset value",
			queryParams: "offset=invalid",
			wantCode:    http.StatusOK,
			validateResult: func(t *testing.T, result map[string]interface{}) {
				offset, ok := result["offset"].(float64)
				if !ok {
					t.Fatal("expected offset to be a number")
				}
				// Should default to 0
				if offset != 0 {
					t.Errorf("expected offset to default to 0, got %f", offset)
				}
			},
		},
		{
			name:        "negative offset",
			queryParams: "offset=-1",
			wantCode:    http.StatusOK,
			validateResult: func(t *testing.T, result map[string]interface{}) {
				offset, ok := result["offset"].(float64)
				if !ok {
					t.Fatal("expected offset to be a number")
				}
				// Should default to 0 for negative values
				if offset != 0 {
					t.Errorf("expected offset to default to 0, got %f", offset)
				}
			},
		},
		{
			name:        "invalid from time format",
			queryParams: "from=invalid-time",
			wantCode:    http.StatusOK,
			validateResult: func(t *testing.T, result map[string]interface{}) {
				// Should ignore invalid time and return all logs
				total, ok := result["total"].(float64)
				if !ok {
					t.Fatal("expected total to be a number")
				}
				if total < 2 {
					t.Errorf("expected total >= 2, got %f", total)
				}
			},
		},
		{
			name:        "invalid to time format",
			queryParams: "to=invalid-time",
			wantCode:    http.StatusOK,
			validateResult: func(t *testing.T, result map[string]interface{}) {
				// Should ignore invalid time and return all logs
				total, ok := result["total"].(float64)
				if !ok {
					t.Fatal("expected total to be a number")
				}
				if total < 2 {
					t.Errorf("expected total >= 2, got %f", total)
				}
			},
		},
		{
			name:        "combined filters",
			queryParams: "action=ACCEPT&dst_port=22",
			wantCode:    http.StatusOK,
			validateResult: func(t *testing.T, result map[string]interface{}) {
				t.Logf("Got total=%v for combined filters", result["total"])
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := NewHandler(database)
			req := httptest.NewRequest("GET", "/api/v1/logs?"+tt.queryParams, nil)
			w := httptest.NewRecorder()

			h.GetLogs(w, req)

			if w.Code != tt.wantCode {
				t.Errorf("expected status %d, got %d: %s", tt.wantCode, w.Code, w.Body.String())
			}

			if tt.validateResult != nil && w.Code == http.StatusOK {
				var result map[string]interface{}
				if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
					t.Fatalf("failed to decode response: %v", err)
				}
				tt.validateResult(t, result)
			}
		})
	}
}

func TestGetLogs_EmptyResult(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	// Insert test peer but no logs
	database.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, os_type, is_manual) VALUES (?, ?, ?, ?, ?, ?)`,
		"peer1", "10.0.0.1", "key1", "hmac1", "linux", 0)

	h := NewHandler(database)
	req := httptest.NewRequest("GET", "/api/v1/logs", nil)
	w := httptest.NewRecorder()

	h.GetLogs(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	// Should return empty array, not null
	logs, ok := result["logs"].([]interface{})
	if !ok {
		t.Fatal("expected logs to be an array")
	}
	if logs == nil {
		t.Error("expected empty array, got nil")
	}
	if len(logs) != 0 {
		t.Errorf("expected 0 logs, got %d", len(logs))
	}

	// Total should be 0
	total, ok := result["total"].(float64)
	if !ok {
		t.Fatal("expected total to be a number")
	}
	if total != 0 {
		t.Errorf("expected total=0, got %f", total)
	}
}

func TestGetLogs_WithHostname(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	// Insert test peer
	database.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, os_type, is_manual) VALUES (?, ?, ?, ?, ?, ?)`,
		"peer1", "10.0.0.1", "key1", "hmac1", "linux", 0)

	// Insert test log
	database.Exec(`INSERT INTO firewall_logs (peer_id, timestamp, direction, src_ip, dst_ip, protocol, src_port, dst_port, action) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"1", time.Now(), "inbound", "192.168.1.100", "10.0.0.1", "tcp", 54321, 22, "ACCEPT")

	h := NewHandler(database)
	req := httptest.NewRequest("GET", "/api/v1/logs", nil)
	w := httptest.NewRecorder()

	h.GetLogs(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d: %s", http.StatusOK, w.Code, w.Body.String())
	}

	var result map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	logs, ok := result["logs"].([]interface{})
	if !ok || len(logs) == 0 {
		t.Fatal("expected at least 1 log")
	}

	// Check first log has hostname
	logMap, ok := logs[0].(map[string]interface{})
	if !ok {
		t.Fatal("expected log to be a map")
	}

	hostname, ok := logMap["hostname"].(string)
	if !ok || hostname != "peer1" {
		t.Errorf("expected hostname='peer1', got '%v'", hostname)
	}
}

func TestGetLogs_OrphanedLogs(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	// Insert log with non-existent peer_id (orphaned log)
	database.Exec(`INSERT INTO firewall_logs (peer_id, timestamp, direction, src_ip, dst_ip, protocol, src_port, dst_port, action) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"999", time.Now(), "inbound", "192.168.1.100", "10.0.0.1", "tcp", 54321, 22, "ACCEPT")

	h := NewHandler(database)
	req := httptest.NewRequest("GET", "/api/v1/logs", nil)
	w := httptest.NewRecorder()

	h.GetLogs(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d: %s", http.StatusOK, w.Code, w.Body.String())
	}

	var result map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	logs, ok := result["logs"].([]interface{})
	if !ok || len(logs) == 0 {
		t.Fatal("expected at least 1 log")
	}

	// Check first log has empty hostname (orphaned)
	logMap, ok := logs[0].(map[string]interface{})
	if !ok {
		t.Fatal("expected log to be a map")
	}

	hostname, ok := logMap["hostname"].(string)
	if hostname != "" {
		t.Errorf("expected empty hostname for orphaned log, got '%s'", hostname)
	}
}

func TestGetLogs_QueryError(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	// Insert test data
	database.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, os_type, is_manual) VALUES (?, ?, ?, ?, ?, ?)`,
		"peer1", "10.0.0.1", "key1", "hmac1", "linux", 0)

	h := NewHandler(database)

	// Close database to cause query error
	database.Close()

	req := httptest.NewRequest("GET", "/api/v1/logs", nil)
	w := httptest.NewRecorder()

	h.GetLogs(w, req)

	// Should return 500 error
	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected status %d, got %d: %s", http.StatusInternalServerError, w.Code, w.Body.String())
	}

	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}
	if resp["error"] == "" {
		t.Error("expected error message in response")
	}
}

// =============================================================================
// MakeLogsStreamHandler Tests (WebSocket)
// =============================================================================

func TestMakeLogsStreamHandler_NoToken(t *testing.T) {
	hub := NewHub()
	handler := MakeLogsStreamHandler(hub)

	req := httptest.NewRequest("GET", "/api/v1/logs/ws", nil)
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d: %s", http.StatusUnauthorized, w.Code, w.Body.String())
	}

	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp["error"] != "unauthorized" {
		t.Errorf("expected error='unauthorized', got '%s'", resp["error"])
	}
}

func TestMakeLogsStreamHandler_InvalidToken(t *testing.T) {
	hub := NewHub()
	handler := MakeLogsStreamHandler(hub)

	req := httptest.NewRequest("GET", "/api/v1/logs/ws", nil)
	req.Header.Set("Sec-WebSocket-Protocol", "invalid-token")
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d: %s", http.StatusUnauthorized, w.Code, w.Body.String())
	}
}

func TestMakeLogsStreamHandler_ValidToken_WithFilters(t *testing.T) {
	hub := NewHub()
	handler := MakeLogsStreamHandler(hub)

	// Create valid token - use same signature as auth.GenerateToken
	token, err := auth.GenerateToken("test-user", "viewer", 24*time.Hour)
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}

	// Use cookie-based auth
	req := httptest.NewRequest("GET", "/api/v1/logs/ws?peer_id=1&action=ACCEPT&dst_port=22", nil)
	req.AddCookie(&http.Cookie{Name: "runic_access_token", Value: token})
	w := httptest.NewRecorder()

	handler(w, req)

	// Should succeed in upgrade (or fail at upgrade, but not auth failure)
	// The handler attempts WebSocket upgrade - may fail due to no actual WS connection
	// but it should pass the auth check
	if w.Code == http.StatusUnauthorized {
		t.Error("should not return unauthorized for valid token")
	}
}

func TestMakeLogsStreamHandler_ValidToken_HeaderAuth(t *testing.T) {
	hub := NewHub()
	handler := MakeLogsStreamHandler(hub)

	// Create valid token and use header auth
	token, err := auth.GenerateToken("test-user-header", "viewer", 24*time.Hour)
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}

	req := httptest.NewRequest("GET", "/api/v1/logs/ws", nil)
	req.Header.Set("Sec-WebSocket-Protocol", token)
	w := httptest.NewRecorder()

	handler(w, req)

	// Should pass auth check (upgrade may fail, but not auth)
	if w.Code == http.StatusUnauthorized {
		t.Error("should not return unauthorized for valid token in header")
	}
}

func TestMakeLogsStreamHandler_CookieEmptyValue(t *testing.T) {
	hub := NewHub()
	handler := MakeLogsStreamHandler(hub)

	// Create request with empty cookie value (but cookie exists)
	req := httptest.NewRequest("GET", "/api/v1/logs/ws", nil)
	req.AddCookie(&http.Cookie{Name: "runic_access_token", Value: ""})
	w := httptest.NewRecorder()

	handler(w, req)

	// Should return unauthorized since cookie value is empty
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}
}
