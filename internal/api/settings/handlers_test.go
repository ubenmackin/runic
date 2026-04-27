package settings

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"runic/internal/testutil"

	runicversion "runic/internal/common/version"
)

// =============================================================================
// Test NewHandler
// =============================================================================

func TestNewHandler(t *testing.T) {
	db, cleanup := testutil.SetupTestDBWithSecret(t)
	defer cleanup()

	logsDB, logsCleanup := testutil.SetupTestLogsDB(t)
	defer logsCleanup()

	handler := NewHandler(db, logsDB, "/path/to/logs.db")
	if handler == nil {
		t.Fatal("expected non-nil handler")
	}
	if handler.DB != db {
		t.Error("expected DB to be set")
	}
	if handler.LogsDB != logsDB {
		t.Error("expected LogsDB to be set")
	}
	if handler.logsDBPath != "/path/to/logs.db" {
		t.Errorf("expected logsDBPath '/path/to/logs.db', got '%s'", handler.logsDBPath)
	}
}

// =============================================================================
// Test GetLogSettings
// =============================================================================

func TestGetLogSettings(t *testing.T) {
	tests := []struct {
		name      string
		setup     func(t *testing.T, db *sql.DB)
		wantCode  int
		checkResp func(t *testing.T, w *httptest.ResponseRecorder)
	}{
		{
			name:     "default retention days when not set",
			setup:    nil,
			wantCode: http.StatusOK,
			checkResp: func(t *testing.T, w *httptest.ResponseRecorder) {
				var resp LogSettings
				if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
					t.Fatalf("failed to decode response: %v", err)
				}
				if resp.RetentionDays != 30 {
					t.Errorf("expected retention days 30, got %d", resp.RetentionDays)
				}
				if resp.RetentionLabel != "30 Days" {
					t.Errorf("expected retention label '30 Days', got '%s'", resp.RetentionLabel)
				}
			},
		},
		{
			name: "custom retention days from database",
			setup: func(t *testing.T, db *sql.DB) {
				db.Exec(`INSERT INTO system_config (key, value) VALUES ('log_retention_days', '90')`)
			},
			wantCode: http.StatusOK,
			checkResp: func(t *testing.T, w *httptest.ResponseRecorder) {
				var resp LogSettings
				if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
					t.Fatalf("failed to decode response: %v", err)
				}
				if resp.RetentionDays != 90 {
					t.Errorf("expected retention days 90, got %d", resp.RetentionDays)
				}
				if resp.RetentionLabel != "90 Days" {
					t.Errorf("expected retention label '90 Days', got '%s'", resp.RetentionLabel)
				}
			},
		},
		{
			name: "log count query works correctly",
			setup: func(t *testing.T, db *sql.DB) {
				// Insert test logs into the logs database
			},
			wantCode: http.StatusOK,
			checkResp: func(t *testing.T, w *httptest.ResponseRecorder) {
				var resp LogSettings
				if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
					t.Fatalf("failed to decode response: %v", err)
				}
				// Log count should be 0 since we didn't insert any logs
				if resp.LogCount != 0 {
					t.Errorf("expected log count 0, got %d", resp.LogCount)
				}
			},
		},
		{
			name: "retention label -1 (unlimited)",
			setup: func(t *testing.T, db *sql.DB) {
				db.Exec(`INSERT INTO system_config (key, value) VALUES ('log_retention_days', '-1')`)
			},
			wantCode: http.StatusOK,
			checkResp: func(t *testing.T, w *httptest.ResponseRecorder) {
				var resp LogSettings
				if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
					t.Fatalf("failed to decode response: %v", err)
				}
				if resp.RetentionDays != -1 {
					t.Errorf("expected retention days -1, got %d", resp.RetentionDays)
				}
				if resp.RetentionLabel != "Unlimited" {
					t.Errorf("expected retention label 'Unlimited', got '%s'", resp.RetentionLabel)
				}
			},
		},
		{
			name: "retention label 0 (disabled)",
			setup: func(t *testing.T, db *sql.DB) {
				db.Exec(`INSERT INTO system_config (key, value) VALUES ('log_retention_days', '0')`)
			},
			wantCode: http.StatusOK,
			checkResp: func(t *testing.T, w *httptest.ResponseRecorder) {
				var resp LogSettings
				if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
					t.Fatalf("failed to decode response: %v", err)
				}
				if resp.RetentionDays != 0 {
					t.Errorf("expected retention days 0, got %d", resp.RetentionDays)
				}
				if resp.RetentionLabel != "Disabled" {
					t.Errorf("expected retention label 'Disabled', got '%s'", resp.RetentionLabel)
				}
			},
		},
		{
			name: "retention label 1 day",
			setup: func(t *testing.T, db *sql.DB) {
				db.Exec(`INSERT INTO system_config (key, value) VALUES ('log_retention_days', '1')`)
			},
			wantCode: http.StatusOK,
			checkResp: func(t *testing.T, w *httptest.ResponseRecorder) {
				var resp LogSettings
				if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
					t.Fatalf("failed to decode response: %v", err)
				}
				if resp.RetentionDays != 1 {
					t.Errorf("expected retention days 1, got %d", resp.RetentionDays)
				}
				if resp.RetentionLabel != "1 Day" {
					t.Errorf("expected retention label '1 Day', got '%s'", resp.RetentionLabel)
				}
			},
		},
		{
			name: "retention label 14 days",
			setup: func(t *testing.T, db *sql.DB) {
				db.Exec(`INSERT INTO system_config (key, value) VALUES ('log_retention_days', '14')`)
			},
			wantCode: http.StatusOK,
			checkResp: func(t *testing.T, w *httptest.ResponseRecorder) {
				var resp LogSettings
				if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
					t.Fatalf("failed to decode response: %v", err)
				}
				if resp.RetentionDays != 14 {
					t.Errorf("expected retention days 14, got %d", resp.RetentionDays)
				}
				if resp.RetentionLabel != "14 Days" {
					t.Errorf("expected retention label '14 Days', got '%s'", resp.RetentionLabel)
				}
			},
		},
		{
			name: "retention label 30 days",
			setup: func(t *testing.T, db *sql.DB) {
				db.Exec(`INSERT INTO system_config (key, value) VALUES ('log_retention_days', '30')`)
			},
			wantCode: http.StatusOK,
			checkResp: func(t *testing.T, w *httptest.ResponseRecorder) {
				var resp LogSettings
				if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
					t.Fatalf("failed to decode response: %v", err)
				}
				if resp.RetentionDays != 30 {
					t.Errorf("expected retention days 30, got %d", resp.RetentionDays)
				}
				if resp.RetentionLabel != "30 Days" {
					t.Errorf("expected retention label '30 Days', got '%s'", resp.RetentionLabel)
				}
			},
		},
		{
			name: "retention label 90 days",
			setup: func(t *testing.T, db *sql.DB) {
				db.Exec(`INSERT INTO system_config (key, value) VALUES ('log_retention_days', '90')`)
			},
			wantCode: http.StatusOK,
			checkResp: func(t *testing.T, w *httptest.ResponseRecorder) {
				var resp LogSettings
				if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
					t.Fatalf("failed to decode response: %v", err)
				}
				if resp.RetentionDays != 90 {
					t.Errorf("expected retention days 90, got %d", resp.RetentionDays)
				}
				if resp.RetentionLabel != "90 Days" {
					t.Errorf("expected retention label '90 Days', got '%s'", resp.RetentionLabel)
				}
			},
		},
		{
			name: "retention label 365 days",
			setup: func(t *testing.T, db *sql.DB) {
				db.Exec(`INSERT INTO system_config (key, value) VALUES ('log_retention_days', '365')`)
			},
			wantCode: http.StatusOK,
			checkResp: func(t *testing.T, w *httptest.ResponseRecorder) {
				var resp LogSettings
				if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
					t.Fatalf("failed to decode response: %v", err)
				}
				if resp.RetentionDays != 365 {
					t.Errorf("expected retention days 365, got %d", resp.RetentionDays)
				}
				if resp.RetentionLabel != "365 Days" {
					t.Errorf("expected retention label '365 Days', got '%s'", resp.RetentionLabel)
				}
			},
		},
		{
			name: "retention label custom days",
			setup: func(t *testing.T, db *sql.DB) {
				db.Exec(`INSERT INTO system_config (key, value) VALUES ('log_retention_days', '45')`)
			},
			wantCode: http.StatusOK,
			checkResp: func(t *testing.T, w *httptest.ResponseRecorder) {
				var resp LogSettings
				if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
					t.Fatalf("failed to decode response: %v", err)
				}
				if resp.RetentionDays != 45 {
					t.Errorf("expected retention days 45, got %d", resp.RetentionDays)
				}
				if resp.RetentionLabel != "45 Days" {
					t.Errorf("expected retention label '45 Days', got '%s'", resp.RetentionLabel)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, logsDB, cleanup := testutil.SetupTestDBWithSecretAndLogs(t)
			defer cleanup()

			if tt.setup != nil {
				tt.setup(t, db)
			}

			req := httptest.NewRequest("GET", "/api/v1/settings/logs", nil)
			w := httptest.NewRecorder()

			handler := NewHandler(db, logsDB, "/test/logs.db")
			handler.GetLogSettings(w, req)

			if w.Code != tt.wantCode {
				t.Errorf("expected status %d, got %d: %s", tt.wantCode, w.Code, w.Body.String())
			}

			if tt.checkResp != nil {
				tt.checkResp(t, w)
			}
		})
	}
}

// =============================================================================
// Test UpdateLogSettings
// =============================================================================

func TestUpdateLogSettings(t *testing.T) {
	tests := []struct {
		name      string
		setup     func(t *testing.T, db *sql.DB)
		reqBody   string
		wantCode  int
		checkResp func(t *testing.T, w *httptest.ResponseRecorder, db *sql.DB)
	}{
		{
			name:     "valid retention -1 (unlimited)",
			reqBody:  `{"retention_days": -1}`,
			wantCode: http.StatusOK,
			checkResp: func(t *testing.T, w *httptest.ResponseRecorder, db *sql.DB) {
				var resp map[string]interface{}
				if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
					t.Fatalf("failed to decode response: %v", err)
				}
				if int(resp["retention_days"].(float64)) != -1 {
					t.Errorf("expected retention_days -1, got %v", resp["retention_days"])
				}
				if resp["retention_label"] != "Unlimited" {
					t.Errorf("expected retention_label 'Unlimited', got '%s'", resp["retention_label"])
				}
			},
		},
		{
			name:     "valid retention 0 (disabled)",
			reqBody:  `{"retention_days": 0}`,
			wantCode: http.StatusOK,
			checkResp: func(t *testing.T, w *httptest.ResponseRecorder, db *sql.DB) {
				var resp map[string]interface{}
				if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
					t.Fatalf("failed to decode response: %v", err)
				}
				if int(resp["retention_days"].(float64)) != 0 {
					t.Errorf("expected retention_days 0, got %v", resp["retention_days"])
				}
				if resp["retention_label"] != "Disabled" {
					t.Errorf("expected retention_label 'Disabled', got '%s'", resp["retention_label"])
				}
			},
		},
		{
			name:     "valid retention 1",
			reqBody:  `{"retention_days": 1}`,
			wantCode: http.StatusOK,
			checkResp: func(t *testing.T, w *httptest.ResponseRecorder, db *sql.DB) {
				var resp map[string]interface{}
				if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
					t.Fatalf("failed to decode response: %v", err)
				}
				if int(resp["retention_days"].(float64)) != 1 {
					t.Errorf("expected retention_days 1, got %v", resp["retention_days"])
				}
				if resp["retention_label"] != "1 Day" {
					t.Errorf("expected retention_label '1 Day', got '%s'", resp["retention_label"])
				}
			},
		},
		{
			name:     "valid retention 30",
			reqBody:  `{"retention_days": 30}`,
			wantCode: http.StatusOK,
			checkResp: func(t *testing.T, w *httptest.ResponseRecorder, db *sql.DB) {
				var resp map[string]interface{}
				if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
					t.Fatalf("failed to decode response: %v", err)
				}
				if int(resp["retention_days"].(float64)) != 30 {
					t.Errorf("expected retention_days 30, got %v", resp["retention_days"])
				}
			},
		},
		{
			name:     "valid retention 9999 (max)",
			reqBody:  `{"retention_days": 9999}`,
			wantCode: http.StatusOK,
			checkResp: func(t *testing.T, w *httptest.ResponseRecorder, db *sql.DB) {
				var resp map[string]interface{}
				if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
					t.Fatalf("failed to decode response: %v", err)
				}
				if int(resp["retention_days"].(float64)) != 9999 {
					t.Errorf("expected retention_days 9999, got %v", resp["retention_days"])
				}
				if resp["retention_label"] != "9999 Days" {
					t.Errorf("expected retention_label '9999 Days', got '%s'", resp["retention_label"])
				}
			},
		},
		{
			name:     "invalid retention -2 (below -1)",
			reqBody:  `{"retention_days": -2}`,
			wantCode: http.StatusBadRequest,
		},
		{
			name:     "invalid retention 10000 (above 9999)",
			reqBody:  `{"retention_days": 10000}`,
			wantCode: http.StatusBadRequest,
		},
		{
			name:     "invalid JSON body",
			reqBody:  `{invalid json}`,
			wantCode: http.StatusBadRequest,
		},
		{
			name:     "empty body",
			reqBody:  `{}`,
			wantCode: http.StatusOK,
			checkResp: func(t *testing.T, w *httptest.ResponseRecorder, db *sql.DB) {
				// Default value should be 0
				var resp map[string]interface{}
				if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
					t.Fatalf("failed to decode response: %v", err)
				}
				if int(resp["retention_days"].(float64)) != 0 {
					t.Errorf("expected retention_days 0, got %v", resp["retention_days"])
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

			req := httptest.NewRequest("PUT", "/api/v1/settings/logs", strings.NewReader(tt.reqBody))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			handler := NewHandler(db, nil, "")
			handler.UpdateLogSettings(w, req)

			if w.Code != tt.wantCode {
				t.Errorf("expected status %d, got %d: %s", tt.wantCode, w.Code, w.Body.String())
			}

			if tt.checkResp != nil {
				tt.checkResp(t, w, db)
			}
		})
	}
}

// =============================================================================
// Test ClearAllLogs
// =============================================================================

func TestClearAllLogs(t *testing.T) {
	tests := []struct {
		name      string
		setup     func(t *testing.T, db *sql.DB, logsDB *sql.DB)
		wantCode  int
		checkResp func(t *testing.T, w *httptest.ResponseRecorder)
	}{
		{
			name: "successful deletion with logs",
			setup: func(t *testing.T, db *sql.DB, logsDB *sql.DB) {
				// Insert some test logs using correct schema columns
				logsDB.Exec(`INSERT INTO firewall_logs (peer_id, peer_hostname, timestamp, event_type, source_ip, dest_ip, protocol, source_port, dest_port, action) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, "1", "peer1", time.Now(), "inbound", "192.168.1.1", "10.0.0.1", "tcp", 12345, 22, "ACCEPT")
				logsDB.Exec(`INSERT INTO firewall_logs (peer_id, peer_hostname, timestamp, event_type, source_ip, dest_ip, protocol, source_port, dest_port, action) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, "1", "peer1", time.Now(), "outbound", "10.0.0.1", "8.8.8.8", "udp", 53, 53, "ACCEPT")
			},
			wantCode: http.StatusOK,
			checkResp: func(t *testing.T, w *httptest.ResponseRecorder) {
				var resp map[string]interface{}
				if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
					t.Fatalf("failed to decode response: %v", err)
				}
				if int(resp["deleted"].(float64)) != 2 {
					t.Errorf("expected deleted=2, got %v", resp["deleted"])
				}
			},
		},
		{
			name:     "successful deletion with no logs",
			setup:    nil,
			wantCode: http.StatusOK,
			checkResp: func(t *testing.T, w *httptest.ResponseRecorder) {
				var resp map[string]interface{}
				if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
					t.Fatalf("failed to decode response: %v", err)
				}
				if int(resp["deleted"].(float64)) != 0 {
					t.Errorf("expected deleted=0, got %v", resp["deleted"])
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, logsDB, cleanup := testutil.SetupTestDBWithSecretAndLogs(t)
			defer cleanup()

			if tt.setup != nil {
				tt.setup(t, db, logsDB)
			}

			req := httptest.NewRequest("DELETE", "/api/v1/settings/logs/clear", nil)
			w := httptest.NewRecorder()

			handler := NewHandler(db, logsDB, "/test/logs.db")
			handler.ClearAllLogs(w, req)

			if w.Code != tt.wantCode {
				t.Errorf("expected status %d, got %d: %s", tt.wantCode, w.Code, w.Body.String())
			}

			if tt.checkResp != nil {
				tt.checkResp(t, w)
			}
		})
	}
}

func TestClearAllLogs_LogsDBNotInitialized(t *testing.T) {
	db, cleanup := testutil.SetupTestDBWithSecret(t)
	defer cleanup()

	req := httptest.NewRequest("DELETE", "/api/v1/settings/logs/clear", nil)
	w := httptest.NewRecorder()

	// Create handler with nil LogsDB
	handler := NewHandler(db, nil, "")
	handler.ClearAllLogs(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected status %d, got %d: %s", http.StatusInternalServerError, w.Code, w.Body.String())
	}
}

// =============================================================================
// Test getRetentionLabel
// =============================================================================

func TestGetRetentionLabel(t *testing.T) {
	tests := []struct {
		days int
		want string
	}{
		{-1, "Unlimited"},
		{0, "Disabled"},
		{1, "1 Day"},
		{14, "14 Days"},
		{30, "30 Days"},
		{90, "90 Days"},
		{365, "365 Days"},
		{7, "7 Days"},
		{45, "45 Days"},
		{100, "100 Days"},
		{9999, "9999 Days"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := getRetentionLabel(tt.days)
			if got != tt.want {
				t.Errorf("getRetentionLabel(%d) = %s, want %s", tt.days, got, tt.want)
			}
		})
	}
}

// =============================================================================
// Test GetLogSettings with logs count
// =============================================================================

func TestGetLogSettings_LogCountAndSize(t *testing.T) {
	db, logsDB, cleanup := testutil.SetupTestDBWithSecretAndLogs(t)
	defer cleanup()

	// Insert some test logs using correct schema columns
	for i := 0; i < 100; i++ {
		logsDB.Exec(`INSERT INTO firewall_logs (peer_id, peer_hostname, timestamp, event_type, source_ip, dest_ip, protocol, source_port, dest_port, action) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, "1", "peer1", time.Now(), "inbound", "192.168.1.1", "10.0.0.1", "tcp", 12345, 22, "ACCEPT")
	}

	req := httptest.NewRequest("GET", "/api/v1/settings/logs", nil)
	w := httptest.NewRecorder()

	handler := NewHandler(db, logsDB, "/test/logs.db")
	handler.GetLogSettings(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d: %s", http.StatusOK, w.Code, w.Body.String())
	}

	var resp LogSettings
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.LogCount != 100 {
		t.Errorf("expected log count 100, got %d", resp.LogCount)
	}

	// Estimated size: (100 * 500) / (1024 * 1024) = 50000 / 1048576 ≈ 0 MB
	if resp.EstimatedSizeMB < 0 {
		t.Errorf("expected non-negative estimated size, got %d", resp.EstimatedSizeMB)
	}

	if resp.LogsDBPath != "/test/logs.db" {
		t.Errorf("expected logs_db_path '/test/logs.db', got '%s'", resp.LogsDBPath)
	}
}

// =============================================================================
// Test GetLogSettings with nil LogsDB
// =============================================================================

func TestGetLogSettings_NilLogsDB(t *testing.T) {
	db, cleanup := testutil.SetupTestDBWithSecret(t)
	defer cleanup()

	req := httptest.NewRequest("GET", "/api/v1/settings/logs", nil)
	w := httptest.NewRecorder()

	// Create handler with nil LogsDB
	handler := NewHandler(db, nil, "/test/logs.db")
	handler.GetLogSettings(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d: %s", http.StatusOK, w.Code, w.Body.String())
	}

	var resp LogSettings
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	// Log count should be 0 when LogsDB is nil
	if resp.LogCount != 0 {
		t.Errorf("expected log count 0, got %d", resp.LogCount)
	}
}

// =============================================================================
// Test GetInstanceSettings
// =============================================================================

func TestGetInstanceSettings(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(t *testing.T, db *sql.DB)
		wantCode int
		wantURL  string
	}{
		{
			name:     "instance_url not set - returns empty string",
			setup:    nil,
			wantCode: http.StatusOK,
			wantURL:  "",
		},
		{
			name: "instance_url set - returns the URL",
			setup: func(t *testing.T, db *sql.DB) {
				db.Exec(`INSERT INTO system_config (key, value) VALUES ('instance_url', 'https://example.com')`)
			},
			wantCode: http.StatusOK,
			wantURL:  "https://example.com",
		},
		{
			name: "instance_url set to empty string",
			setup: func(t *testing.T, db *sql.DB) {
				db.Exec(`INSERT INTO system_config (key, value) VALUES ('instance_url', '')`)
			},
			wantCode: http.StatusOK,
			wantURL:  "",
		},
		{
			name: "instance_url with port",
			setup: func(t *testing.T, db *sql.DB) {
				db.Exec(`INSERT INTO system_config (key, value) VALUES ('instance_url', 'https://example.com:8443')`)
			},
			wantCode: http.StatusOK,
			wantURL:  "https://example.com:8443",
		},
		{
			name: "instance_url with path",
			setup: func(t *testing.T, db *sql.DB) {
				db.Exec(`INSERT INTO system_config (key, value) VALUES ('instance_url', 'https://example.com/runic')`)
			},
			wantCode: http.StatusOK,
			wantURL:  "https://example.com/runic",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, cleanup := testutil.SetupTestDBWithSecret(t)
			defer cleanup()

			if tt.setup != nil {
				tt.setup(t, db)
			}

			req := httptest.NewRequest("GET", "/api/v1/settings/instance", nil)
			w := httptest.NewRecorder()

			handler := NewHandler(db, nil, "")
			handler.GetInstanceSettings(w, req)

			if w.Code != tt.wantCode {
				t.Errorf("expected status %d, got %d: %s", tt.wantCode, w.Code, w.Body.String())
			}

			var resp map[string]string
			if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
				t.Fatalf("failed to decode response: %v", err)
			}

			if resp["url"] != tt.wantURL {
				t.Errorf("expected url '%s', got '%s'", tt.wantURL, resp["url"])
			}
		})
	}
}

// =============================================================================
// Test UpdateInstanceSettings
// =============================================================================

func TestUpdateInstanceSettings(t *testing.T) {
	tests := []struct {
		name     string
		reqBody  string
		wantCode int
		wantURL  string
	}{
		{
			name:     "valid https URL",
			reqBody:  `{"url": "https://example.com"}`,
			wantCode: http.StatusOK,
			wantURL:  "https://example.com",
		},
		{
			name:     "valid http URL",
			reqBody:  `{"url": "http://localhost:8080"}`,
			wantCode: http.StatusOK,
			wantURL:  "http://localhost:8080",
		},
		{
			name:     "valid URL with path",
			reqBody:  `{"url": "https://example.com/runic/api"}`,
			wantCode: http.StatusOK,
			wantURL:  "https://example.com/runic/api",
		},
		{
			name:     "empty URL - should be allowed",
			reqBody:  `{"url": ""}`,
			wantCode: http.StatusOK,
			wantURL:  "",
		},
		{
			name:     "URL with port",
			reqBody:  `{"url": "https://example.com:9443"}`,
			wantCode: http.StatusOK,
			wantURL:  "https://example.com:9443",
		},
		{
			name:     "IP address URL",
			reqBody:  `{"url": "http://192.168.1.100:3000"}`,
			wantCode: http.StatusOK,
			wantURL:  "http://192.168.1.100:3000",
		},
		{
			name:     "invalid URL - malformed",
			reqBody:  `{"url": "://invalid-url"}`,
			wantCode: http.StatusBadRequest,
		},
		{
			name:     "invalid JSON body",
			reqBody:  `{invalid json}`,
			wantCode: http.StatusBadRequest,
		},
		{
			name:     "empty body - uses default empty",
			reqBody:  `{}`,
			wantCode: http.StatusOK,
			wantURL:  "",
		},
		// Security test cases
		{
			name:     "javascript URL scheme - should be rejected",
			reqBody:  `{"url": "javascript:alert(1)"}`,
			wantCode: http.StatusBadRequest,
		},
		{
			name:     "data URL scheme - should be rejected",
			reqBody:  `{"url": "data:text/html,<script>alert(1)</script>"}`,
			wantCode: http.StatusBadRequest,
		},
		{
			name:     "file URL scheme - should be rejected",
			reqBody:  `{"url": "file:///etc/passwd"}`,
			wantCode: http.StatusBadRequest,
		},
		{
			name:     "URL exceeds max length - should be rejected",
			reqBody:  `{"url": "https://example.com/` + strings.Repeat("a", 2100) + `"}`,
			wantCode: http.StatusBadRequest,
		},
		{
			name:     "SQL injection attempt in query params - should be sanitized",
			reqBody:  `{"url": "https://example.com/path?q=1'; DROP TABLE system_config; --"}`,
			wantCode: http.StatusOK,
			wantURL:  "https://example.com/path?q=1'; DROP TABLE system_config; --",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, cleanup := testutil.SetupTestDBWithSecret(t)
			defer cleanup()

			req := httptest.NewRequest("PUT", "/api/v1/settings/instance", strings.NewReader(tt.reqBody))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			handler := NewHandler(db, nil, "")
			handler.UpdateInstanceSettings(w, req)

			if w.Code != tt.wantCode {
				t.Errorf("expected status %d, got %d: %s", tt.wantCode, w.Code, w.Body.String())
			}

			if tt.wantCode == http.StatusOK {
				var resp map[string]string
				if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
					t.Fatalf("failed to decode response: %v", err)
				}

				if resp["url"] != tt.wantURL {
					t.Errorf("expected url '%s', got '%s'", tt.wantURL, resp["url"])
				}

				// Verify the URL was persisted in the database
				var storedURL string
				err := db.QueryRow("SELECT value FROM system_config WHERE key = 'instance_url'").Scan(&storedURL)
				if err != nil {
					t.Fatalf("failed to query stored URL: %v", err)
				}
				if storedURL != tt.wantURL {
					t.Errorf("expected stored url '%s', got '%s'", tt.wantURL, storedURL)
				}
			}
		})
	}
}

// =============================================================================
// Test UpdateInstanceSettings - update existing value
// =============================================================================

func TestUpdateInstanceSettings_UpdateExisting(t *testing.T) {
	db, cleanup := testutil.SetupTestDBWithSecret(t)
	defer cleanup()

	// Set initial value
	db.Exec(`INSERT INTO system_config (key, value) VALUES ('instance_url', 'https://old.example.com')`)

	// Update to new value
	req := httptest.NewRequest("PUT", "/api/v1/settings/instance", strings.NewReader(`{"url": "https://new.example.com"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler := NewHandler(db, nil, "")
	handler.UpdateInstanceSettings(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d: %s", http.StatusOK, w.Code, w.Body.String())
	}

	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp["url"] != "https://new.example.com" {
		t.Errorf("expected url 'https://new.example.com', got '%s'", resp["url"])
	}

	// Verify only one row exists
	var count int
	db.QueryRow("SELECT COUNT(*) FROM system_config WHERE key = 'instance_url'").Scan(&count)
	if count != 1 {
		t.Errorf("expected 1 row, got %d", count)
	}
}

// =============================================================================
// Test GetAgentVersionSettings and UpdateAgentVersionSettings
// =============================================================================

func TestAgentVersionSettings(t *testing.T) {
	t.Run("defaults to server version when not set", func(t *testing.T) {
		db, cleanup := testutil.SetupTestDBWithSecret(t)
		defer cleanup()

		handler := NewHandler(db, nil, "")

		req := httptest.NewRequest("GET", "/api/v1/settings/agent-version", nil)
		w := httptest.NewRecorder()
		handler.GetAgentVersionSettings(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
		}

		var resp map[string]interface{}
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		if resp["is_default"] != true {
			t.Errorf("expected is_default true, got %v", resp["is_default"])
		}
	if resp["latest_agent_version"] != runicversion.AgentVersion {
		t.Errorf("expected agent version %s, got %v", runicversion.AgentVersion, resp["latest_agent_version"])
	}
})

	t.Run("sets and gets explicit version", func(t *testing.T) {
		db, cleanup := testutil.SetupTestDBWithSecret(t)
		defer cleanup()

		handler := NewHandler(db, nil, "")

		// Set a version
		body, _ := json.Marshal(map[string]string{"latest_agent_version": "1.2.3"})
		req := httptest.NewRequest("PUT", "/api/v1/settings/agent-version", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		handler.UpdateAgentVersionSettings(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
		}

		// Get the version
		req = httptest.NewRequest("GET", "/api/v1/settings/agent-version", nil)
		w = httptest.NewRecorder()
		handler.GetAgentVersionSettings(w, req)

		var resp map[string]interface{}
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		if resp["latest_agent_version"] != "1.2.3" {
			t.Errorf("expected version 1.2.3, got %v", resp["latest_agent_version"])
		}
		if resp["is_default"] != false {
			t.Errorf("expected is_default false, got %v", resp["is_default"])
		}
	})

	t.Run("rejects too-long version string", func(t *testing.T) {
		db, cleanup := testutil.SetupTestDBWithSecret(t)
		defer cleanup()

		handler := NewHandler(db, nil, "")

		longVersion := strings.Repeat("x", 51)
		body, _ := json.Marshal(map[string]string{"latest_agent_version": longVersion})
		req := httptest.NewRequest("PUT", "/api/v1/settings/agent-version", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		handler.UpdateAgentVersionSettings(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("expected 400, got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("empty string reverts to server version", func(t *testing.T) {
		db, cleanup := testutil.SetupTestDBWithSecret(t)
		defer cleanup()

		handler := NewHandler(db, nil, "")

		// First set an explicit version
		body, _ := json.Marshal(map[string]string{"latest_agent_version": "2.0.0"})
		req := httptest.NewRequest("PUT", "/api/v1/settings/agent-version", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		handler.UpdateAgentVersionSettings(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200 setting version, got %d: %s", w.Code, w.Body.String())
		}

		// Now revert with empty string
		body, _ = json.Marshal(map[string]string{"latest_agent_version": ""})
		req = httptest.NewRequest("PUT", "/api/v1/settings/agent-version", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w = httptest.NewRecorder()
		handler.UpdateAgentVersionSettings(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
		}

		var resp map[string]interface{}
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		if resp["is_default"] != true {
			t.Errorf("expected is_default true when set to empty, got %v", resp["is_default"])
		}
	if resp["latest_agent_version"] != runicversion.AgentVersion {
		t.Errorf("expected agent version %s, got %v", runicversion.AgentVersion, resp["latest_agent_version"])
	}
})
}
