package alerts

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"runic/internal/alerts"
	"runic/internal/auth"
	"runic/internal/crypto"
	"runic/internal/testutil"
)

// muxVars is a helper to mock gorilla/mux vars
var muxVars = testutil.MuxVars

// mockSMTPSender is a mock implementation of SMTPSender for testing
type mockSMTPSender struct {
	sendCalled bool
	lastTo     string
	lastEvent  *alerts.AlertEvent
	sendError  error
}

func (m *mockSMTPSender) SendAlertEmail(to string, event *alerts.AlertEvent) error {
	m.sendCalled = true
	m.lastTo = to
	m.lastEvent = event
	return m.sendError
}

// mockAlertService is a mock alert service that returns our mock SMTPSender
type mockAlertService struct {
	smtpSender *mockSMTPSender
}

func (m *mockAlertService) GetSMTPSender() *alerts.SMTPSender {
	// Return nil since we can't easily mock the SMTPSender type
	// Tests will need to use real SMTPSender or test via integration
	return nil
}

// TestGetSMTPConfig tests the GET /settings/smtp endpoint.
func TestGetSMTPConfig(t *testing.T) {
	tests := []struct {
		name       string
		setup      func(t *testing.T, db *sql.DB)
		wantCode   int
		wantConfig map[string]interface{}
	}{
		{
			name: "returns config with password masked",
			setup: func(t *testing.T, db *sql.DB) {
				// Insert SMTP config
				db.Exec(`INSERT INTO system_config (key, value) VALUES ('smtp_host', 'smtp.example.com')`)
				db.Exec(`INSERT INTO system_config (key, value) VALUES ('smtp_port', '587')`)
				db.Exec(`INSERT INTO system_config (key, value) VALUES ('smtp_username', 'testuser')`)
				db.Exec(`INSERT INTO system_config (key, value) VALUES ('smtp_password', 'encrypted_password')`)
				db.Exec(`INSERT INTO system_config (key, value) VALUES ('smtp_use_tls', '1')`)
				db.Exec(`INSERT INTO system_config (key, value) VALUES ('smtp_from_address', 'alerts@example.com')`)
				db.Exec(`INSERT INTO system_config (key, value) VALUES ('smtp_enabled', '1')`)
			},
			wantCode: http.StatusOK,
			wantConfig: map[string]interface{}{
				"host":         "smtp.example.com",
				"port":         float64(587),
				"username":     "testuser",
				"password_set": true,
				"use_tls":      true,
				"from_address": "alerts@example.com",
				"enabled":      true,
			},
		},
		{
			name: "returns config without password_set when no password",
			setup: func(t *testing.T, db *sql.DB) {
				db.Exec(`INSERT INTO system_config (key, value) VALUES ('smtp_host', 'smtp.example.com')`)
				db.Exec(`INSERT INTO system_config (key, value) VALUES ('smtp_port', '587')`)
				// No password inserted
			},
			wantCode: http.StatusOK,
			wantConfig: map[string]interface{}{
				"host":         "smtp.example.com",
				"port":         float64(587),
				"username":     "",
				"password_set": false,
				"use_tls":      false,
				"from_address": "",
				"enabled":      false,
			},
		},
		{
			name: "returns empty config when not configured",
			setup: func(t *testing.T, db *sql.DB) {
				// No SMTP config inserted
			},
			wantCode: http.StatusOK,
			wantConfig: map[string]interface{}{
				"host":         "",
				"port":         float64(0),
				"username":     "",
				"password_set": false,
				"use_tls":      false,
				"from_address": "",
				"enabled":      false,
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

			req := httptest.NewRequest("GET", "/api/v1/settings/smtp", nil)
			w := httptest.NewRecorder()

			handler := NewHandler(database, nil, nil)
			handler.GetSMTPConfig(w, req)

			if w.Code != tt.wantCode {
				t.Errorf("expected status %d, got %d: %s", tt.wantCode, w.Code, w.Body.String())
			}

			var resp map[string]interface{}
			if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
				t.Fatalf("failed to decode response: %v", err)
			}

			for key, expectedValue := range tt.wantConfig {
				if resp[key] != expectedValue {
					t.Errorf("expected %s=%v, got %v", key, expectedValue, resp[key])
				}
			}

			// Verify password is never returned
			if _, ok := resp["password"]; ok {
				t.Error("password should not be returned in response")
			}
		})
	}
}

// TestUpdateSMTPConfig tests the PUT /settings/smtp endpoint.
func TestUpdateSMTPConfig(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		setup    func(t *testing.T, db *sql.DB)
		wantCode int
		wantErr  string
		verify   func(t *testing.T, db *sql.DB)
	}{
		{
			name: "update SMTP config successfully",
			body: `{"host":"smtp.new.com","port":465,"username":"newuser","password":"newpass","use_tls":true,"from_address":"new@example.com","enabled":true}`,
			setup: func(t *testing.T, db *sql.DB) {
				db.Exec(`INSERT INTO system_config (key, value) VALUES ('smtp_host', 'old.smtp.com')`)
			},
			wantCode: http.StatusOK,
			verify: func(t *testing.T, db *sql.DB) {
				var host string
				err := db.QueryRow("SELECT value FROM system_config WHERE key = 'smtp_host'").Scan(&host)
				if err != nil {
					t.Fatalf("failed to query smtp_host: %v", err)
				}
				if host != "smtp.new.com" {
					t.Errorf("expected host smtp.new.com, got %s", host)
				}
			},
		},
		{
			name:     "invalid JSON",
			body:     `{"invalid":}`,
			setup:    nil,
			wantCode: http.StatusBadRequest,
			wantErr:  "invalid JSON",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			database, cleanup := testutil.SetupTestDB(t)
			defer cleanup()

			if tt.setup != nil {
				tt.setup(t, database)
			}

			req := httptest.NewRequest("PUT", "/api/v1/settings/smtp", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			encryptor, _ := crypto.NewEncryptor("test-passphrase-32-bytes-long!!")
			handler := NewHandler(database, nil, encryptor)
			handler.UpdateSMTPConfig(w, req)

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

			if tt.verify != nil {
				tt.verify(t, database)
			}
		})
	}
}

// TestUpdateSMTPConfig_WithEncryption tests that passwords are encrypted when stored.
func TestUpdateSMTPConfig_WithEncryption(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	encryptor, err := crypto.NewEncryptor("test-passphrase-32-bytes-long!!")
	if err != nil {
		t.Fatalf("failed to create encryptor: %v", err)
	}

	body := `{"host":"smtp.test.com","port":587,"username":"testuser","password":"my-secret-password","use_tls":true,"from_address":"test@example.com","enabled":true}`
	req := httptest.NewRequest("PUT", "/api/v1/settings/smtp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler := NewHandler(database, nil, encryptor)
	handler.UpdateSMTPConfig(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d: %s", http.StatusOK, w.Code, w.Body.String())
	}

	var storedPassword string
	err = database.QueryRow("SELECT value FROM system_config WHERE key = 'smtp_password'").Scan(&storedPassword)
	if err != nil {
		t.Fatalf("failed to query smtp_password: %v", err)
	}

	if storedPassword == "my-secret-password" {
		t.Error("password should be encrypted, not stored in plaintext")
	}

	decrypted, err := encryptor.Decrypt(storedPassword)
	if err != nil {
		t.Fatalf("failed to decrypt password: %v", err)
	}
	if decrypted != "my-secret-password" {
		t.Errorf("expected decrypted password 'my-secret-password', got %s", decrypted)
	}
}

// TestSendTestEmail tests the POST /settings/smtp/test endpoint.
func TestSendTestEmail(t *testing.T) {
	tests := []struct {
		name       string
		setup      func(t *testing.T, db *sql.DB)
		wantCode   int
		wantErr    string
		wantFields map[string]interface{}
	}{
		{
			name:     "user not authenticated",
			setup:    nil,
			wantCode: http.StatusUnauthorized,
			wantErr:  "not authenticated",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			database, cleanup := testutil.SetupTestDB(t)
			defer cleanup()

			if tt.setup != nil {
				tt.setup(t, database)
			}

			req := httptest.NewRequest("POST", "/api/v1/settings/smtp/test", nil)
			w := httptest.NewRecorder()

			handler := NewHandler(database, nil, nil)
			handler.TestSMTP(w, req)

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

// TestSendTestEmail_WithUserContext tests sending test email with authenticated user.
func TestSendTestEmail_WithUserContext(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	database.Exec(`INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)`,
		"testuser", "test@example.com", "hashedpassword", "admin")

	req := httptest.NewRequest("POST", "/api/v1/settings/smtp/test", nil)
	ctx := auth.SetContextForTest(req.Context(), "admin", "testuser")
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	handler := NewHandler(database, nil, nil)
	handler.TestSMTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected status %d, got %d: %s", http.StatusInternalServerError, w.Code, w.Body.String())
	}
}

// TestGetAlertRules tests the GET /alert-rules endpoint.
func TestGetAlertRules(t *testing.T) {
	tests := []struct {
		name       string
		setup      func(t *testing.T, db *sql.DB)
		wantCode   int
		wantCount  int
		wantErr    string
		checkRules func(t *testing.T, rules []alerts.AlertRule)
	}{
		{
			name: "returns all alert rules",
			setup: func(t *testing.T, db *sql.DB) {
				db.Exec(`INSERT INTO alert_rules (name, alert_type, enabled, threshold_value, threshold_window_minutes, throttle_minutes) VALUES (?, ?, ?, ?, ?, ?)`,
					"Peer Offline Alert", "peer_offline", 1, 0, 5, 15)
				db.Exec(`INSERT INTO alert_rules (name, alert_type, enabled, threshold_value, threshold_window_minutes, throttle_minutes) VALUES (?, ?, ?, ?, ?, ?)`,
					"Bundle Failed Alert", "bundle_failed", 1, 0, 5, 30)
				db.Exec(`INSERT INTO alert_rules (name, alert_type, enabled, threshold_value, threshold_window_minutes, throttle_minutes) VALUES (?, ?, ?, ?, ?, ?)`,
					"Blocked Spike Alert", "blocked_spike", 1, 100, 5, 10)
			},
			wantCode:  http.StatusOK,
			wantCount: 3,
		},
		{
			name:      "returns empty array when no rules",
			setup:     nil,
			wantCode:  http.StatusOK,
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			database, cleanup := testutil.SetupTestDB(t)
			defer cleanup()

			if tt.setup != nil {
				tt.setup(t, database)
			}

			req := httptest.NewRequest("GET", "/api/v1/alert-rules", nil)
			w := httptest.NewRecorder()

			handler := NewHandler(database, nil, nil)
			handler.ListAlertRules(w, req)

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
			} else {
				var rules []alerts.AlertRule
				if err := json.Unmarshal(w.Body.Bytes(), &rules); err != nil {
					t.Fatalf("failed to decode response: %v", err)
				}
				if len(rules) != tt.wantCount {
					t.Errorf("expected %d rules, got %d", tt.wantCount, len(rules))
				}
				if tt.checkRules != nil {
					tt.checkRules(t, rules)
				}
			}
		})
	}
}

// TestUpdateAlertRule tests the PUT /alert-rules/{id} endpoint.
func TestUpdateAlertRule(t *testing.T) {
	tests := []struct {
		name     string
		ruleID   string
		body     string
		setup    func(t *testing.T, db *sql.DB)
		wantCode int
		wantErr  string
		verify   func(t *testing.T, db *sql.DB)
	}{
		{
			name:   "update alert rule successfully",
			ruleID: "1",
			body:   `{"name":"Updated Rule","enabled":false,"threshold_value":50}`,
			setup: func(t *testing.T, db *sql.DB) {
				db.Exec(`INSERT INTO alert_rules (name, alert_type, enabled, threshold_value, threshold_window_minutes, throttle_minutes) VALUES (?, ?, ?, ?, ?, ?)`, "Original Rule", "peer_offline", 1, 0, 5, 15)
			},
			wantCode: http.StatusOK,
			verify: func(t *testing.T, db *sql.DB) {
				var name string
				var enabled bool
				var thresholdValue int
				err := db.QueryRow("SELECT name, enabled, threshold_value FROM alert_rules WHERE id = 1").Scan(&name, &enabled, &thresholdValue)
				if err != nil {
					t.Fatalf("failed to query rule: %v", err)
				}
				if name != "Updated Rule" {
					t.Errorf("expected name 'Updated Rule', got %s", name)
				}
				if enabled {
					t.Error("expected enabled to be false")
				}
				if thresholdValue != 50 {
					t.Errorf("expected threshold_value 50, got %d", thresholdValue)
				}
			},
		},
		{
			name:     "invalid rule ID",
			ruleID:   "invalid",
			body:     `{"name":"Test"}`,
			setup:    nil,
			wantCode: http.StatusBadRequest,
			wantErr:  "invalid rule id",
		},
		{
			name:     "rule not found",
			ruleID:   "999",
			body:     `{"name":"Test"}`,
			setup:    nil,
			wantCode: http.StatusNotFound,
			wantErr:  "alert rule not found",
		},
		{
			name:   "invalid JSON",
			ruleID: "1",
			body:   `{"invalid":}`,
			setup: func(t *testing.T, db *sql.DB) {
				db.Exec(`INSERT INTO alert_rules (name, alert_type, enabled, threshold_value, threshold_window_minutes, throttle_minutes) VALUES (?, ?, ?, ?, ?, ?)`, "Test Rule", "peer_offline", 1, 0, 5, 15)
			},
			wantCode: http.StatusBadRequest,
			wantErr:  "invalid JSON",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			database, cleanup := testutil.SetupTestDB(t)
			defer cleanup()

			if tt.setup != nil {
				tt.setup(t, database)
			}

			req := httptest.NewRequest("PUT", "/api/v1/alert-rules/"+tt.ruleID, strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			req = muxVars(req, map[string]string{"id": tt.ruleID})
			w := httptest.NewRecorder()

			handler := NewHandler(database, nil, nil)
			handler.UpdateAlertRule(w, req)

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

			if tt.verify != nil {
				tt.verify(t, database)
			}
		})
	}
}

// TestGetAlertHistory tests the GET /alerts endpoint with pagination.
func TestGetAlertHistory(t *testing.T) {
	tests := []struct {
		name      string
		query     string
		setup     func(t *testing.T, db *sql.DB)
		wantCode  int
		wantCount int
		wantErr   string
		checkResp func(t *testing.T, resp map[string]interface{})
	}{
		{
			name:      "returns paginated alerts with default params",
			query:     "",
			setup:     nil,
			wantCode:  http.StatusOK,
			wantCount: 0,
			checkResp: func(t *testing.T, resp map[string]interface{}) {
				alertsRaw := resp["alerts"]
				if alertsRaw == nil {
					return
				}
				alerts, ok := alertsRaw.([]interface{})
				if !ok {
					t.Fatalf("expected alerts to be an array or nil, got %T", alertsRaw)
				}
				if len(alerts) != 0 {
					t.Errorf("expected 0 alerts, got %d", len(alerts))
				}
			},
		},
		{
			name:  "returns paginated alerts with custom limit",
			query: "?limit=2",
			setup: func(t *testing.T, db *sql.DB) {
				for i := 0; i < 5; i++ {
					db.Exec(`INSERT INTO alert_history (rule_id, alert_type, severity, subject, message, metadata, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
						1, "peer_offline", "warning", "Test Alert", "Test message", "{}", "sent", time.Now().Add(time.Duration(i)*time.Minute))
				}
			},
			wantCode:  http.StatusOK,
			wantCount: 2,
			checkResp: func(t *testing.T, resp map[string]interface{}) {
				if resp["limit"].(float64) != 2 {
					t.Errorf("expected limit 2, got %v", resp["limit"])
				}
			},
		},
		{
			name:  "handles offset correctly",
			query: "?limit=2&offset=2",
			setup: func(t *testing.T, db *sql.DB) {
				for i := 0; i < 5; i++ {
					db.Exec(`INSERT INTO alert_history (rule_id, alert_type, severity, subject, message, metadata, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
						1, "peer_offline", "warning", "Test Alert", "Test message", "{}", "sent", time.Now().Add(time.Duration(i)*time.Minute))
				}
			},
			wantCode:  http.StatusOK,
			wantCount: 2,
			checkResp: func(t *testing.T, resp map[string]interface{}) {
				if resp["offset"].(float64) != 2 {
					t.Errorf("expected offset 2, got %v", resp["offset"])
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

			req := httptest.NewRequest("GET", "/api/v1/alerts"+tt.query, nil)
			w := httptest.NewRecorder()

			handler := NewHandler(database, nil, nil)
			handler.ListAlerts(w, req)

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
			} else {
				var resp map[string]interface{}
				if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
					t.Fatalf("failed to decode response: %v", err)
				}
				if tt.checkResp != nil {
					tt.checkResp(t, resp)
				}
			}
		})
	}
}

// TestNotificationPrefsCRUD tests the notification preferences endpoints.
func TestNotificationPrefsCRUD(t *testing.T) {
	t.Run("get default preferences for new user", func(t *testing.T) {
		database, cleanup := testutil.SetupTestDB(t)
		defer cleanup()

		database.Exec(`INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)`,
			"testuser", "test@example.com", "hashedpassword", "viewer")

		req := httptest.NewRequest("GET", "/api/v1/users/me/notification-preferences", nil)
		ctx := auth.SetContextForTest(req.Context(), "viewer", "testuser")
		req = req.WithContext(ctx)
		w := httptest.NewRecorder()

		handler := NewHandler(database, nil, nil)
		handler.GetNotificationPrefs(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected status %d, got %d: %s", http.StatusOK, w.Code, w.Body.String())
		}

		var resp map[string]interface{}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		if resp["quiet_hours_start"] != "22:00" {
			t.Errorf("expected default quiet_hours_start '22:00', got %v", resp["quiet_hours_start"])
		}
		if resp["quiet_hours_end"] != "07:00" {
			t.Errorf("expected default quiet_hours_end '07:00', got %v", resp["quiet_hours_end"])
		}
	})

	t.Run("update preferences", func(t *testing.T) {
		database, cleanup := testutil.SetupTestDB(t)
		defer cleanup()

		database.Exec(`INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)`,
			"testuser", "test@example.com", "hashedpassword", "viewer")

		body := `{"quiet_hours_start":"23:00","quiet_hours_end":"06:00","digest_enabled":true}`
		req := httptest.NewRequest("PUT", "/api/v1/users/me/notification-preferences", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		ctx := auth.SetContextForTest(req.Context(), "viewer", "testuser")
		req = req.WithContext(ctx)
		w := httptest.NewRecorder()

		handler := NewHandler(database, nil, nil)
		handler.UpdateNotificationPrefs(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected status %d, got %d: %s", http.StatusOK, w.Code, w.Body.String())
		}

		var quietHoursStart, quietHoursEnd string
		var digestEnabled bool
		err := database.QueryRow(`
			SELECT quiet_hours_start, quiet_hours_end, digest_enabled
			FROM user_notification_preferences WHERE user_id = 1`).Scan(
			&quietHoursStart, &quietHoursEnd, &digestEnabled)
		if err != nil {
			t.Fatalf("failed to query preferences: %v", err)
		}

		if quietHoursStart != "23:00" {
			t.Errorf("expected quiet_hours_start '23:00', got %s", quietHoursStart)
		}
		if quietHoursEnd != "06:00" {
			t.Errorf("expected quiet_hours_end '06:00', got %s", quietHoursEnd)
		}
		if !digestEnabled {
			t.Error("expected digest_enabled to be true")
		}
	})

	t.Run("get existing preferences", func(t *testing.T) {
		database, cleanup := testutil.SetupTestDB(t)
		defer cleanup()

		database.Exec(`INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)`,
			"testuser", "test@example.com", "hashedpassword", "viewer")

		database.Exec(`INSERT INTO user_notification_preferences (user_id, quiet_hours_start, quiet_hours_end, digest_enabled) VALUES (?, ?, ?, ?)`,
			1, "21:00", "08:00", true)

		req := httptest.NewRequest("GET", "/api/v1/users/me/notification-preferences", nil)
		ctx := auth.SetContextForTest(req.Context(), "viewer", "testuser")
		req = req.WithContext(ctx)
		w := httptest.NewRecorder()

		handler := NewHandler(database, nil, nil)
		handler.GetNotificationPrefs(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected status %d, got %d: %s", http.StatusOK, w.Code, w.Body.String())
		}

		var resp map[string]interface{}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		if resp["quiet_hours_start"] != "21:00" {
			t.Errorf("expected quiet_hours_start '21:00', got %v", resp["quiet_hours_start"])
		}
	})
}

// TestNotificationPrefs_Unauthorized tests that unauthenticated requests are rejected.
func TestNotificationPrefs_Unauthorized(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	req := httptest.NewRequest("GET", "/api/v1/users/me/notification-preferences", nil)
	w := httptest.NewRecorder()

	handler := NewHandler(database, nil, nil)
	handler.GetNotificationPrefs(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d: %s", http.StatusUnauthorized, w.Code, w.Body.String())
	}

	req = httptest.NewRequest("PUT", "/api/v1/users/me/notification-preferences", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()

	handler.UpdateNotificationPrefs(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d: %s", http.StatusUnauthorized, w.Code, w.Body.String())
	}
}

// TestUnauthorized tests that various endpoints reject unauthenticated requests.
func TestUnauthorized(t *testing.T) {
	tests := []struct {
		name     string
		method   string
		path     string
		body     string
		wantCode int
	}{
		{
			name:     "TestSMTP without auth",
			method:   "POST",
			path:     "/api/v1/settings/smtp/test",
			wantCode: http.StatusUnauthorized,
		},
		{
			name:     "GetNotificationPrefs without auth",
			method:   "GET",
			path:     "/api/v1/users/me/notification-preferences",
			wantCode: http.StatusUnauthorized,
		},
		{
			name:     "UpdateNotificationPrefs without auth",
			method:   "PUT",
			path:     "/api/v1/users/me/notification-preferences",
			body:     `{}`,
			wantCode: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			database, cleanup := testutil.SetupTestDB(t)
			defer cleanup()

			var bodyReader *strings.Reader
			if tt.body != "" {
				bodyReader = strings.NewReader(tt.body)
			} else {
				bodyReader = strings.NewReader("")
			}

			req := httptest.NewRequest(tt.method, tt.path, bodyReader)
			if tt.body != "" {
				req.Header.Set("Content-Type", "application/json")
			}
			w := httptest.NewRecorder()

			handler := NewHandler(database, nil, nil)

			switch {
			case strings.Contains(tt.path, "notification-preferences"):
				if tt.method == "GET" {
					handler.GetNotificationPrefs(w, req)
				} else {
					handler.UpdateNotificationPrefs(w, req)
				}
			case strings.Contains(tt.path, "smtp/test"):
				handler.TestSMTP(w, req)
			}

			if w.Code != tt.wantCode {
				t.Errorf("expected status %d, got %d: %s", tt.wantCode, w.Code, w.Body.String())
			}
		})
	}
}

// TestNotificationPrefs_TimezoneValidation tests the timezone sync validation in UpdateNotificationPrefs.
func TestNotificationPrefs_TimezoneValidation(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		wantCode int
		wantErr  string
		verify   func(t *testing.T, db *sql.DB)
	}{
		{
			name:     "rejects mismatched timezone fields",
			body:     `{"quiet_hours_timezone":"America/New_York","digest_timezone":"Europe/London"}`,
			wantCode: http.StatusBadRequest,
			wantErr:  "quiet_hours_timezone and digest_timezone must be the same",
		},
		{
			name:     "accepts valid timezone and syncs both fields",
			body:     `{"quiet_hours_timezone":"America/New_York"}`,
			wantCode: http.StatusOK,
			verify: func(t *testing.T, db *sql.DB) {
				var quietTz, digestTz string
				err := db.QueryRow(`
					SELECT quiet_hours_timezone, digest_timezone
					FROM user_notification_preferences WHERE user_id = 1`).Scan(&quietTz, &digestTz)
				if err != nil {
					t.Fatalf("failed to query preferences: %v", err)
				}
				if quietTz != "America/New_York" {
					t.Errorf("expected quiet_hours_timezone 'America/New_York', got %s", quietTz)
				}
				if digestTz != "America/New_York" {
					t.Errorf("expected digest_timezone 'America/New_York', got %s", digestTz)
				}
			},
		},
		{
			name:     "accepts valid timezone via digest_timezone and syncs both fields",
			body:     `{"digest_timezone":"Europe/Paris"}`,
			wantCode: http.StatusOK,
			verify: func(t *testing.T, db *sql.DB) {
				var quietTz, digestTz string
				err := db.QueryRow(`
					SELECT quiet_hours_timezone, digest_timezone
					FROM user_notification_preferences WHERE user_id = 1`).Scan(&quietTz, &digestTz)
				if err != nil {
					t.Fatalf("failed to query preferences: %v", err)
				}
				if quietTz != "Europe/Paris" {
					t.Errorf("expected quiet_hours_timezone 'Europe/Paris', got %s", quietTz)
				}
				if digestTz != "Europe/Paris" {
					t.Errorf("expected digest_timezone 'Europe/Paris', got %s", digestTz)
				}
			},
		},
		{
			name:     "rejects invalid IANA timezone identifier",
			body:     `{"quiet_hours_timezone":"Invalid/Timezone"}`,
			wantCode: http.StatusBadRequest,
			wantErr:  "Invalid timezone: must be valid IANA timezone identifier",
		},
		{
			name:     "rejects invalid timezone via digest_timezone",
			body:     `{"digest_timezone":"NotAReal/Timezone"}`,
			wantCode: http.StatusBadRequest,
			wantErr:  "Invalid timezone: must be valid IANA timezone identifier",
		},
		{
			name:     "accepts matching timezone fields",
			body:     `{"quiet_hours_timezone":"Asia/Tokyo","digest_timezone":"Asia/Tokyo"}`,
			wantCode: http.StatusOK,
			verify: func(t *testing.T, db *sql.DB) {
				var quietTz, digestTz string
				err := db.QueryRow(`
					SELECT quiet_hours_timezone, digest_timezone
					FROM user_notification_preferences WHERE user_id = 1`).Scan(&quietTz, &digestTz)
				if err != nil {
					t.Fatalf("failed to query preferences: %v", err)
				}
				if quietTz != "Asia/Tokyo" {
					t.Errorf("expected quiet_hours_timezone 'Asia/Tokyo', got %s", quietTz)
				}
				if digestTz != "Asia/Tokyo" {
					t.Errorf("expected digest_timezone 'Asia/Tokyo', got %s", digestTz)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			database, cleanup := testutil.SetupTestDB(t)
			defer cleanup()

			database.Exec(`INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)`,
				"testuser", "test@example.com", "hashedpassword", "viewer")

			req := httptest.NewRequest("PUT", "/api/v1/users/me/notification-preferences", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			ctx := auth.SetContextForTest(req.Context(), "viewer", "testuser")
			req = req.WithContext(ctx)
			w := httptest.NewRecorder()

			handler := NewHandler(database, nil, nil)
			handler.UpdateNotificationPrefs(w, req)

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

			if tt.verify != nil {
				tt.verify(t, database)
			}
		})
	}
}

// TestGetAlert tests the GET /alerts/{id} endpoint.
func TestGetAlert(t *testing.T) {
	tests := []struct {
		name      string
		alertID   string
		setup     func(t *testing.T, db *sql.DB)
		wantCode  int
		wantErr   string
		wantAlert func(t *testing.T, resp map[string]interface{})
	}{
		{
			name:     "get alert by ID",
			alertID:  "1",
			wantCode: http.StatusOK,
			setup: func(t *testing.T, db *sql.DB) {
				db.Exec(`INSERT INTO alert_history (rule_id, alert_type, severity, subject, message, metadata, status) VALUES (?, ?, ?, ?, ?, ?, ?)`,
					1, "peer_offline", "warning", "Peer Offline", "Peer went offline", "{}", "sent")
			},
			wantAlert: func(t *testing.T, resp map[string]interface{}) {
				if resp["alert_type"] != "peer_offline" {
					t.Errorf("expected alert_type 'peer_offline', got %v", resp["alert_type"])
				}
				if resp["subject"] != "Peer Offline" {
					t.Errorf("expected subject 'Peer Offline', got %v", resp["subject"])
				}
			},
		},
		{
			name:     "invalid alert ID",
			alertID:  "invalid",
			setup:    nil,
			wantCode: http.StatusBadRequest,
			wantErr:  "invalid alert id",
		},
		{
			name:     "alert not found",
			alertID:  "999",
			setup:    nil,
			wantCode: http.StatusNotFound,
			wantErr:  "alert not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			database, cleanup := testutil.SetupTestDB(t)
			defer cleanup()

			if tt.setup != nil {
				tt.setup(t, database)
			}

			req := httptest.NewRequest("GET", "/api/v1/alerts/"+tt.alertID, nil)
			req = muxVars(req, map[string]string{"id": tt.alertID})
			w := httptest.NewRecorder()

			handler := NewHandler(database, nil, nil)
			handler.GetAlert(w, req)

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

			if tt.wantAlert != nil {
				var resp map[string]interface{}
				if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
					t.Fatalf("failed to decode response: %v", err)
				}
				tt.wantAlert(t, resp)
			}
		})
	}
}

// TestListAlertsWithFiltering tests filtering functionality for ListAlerts.
func TestListAlertsWithFiltering(t *testing.T) {
	tests := []struct {
		name      string
		query     string
		setup     func(t *testing.T, db *sql.DB)
		wantCount int
		wantTotal int
		checkResp func(t *testing.T, resp map[string]interface{})
	}{
		{
			name:      "filter by alert_type",
			query:     "?alert_type=peer_offline",
			wantCount: 2,
			wantTotal: 2,
			setup: func(t *testing.T, db *sql.DB) {
				db.Exec(`INSERT INTO alert_history (rule_id, alert_type, severity, subject, message, metadata, status) VALUES (?, ?, ?, ?, ?, ?, ?)`, 1, "peer_offline", "warning", "Test 1", "Message 1", "{}", "sent")
				db.Exec(`INSERT INTO alert_history (rule_id, alert_type, severity, subject, message, metadata, status) VALUES (?, ?, ?, ?, ?, ?, ?)`, 1, "peer_offline", "warning", "Test 2", "Message 2", "{}", "sent")
				db.Exec(`INSERT INTO alert_history (rule_id, alert_type, severity, subject, message, metadata, status) VALUES (?, ?, ?, ?, ?, ?, ?)`, 1, "bundle_failed", "critical", "Test 3", "Message 3", "{}", "sent")
			},
			checkResp: func(t *testing.T, resp map[string]interface{}) {
				alerts := resp["alerts"].([]interface{})
				for _, a := range alerts {
					alert := a.(map[string]interface{})
					if alert["alert_type"] != "peer_offline" {
						t.Errorf("expected alert_type peer_offline, got %v", alert["alert_type"])
					}
				}
			},
		},
		{
			name:      "filter by severity",
			query:     "?severity=critical",
			wantCount: 1,
			wantTotal: 1,
			setup: func(t *testing.T, db *sql.DB) {
				db.Exec(`INSERT INTO alert_history (rule_id, alert_type, severity, subject, message, metadata, status) VALUES (?, ?, ?, ?, ?, ?, ?)`, 1, "peer_offline", "warning", "Test 1", "Message 1", "{}", "sent")
				db.Exec(`INSERT INTO alert_history (rule_id, alert_type, severity, subject, message, metadata, status) VALUES (?, ?, ?, ?, ?, ?, ?)`, 1, "bundle_failed", "critical", "Test 2", "Message 2", "{}", "sent")
			},
		},
		{
			name:      "filter by status",
			query:     "?status=failed",
			wantCount: 1,
			wantTotal: 1,
			setup: func(t *testing.T, db *sql.DB) {
				db.Exec(`INSERT INTO alert_history (rule_id, alert_type, severity, subject, message, metadata, status) VALUES (?, ?, ?, ?, ?, ?, ?)`, 1, "peer_offline", "warning", "Test 1", "Message 1", "{}", "sent")
				db.Exec(`INSERT INTO alert_history (rule_id, alert_type, severity, subject, message, metadata, status) VALUES (?, ?, ?, ?, ?, ?, ?)`, 1, "bundle_failed", "critical", "Test 2", "Message 2", "{}", "failed")
			},
		},
		{
			name:      "filter by multiple parameters",
			query:     "?alert_type=peer_offline&severity=warning&status=sent",
			wantCount: 2,
			wantTotal: 2,
			setup: func(t *testing.T, db *sql.DB) {
				db.Exec(`INSERT INTO alert_history (rule_id, alert_type, severity, subject, message, metadata, status) VALUES (?, ?, ?, ?, ?, ?, ?)`, 1, "peer_offline", "warning", "Test 1", "Message 1", "{}", "sent")
				db.Exec(`INSERT INTO alert_history (rule_id, alert_type, severity, subject, message, metadata, status) VALUES (?, ?, ?, ?, ?, ?, ?)`, 1, "peer_offline", "warning", "Test 2", "Message 2", "{}", "sent")
				db.Exec(`INSERT INTO alert_history (rule_id, alert_type, severity, subject, message, metadata, status) VALUES (?, ?, ?, ?, ?, ?, ?)`, 1, "peer_offline", "critical", "Test 3", "Message 3", "{}", "sent")
				db.Exec(`INSERT INTO alert_history (rule_id, alert_type, severity, subject, message, metadata, status) VALUES (?, ?, ?, ?, ?, ?, ?)`, 1, "bundle_failed", "warning", "Test 4", "Message 4", "{}", "sent")
			},
		},
		{
			name:      "pagination with page parameter",
			query:     "?page=2&limit=2",
			wantCount: 2,
			wantTotal: 5,
			setup: func(t *testing.T, db *sql.DB) {
				for i := 0; i < 5; i++ {
					db.Exec(`INSERT INTO alert_history (rule_id, alert_type, severity, subject, message, metadata, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
						1, "peer_offline", "warning", "Test Alert", "Test message", "{}", "sent", time.Now().Add(time.Duration(i)*time.Minute))
				}
			},
			checkResp: func(t *testing.T, resp map[string]interface{}) {
				if resp["limit"].(float64) != 2 {
					t.Errorf("expected limit 2, got %v", resp["limit"])
				}
				if resp["offset"].(float64) != 2 {
					t.Errorf("expected offset 2 (from page=2), got %v", resp["offset"])
				}
				if resp["total"].(float64) != 5 {
					t.Errorf("expected total 5, got %v", resp["total"])
				}
			},
		},
		{
			name:      "returns total count",
			query:     "?limit=2",
			wantCount: 2,
			wantTotal: 5,
			setup: func(t *testing.T, db *sql.DB) {
				for i := 0; i < 5; i++ {
					db.Exec(`INSERT INTO alert_history (rule_id, alert_type, severity, subject, message, metadata, status) VALUES (?, ?, ?, ?, ?, ?, ?)`,
						1, "peer_offline", "warning", "Test Alert", "Test message", "{}", "sent")
				}
			},
			checkResp: func(t *testing.T, resp map[string]interface{}) {
				if resp["total"] == nil {
					t.Error("expected total field in response")
				}
				if resp["total"].(float64) != 5 {
					t.Errorf("expected total 5, got %v", resp["total"])
				}
			},
		},
		{
			name:      "page takes precedence over offset",
			query:     "?page=3&limit=1&offset=100",
			wantCount: 1,
			wantTotal: 5,
			setup: func(t *testing.T, db *sql.DB) {
				for i := 0; i < 5; i++ {
					db.Exec(`INSERT INTO alert_history (rule_id, alert_type, severity, subject, message, metadata, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
						1, "peer_offline", "warning", "Test Alert", "Test message", "{}", "sent", time.Now().Add(time.Duration(i)*time.Minute))
				}
			},
			checkResp: func(t *testing.T, resp map[string]interface{}) {
				// page=3, limit=1 means offset should be (3-1)*1 = 2
				if resp["offset"].(float64) != 2 {
					t.Errorf("expected offset 2 (from page=3), got %v", resp["offset"])
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

			req := httptest.NewRequest("GET", "/api/v1/alerts"+tt.query, nil)
			w := httptest.NewRecorder()

			handler := NewHandler(database, nil, nil)
			handler.ListAlerts(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("expected status %d, got %d: %s", http.StatusOK, w.Code, w.Body.String())
			}

			var resp map[string]interface{}
			if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
				t.Fatalf("failed to decode response: %v", err)
			}

			alerts := resp["alerts"].([]interface{})
			if len(alerts) != tt.wantCount {
				t.Errorf("expected %d alerts, got %d", tt.wantCount, len(alerts))
			}

			if resp["total"].(float64) != float64(tt.wantTotal) {
				t.Errorf("expected total %d, got %v", tt.wantTotal, resp["total"])
			}

			if tt.checkResp != nil {
				tt.checkResp(t, resp)
			}
		})
	}
}
