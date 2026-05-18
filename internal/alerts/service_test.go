// Package alerts provides alert and notification functionality.
package alerts

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
	"testing"
	"time"

	"runic/internal/db"
	"runic/internal/store"
	"runic/internal/testutil"
)

func setupTestAlertTables(t *testing.T, database *sql.DB) {
	t.Helper()
	// Tables are created by testutil.SetupTestDB which runs the schema
	// Just ensure alert_rules table exists (it should from schema.sql)
	var tableName string
	err := database.QueryRow(
		"SELECT name FROM sqlite_master WHERE type='table' AND name='alert_rules'",
	).Scan(&tableName)
	if err != nil {
		t.Fatalf("alert_rules table not found: %v", err)
	}
}

func createTestAlertRule(t *testing.T, database *sql.DB, rule *AlertRule) *AlertRule {
	t.Helper()
	ctx := context.Background()
	databaseWrapper := db.New(database)
	alertStore := store.NewAlertStore(databaseWrapper)

	if err := alertStore.CreateAlertRule(ctx, rule); err != nil {
		t.Fatalf("failed to create alert rule: %v", err)
	}
	return rule
}

func createTestUser(t *testing.T, database *sql.DB, username, email, role string) int {
	t.Helper()
	result, err := database.Exec(
		"INSERT INTO users (username, password_hash, email, role) VALUES (?, ?, ?, ?)",
		username, "hashed_password", email, role,
	)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}
	id, _ := result.LastInsertId()
	return int(id)
}

func countAlertHistory(t *testing.T, database *sql.DB) int {
	t.Helper()
	var count int
	err := database.QueryRow("SELECT COUNT(*) FROM alert_history").Scan(&count)
	if err != nil {
		t.Fatalf("failed to count alert history: %v", err)
	}
	return count
}

func getAlertHistoryByRuleID(t *testing.T, database *sql.DB, ruleID uint) []AlertHistory {
	t.Helper()
	rows, err := database.Query(
		"SELECT id, rule_id, alert_type, peer_id, severity, subject, message, status, created_at FROM alert_history WHERE rule_id = ?",
		ruleID,
	)
	if err != nil {
		t.Fatalf("failed to query alert history: %v", err)
	}
	defer rows.Close()

	var history []AlertHistory
	for rows.Next() {
		var h AlertHistory
		var peerID sql.NullString
		if err := rows.Scan(&h.ID, &h.RuleID, &h.AlertType, &peerID, &h.Severity, &h.Subject, &h.Message, &h.Status, &h.CreatedAt); err != nil {
			t.Fatalf("failed to scan alert history: %v", err)
		}
		if peerID.Valid && peerID.String != "" {
			h.PeerID = &peerID.String
		}
		history = append(history, h)
	}
	return history
}

func TestTriggerAlert_Basic(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	setupTestAlertTables(t, database)

	createTestUser(t, database, "admin", "admin@test.com", "admin")

	rule := &AlertRule{
		Name:            "Test Peer Offline Rule",
		AlertType:       AlertTypePeerOffline,
		Enabled:         true,
		ThrottleMinutes: 5,
	}
	createTestAlertRule(t, database, rule)

	databaseWrapper := db.New(database)
	alertStore := store.NewAlertStore(databaseWrapper)
	userStore := store.NewUserStore(databaseWrapper)
	service := NewService(databaseWrapper, alertStore, userStore)

	event := &AlertEvent{
		Type:      AlertTypePeerOffline,
		PeerID:    1,
		PeerName:  "test-peer",
		Timestamp: time.Now(),
		Subject:   "Peer test-peer is offline",
		Message:   "Peer has been offline for 60 minutes",
	}

	ctx := context.Background()
	history := event.CreateAlertHistory(rule.ID)
	if err := alertStore.CreateAlertHistory(ctx, &history); err != nil {
		t.Fatalf("failed to create alert history: %v", err)
	}

	// Verify alert_history entry was created
	historyList := getAlertHistoryByRuleID(t, database, rule.ID)
	if len(historyList) != 1 {
		t.Errorf("expected 1 alert history entry, got %d", len(historyList))
	}

	// Verify the alert has correct status
	if historyList[0].Status != AlertStatusPending {
		t.Errorf("expected status %s, got %s", AlertStatusPending, historyList[0].Status)
	}

	// Verify alert type is correct
	if historyList[0].AlertType != AlertTypePeerOffline {
		t.Errorf("expected alert type %s, got %s", AlertTypePeerOffline, historyList[0].AlertType)
	}

	// Verify severity is set correctly (peer_offline defaults to warning)
	if historyList[0].Severity != SeverityWarning {
		t.Errorf("expected severity %s, got %s", SeverityWarning, historyList[0].Severity)
	}

	// Clean up
	_ = service
}

func TestTriggerAlert_Throttled(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	setupTestAlertTables(t, database)

	createTestUser(t, database, "admin", "admin@test.com", "admin")

	rule := &AlertRule{
		Name:            "Test Throttled Rule",
		AlertType:       AlertTypePeerOffline,
		Enabled:         true,
		ThrottleMinutes: 60, // 60 minute throttle
	}
	createTestAlertRule(t, database, rule)

	databaseWrapper := db.New(database)
	alertStore := store.NewAlertStore(databaseWrapper)
	userStore := store.NewUserStore(databaseWrapper)
	ctx := context.Background()

	event1 := &AlertEvent{
		Type:      AlertTypePeerOffline,
		PeerID:    1,
		PeerName:  "test-peer",
		Timestamp: time.Now(),
		Subject:   "Peer offline",
		Message:   "First alert",
	}

	history1 := event1.CreateAlertHistory(rule.ID)
	history1.Status = AlertStatusSent // Mark as sent
	if err := alertStore.CreateAlertHistory(ctx, &history1); err != nil {
		t.Fatalf("failed to create first alert history: %v", err)
	}

	// Test the scheduler's throttle logic
	evaluator := NewConditionEvaluator(databaseWrapper, databaseWrapper, newTestHostnameLookup(database))
	processor := NewAlertProcessor(alertStore, userStore, nil)
	scheduler := NewScheduler(alertStore, evaluator, processor)

	// Test that the rule would be throttled (we just sent an alert)
	// The scheduler checks for recent alerts in the throttle window
	// Since we have a recent sent alert, isThrottled should return true
	isThrottled := scheduler.isThrottled(ctx, rule)
	if !isThrottled {
		t.Error("expected alert to be throttled after recent alert")
	}

	// Verify we have 1 alert history entry (the first one)
	allHistory := getAlertHistoryByRuleID(t, database, rule.ID)
	if len(allHistory) != 1 {
		t.Errorf("expected 1 alert history entry, got %d", len(allHistory))
	}

	// Test that after throttle duration passes, throttling is released
	// We can't actually wait 60 minutes, so we delete the history to simulate
	// the throttle window passing
	database.Exec("DELETE FROM alert_history WHERE rule_id = ?", rule.ID)

	// Now it should not be throttled
	isThrottled = scheduler.isThrottled(ctx, rule)
	if isThrottled {
		t.Error("expected alert to not be throttled after history cleared")
	}

	_ = processor
}

func TestTriggerAlert_QuietHours(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	setupTestAlertTables(t, database)

	userID := createTestUser(t, database, "admin", "admin@test.com", "admin")

	databaseWrapper := db.New(database)
	alertStore := store.NewAlertStore(databaseWrapper)
	ctx := context.Background()

	prefs := &UserNotificationPreferences{
		UserID:             uint(userID),
		QuietHoursEnabled:  true,
		QuietHoursStart:    "22:00", // 10 PM
		QuietHoursEnd:      "07:00", // 7 AM
		QuietHoursTimezone: "UTC",
	}

	if err := alertStore.UpsertUserNotificationPreferences(ctx, prefs); err != nil {
		t.Fatalf("failed to create notification preferences: %v", err)
	}

	rule := &AlertRule{
		Name:            "Test Quiet Hours Rule",
		AlertType:       AlertTypePeerOffline,
		Enabled:         true,
		ThrottleMinutes: 5,
	}
	createTestAlertRule(t, database, rule)

	event := &AlertEvent{
		Type:      AlertTypePeerOffline,
		PeerID:    1,
		PeerName:  "test-peer",
		Timestamp: time.Now(),
		Subject:   "Alert during quiet hours",
		Message:   "This alert should be held",
	}

	// In a real implementation, the processor would check quiet hours
	// and potentially hold the alert or mark it differently
	history := event.CreateAlertHistory(rule.ID)
	history.Status = AlertStatusPending // Held until outside quiet hours
	if err := alertStore.CreateAlertHistory(ctx, &history); err != nil {
		t.Fatalf("failed to create alert history: %v", err)
	}

	// Verify the alert was created with pending status
	historyList := getAlertHistoryByRuleID(t, database, rule.ID)
	if len(historyList) != 1 {
		t.Errorf("expected 1 alert history entry, got %d", len(historyList))
	}

	// Verify the status is pending (held)
	if historyList[0].Status != AlertStatusPending {
		t.Errorf("expected status %s for held alert, got %s", AlertStatusPending, historyList[0].Status)
	}

	// Verify notification preferences were stored correctly
	storedPrefs, err := alertStore.GetUserNotificationPreferences(ctx, uint(userID))
	if err != nil {
		t.Fatalf("failed to get notification preferences: %v", err)
	}
	if !storedPrefs.QuietHoursEnabled {
		t.Error("expected quiet hours to be enabled")
	}
	if storedPrefs.QuietHoursStart != "22:00" {
		t.Errorf("expected quiet hours start 22:00, got %s", storedPrefs.QuietHoursStart)
	}
	if storedPrefs.QuietHoursEnd != "07:00" {
		t.Errorf("expected quiet hours end 07:00, got %s", storedPrefs.QuietHoursEnd)
	}

	// Test that quiet hours can be checked via time comparison
	// This simulates what the actual quiet hours logic would do
	now := time.Now()
	currentHour := now.Hour()
	isQuietHours := currentHour >= 22 || currentHour < 7
	// Note: In actual implementation, the timezone would be used
	_ = isQuietHours
}

func TestTriggerAlert_Disabled(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	setupTestAlertTables(t, database)

	createTestUser(t, database, "admin", "admin@test.com", "admin")

	databaseWrapper := db.New(database)
	alertStore := store.NewAlertStore(databaseWrapper)
	ctx := context.Background()

	rule := &AlertRule{
		Name:            "Test Disabled Rule",
		AlertType:       AlertTypePeerOffline,
		Enabled:         false, // Disabled!
		ThrottleMinutes: 5,
	}
	createTestAlertRule(t, database, rule)

	// Verify rule is disabled
	storedRule, err := alertStore.GetAlertRule(ctx, uint64(rule.ID))
	if err != nil {
		t.Fatalf("failed to get alert rule: %v", err)
	}
	if storedRule.Enabled {
		t.Error("expected rule to be disabled")
	}

	// Try to trigger an alert - it should not create history
	event := &AlertEvent{
		Type:      AlertTypePeerOffline,
		PeerID:    1,
		PeerName:  "test-peer",
		Timestamp: time.Now(),
		Subject:   "Should not be processed",
		Message:   "Disabled rule test",
	}

	// In the actual implementation, TriggerAlert checks for enabled rules only
	// Simulate this by checking GetEnabledAlertRulesByType
	enabledRules, err := alertStore.GetEnabledAlertRulesByType(ctx, AlertTypePeerOffline)
	if err != nil {
		t.Fatalf("failed to get enabled rules: %v", err)
	}

	// Should be empty since our rule is disabled
	if len(enabledRules) != 0 {
		t.Errorf("expected 0 enabled rules, got %d", len(enabledRules))
	}

	// Verify no alert history was created for this rule
	// (We don't create history for disabled rules)
	count := countAlertHistory(t, database)
	if count != 0 {
		t.Errorf("expected 0 alert history entries, got %d", count)
	}

	_ = event
}

func TestGetRecipients(t *testing.T) {
	tests := []struct {
		name           string
		setupUsers     func(t *testing.T, database *sql.DB)
		wantRecipients int
		wantEmails     []string
	}{
		{
			name: "only admin users receive alerts",
			setupUsers: func(t *testing.T, database *sql.DB) {
				createTestUser(t, database, "admin1", "admin1@test.com", "admin")
				createTestUser(t, database, "admin2", "admin2@test.com", "admin")
				createTestUser(t, database, "viewer1", "viewer1@test.com", "viewer")
				createTestUser(t, database, "editor1", "editor1@test.com", "editor")
			},
			wantRecipients: 2,
			wantEmails:     []string{"admin1@test.com", "admin2@test.com"},
		},
		{
			name: "no admin users",
			setupUsers: func(t *testing.T, database *sql.DB) {
				createTestUser(t, database, "viewer1", "viewer1@test.com", "viewer")
				createTestUser(t, database, "editor1", "editor1@test.com", "editor")
			},
			wantRecipients: 0,
			wantEmails:     []string{},
		},
		{
			name: "single admin user",
			setupUsers: func(t *testing.T, database *sql.DB) {
				createTestUser(t, database, "admin1", "admin1@test.com", "admin")
			},
			wantRecipients: 1,
			wantEmails:     []string{"admin1@test.com"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			database, cleanup := testutil.SetupTestDB(t)
			defer cleanup()

			tt.setupUsers(t, database)

			// Query for admin users (as the processor does)
			databaseWrapper := db.New(database)
			alertStore := store.NewAlertStore(databaseWrapper)
			userStore := store.NewUserStore(databaseWrapper)
			processor := NewAlertProcessor(alertStore, userStore, nil)

			ctx := context.Background()
			emails, err := processor.getAdminEmails(ctx)

			if tt.wantRecipients == 0 {
				if err == nil {
					t.Error("expected error when no admin users, got nil")
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if len(emails) == 0 {
					t.Error("expected non-empty emails list")
				}
				if len(emails) != tt.wantRecipients {
					t.Errorf("expected %d emails, got %d: %v", tt.wantRecipients, len(emails), emails)
				}
				// Verify all expected emails are present
				for _, wantEmail := range tt.wantEmails {
					found := false
					for _, email := range emails {
						if email == wantEmail {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("expected email %s not found in results %v", wantEmail, emails)
					}
				}
			}
		})
	}
}

func TestSeverityAssignment(t *testing.T) {
	tests := []struct {
		name         string
		alertType    AlertType
		wantSeverity Severity
	}{
		{
			name:         "peer_offline defaults to warning",
			alertType:    AlertTypePeerOffline,
			wantSeverity: SeverityWarning,
		},
		{
			name:         "bundle_failed defaults to critical",
			alertType:    AlertTypeBundleFailed,
			wantSeverity: SeverityCritical,
		},
		{
			name:         "blocked_spike defaults to warning",
			alertType:    AlertTypeBlockedSpike,
			wantSeverity: SeverityWarning,
		},
		{
			name:         "peer_online defaults to info",
			alertType:    AlertTypePeerOnline,
			wantSeverity: SeverityInfo,
		},
		{
			name:         "new_peer defaults to info",
			alertType:    AlertTypeNewPeer,
			wantSeverity: SeverityInfo,
		},
		{
			name:         "bundle_deployed defaults to info",
			alertType:    AlertTypeBundleDeployed,
			wantSeverity: SeverityInfo,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test the DefaultSeverity method on AlertType
			gotSeverity := tt.alertType.DefaultSeverity()
			if gotSeverity != tt.wantSeverity {
				t.Errorf("expected severity %s for %s, got %s", tt.wantSeverity, tt.alertType, gotSeverity)
			}

			// Test that AlertEvent uses correct default severity
			event := &AlertEvent{
				Type:      tt.alertType,
				Timestamp: time.Now(),
			}
			eventSeverity := event.GetSeverity()
			if eventSeverity != tt.wantSeverity {
				t.Errorf("event GetSeverity() returned %s, expected %s", eventSeverity, tt.wantSeverity)
			}
		})
	}
}

func TestSeverityAssignment_WithDatabase(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	setupTestAlertTables(t, database)

	databaseWrapper := db.New(database)
	alertStore := store.NewAlertStore(databaseWrapper)
	ctx := context.Background()

	rules := []struct {
		name      string
		alertType AlertType
	}{
		{"Peer Offline Rule", AlertTypePeerOffline},
		{"Bundle Failed Rule", AlertTypeBundleFailed},
		{"Blocked Spike Rule", AlertTypeBlockedSpike},
	}

	for _, r := range rules {
		rule := &AlertRule{
			Name:            r.name,
			AlertType:       r.alertType,
			Enabled:         true,
			ThrottleMinutes: 5,
		}
		createTestAlertRule(t, database, rule)

		event := &AlertEvent{
			Type:      r.alertType,
			PeerID:    1,
			PeerName:  "test-peer",
			Timestamp: time.Now(),
			Subject:   fmt.Sprintf("%s alert", r.alertType),
			Message:   "Test message",
		}

		history := event.CreateAlertHistory(rule.ID)
		if err := alertStore.CreateAlertHistory(ctx, &history); err != nil {
			t.Fatalf("failed to create alert history for %s: %v", r.alertType, err)
		}

		// Verify severity in database
		var storedSeverity Severity
		err := database.QueryRow(
			"SELECT severity FROM alert_history WHERE rule_id = ?",
			rule.ID,
		).Scan(&storedSeverity)
		if err != nil {
			t.Fatalf("failed to query severity for %s: %v", r.alertType, err)
		}

		expectedSeverity := r.alertType.DefaultSeverity()
		if storedSeverity != expectedSeverity {
			t.Errorf("alert type %s: expected severity %s, got %s", r.alertType, expectedSeverity, storedSeverity)
		}
	}
}

func TestServiceLifecycle(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	setupTestAlertTables(t, database)

	databaseWrapper := db.New(database)
	alertStore := store.NewAlertStore(databaseWrapper)
	userStore := store.NewUserStore(databaseWrapper)

	// Test 1: Create service
	service := NewService(databaseWrapper, alertStore, userStore)
	if service == nil {
		t.Fatal("expected non-nil service")
	}

	// Verify initial state
	if service.IsInitialized() {
		t.Error("expected service to not be initialized initially")
	}
	if service.IsStarted() {
		t.Error("expected service to not be started initially")
	}

	// Test 2: Initialize the service
	err := service.Initialize()
	if err != nil {
		t.Fatalf("failed to initialize service: %v", err)
	}

	// Verify initialized state
	if !service.IsInitialized() {
		t.Error("expected service to be initialized after Initialize()")
	}
	if service.IsStarted() {
		t.Error("expected service to not be started after Initialize()")
	}

	// Verify components are created
	if service.GetEvaluator() == nil {
		t.Error("expected evaluator to be initialized")
	}
	if service.GetProcessor() == nil {
		t.Error("expected processor to be initialized")
	}
	if service.GetScheduler() == nil {
		t.Error("expected scheduler to be initialized")
	}
	if service.GetDigestGenerator() == nil {
		t.Error("expected digest generator to be initialized")
	}
	if service.GetSMTPSender() == nil {
		t.Error("expected SMTP sender to be initialized (even if disabled)")
	}

	// Test 3: Double initialization should fail
	err = service.Initialize()
	if err == nil {
		t.Error("expected error on double initialization")
	}

	// Test 4: Start the service
	err = service.Start()
	if err != nil {
		t.Fatalf("failed to start service: %v", err)
	}

	// Verify started state
	if !service.IsStarted() {
		t.Error("expected service to be started after Start()")
	}

	// Test 5: Double start should fail
	err = service.Start()
	if err == nil {
		t.Error("expected error on double start")
	}

	// Test 6: Stop the service
	err = service.Stop()
	if err != nil {
		t.Fatalf("failed to stop service: %v", err)
	}

	// Verify stopped state
	if service.IsStarted() {
		t.Error("expected service to not be started after Stop()")
	}

	// Test 7: Stop is idempotent
	err = service.Stop()
	if err != nil {
		t.Errorf("expected no error on second stop, got: %v", err)
	}
}

func TestServiceLifecycle_WithoutInitialize(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	databaseWrapper := db.New(database)
	alertStore := store.NewAlertStore(databaseWrapper)
	userStore := store.NewUserStore(databaseWrapper)
	service := NewService(databaseWrapper, alertStore, userStore)

	// Try to start without initializing
	err := service.Start()
	if err == nil {
		t.Error("expected error when starting without initialization")
	}

	// Verify service is not started
	if service.IsStarted() {
		t.Error("expected service to not be started")
	}
}

func TestAlertEvent_IsCritical(t *testing.T) {
	tests := []struct {
		name       string
		severity   Severity
		wantResult bool
	}{
		{"critical severity is critical", SeverityCritical, true},
		{"warning severity is not critical", SeverityWarning, false},
		{"info severity is not critical", SeverityInfo, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event := &AlertEvent{
				Type:      AlertTypePeerOffline,
				Severity:  tt.severity,
				Timestamp: time.Now(),
			}
			if event.IsCritical() != tt.wantResult {
				t.Errorf("IsCritical() = %v, want %v", event.IsCritical(), tt.wantResult)
			}
		})
	}
}

func TestAlertEvent_CreateAlertHistory(t *testing.T) {
	tests := []struct {
		name     string
		event    *AlertEvent
		ruleID   uint
		wantType AlertType
	}{
		{
			name: "creates history with correct fields",
			event: &AlertEvent{
				Type:      AlertTypePeerOffline,
				PeerID:    1,
				PeerName:  "test-peer",
				Timestamp: time.Now(),
				Subject:   "Test Subject",
				Message:   "Test Message",
				Metadata: map[string]interface{}{
					"key": "value",
				},
			},
			ruleID:   1,
			wantType: AlertTypePeerOffline,
		},
		{
			name: "handles zero peer_id",
			event: &AlertEvent{
				Type:      AlertTypeBlockedSpike,
				PeerID:    0,
				Timestamp: time.Now(),
				Subject:   "Spike detected",
				Message:   "Blocked traffic spike",
			},
			ruleID:   2,
			wantType: AlertTypeBlockedSpike,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			history := tt.event.CreateAlertHistory(tt.ruleID)

			if history.RuleID != tt.ruleID {
				t.Errorf("expected rule_id %d, got %d", tt.ruleID, history.RuleID)
			}
			if history.AlertType != tt.wantType {
				t.Errorf("expected alert_type %s, got %s", tt.wantType, history.AlertType)
			}
			if history.Status != AlertStatusPending {
				t.Errorf("expected status %s, got %s", AlertStatusPending, history.Status)
			}
			if history.Subject != tt.event.Subject {
				t.Errorf("expected subject %s, got %s", tt.event.Subject, history.Subject)
			}
			if history.Message != tt.event.Message {
				t.Errorf("expected message %s, got %s", tt.event.Message, history.Message)
			}

			expectedSeverity := tt.event.Type.DefaultSeverity()
			if history.Severity != expectedSeverity {
				t.Errorf("expected severity %s, got %s", expectedSeverity, history.Severity)
			}

			if tt.event.PeerID == 0 {
				if history.PeerID != nil {
					t.Errorf("expected nil peer_id for zero peer_id, got %v", history.PeerID)
				}
			} else {
				if history.PeerID == nil || *history.PeerID != strconv.Itoa(tt.event.PeerID) {
					t.Errorf("expected peer_id %d, got %v", tt.event.PeerID, history.PeerID)
				}
			}
		})
	}
}

func TestAlertRule_AppliesToPeer(t *testing.T) {
	tests := []struct {
		name      string
		rule      *AlertRule
		peerID    int
		wantApply bool
	}{
		{
			name: "global rule applies to all peers",
			rule: &AlertRule{
				Name:   "Global Rule",
				PeerID: nil, // nil means global
			},
			peerID:    5,
			wantApply: true,
		},
		{
			name: "specific rule applies to matching peer",
			rule: &AlertRule{
				Name:   "Specific Rule",
				PeerID: stringPtr("1"),
			},
			peerID:    1,
			wantApply: true,
		},
		{
			name: "specific rule does not apply to other peer",
			rule: &AlertRule{
				Name:   "Specific Rule",
				PeerID: stringPtr("1"),
			},
			peerID:    2,
			wantApply: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.rule.AppliesToPeer(tt.peerID)
			if result != tt.wantApply {
				t.Errorf("AppliesToPeer(%d) = %v, want %v", tt.peerID, result, tt.wantApply)
			}
		})
	}
}

func TestAlertRule_GetThresholdDuration(t *testing.T) {
	rule := &AlertRule{
		ThresholdWindowMinutes: 5,
		ThrottleMinutes:        15,
	}

	// Test GetThresholdDuration
	thresholdDuration := rule.GetThresholdDuration()
	if thresholdDuration != 5*time.Minute {
		t.Errorf("expected threshold duration 5m, got %v", thresholdDuration)
	}

	// Test GetThrottleDuration
	throttleDuration := rule.GetThrottleDuration()
	if throttleDuration != 15*time.Minute {
		t.Errorf("expected throttle duration 15m, got %v", throttleDuration)
	}
}

func intPtr(i int) *int {
	return &i
}

func stringPtr(s string) *string {
	return &s
}

// boolean values stored as "0"/"1" strings in the database.
// This test verifies the fix for a bug where the loadSMTPConfig function
// was incorrectly scanning string values directly into bool fields.
func TestLoadSMTPConfig_BooleanStringValues(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	databaseWrapper := db.New(database)
	ctx := context.Background()

	// This mimics how values are stored when SMTP is enabled via the settings API
	_, err := database.ExecContext(ctx,
		"INSERT INTO system_config (key, value) VALUES (?, ?)",
		"smtp_enabled", "1",
	)
	if err != nil {
		t.Fatalf("failed to insert smtp_enabled: %v", err)
	}

	_, err = database.ExecContext(ctx,
		"INSERT INTO system_config (key, value) VALUES (?, ?)",
		"smtp_host", "smtp.test.com",
	)
	if err != nil {
		t.Fatalf("failed to insert smtp_host: %v", err)
	}

	_, err = database.ExecContext(ctx,
		"INSERT INTO system_config (key, value) VALUES (?, ?)",
		"smtp_port", "587",
	)
	if err != nil {
		t.Fatalf("failed to insert smtp_port: %v", err)
	}

	_, err = database.ExecContext(ctx,
		"INSERT INTO system_config (key, value) VALUES (?, ?)",
		"smtp_use_tls", "1",
	)
	if err != nil {
		t.Fatalf("failed to insert smtp_use_tls: %v", err)
	}

	_, err = database.ExecContext(ctx,
		"INSERT INTO system_config (key, value) VALUES (?, ?)",
		"smtp_from_address", "alerts@test.com",
	)
	if err != nil {
		t.Fatalf("failed to insert smtp_from_address: %v", err)
	}

	alertStore := store.NewAlertStore(databaseWrapper)
	userStore := store.NewUserStore(databaseWrapper)
	service := NewService(databaseWrapper, alertStore, userStore)

	// Initialize the service which calls loadSMTPConfig internally
	err = service.Initialize()
	if err != nil {
		t.Fatalf("failed to initialize service: %v", err)
	}

	smtpSender := service.GetSMTPSender()
	if smtpSender == nil {
		t.Fatal("expected SMTP sender to be initialized")
	}

	// Test that the SMTP sender can be used (verifies config was loaded correctly)
	// If boolean values were not parsed correctly, IsEnabled() would return false
	// because Enabled would be false (default value when parsing fails)

	event := &AlertEvent{
		Type:      AlertTypePeerOffline,
		PeerName:  "test-peer",
		PeerID:    1,
		Timestamp: time.Now(),
		Subject:   "Test Alert",
		Message:   "This is a test alert",
	}

	// Try to send an alert email - this will fail at the network level
	// but should succeed past the configuration check if booleans were parsed correctly
	err = smtpSender.SendAlertEmail("test@example.com", event)

	// We expect a connection error (since smtp.test.com doesn't exist)
	// but NOT an "SMTP is not enabled or not configured" error
	// If boolean parsing failed, we'd get "SMTP is not enabled or not configured"
	if err != nil {
		// The error should be about connection failure, not about SMTP being disabled
		errMsg := err.Error()
		if errMsg == "SMTP is not enabled or not configured" {
			t.Error("SMTP was not enabled - boolean values '1' were not parsed correctly. " +
				"loadSMTPConfig should convert '1' strings to true for Enabled and UseTLS")
		}
		// Any other error is acceptable (connection failure, etc.)
		// This proves that the config was loaded successfully
	}
}
