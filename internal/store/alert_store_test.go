package store

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"

	"runic/internal/db"
	"runic/internal/models"

	_ "github.com/mattn/go-sqlite3"
)

func setupAlertStoreTestDB(t *testing.T) (*AlertStore, *sql.DB, func()) {
	t.Helper()
	f, err := os.CreateTemp("", "runic-alert-store-test-*.db")
	if err != nil {
		t.Fatal(err)
	}
	dbPath := f.Name()
	if cErr := f.Close(); cErr != nil {
		t.Logf("Failed to close temp file: %v", cErr)
	}

	database, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		os.Remove(dbPath)
		t.Fatal(err)
	}

	if _, err := database.Exec("PRAGMA foreign_keys=ON"); err != nil {
		database.Close()
		os.Remove(dbPath)
		t.Fatal(err)
	}

	if _, err := database.Exec(db.Schema()); err != nil {
		database.Close()
		os.Remove(dbPath)
		t.Fatal(err)
	}

	store := NewAlertStore(db.New(database))
	cleanup := func() {
		database.Close()
		os.Remove(dbPath)
	}
	return store, database, cleanup
}

func TestAlertStore_CreateAndGetAlertRule(t *testing.T) {
	store, _, cleanup := setupAlertStoreTestDB(t)
	defer cleanup()
	ctx := context.Background()

	rule := &models.AlertRule{
		Name:                   "Test Peer Offline",
		AlertType:              models.AlertTypePeerOffline,
		Enabled:                true,
		ThresholdValue:         5,
		ThresholdWindowMinutes: 10,
		ThrottleMinutes:        15,
	}

	err := store.CreateAlertRule(ctx, rule)
	if err != nil {
		t.Fatalf("CreateAlertRule failed: %v", err)
	}
	if rule.ID == 0 {
		t.Error("expected rule ID to be set after creation")
	}
	if rule.CreatedAt.IsZero() {
		t.Error("expected created_at to be set after creation")
	}

	got, err := store.GetAlertRule(ctx, uint64(rule.ID))
	if err != nil {
		t.Fatalf("GetAlertRule failed: %v", err)
	}
	if got.Name != rule.Name {
		t.Errorf("expected name %q, got %q", rule.Name, got.Name)
	}
	if got.AlertType != rule.AlertType {
		t.Errorf("expected alert_type %q, got %q", rule.AlertType, got.AlertType)
	}
	if got.Enabled != rule.Enabled {
		t.Errorf("expected enabled %v, got %v", rule.Enabled, got.Enabled)
	}
}

func TestAlertStore_CreateAlertRule_NormalizeEmptyPeerID(t *testing.T) {
	store, _, cleanup := setupAlertStoreTestDB(t)
	defer cleanup()
	ctx := context.Background()

	emptyPeerID := ""
	rule := &models.AlertRule{
		Name:            "Rule with empty peer_id",
		AlertType:       models.AlertTypePeerOffline,
		Enabled:         true,
		PeerID:          &emptyPeerID,
		ThrottleMinutes: 5,
	}

	err := store.CreateAlertRule(ctx, rule)
	if err != nil {
		t.Fatalf("CreateAlertRule failed: %v", err)
	}
	if rule.PeerID != nil {
		t.Errorf("expected PeerID to be nil after normalizing empty string, got %v", rule.PeerID)
	}
}

func TestAlertStore_GetAlertRule_NotFound(t *testing.T) {
	store, _, cleanup := setupAlertStoreTestDB(t)
	defer cleanup()
	ctx := context.Background()

	_, err := store.GetAlertRule(ctx, 99999)
	if err == nil {
		t.Error("expected error for non-existent rule, got nil")
	}
	if err != models.ErrAlertRuleNotFound {
		t.Errorf("expected ErrAlertRuleNotFound, got %v", err)
	}
}

func TestAlertStore_ListAlertRules(t *testing.T) {
	store, _, cleanup := setupAlertStoreTestDB(t)
	defer cleanup()
	ctx := context.Background()

	// Initially empty
	rules, err := store.ListAlertRules(ctx)
	if err != nil {
		t.Fatalf("ListAlertRules failed: %v", err)
	}
	if len(rules) != 0 {
		t.Errorf("expected 0 rules, got %d", len(rules))
	}

	// Create two rules
	for i := 0; i < 2; i++ {
		rule := &models.AlertRule{
			Name:            fmt.Sprintf("Rule %d", i),
			AlertType:       models.AlertTypePeerOffline,
			Enabled:         true,
			ThrottleMinutes: 5,
		}
		if err := store.CreateAlertRule(ctx, rule); err != nil {
			t.Fatalf("CreateAlertRule %d failed: %v", i, err)
		}
	}

	rules, err = store.ListAlertRules(ctx)
	if err != nil {
		t.Fatalf("ListAlertRules failed: %v", err)
	}
	if len(rules) != 2 {
		t.Errorf("expected 2 rules, got %d", len(rules))
	}
}

func TestAlertStore_UpdateAlertRule(t *testing.T) {
	store, _, cleanup := setupAlertStoreTestDB(t)
	defer cleanup()
	ctx := context.Background()

	rule := &models.AlertRule{
		Name:            "Original Name",
		AlertType:       models.AlertTypePeerOffline,
		Enabled:         true,
		ThrottleMinutes: 10,
	}
	if err := store.CreateAlertRule(ctx, rule); err != nil {
		t.Fatalf("CreateAlertRule failed: %v", err)
	}

	rule.Name = "Updated Name"
	rule.Enabled = false
	rule.ThrottleMinutes = 30

	err := store.UpdateAlertRule(ctx, rule)
	if err != nil {
		t.Fatalf("UpdateAlertRule failed: %v", err)
	}

	got, err := store.GetAlertRule(ctx, uint64(rule.ID))
	if err != nil {
		t.Fatalf("GetAlertRule failed: %v", err)
	}
	if got.Name != "Updated Name" {
		t.Errorf("expected name %q, got %q", "Updated Name", got.Name)
	}
	if got.Enabled != false {
		t.Errorf("expected enabled false, got %v", got.Enabled)
	}
	if got.ThrottleMinutes != 30 {
		t.Errorf("expected throttle_minutes 30, got %d", got.ThrottleMinutes)
	}
}

func TestAlertStore_UpdateAlertRule_NotFound(t *testing.T) {
	store, _, cleanup := setupAlertStoreTestDB(t)
	defer cleanup()
	ctx := context.Background()

	rule := &models.AlertRule{
		ID:   99999,
		Name: "Nonexistent",
	}

	err := store.UpdateAlertRule(ctx, rule)
	if err == nil {
		t.Error("expected error for updating non-existent rule, got nil")
	}
	if err != models.ErrAlertRuleNotFound {
		t.Errorf("expected ErrAlertRuleNotFound, got %v", err)
	}
}

func TestAlertStore_CreateAndGetAlertHistory(t *testing.T) {
	store, _, cleanup := setupAlertStoreTestDB(t)
	defer cleanup()
	ctx := context.Background()

	// Create a rule first
	rule := &models.AlertRule{
		Name:            "History Test Rule",
		AlertType:       models.AlertTypePeerOffline,
		Enabled:         true,
		ThrottleMinutes: 5,
	}
	if err := store.CreateAlertRule(ctx, rule); err != nil {
		t.Fatalf("CreateAlertRule failed: %v", err)
	}

	peerID := "1"
	history := &models.AlertHistory{
		RuleID:    rule.ID,
		AlertType: models.AlertTypePeerOffline,
		PeerID:    &peerID,
		Severity:  models.SeverityWarning,
		Subject:   "Peer offline",
		Message:   "Peer has been offline for 60 minutes",
		Status:    models.AlertStatusPending,
	}

	err := store.CreateAlertHistory(ctx, history)
	if err != nil {
		t.Fatalf("CreateAlertHistory failed: %v", err)
	}
	if history.ID == 0 {
		t.Error("expected history ID to be set after creation")
	}

	got, err := store.GetAlertHistory(ctx, int(history.ID))
	if err != nil {
		t.Fatalf("GetAlertHistory failed: %v", err)
	}
	if got.Subject != history.Subject {
		t.Errorf("expected subject %q, got %q", history.Subject, got.Subject)
	}
	if got.Status != models.AlertStatusPending {
		t.Errorf("expected status %q, got %q", models.AlertStatusPending, got.Status)
	}
}

func TestAlertStore_GetAlertHistory_NotFound(t *testing.T) {
	store, _, cleanup := setupAlertStoreTestDB(t)
	defer cleanup()
	ctx := context.Background()

	_, err := store.GetAlertHistory(ctx, 99999)
	if err == nil {
		t.Error("expected error for non-existent history, got nil")
	}
	if err != models.ErrAlertHistoryNotFound {
		t.Errorf("expected ErrAlertHistoryNotFound, got %v", err)
	}
}

func TestAlertStore_ListAlertHistory(t *testing.T) {
	store, _, cleanup := setupAlertStoreTestDB(t)
	defer cleanup()
	ctx := context.Background()

	// Create a rule
	rule := &models.AlertRule{
		Name:            "List History Rule",
		AlertType:       models.AlertTypePeerOffline,
		Enabled:         true,
		ThrottleMinutes: 5,
	}
	if err := store.CreateAlertRule(ctx, rule); err != nil {
		t.Fatalf("CreateAlertRule failed: %v", err)
	}

	// Create alert history entries
	for i := 0; i < 3; i++ {
		history := &models.AlertHistory{
			RuleID:    rule.ID,
			AlertType: models.AlertTypePeerOffline,
			Severity:  models.SeverityWarning,
			Subject:   fmt.Sprintf("Alert %d", i),
			Message:   "Test message",
			Status:    models.AlertStatusPending,
		}
		if err := store.CreateAlertHistory(ctx, history); err != nil {
			t.Fatalf("CreateAlertHistory %d failed: %v", i, err)
		}
	}

	// List with pagination
	result, err := store.ListAlertHistory(ctx, &models.AlertHistoryFilter{Limit: 2, Offset: 0})
	if err != nil {
		t.Fatalf("ListAlertHistory failed: %v", err)
	}
	if result.Total != 3 {
		t.Errorf("expected total 3, got %d", result.Total)
	}
	if len(result.Alerts) != 2 {
		t.Errorf("expected 2 alerts on page, got %d", len(result.Alerts))
	}
	if result.Limit != 2 {
		t.Errorf("expected limit 2, got %d", result.Limit)
	}
}

func TestAlertStore_ListAlertHistory_FilterByStatus(t *testing.T) {
	store, _, cleanup := setupAlertStoreTestDB(t)
	defer cleanup()
	ctx := context.Background()

	rule := &models.AlertRule{
		Name:            "Filter Status Rule",
		AlertType:       models.AlertTypePeerOffline,
		Enabled:         true,
		ThrottleMinutes: 5,
	}
	if err := store.CreateAlertRule(ctx, rule); err != nil {
		t.Fatalf("CreateAlertRule failed: %v", err)
	}

	// Create one pending and one sent
	for _, status := range []models.AlertStatus{models.AlertStatusPending, models.AlertStatusSent} {
		history := &models.AlertHistory{
			RuleID:    rule.ID,
			AlertType: models.AlertTypePeerOffline,
			Severity:  models.SeverityWarning,
			Subject:   "Subject",
			Message:   "Message",
			Status:    status,
		}
		if err := store.CreateAlertHistory(ctx, history); err != nil {
			t.Fatalf("CreateAlertHistory failed: %v", err)
		}
	}

	result, err := store.ListAlertHistory(ctx, &models.AlertHistoryFilter{Status: "sent"})
	if err != nil {
		t.Fatalf("ListAlertHistory failed: %v", err)
	}
	if result.Total != 1 {
		t.Errorf("expected total 1 for sent filter, got %d", result.Total)
	}
}

func TestAlertStore_DeleteAlertHistory(t *testing.T) {
	store, _, cleanup := setupAlertStoreTestDB(t)
	defer cleanup()
	ctx := context.Background()

	rule := &models.AlertRule{
		Name:            "Delete History Rule",
		AlertType:       models.AlertTypePeerOffline,
		Enabled:         true,
		ThrottleMinutes: 5,
	}
	if err := store.CreateAlertRule(ctx, rule); err != nil {
		t.Fatalf("CreateAlertRule failed: %v", err)
	}

	history := &models.AlertHistory{
		RuleID:    rule.ID,
		AlertType: models.AlertTypePeerOffline,
		Severity:  models.SeverityWarning,
		Subject:   "To delete",
		Message:   "Message",
		Status:    models.AlertStatusPending,
	}
	if err := store.CreateAlertHistory(ctx, history); err != nil {
		t.Fatalf("CreateAlertHistory failed: %v", err)
	}

	err := store.DeleteAlertHistory(ctx, uint64(history.ID))
	if err != nil {
		t.Fatalf("DeleteAlertHistory failed: %v", err)
	}

	_, err = store.GetAlertHistory(ctx, int(history.ID))
	if err == nil {
		t.Error("expected error after deletion, got nil")
	}
}

func TestAlertStore_DeleteAlertHistory_NotFound(t *testing.T) {
	store, _, cleanup := setupAlertStoreTestDB(t)
	defer cleanup()
	ctx := context.Background()

	err := store.DeleteAlertHistory(ctx, 99999)
	if err == nil {
		t.Error("expected error for deleting non-existent history, got nil")
	}
	if err != models.ErrAlertHistoryNotFound {
		t.Errorf("expected ErrAlertHistoryNotFound, got %v", err)
	}
}

func TestAlertStore_ClearAllAlertHistory(t *testing.T) {
	store, _, cleanup := setupAlertStoreTestDB(t)
	defer cleanup()
	ctx := context.Background()

	rule := &models.AlertRule{
		Name:            "Clear All Rule",
		AlertType:       models.AlertTypePeerOffline,
		Enabled:         true,
		ThrottleMinutes: 5,
	}
	if err := store.CreateAlertRule(ctx, rule); err != nil {
		t.Fatalf("CreateAlertRule failed: %v", err)
	}

	for i := 0; i < 5; i++ {
		history := &models.AlertHistory{
			RuleID:    rule.ID,
			AlertType: models.AlertTypePeerOffline,
			Severity:  models.SeverityWarning,
			Subject:   "Alert",
			Message:   "Message",
			Status:    models.AlertStatusPending,
		}
		if err := store.CreateAlertHistory(ctx, history); err != nil {
			t.Fatalf("CreateAlertHistory %d failed: %v", i, err)
		}
	}

	err := store.ClearAllAlertHistory(ctx)
	if err != nil {
		t.Fatalf("ClearAllAlertHistory failed: %v", err)
	}

	result, err := store.ListAlertHistory(ctx, &models.AlertHistoryFilter{})
	if err != nil {
		t.Fatalf("ListAlertHistory failed: %v", err)
	}
	if result.Total != 0 {
		t.Errorf("expected 0 total after clear, got %d", result.Total)
	}
}

func TestAlertStore_GetEnabledAlertRulesByType(t *testing.T) {
	store, _, cleanup := setupAlertStoreTestDB(t)
	defer cleanup()
	ctx := context.Background()

	// Create enabled and disabled rules of different types
	rules := []struct {
		name      string
		alertType models.AlertType
		enabled   bool
	}{
		{"Offline Enabled", models.AlertTypePeerOffline, true},
		{"Offline Disabled", models.AlertTypePeerOffline, false},
		{"Spike Enabled", models.AlertTypeBlockedSpike, true},
	}
	for _, r := range rules {
		rule := &models.AlertRule{
			Name:            r.name,
			AlertType:       r.alertType,
			Enabled:         r.enabled,
			ThrottleMinutes: 5,
		}
		if err := store.CreateAlertRule(ctx, rule); err != nil {
			t.Fatalf("CreateAlertRule failed: %v", err)
		}
	}

	enabledOffline, err := store.GetEnabledAlertRulesByType(ctx, models.AlertTypePeerOffline)
	if err != nil {
		t.Fatalf("GetEnabledAlertRulesByType failed: %v", err)
	}
	if len(enabledOffline) != 1 {
		t.Errorf("expected 1 enabled peer_offline rule, got %d", len(enabledOffline))
	}

	enabledSpike, err := store.GetEnabledAlertRulesByType(ctx, models.AlertTypeBlockedSpike)
	if err != nil {
		t.Fatalf("GetEnabledAlertRulesByType failed: %v", err)
	}
	if len(enabledSpike) != 1 {
		t.Errorf("expected 1 enabled blocked_spike rule, got %d", len(enabledSpike))
	}
}

func TestAlertStore_IsAlertThrottled(t *testing.T) {
	store, _, cleanup := setupAlertStoreTestDB(t)
	defer cleanup()
	ctx := context.Background()

	rule := &models.AlertRule{
		Name:            "Throttle Test Rule",
		AlertType:       models.AlertTypePeerOffline,
		Enabled:         true,
		ThrottleMinutes: 60,
	}
	if err := store.CreateAlertRule(ctx, rule); err != nil {
		t.Fatalf("CreateAlertRule failed: %v", err)
	}

	// No history — not throttled
	cutoff := time.Now().Add(-time.Hour)
	throttled, err := store.IsAlertThrottled(ctx, rule.ID, cutoff)
	if err != nil {
		t.Fatalf("IsAlertThrottled failed: %v", err)
	}
	if throttled {
		t.Error("expected not throttled with no history")
	}

	// Create a sent alert within the throttle window
	history := &models.AlertHistory{
		RuleID:    rule.ID,
		AlertType: models.AlertTypePeerOffline,
		Severity:  models.SeverityWarning,
		Subject:   "Recent alert",
		Message:   "Message",
		Status:    models.AlertStatusSent,
	}
	if err := store.CreateAlertHistory(ctx, history); err != nil {
		t.Fatalf("CreateAlertHistory failed: %v", err)
	}

	// Now it should be throttled (cutoff is 1 hour ago, alert was just created)
	throttled, err = store.IsAlertThrottled(ctx, rule.ID, cutoff)
	if err != nil {
		t.Fatalf("IsAlertThrottled failed: %v", err)
	}
	if !throttled {
		t.Error("expected throttled after recent sent alert")
	}
}

func TestAlertStore_SMTPConfig(t *testing.T) {
	store, _, cleanup := setupAlertStoreTestDB(t)
	defer cleanup()
	ctx := context.Background()

	// Initially no config — should return zero values without error
	config, err := store.GetSMTPConfig(ctx)
	if err != nil {
		t.Fatalf("GetSMTPConfig failed: %v", err)
	}
	if config.Enabled {
		t.Error("expected enabled=false for empty config")
	}

	// Upsert settings
	settings := map[string]string{
		"smtp_host":         "smtp.example.com",
		"smtp_port":         "587",
		"smtp_username":     "user@example.com",
		"smtp_password":     "secret",
		"smtp_use_tls":      "1",
		"smtp_from_address": "alerts@example.com",
		"smtp_enabled":      "1",
	}
	err = store.UpsertSMTPSettings(ctx, settings)
	if err != nil {
		t.Fatalf("UpsertSMTPSettings failed: %v", err)
	}

	config, err = store.GetSMTPConfig(ctx)
	if err != nil {
		t.Fatalf("GetSMTPConfig failed: %v", err)
	}
	if config.Host != "smtp.example.com" {
		t.Errorf("expected host %q, got %q", "smtp.example.com", config.Host)
	}
	if config.Port != 587 {
		t.Errorf("expected port 587, got %d", config.Port)
	}
	if !config.Enabled {
		t.Error("expected enabled=true")
	}
	if !config.UseTLS {
		t.Error("expected use_tls=true")
	}
	if config.PasswordSet != true {
		t.Error("expected password_set=true")
	}
}

func TestAlertStore_UserNotificationPreferences(t *testing.T) {
	store, dbConn, cleanup := setupAlertStoreTestDB(t)
	defer cleanup()
	ctx := context.Background()

	// Create a user first
	result, err := dbConn.ExecContext(ctx,
		"INSERT INTO users (username, password_hash, email, role) VALUES (?, ?, ?, ?)",
		"testuser", "hash", "test@example.com", "admin")
	if err != nil {
		t.Fatalf("insert user failed: %v", err)
	}
	userID, _ := result.LastInsertId()

	// No preferences yet — should error
	_, err = store.GetUserNotificationPreferences(ctx, uint(userID))
	if err == nil {
		t.Error("expected error for missing preferences, got nil")
	}

	// Upsert preferences
	prefs := &models.UserNotificationPreferences{
		UserID:             uint(userID),
		QuietHoursEnabled:  true,
		QuietHoursStart:    "22:00",
		QuietHoursEnd:      "07:00",
		QuietHoursTimezone: "UTC",
		DigestEnabled:      false,
		DigestFrequency:    "daily",
		DigestTime:         "09:00",
		DigestTimezone:     "UTC",
	}
	err = store.UpsertUserNotificationPreferences(ctx, prefs)
	if err != nil {
		t.Fatalf("UpsertUserNotificationPreferences failed: %v", err)
	}

	got, err := store.GetUserNotificationPreferences(ctx, uint(userID))
	if err != nil {
		t.Fatalf("GetUserNotificationPreferences failed: %v", err)
	}
	if !got.QuietHoursEnabled {
		t.Error("expected quiet_hours_enabled=true")
	}
	if got.QuietHoursStart != "22:00" {
		t.Errorf("expected quiet_hours_start 22:00, got %s", got.QuietHoursStart)
	}

	// Update (upsert) preferences
	prefs.QuietHoursEnabled = false
	prefs.QuietHoursStart = "23:00"
	err = store.UpsertUserNotificationPreferences(ctx, prefs)
	if err != nil {
		t.Fatalf("UpsertUserNotificationPreferences (update) failed: %v", err)
	}

	got, err = store.GetUserNotificationPreferences(ctx, uint(userID))
	if err != nil {
		t.Fatalf("GetUserNotificationPreferences failed: %v", err)
	}
	if got.QuietHoursEnabled {
		t.Error("expected quiet_hours_enabled=false after update")
	}
	if got.QuietHoursStart != "23:00" {
		t.Errorf("expected quiet_hours_start 23:00, got %s", got.QuietHoursStart)
	}
}

func TestAlertStore_UpdateAlertHistoryStatus(t *testing.T) {
	store, _, cleanup := setupAlertStoreTestDB(t)
	defer cleanup()
	ctx := context.Background()

	rule := &models.AlertRule{
		Name:            "Status Update Rule",
		AlertType:       models.AlertTypePeerOffline,
		Enabled:         true,
		ThrottleMinutes: 5,
	}
	if err := store.CreateAlertRule(ctx, rule); err != nil {
		t.Fatalf("CreateAlertRule failed: %v", err)
	}

	history := &models.AlertHistory{
		RuleID:    rule.ID,
		AlertType: models.AlertTypePeerOffline,
		Severity:  models.SeverityWarning,
		Subject:   "Status test",
		Message:   "Message",
		Status:    models.AlertStatusPending,
	}
	if err := store.CreateAlertHistory(ctx, history); err != nil {
		t.Fatalf("CreateAlertHistory failed: %v", err)
	}

	err := store.UpdateAlertHistoryStatus(ctx, uint64(history.ID), models.AlertStatusSent, "")
	if err != nil {
		t.Fatalf("UpdateAlertHistoryStatus failed: %v", err)
	}

	got, err := store.GetAlertHistory(ctx, int(history.ID))
	if err != nil {
		t.Fatalf("GetAlertHistory failed: %v", err)
	}
	if got.Status != models.AlertStatusSent {
		t.Errorf("expected status %q, got %q", models.AlertStatusSent, got.Status)
	}

	// Update with error message
	err = store.UpdateAlertHistoryStatus(ctx, uint64(history.ID), models.AlertStatusFailed, "connection refused")
	if err != nil {
		t.Fatalf("UpdateAlertHistoryStatus (failed) failed: %v", err)
	}

	got, err = store.GetAlertHistory(ctx, int(history.ID))
	if err != nil {
		t.Fatalf("GetAlertHistory failed: %v", err)
	}
	if got.Status != models.AlertStatusFailed {
		t.Errorf("expected status %q, got %q", models.AlertStatusFailed, got.Status)
	}
}

func TestAlertStore_UpdateAlertHistoryStatus_NotFound(t *testing.T) {
	store, _, cleanup := setupAlertStoreTestDB(t)
	defer cleanup()
	ctx := context.Background()

	err := store.UpdateAlertHistoryStatus(ctx, 99999, models.AlertStatusSent, "")
	if err == nil {
		t.Error("expected error for non-existent history, got nil")
	}
	if err != models.ErrAlertHistoryNotFound {
		t.Errorf("expected ErrAlertHistoryNotFound, got %v", err)
	}
}
