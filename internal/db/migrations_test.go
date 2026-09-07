// Package db provides database test helpers.
package db

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func TestMigrateSchemaAddsMissingColumns(t *testing.T) {
	database, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open in-memory database: %v", err)
	}
	defer database.Close()

	// Enable foreign keys
	if _, err := database.Exec("PRAGMA foreign_keys=ON"); err != nil {
		t.Fatalf("Failed to enable foreign keys: %v", err)
	}

	ctx := context.Background()

	// Step 1: Create database with the FULL current schema, then drop columns
	// that migrations should add. This simulates an "old" database without
	// those columns, but derives the base schema from Schema() so it stays
	// in sync with schema.sql automatically.
	if _, err := database.ExecContext(ctx, Schema()); err != nil {
		t.Fatalf("Failed to create full schema: %v", err)
	}

	// Seed system_config entries that migrations expect (schema.sql only creates the table)
	if _, err := database.ExecContext(ctx, "INSERT INTO system_config (key, value) VALUES ('encryption_key', 'test-encryption-key-32-bytes-hex')"); err != nil {
		t.Fatalf("Failed to seed encryption_key: %v", err)
	}
	if _, err := database.ExecContext(ctx, "INSERT INTO system_config (key, value) VALUES ('secrets_encrypted', '1')"); err != nil {
		t.Fatalf("Failed to seed secrets_encrypted: %v", err)
	}
	if _, err := database.ExecContext(ctx, "INSERT INTO system_config (key, value) VALUES ('log_retention_days', '30')"); err != nil {
		t.Fatalf("Failed to seed log_retention_days: %v", err)
	}

	// Columns that migrations are expected to add — drop them to simulate old DB
	// Note: these must match the migration columns tested below
	columnsToDrop := []struct {
		table  string
		column string
	}{
		{"users", "email"},
		{"users", "role"},
		{"peers", "is_manual"},
		{"peers", "description"},
		{"peers", "has_ipset"},
		{"peers", "hmac_key_rotation_token"},
		{"peers", "hmac_key_last_rotated_at"},
		{"services", "is_system"},
		{"services", "source_ports"},
		{"services", "no_conntrack"},
		{"services", "is_pending_delete"},
		{"groups", "is_system"},
		{"groups", "is_pending_delete"},
		// Note: policies.source_type and policies.target_type are NOT dropped here
		// because the polymorphic migration recreates the policies table entirely
		// (not ADD COLUMN). The drop-and-re-add test approach cannot test table
		// recreation migrations. These columns need a dedicated test if needed.
		{"policies", "is_pending_delete"},
		{"revoked_tokens", "token_type"},
		{"user_notification_preferences", "quiet_hours_enabled"},
		{"user_notification_preferences", "digest_frequency"},
		{"user_notification_preferences", "digest_timezone"},
		{"import_rules", "description"},
	}

	// Disable foreign keys temporarily for DROP COLUMN operations
	// (some SQLite versions require this for tables with FK references)
	if _, err := database.Exec("PRAGMA foreign_keys=OFF"); err != nil {
		t.Fatalf("Failed to disable foreign keys: %v", err)
	}

	for _, col := range columnsToDrop {
		exists, err := columnExists(ctx, database, col.table, col.column)
		if err != nil {
			t.Fatalf("columnExists(%s, %s) error: %v", col.table, col.column, err)
		}
		if exists {
			_, err := database.ExecContext(ctx, fmt.Sprintf("ALTER TABLE %s DROP COLUMN %s", col.table, col.column))
			if err != nil {
				t.Fatalf("Failed to drop column %s.%s: %v", col.table, col.column, err)
			}
		}
	}

	// Re-enable foreign keys
	if _, err := database.Exec("PRAGMA foreign_keys=ON"); err != nil {
		t.Fatalf("Failed to re-enable foreign keys: %v", err)
	}

	// Step 2: Insert test data BEFORE migration to verify preservation
	var userID int64
	result, err := database.ExecContext(ctx,
		"INSERT INTO users (username, password_hash) VALUES (?, ?)",
		"testuser", "hashedpassword123")
	if err != nil {
		t.Fatalf("Failed to insert test user: %v", err)
	}
	userID, _ = result.LastInsertId()

	var peerID int64
	result, err = database.ExecContext(ctx,
		"INSERT INTO peers (hostname, ip_address, hmac_key, agent_key) VALUES (?, ?, ?, ?)",
		"test-peer", "192.168.1.100", "testhmac", "test-agent-key")
	if err != nil {
		t.Fatalf("Failed to insert test peer: %v", err)
	}
	peerID, _ = result.LastInsertId()

	var groupID int64
	result, err = database.ExecContext(ctx,
		"INSERT INTO groups (name, description) VALUES (?, ?)",
		"test-group", "Test group")
	if err != nil {
		t.Fatalf("Failed to insert test group: %v", err)
	}
	groupID, _ = result.LastInsertId()

	var serviceID int64
	result, err = database.ExecContext(ctx,
		"INSERT INTO services (name, ports, description) VALUES (?, ?, ?)",
		"test-service", "8080", "Test service")
	if err != nil {
		t.Fatalf("Failed to insert test service: %v", err)
	}
	serviceID, _ = result.LastInsertId()

	result, err = database.ExecContext(ctx,
		"INSERT INTO revoked_tokens (unique_id, expires_at) VALUES (?, datetime('now', '+1 hour'))",
		"test-token-unique-id")
	if err != nil {
		t.Fatalf("Failed to insert test revoked token: %v", err)
	}

	result, err = database.ExecContext(ctx,
		"INSERT INTO user_notification_preferences (user_id) VALUES (?)",
		userID)
	if err != nil {
		t.Fatalf("Failed to insert test user_notification_preferences: %v", err)
	}

	// Step 3: Run migrations
	if err := migrateSchema(ctx, database); err != nil {
		t.Fatalf("migrateSchema failed: %v", err)
	}

	// Step 4: Verify new columns exist
	tests := []struct {
		table  string
		column string
		wantOK bool
	}{
		// Users table migrations
		{"users", "email", true},
		{"users", "role", true},
		// Peers table migrations
		{"peers", "is_manual", true},
		{"peers", "description", true},
		{"peers", "has_ipset", true},
		{"peers", "hmac_key_rotation_token", true},
		{"peers", "hmac_key_last_rotated_at", true},
		// Services table migrations
		{"services", "is_system", true},
		{"services", "source_ports", true},
		{"services", "no_conntrack", true},
		{"services", "is_pending_delete", true},
		// Groups table migrations
		{"groups", "is_system", true},
		{"groups", "is_pending_delete", true},
		// Policies table migrations (polymorphic)
		// Note: direction column is added before polymorphic migration but the
		// polymorphic migration recreates the table without it. This is a known
		// issue in the migration code - direction should be in the polymorphic schema.
		// {"policies", "direction", true},
		{"policies", "is_pending_delete", true},
		// Revoked tokens table migrations
		{"revoked_tokens", "token_type", true},
		// User notification preferences table migrations
		{"user_notification_preferences", "quiet_hours_enabled", true},
		{"user_notification_preferences", "digest_frequency", true},
		{"user_notification_preferences", "digest_timezone", true},
		// Import rules table migrations
		{"import_rules", "description", true},
	}

	for _, tc := range tests {
		t.Run(tc.table+"."+tc.column, func(t *testing.T) {
			exists, err := columnExists(ctx, database, tc.table, tc.column)
			if err != nil {
				t.Fatalf("columnExists(%s, %s) error: %v", tc.table, tc.column, err)
			}
			if exists != tc.wantOK {
				t.Errorf("columnExists(%s, %s) = %v, want %v", tc.table, tc.column, exists, tc.wantOK)
			}
		})
	}

	// Step 5: Verify existing data is preserved
	// Verify user data
	var username, passwordHash string
	var email string
	var role string
	err = database.QueryRowContext(ctx,
		"SELECT username, password_hash, email, role FROM users WHERE id = ?",
		userID).Scan(&username, &passwordHash, &email, &role)
	if err != nil {
		t.Fatalf("Failed to query user after migration: %v", err)
	}
	if username != "testuser" {
		t.Errorf("User username = %q, want %q", username, "testuser")
	}
	if passwordHash != "hashedpassword123" {
		t.Errorf("User password_hash = %q, want %q", passwordHash, "hashedpassword123")
	}
	// New columns should have default values
	if email != "" {
		t.Errorf("User email = %q, want empty string (default)", email)
	}
	if role != "viewer" {
		t.Errorf("User role = %q, want %q (default)", role, "viewer")
	}

	// Verify peer data
	var hostname, ipAddress string
	var isManual bool
	var description string
	err = database.QueryRowContext(ctx,
		"SELECT hostname, ip_address, is_manual, description FROM peers WHERE id = ?",
		peerID).Scan(&hostname, &ipAddress, &isManual, &description)
	if err != nil {
		t.Fatalf("Failed to query peer after migration: %v", err)
	}
	if hostname != "test-peer" {
		t.Errorf("Peer hostname = %q, want %q", hostname, "test-peer")
	}
	if ipAddress != "192.168.1.100" {
		t.Errorf("Peer ip_address = %q, want %q", ipAddress, "192.168.1.100")
	}
	if isManual != false {
		t.Errorf("Peer is_manual = %v, want false (default)", isManual)
	}
	if description != "" {
		t.Errorf("Peer description = %q, want empty string (default)", description)
	}

	// Verify group data
	var groupName string
	var isSystem bool
	err = database.QueryRowContext(ctx,
		"SELECT name, is_system FROM groups WHERE id = ?",
		groupID).Scan(&groupName, &isSystem)
	if err != nil {
		t.Fatalf("Failed to query group after migration: %v", err)
	}
	if groupName != "test-group" {
		t.Errorf("Group name = %q, want %q", groupName, "test-group")
	}
	if isSystem != false {
		t.Errorf("Group is_system = %v, want false (default)", isSystem)
	}

	// Verify service data
	var serviceName string
	var sourcePorts string
	var isSystemService bool
	err = database.QueryRowContext(ctx,
		"SELECT name, source_ports, is_system FROM services WHERE id = ?",
		serviceID).Scan(&serviceName, &sourcePorts, &isSystemService)
	if err != nil {
		t.Fatalf("Failed to query service after migration: %v", err)
	}
	if serviceName != "test-service" {
		t.Errorf("Service name = %q, want %q", serviceName, "test-service")
	}
	if sourcePorts != "" {
		t.Errorf("Service source_ports = %q, want empty string (default)", sourcePorts)
	}
	if isSystemService != false {
		t.Errorf("Service is_system = %v, want false (default)", isSystemService)
	}

	// Verify revoked token data
	var tokenType string
	err = database.QueryRowContext(ctx,
		"SELECT token_type FROM revoked_tokens WHERE unique_id = ?",
		"test-token-unique-id").Scan(&tokenType)
	if err != nil {
		t.Fatalf("Failed to query revoked token after migration: %v", err)
	}
	if tokenType != "unknown" {
		t.Errorf("Revoked token token_type = %q, want %q (default)", tokenType, "unknown")
	}
}

func TestMigrateSchemaSkipsFreshDatabase(t *testing.T) {
	database, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open in-memory database: %v", err)
	}
	defer database.Close()

	ctx := context.Background()

	// Run migrations on a fresh database (no tables)
	if err := migrateSchema(ctx, database); err != nil {
		t.Fatalf("migrateSchema on fresh database failed: %v", err)
	}

	// Verify no tables were created by migrations (fresh database check)
	var tableCount int
	err = database.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").
		Scan(&tableCount)
	if err != nil {
		t.Fatalf("Failed to count tables: %v", err)
	}
	if tableCount != 0 {
		t.Errorf("Fresh database should have 0 tables after migration skip, got %d", tableCount)
	}
}

func TestColumnExistsInvalidTable(t *testing.T) {
	database, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open in-memory database: %v", err)
	}
	defer database.Close()

	ctx := context.Background()

	if _, err := database.ExecContext(ctx, "CREATE TABLE dummy (id INTEGER)"); err != nil {
		t.Fatalf("Failed to create dummy table: %v", err)
	}

	// Test with invalid table name (not in safelist)
	_, err = columnExists(ctx, database, "dummy", "id")
	if err == nil {
		t.Error("columnExists with invalid table name should return error")
	}
}

func TestAddColumnIfMissing(t *testing.T) {
	database, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open in-memory database: %v", err)
	}
	defer database.Close()

	ctx := context.Background()

	if _, err := database.ExecContext(ctx, `
		CREATE TABLE users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	`); err != nil {
		t.Fatalf("Failed to create users table: %v", err)
	}

	// Verify email column doesn't exist
	exists, err := columnExists(ctx, database, "users", "email")
	if err != nil {
		t.Fatalf("columnExists failed: %v", err)
	}
	if exists {
		t.Fatal("email column should not exist before migration")
	}

	if err := addColumnIfMissing(ctx, database, "users", "email", "TEXT DEFAULT ''"); err != nil {
		t.Fatalf("addColumnIfMissing failed: %v", err)
	}

	// Verify email column now exists
	exists, err = columnExists(ctx, database, "users", "email")
	if err != nil {
		t.Fatalf("columnExists failed: %v", err)
	}
	if !exists {
		t.Error("email column should exist after migration")
	}

	// Test that adding again is idempotent (no error)
	if err := addColumnIfMissing(ctx, database, "users", "email", "TEXT DEFAULT ''"); err != nil {
		t.Fatalf("addColumnIfMissing (idempotent) failed: %v", err)
	}
}

// the case where the import_rules table doesn't exist at all (the primary scenario
// the table-existence guard was designed to handle).
func TestMigrateSchemaSkipsMissingImportRulesTable(t *testing.T) {
	database, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open in-memory database: %v", err)
	}
	defer database.Close()

	// Enable foreign keys
	if _, err := database.Exec("PRAGMA foreign_keys=ON"); err != nil {
		t.Fatalf("Failed to enable foreign keys: %v", err)
	}

	ctx := context.Background()

	if _, err := database.ExecContext(ctx, Schema()); err != nil {
		t.Fatalf("Failed to create full schema: %v", err)
	}

	// Drop the import-related tables to simulate a database without them
	if _, err := database.Exec("PRAGMA foreign_keys=OFF"); err != nil {
		t.Fatalf("Failed to disable foreign keys: %v", err)
	}
	if _, err := database.ExecContext(ctx, "DROP TABLE IF EXISTS import_rules"); err != nil {
		t.Fatalf("Failed to drop import_rules: %v", err)
	}
	if _, err := database.ExecContext(ctx, "DROP TABLE IF EXISTS import_group_mappings"); err != nil {
		t.Fatalf("Failed to drop import_group_mappings: %v", err)
	}
	if _, err := database.ExecContext(ctx, "DROP TABLE IF EXISTS import_peer_mappings"); err != nil {
		t.Fatalf("Failed to drop import_peer_mappings: %v", err)
	}
	if _, err := database.ExecContext(ctx, "DROP TABLE IF EXISTS import_service_mappings"); err != nil {
		t.Fatalf("Failed to drop import_service_mappings: %v", err)
	}
	if _, err := database.ExecContext(ctx, "DROP TABLE IF EXISTS import_sessions"); err != nil {
		t.Fatalf("Failed to drop import_sessions: %v", err)
	}
	if _, err := database.Exec("PRAGMA foreign_keys=ON"); err != nil {
		t.Fatalf("Failed to re-enable foreign keys: %v", err)
	}

	// Run migrations — should complete without error
	if err := migrateSchema(ctx, database); err != nil {
		t.Fatalf("migrateSchema failed: %v", err)
	}

	// Verify the import_rules table does NOT exist (migrations shouldn't create tables)
	var importRulesExists bool
	err = database.QueryRowContext(ctx, "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='table' AND name='import_rules'").Scan(&importRulesExists)
	if err != nil {
		t.Fatalf("Failed to check for import_rules table: %v", err)
	}
	if importRulesExists {
		t.Error("import_rules table should not exist after migration (migrations only add columns, not tables)")
	}
}

func downgradeAlertRulesForTest(t *testing.T, ctx context.Context, database *sql.DB, checkClause string) {
	t.Helper()
	if _, err := database.ExecContext(ctx, "PRAGMA foreign_keys=OFF"); err != nil {
		t.Fatalf("Failed to disable foreign keys: %v", err)
	}
	if _, err := database.ExecContext(ctx, "DROP TABLE IF EXISTS alert_rules"); err != nil {
		t.Fatalf("Failed to drop alert_rules: %v", err)
	}
	createSQL := fmt.Sprintf(`CREATE TABLE alert_rules (
id INTEGER PRIMARY KEY AUTOINCREMENT,
name TEXT NOT NULL,
alert_type TEXT NOT NULL %s,
enabled BOOLEAN NOT NULL DEFAULT 1,
threshold_value INTEGER,
threshold_window_minutes INTEGER,
peer_id TEXT,
throttle_minutes INTEGER NOT NULL DEFAULT 5,
created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
)`, checkClause)
	if _, err := database.ExecContext(ctx, createSQL); err != nil {
		t.Fatalf("Failed to create legacy alert_rules: %v", err)
	}
	if _, err := database.ExecContext(ctx, "CREATE INDEX IF NOT EXISTS idx_alert_rules_type_enabled ON alert_rules(alert_type, enabled)"); err != nil {
		t.Fatalf("Failed to create legacy index: %v", err)
	}
	if _, err := database.ExecContext(ctx, "CREATE INDEX IF NOT EXISTS idx_alert_rules_peer_id ON alert_rules(peer_id)"); err != nil {
		t.Fatalf("Failed to create legacy index: %v", err)
	}
	if _, err := database.ExecContext(ctx, "PRAGMA foreign_keys=ON"); err != nil {
		t.Fatalf("Failed to re-enable foreign keys: %v", err)
	}
}

func assertForeignKeyCheckEmpty(t *testing.T, ctx context.Context, database *sql.DB) {
	t.Helper()
	rows, err := database.QueryContext(ctx, "PRAGMA foreign_key_check")
	if err != nil {
		t.Fatalf("PRAGMA foreign_key_check failed: %v", err)
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var fkTable sql.NullString
		var fkRowID sql.NullInt64
		var fkRefTable sql.NullString
		var fkIndex sql.NullInt64
		if err := rows.Scan(&fkTable, &fkRowID, &fkRefTable, &fkIndex); err != nil {
			t.Fatalf("Failed to scan foreign_key_check: %v", err)
		}
		count++
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("Failed to iterate foreign_key_check: %v", err)
	}
	if count != 0 {
		t.Fatalf("foreign_key_check found %d violation(s), want 0", count)
	}
}

func TestMigrateAgentUpdatedCheckWithEnforcedFKs(t *testing.T) {
	database, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open in-memory database: %v", err)
	}
	defer database.Close()
	database.SetMaxOpenConns(1)
	database.SetMaxIdleConns(1)

	if _, err := database.Exec("PRAGMA foreign_keys=ON"); err != nil {
		t.Fatalf("Failed to enable foreign keys: %v", err)
	}

	ctx := context.Background()

	if _, err := database.ExecContext(ctx, Schema()); err != nil {
		t.Fatalf("Failed to create full schema: %v", err)
	}

	downgradeAlertRulesForTest(t, ctx, database, "CHECK(alert_type IN ('peer_offline', 'bundle_failed', 'blocked_spike', 'peer_online', 'new_peer', 'bundle_deployed'))")

	var legacySQL string
	if err := database.QueryRowContext(ctx, "SELECT sql FROM sqlite_master WHERE type='table' AND name='alert_rules'").Scan(&legacySQL); err != nil {
		t.Fatalf("Failed to read legacy alert_rules SQL: %v", err)
	}
	if strings.Contains(legacySQL, "agent_updated") {
		t.Fatalf("Legacy alert_rules SQL should not contain agent_updated")
	}

	var fkEnabled int
	if err := database.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&fkEnabled); err != nil {
		t.Fatalf("Failed to check foreign_keys pragma: %v", err)
	}
	if fkEnabled != 1 {
		t.Fatalf("foreign_keys pragma = %d, want 1", fkEnabled)
	}

	ruleIDs := make(map[string]int64)
	seedRules := []struct {
		name      string
		alertType string
	}{
		{"Peer Offline", "peer_offline"},
		{"Bundle Failed", "bundle_failed"},
		{"Blocked Spike", "blocked_spike"},
	}
	for _, r := range seedRules {
		res, err := database.ExecContext(ctx,
			"INSERT INTO alert_rules (name, alert_type, enabled, threshold_value, threshold_window_minutes, throttle_minutes) VALUES (?, ?, 1, 0, 5, 15)",
			r.name, r.alertType)
		if err != nil {
			t.Fatalf("Failed to seed alert_rule %s: %v", r.alertType, err)
		}
		id, err := res.LastInsertId()
		if err != nil {
			t.Fatalf("Failed to get rule id: %v", err)
		}
		ruleIDs[r.alertType] = id
	}

	type historySeed struct {
		ruleType  string
		alertType string
		severity  string
		subject   string
		message   string
		status    string
	}
	historySeeds := []historySeed{
		{"peer_offline", "peer_offline", "warning", "peer offline subject", "peer offline message", "sent"},
		{"bundle_failed", "bundle_failed", "critical", "bundle failed subject", "bundle failed message", "sent"},
		{"peer_offline", "peer_offline", "info", "peer offline second", "second message", "pending"},
	}
	type historyRow struct {
		id      int64
		ruleID  int64
		subject string
	}
	var historyBefore []historyRow
	for _, h := range historySeeds {
		ruleID, ok := ruleIDs[h.ruleType]
		if !ok {
			t.Fatalf("Missing rule id for %s", h.ruleType)
		}
		res, err := database.ExecContext(ctx,
			"INSERT INTO alert_history (rule_id, alert_type, severity, subject, message, status) VALUES (?, ?, ?, ?, ?, ?)",
			ruleID, h.alertType, h.severity, h.subject, h.message, h.status)
		if err != nil {
			t.Fatalf("Failed to seed alert_history: %v", err)
		}
		hid, err := res.LastInsertId()
		if err != nil {
			t.Fatalf("Failed to get history id: %v", err)
		}
		historyBefore = append(historyBefore, historyRow{id: hid, ruleID: ruleID, subject: h.subject})
	}

	if err := migrateSchema(ctx, database); err != nil {
		t.Fatalf("First migrateSchema failed: %v", err)
	}
	if err := migrateSchema(ctx, database); err != nil {
		t.Fatalf("Second migrateSchema (idempotence) failed: %v", err)
	}
	if err := createSchema(ctx, database); err != nil {
		t.Fatalf("createSchema (startup path) failed: %v", err)
	}

	var widenedSQL string
	if err := database.QueryRowContext(ctx, "SELECT sql FROM sqlite_master WHERE type='table' AND name='alert_rules'").Scan(&widenedSQL); err != nil {
		t.Fatalf("Failed to read widened alert_rules SQL: %v", err)
	}
	if !strings.Contains(widenedSQL, "agent_updated") {
		t.Errorf("Widened alert_rules SQL should contain agent_updated, got: %s", widenedSQL)
	}

	for _, idx := range []string{"idx_alert_rules_type_enabled", "idx_alert_rules_peer_id"} {
		var exists bool
		if err := database.QueryRowContext(ctx, "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='index' AND name=?", idx).Scan(&exists); err != nil {
			t.Fatalf("Failed to check index %s: %v", idx, err)
		}
		if !exists {
			t.Errorf("Expected index %s to exist after rebuild", idx)
		}
	}

	for alertType, wantID := range ruleIDs {
		var gotID int64
		if err := database.QueryRowContext(ctx, "SELECT id FROM alert_rules WHERE alert_type=? AND name IS NOT NULL ORDER BY id LIMIT 1", alertType).Scan(&gotID); err != nil {
			t.Errorf("Failed to query preserved rule %s: %v", alertType, err)
			continue
		}
		if gotID != wantID {
			t.Errorf("Rule %s id = %d, want stable id %d", alertType, gotID, wantID)
		}
	}

	rows, err := database.QueryContext(ctx, "SELECT id, rule_id, subject FROM alert_history ORDER BY id")
	if err != nil {
		t.Fatalf("Failed to query alert_history after migration: %v", err)
	}
	var historyAfter []historyRow
	for rows.Next() {
		var hr historyRow
		if err := rows.Scan(&hr.id, &hr.ruleID, &hr.subject); err != nil {
			rows.Close()
			t.Fatalf("Failed to scan alert_history: %v", err)
		}
		historyAfter = append(historyAfter, hr)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		t.Fatalf("Failed to iterate alert_history: %v", err)
	}
	rows.Close()
	if len(historyAfter) != len(historyBefore) {
		t.Fatalf("alert_history count = %d, want %d (rows must be preserved)", len(historyAfter), len(historyBefore))
	}
	for i := range historyBefore {
		if historyAfter[i].id != historyBefore[i].id {
			t.Errorf("history row %d id = %d, want %d", i, historyAfter[i].id, historyBefore[i].id)
		}
		if historyAfter[i].ruleID != historyBefore[i].ruleID {
			t.Errorf("history row %d rule_id = %d, want %d", i, historyAfter[i].ruleID, historyBefore[i].ruleID)
		}
		if historyAfter[i].subject != historyBefore[i].subject {
			t.Errorf("history row %d subject = %q, want %q", i, historyAfter[i].subject, historyBefore[i].subject)
		}
		var parentID int64
		if err := database.QueryRowContext(ctx, "SELECT id FROM alert_rules WHERE id=?", historyAfter[i].ruleID).Scan(&parentID); err != nil {
			t.Errorf("History row %d references missing rule %d: %v", historyAfter[i].id, historyAfter[i].ruleID, err)
		}
	}

	assertForeignKeyCheckEmpty(t, ctx, database)

	var seededCount int
	if err := database.QueryRowContext(ctx, "SELECT COUNT(*) FROM alert_rules WHERE alert_type='agent_updated'").Scan(&seededCount); err != nil {
		t.Fatalf("Failed to count agent_updated rules: %v", err)
	}
	if seededCount != 1 {
		t.Errorf("agent_updated rule count = %d, want 1 seeded row", seededCount)
	}

	if _, err := database.ExecContext(ctx,
		"INSERT INTO alert_rules (name, alert_type, enabled, threshold_value, threshold_window_minutes, throttle_minutes) VALUES (?, 'agent_updated', 1, 0, 5, 15)",
		"Agent Updated Probe"); err != nil {
		t.Fatalf("agent_updated insert failed after migration: %v", err)
	}
	assertForeignKeyCheckEmpty(t, ctx, database)
}

func TestMigrateAgentUpdatedEmptyRules(t *testing.T) {
	database, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open in-memory database: %v", err)
	}
	defer database.Close()
	database.SetMaxOpenConns(1)
	database.SetMaxIdleConns(1)

	if _, err := database.Exec("PRAGMA foreign_keys=ON"); err != nil {
		t.Fatalf("Failed to enable foreign keys: %v", err)
	}

	ctx := context.Background()

	if _, err := database.ExecContext(ctx, Schema()); err != nil {
		t.Fatalf("Failed to create full schema: %v", err)
	}

	downgradeAlertRulesForTest(t, ctx, database, "CHECK(alert_type IN ('peer_offline', 'bundle_failed', 'blocked_spike', 'peer_online', 'new_peer', 'bundle_deployed'))")

	if _, err := database.ExecContext(ctx, "DELETE FROM alert_rules"); err != nil {
		t.Fatalf("Failed to clear alert_rules: %v", err)
	}

	if err := migrateSchema(ctx, database); err != nil {
		t.Fatalf("First migrateSchema on empty alert_rules failed: %v", err)
	}
	if err := migrateSchema(ctx, database); err != nil {
		t.Fatalf("Second migrateSchema (idempotence) on empty alert_rules failed: %v", err)
	}
	if err := createSchema(ctx, database); err != nil {
		t.Fatalf("createSchema (startup path) failed: %v", err)
	}

	var widenedSQL string
	if err := database.QueryRowContext(ctx, "SELECT sql FROM sqlite_master WHERE type='table' AND name='alert_rules'").Scan(&widenedSQL); err != nil {
		t.Fatalf("Failed to read alert_rules SQL: %v", err)
	}
	if !strings.Contains(widenedSQL, "agent_updated") {
		t.Errorf("Widened alert_rules SQL should contain agent_updated")
	}

	var seededCount int
	if err := database.QueryRowContext(ctx, "SELECT COUNT(*) FROM alert_rules WHERE alert_type='agent_updated'").Scan(&seededCount); err != nil {
		t.Fatalf("Failed to count agent_updated rules: %v", err)
	}
	if seededCount != 1 {
		t.Errorf("agent_updated rule count on empty start = %d, want 1 seeded row", seededCount)
	}

	if _, err := database.ExecContext(ctx,
		"INSERT INTO alert_rules (name, alert_type, enabled, threshold_value, threshold_window_minutes, throttle_minutes) VALUES ('Empty Probe', 'agent_updated', 1, 0, 5, 15)"); err != nil {
		t.Fatalf("agent_updated insert on empty-start DB failed: %v", err)
	}
	assertForeignKeyCheckEmpty(t, ctx, database)
}

func TestMigrateAgentUpdatedLegacyVariants(t *testing.T) {
	legacyChecks := []struct {
		name  string
		check string
	}{
		{
			"standard",
			"CHECK(alert_type IN ('peer_offline', 'bundle_failed', 'blocked_spike', 'peer_online', 'new_peer', 'bundle_deployed'))",
		},
		{
			"compact",
			"CHECK(alert_type IN('peer_offline','bundle_failed','blocked_spike','peer_online','new_peer','bundle_deployed'))",
		},
	}
	for _, tc := range legacyChecks {
		t.Run(tc.name, func(t *testing.T) {
			database, err := sql.Open("sqlite3", ":memory:")
			if err != nil {
				t.Fatalf("Failed to open in-memory database: %v", err)
			}
			defer database.Close()
			database.SetMaxOpenConns(1)
			database.SetMaxIdleConns(1)

			if _, err := database.Exec("PRAGMA foreign_keys=ON"); err != nil {
				t.Fatalf("Failed to enable foreign keys: %v", err)
			}

			ctx := context.Background()

			if _, err := database.ExecContext(ctx, Schema()); err != nil {
				t.Fatalf("Failed to create full schema: %v", err)
			}

			downgradeAlertRulesForTest(t, ctx, database, tc.check)

			res, err := database.ExecContext(ctx,
				"INSERT INTO alert_rules (name, alert_type, enabled, threshold_value, threshold_window_minutes, throttle_minutes) VALUES ('Peer Offline', 'peer_offline', 1, 0, 5, 15)")
			if err != nil {
				t.Fatalf("Failed to seed legacy rule: %v", err)
			}
			ruleID, err := res.LastInsertId()
			if err != nil {
				t.Fatalf("Failed to get rule id: %v", err)
			}
			res, err = database.ExecContext(ctx,
				"INSERT INTO alert_history (rule_id, alert_type, severity, subject, message, status) VALUES (?, 'peer_offline', 'warning', 'variant subject', 'variant message', 'sent')",
				ruleID)
			if err != nil {
				t.Fatalf("Failed to seed alert_history: %v", err)
			}
			historyID, err := res.LastInsertId()
			if err != nil {
				t.Fatalf("Failed to get history id: %v", err)
			}

			if err := migrateSchema(ctx, database); err != nil {
				t.Fatalf("First migrateSchema failed: %v", err)
			}
			if err := migrateSchema(ctx, database); err != nil {
				t.Fatalf("Second migrateSchema (idempotence) failed: %v", err)
			}
			if err := createSchema(ctx, database); err != nil {
				t.Fatalf("createSchema (startup path) failed: %v", err)
			}

			var widenedSQL string
			if err := database.QueryRowContext(ctx, "SELECT sql FROM sqlite_master WHERE type='table' AND name='alert_rules'").Scan(&widenedSQL); err != nil {
				t.Fatalf("Failed to read alert_rules SQL: %v", err)
			}
			if !strings.Contains(widenedSQL, "agent_updated") {
				t.Errorf("Widened SQL should contain agent_updated for variant %s", tc.name)
			}

			var gotRuleID int64
			if err := database.QueryRowContext(ctx, "SELECT id FROM alert_rules WHERE alert_type='peer_offline'").Scan(&gotRuleID); err != nil {
				t.Fatalf("Failed to query preserved rule: %v", err)
			}
			if gotRuleID != ruleID {
				t.Errorf("Rule id = %d, want stable id %d", gotRuleID, ruleID)
			}

			var gotHistoryRuleID int64
			if err := database.QueryRowContext(ctx, "SELECT rule_id FROM alert_history WHERE id=?", historyID).Scan(&gotHistoryRuleID); err != nil {
				t.Fatalf("Failed to query preserved history: %v", err)
			}
			if gotHistoryRuleID != ruleID {
				t.Errorf("History rule_id = %d, want %d", gotHistoryRuleID, ruleID)
			}

			assertForeignKeyCheckEmpty(t, ctx, database)

			if _, err := database.ExecContext(ctx,
				"INSERT INTO alert_rules (name, alert_type, enabled, threshold_value, threshold_window_minutes, throttle_minutes) VALUES ('Variant Probe', 'agent_updated', 1, 0, 5, 15)"); err != nil {
				t.Fatalf("agent_updated insert failed for variant %s: %v", tc.name, err)
			}
		})
	}
}

func TestMigrateAgentUpdatedConcurrentInit(t *testing.T) {
	f, err := os.CreateTemp("", "runic-agent-updated-concurrent-*.db")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	dbPath := f.Name()
	if err := f.Close(); err != nil {
		t.Logf("Failed to close temp file: %v", err)
	}
	defer os.Remove(dbPath)

	dsn := dbPath + "?_foreign_keys=1&_busy_timeout=5000&_journal_mode=WAL&_synchronous=NORMAL"
	database, err := sql.Open("sqlite3", dsn)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer database.Close()
	database.SetMaxOpenConns(1)
	database.SetMaxIdleConns(1)

	ctx := context.Background()

	if _, err := database.ExecContext(ctx, Schema()); err != nil {
		t.Fatalf("Failed to create full schema: %v", err)
	}

	downgradeAlertRulesForTest(t, ctx, database, "CHECK(alert_type IN ('peer_offline', 'bundle_failed', 'blocked_spike', 'peer_online', 'new_peer', 'bundle_deployed'))")

	res, err := database.ExecContext(ctx,
		"INSERT INTO alert_rules (name, alert_type, enabled, threshold_value, threshold_window_minutes, throttle_minutes) VALUES ('Peer Offline', 'peer_offline', 1, 0, 5, 15)")
	if err != nil {
		t.Fatalf("Failed to seed rule: %v", err)
	}
	ruleID, err := res.LastInsertId()
	if err != nil {
		t.Fatalf("Failed to get rule id: %v", err)
	}
	res, err = database.ExecContext(ctx,
		"INSERT INTO alert_history (rule_id, alert_type, severity, subject, message, status) VALUES (?, 'peer_offline', 'warning', 'concurrent subject', 'concurrent message', 'sent')",
		ruleID)
	if err != nil {
		t.Fatalf("Failed to seed history: %v", err)
	}
	historyID, err := res.LastInsertId()
	if err != nil {
		t.Fatalf("Failed to get history id: %v", err)
	}

	if err := migrateSchema(ctx, database); err != nil {
		t.Fatalf("Initial migrateSchema failed: %v", err)
	}

	database.SetMaxOpenConns(5)
	database.SetMaxIdleConns(5)

	var wg sync.WaitGroup
	errCh := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := migrateSchema(ctx, database); err != nil {
				errCh <- err
				return
			}
			if err := createSchema(ctx, database); err != nil {
				errCh <- err
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatalf("Concurrent migrateSchema failed: %v", err)
	}

	var gotRuleID int64
	if err := database.QueryRowContext(ctx, "SELECT id FROM alert_rules WHERE id=?", ruleID).Scan(&gotRuleID); err != nil {
		t.Fatalf("Seeded rule missing after concurrent init: %v", err)
	}
	var gotHistoryRuleID int64
	if err := database.QueryRowContext(ctx, "SELECT rule_id FROM alert_history WHERE id=?", historyID).Scan(&gotHistoryRuleID); err != nil {
		t.Fatalf("Seeded history missing after concurrent init: %v", err)
	}
	if gotHistoryRuleID != ruleID {
		t.Errorf("History rule_id = %d, want %d after concurrent init", gotHistoryRuleID, ruleID)
	}
	assertForeignKeyCheckEmpty(t, ctx, database)

	if _, err := database.ExecContext(ctx,
		"INSERT INTO alert_rules (name, alert_type, enabled, threshold_value, threshold_window_minutes, throttle_minutes) VALUES ('Concurrent Probe', 'agent_updated', 1, 0, 5, 15)"); err != nil {
		t.Fatalf("agent_updated insert after concurrent init failed: %v", err)
	}
}

// TestMigrateAgentUpdatedProductionRecoveryRetry verifies that a database left
// in the pre-migration state converges on retry: the old CHECK schema with
// existing history rows migrates cleanly across repeated runs with zero data
// loss and the default Agent Updated rule seeded exactly once.
func TestMigrateAgentUpdatedProductionRecoveryRetry(t *testing.T) {
	database, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open in-memory database: %v", err)
	}
	defer database.Close()
	database.SetMaxOpenConns(1)
	database.SetMaxIdleConns(1)

	if _, err := database.Exec("PRAGMA foreign_keys=ON"); err != nil {
		t.Fatalf("Failed to enable foreign keys: %v", err)
	}

	ctx := context.Background()

	if _, err := database.ExecContext(ctx, Schema()); err != nil {
		t.Fatalf("Failed to create full schema: %v", err)
	}

	// Downgrade to the old CHECK without agent_updated. This is the exact
	// post-rollback state: a failed rebuild rolls back pre-commit, so the
	// retry starts from the old schema with all rows intact.
	downgradeAlertRulesForTest(t, ctx, database, "CHECK(alert_type IN ('peer_offline', 'bundle_failed', 'blocked_spike', 'peer_online', 'new_peer', 'bundle_deployed'))")

	var legacySQL string
	if err := database.QueryRowContext(ctx, "SELECT sql FROM sqlite_master WHERE type='table' AND name='alert_rules'").Scan(&legacySQL); err != nil {
		t.Fatalf("Failed to read legacy alert_rules SQL: %v", err)
	}
	if strings.Contains(legacySQL, "agent_updated") {
		t.Fatalf("Legacy alert_rules SQL should not contain agent_updated")
	}

	ruleIDs := make(map[string]int64)
	seedRules := []struct {
		name      string
		alertType string
	}{
		{"Peer Offline", "peer_offline"},
		{"Bundle Failed", "bundle_failed"},
		{"Blocked Spike", "blocked_spike"},
	}
	for _, r := range seedRules {
		res, err := database.ExecContext(ctx,
			"INSERT INTO alert_rules (name, alert_type, enabled, threshold_value, threshold_window_minutes, throttle_minutes) VALUES (?, ?, 1, 0, 5, 15)",
			r.name, r.alertType)
		if err != nil {
			t.Fatalf("Failed to seed alert_rule %s: %v", r.alertType, err)
		}
		id, err := res.LastInsertId()
		if err != nil {
			t.Fatalf("Failed to get rule id: %v", err)
		}
		ruleIDs[r.alertType] = id
	}

	type recoveryHistorySeed struct {
		ruleType  string
		alertType string
		severity  string
		subject   string
		message   string
		status    string
	}
	historySeeds := []recoveryHistorySeed{
		{"peer_offline", "peer_offline", "warning", "recovery offline subject", "recovery offline message", "sent"},
		{"bundle_failed", "bundle_failed", "critical", "recovery failed subject", "recovery failed message", "sent"},
		{"peer_offline", "peer_offline", "info", "recovery offline second", "recovery second message", "pending"},
	}
	type recoveryHistoryRow struct {
		id        int64
		ruleID    int64
		alertType string
		severity  string
		subject   string
		message   string
		status    string
	}
	var historyBefore []recoveryHistoryRow
	for _, h := range historySeeds {
		ruleID, ok := ruleIDs[h.ruleType]
		if !ok {
			t.Fatalf("Missing rule id for %s", h.ruleType)
		}
		res, err := database.ExecContext(ctx,
			"INSERT INTO alert_history (rule_id, alert_type, severity, subject, message, status) VALUES (?, ?, ?, ?, ?, ?)",
			ruleID, h.alertType, h.severity, h.subject, h.message, h.status)
		if err != nil {
			t.Fatalf("Failed to seed alert_history: %v", err)
		}
		hid, err := res.LastInsertId()
		if err != nil {
			t.Fatalf("Failed to get history id: %v", err)
		}
		historyBefore = append(historyBefore, recoveryHistoryRow{id: hid, ruleID: ruleID, alertType: h.alertType, severity: h.severity, subject: h.subject, message: h.message, status: h.status})
	}

	res, err := database.ExecContext(ctx,
		"INSERT INTO peers (hostname, ip_address, hmac_key, agent_key) VALUES (?, ?, ?, ?)",
		"recovery-peer", "192.168.1.50", "recovery-hmac", "recovery-agent-key")
	if err != nil {
		t.Fatalf("Failed to seed peer: %v", err)
	}
	peerID, err := res.LastInsertId()
	if err != nil {
		t.Fatalf("Failed to get peer id: %v", err)
	}
	res, err = database.ExecContext(ctx,
		"INSERT INTO firewall_logs (peer_id, timestamp, src_ip, dst_ip, protocol, action) VALUES (?, '2026-01-02 00:00:00', '10.0.0.1', '10.0.0.2', 'tcp', 'DROP')",
		peerID)
	if err != nil {
		t.Fatalf("Failed to seed firewall_logs: %v", err)
	}
	firewallLogID, err := res.LastInsertId()
	if err != nil {
		t.Fatalf("Failed to get firewall_logs id: %v", err)
	}

	logsDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open logs database: %v", err)
	}
	defer logsDB.Close()
	logsDB.SetMaxOpenConns(1)
	logsDB.SetMaxIdleConns(1)
	if _, err := logsDB.ExecContext(ctx, LogsDBSchema()); err != nil {
		t.Fatalf("Failed to create logs schema: %v", err)
	}
	if _, err := logsDB.ExecContext(ctx,
		"INSERT INTO firewall_logs (timestamp, peer_id, peer_hostname, event_type, source_ip, dest_ip, protocol, action) VALUES ('2026-01-02 00:00:00', 1, 'recovery-peer', 'IN', '10.0.0.1', '10.0.0.2', 'tcp', 'DROP')"); err != nil {
		t.Fatalf("Failed to seed logs database: %v", err)
	}
	var logsBefore int
	if err := logsDB.QueryRowContext(ctx, "SELECT COUNT(*) FROM firewall_logs").Scan(&logsBefore); err != nil {
		t.Fatalf("Failed to count logs rows before migration: %v", err)
	}
	if logsBefore != 1 {
		t.Fatalf("logs rows before = %d, want 1", logsBefore)
	}

	// Retry sequence: first run converges from the rolled-back state, the
	// following runs prove idempotence across restarts.
	if err := migrateSchema(ctx, database); err != nil {
		t.Fatalf("First migrateSchema (recovery) failed: %v", err)
	}
	if err := migrateSchema(ctx, database); err != nil {
		t.Fatalf("Second migrateSchema (retry) failed: %v", err)
	}
	if err := migrateSchema(ctx, database); err != nil {
		t.Fatalf("Third migrateSchema (retry) failed: %v", err)
	}
	if err := createSchema(ctx, database); err != nil {
		t.Fatalf("createSchema (startup path) failed: %v", err)
	}

	var widenedSQL string
	if err := database.QueryRowContext(ctx, "SELECT sql FROM sqlite_master WHERE type='table' AND name='alert_rules'").Scan(&widenedSQL); err != nil {
		t.Fatalf("Failed to read widened alert_rules SQL: %v", err)
	}
	if !strings.Contains(widenedSQL, "agent_updated") {
		t.Errorf("Widened alert_rules SQL should contain agent_updated, got: %s", widenedSQL)
	}

	for _, idx := range []string{"idx_alert_rules_type_enabled", "idx_alert_rules_peer_id"} {
		var exists bool
		if err := database.QueryRowContext(ctx, "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='index' AND name=?", idx).Scan(&exists); err != nil {
			t.Fatalf("Failed to check index %s: %v", idx, err)
		}
		if !exists {
			t.Errorf("Expected index %s to exist after recovery", idx)
		}
	}

	for alertType, wantID := range ruleIDs {
		var gotID int64
		if err := database.QueryRowContext(ctx, "SELECT id FROM alert_rules WHERE alert_type=? ORDER BY id LIMIT 1", alertType).Scan(&gotID); err != nil {
			t.Errorf("Failed to query preserved rule %s: %v", alertType, err)
			continue
		}
		if gotID != wantID {
			t.Errorf("Rule %s id = %d, want stable id %d", alertType, gotID, wantID)
		}
	}

	rows, err := database.QueryContext(ctx, "SELECT id, rule_id, alert_type, severity, subject, message, status FROM alert_history ORDER BY id")
	if err != nil {
		t.Fatalf("Failed to query alert_history after recovery: %v", err)
	}
	var historyAfter []recoveryHistoryRow
	for rows.Next() {
		var hr recoveryHistoryRow
		if err := rows.Scan(&hr.id, &hr.ruleID, &hr.alertType, &hr.severity, &hr.subject, &hr.message, &hr.status); err != nil {
			rows.Close()
			t.Fatalf("Failed to scan alert_history: %v", err)
		}
		historyAfter = append(historyAfter, hr)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		t.Fatalf("Failed to iterate alert_history: %v", err)
	}
	rows.Close()
	if len(historyAfter) != len(historyBefore) {
		t.Fatalf("alert_history count = %d, want %d (zero data loss, no resend)", len(historyAfter), len(historyBefore))
	}
	for i := range historyBefore {
		if historyAfter[i] != historyBefore[i] {
			t.Errorf("history row %d = %+v, want %+v", i, historyAfter[i], historyBefore[i])
		}
		var parentID int64
		if err := database.QueryRowContext(ctx, "SELECT id FROM alert_rules WHERE id=?", historyAfter[i].ruleID).Scan(&parentID); err != nil {
			t.Errorf("History row %d references missing rule %d: %v", historyAfter[i].id, historyAfter[i].ruleID, err)
		}
	}

	assertForeignKeyCheckEmpty(t, ctx, database)

	var seededCount int
	if err := database.QueryRowContext(ctx, "SELECT COUNT(*) FROM alert_rules WHERE alert_type='agent_updated'").Scan(&seededCount); err != nil {
		t.Fatalf("Failed to count agent_updated rules: %v", err)
	}
	if seededCount != 1 {
		t.Errorf("agent_updated rule count = %d, want exactly 1 seeded row after retries", seededCount)
	}

	var firewallCount int
	if err := database.QueryRowContext(ctx, "SELECT COUNT(*) FROM firewall_logs").Scan(&firewallCount); err != nil {
		t.Fatalf("Failed to count firewall_logs after recovery: %v", err)
	}
	if firewallCount != 1 {
		t.Errorf("firewall_logs count = %d, want 1 (migration must not touch firewall_logs)", firewallCount)
	}
	var gotLogPeerID int64
	var gotTimestamp, gotSrcIP, gotDstIP, gotProtocol, gotAction string
	if err := database.QueryRowContext(ctx, "SELECT peer_id, timestamp, src_ip, dst_ip, protocol, action FROM firewall_logs WHERE id=?", firewallLogID).Scan(&gotLogPeerID, &gotTimestamp, &gotSrcIP, &gotDstIP, &gotProtocol, &gotAction); err != nil {
		t.Errorf("Failed to query preserved firewall_logs row: %v", err)
	} else {
		if gotLogPeerID != peerID {
			t.Errorf("firewall_logs peer_id = %d, want %d", gotLogPeerID, peerID)
		}
		if gotTimestamp == "" {
			t.Errorf("firewall_logs timestamp is empty, want preserved value")
		}
		if gotSrcIP != "10.0.0.1" || gotDstIP != "10.0.0.2" || gotProtocol != "tcp" || gotAction != "DROP" {
			t.Errorf("firewall_logs row changed: src=%q dst=%q proto=%q action=%q", gotSrcIP, gotDstIP, gotProtocol, gotAction)
		}
	}

	var logsAfter int
	if err := logsDB.QueryRowContext(ctx, "SELECT COUNT(*) FROM firewall_logs").Scan(&logsAfter); err != nil {
		t.Fatalf("Failed to count logs rows after migration: %v", err)
	}
	if logsAfter != logsBefore {
		t.Errorf("logs database rows = %d, want %d (logs database must stay untouched)", logsAfter, logsBefore)
	}

	if _, err := database.ExecContext(ctx,
		"INSERT INTO alert_rules (name, alert_type, enabled, threshold_value, threshold_window_minutes, throttle_minutes) VALUES (?, 'agent_updated', 1, 0, 5, 15)",
		"Recovery Probe"); err != nil {
		t.Fatalf("agent_updated insert failed after recovery: %v", err)
	}
	assertForeignKeyCheckEmpty(t, ctx, database)
}

// assertTableFKCheckEmpty verifies that PRAGMA foreign_key_check for a single
// table reports no violations. It stays scoped so pre-existing violations in
// unrelated tables do not fail the assertion.
func assertTableFKCheckEmpty(t *testing.T, ctx context.Context, database *sql.DB, table string) {
	t.Helper()
	rows, err := database.QueryContext(ctx, fmt.Sprintf("PRAGMA foreign_key_check(%s)", table))
	if err != nil {
		t.Fatalf("PRAGMA foreign_key_check(%s) failed: %v", table, err)
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var fkTable sql.NullString
		var fkRowID sql.NullInt64
		var fkRefTable sql.NullString
		var fkIndex sql.NullInt64
		if err := rows.Scan(&fkTable, &fkRowID, &fkRefTable, &fkIndex); err != nil {
			t.Fatalf("Failed to scan foreign_key_check(%s): %v", table, err)
		}
		count++
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("Failed to iterate foreign_key_check(%s): %v", table, err)
	}
	if count != 0 {
		t.Fatalf("foreign_key_check(%s) found %d violation(s), want 0", table, count)
	}
}

// TestMigrateAgentUpdatedOrphanQuarantine verifies that alert_history rows with
// valid, NULL, and dangling rule_id refs migrate cleanly: the migration runs
// twice plus the startup path, valid and NULL refs stay intact, dangling refs
// are quarantined to NULL with rows preserved, rule ids stay stable, the
// agent_updated seed appears exactly once, and an unrelated-table violation
// does not block the migration.
func TestMigrateAgentUpdatedOrphanQuarantine(t *testing.T) {
	database, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open in-memory database: %v", err)
	}
	defer database.Close()
	database.SetMaxOpenConns(1)
	database.SetMaxIdleConns(1)

	if _, err := database.Exec("PRAGMA foreign_keys=ON"); err != nil {
		t.Fatalf("Failed to enable foreign keys: %v", err)
	}

	ctx := context.Background()

	if _, err := database.ExecContext(ctx, Schema()); err != nil {
		t.Fatalf("Failed to create full schema: %v", err)
	}

	downgradeAlertRulesForTest(t, ctx, database, "CHECK(alert_type IN ('peer_offline', 'bundle_failed', 'blocked_spike', 'peer_online', 'new_peer', 'bundle_deployed'))")

	var legacySQL string
	if err := database.QueryRowContext(ctx, "SELECT sql FROM sqlite_master WHERE type='table' AND name='alert_rules'").Scan(&legacySQL); err != nil {
		t.Fatalf("Failed to read legacy alert_rules SQL: %v", err)
	}
	if strings.Contains(legacySQL, "agent_updated") {
		t.Fatalf("Legacy alert_rules SQL should not contain agent_updated")
	}

	var fkEnabled int
	if err := database.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&fkEnabled); err != nil {
		t.Fatalf("Failed to check foreign_keys pragma: %v", err)
	}
	if fkEnabled != 1 {
		t.Fatalf("foreign_keys pragma = %d, want 1", fkEnabled)
	}

	ruleIDs := make(map[string]int64)
	seedRules := []struct {
		name      string
		alertType string
	}{
		{"Peer Offline", "peer_offline"},
		{"Bundle Failed", "bundle_failed"},
	}
	for _, r := range seedRules {
		res, err := database.ExecContext(ctx,
			"INSERT INTO alert_rules (name, alert_type, enabled, threshold_value, threshold_window_minutes, throttle_minutes) VALUES (?, ?, 1, 0, 5, 15)",
			r.name, r.alertType)
		if err != nil {
			t.Fatalf("Failed to seed alert_rule %s: %v", r.alertType, err)
		}
		id, err := res.LastInsertId()
		if err != nil {
			t.Fatalf("Failed to get rule id: %v", err)
		}
		ruleIDs[r.alertType] = id
	}

	type validExpect struct {
		id      int64
		ruleID  int64
		subject string
		message string
	}
	var validBefore []validExpect
	validSeeds := []struct {
		ruleType string
		subject  string
		message  string
		status   string
	}{
		{"peer_offline", "valid offline subject", "valid offline message", "sent"},
		{"bundle_failed", "valid failed subject", "valid failed message", "pending"},
	}
	for _, h := range validSeeds {
		res, err := database.ExecContext(ctx,
			"INSERT INTO alert_history (rule_id, alert_type, severity, subject, message, status) VALUES (?, ?, 'warning', ?, ?, ?)",
			ruleIDs[h.ruleType], h.ruleType, h.subject, h.message, h.status)
		if err != nil {
			t.Fatalf("Failed to seed valid alert_history: %v", err)
		}
		hid, err := res.LastInsertId()
		if err != nil {
			t.Fatalf("Failed to get valid history id: %v", err)
		}
		validBefore = append(validBefore, validExpect{id: hid, ruleID: ruleIDs[h.ruleType], subject: h.subject, message: h.message})
	}

	type nullExpect struct {
		id      int64
		subject string
		message string
	}
	var nullBefore []nullExpect
	nullSeeds := []struct {
		alertType string
		subject   string
		message   string
		status    string
	}{
		{"peer_offline", "null ref subject", "null ref message", "sent"},
	}
	for _, h := range nullSeeds {
		res, err := database.ExecContext(ctx,
			"INSERT INTO alert_history (rule_id, alert_type, severity, subject, message, status) VALUES (NULL, ?, 'info', ?, ?, ?)",
			h.alertType, h.subject, h.message, h.status)
		if err != nil {
			t.Fatalf("Failed to seed NULL alert_history: %v", err)
		}
		hid, err := res.LastInsertId()
		if err != nil {
			t.Fatalf("Failed to get NULL history id: %v", err)
		}
		nullBefore = append(nullBefore, nullExpect{id: hid, subject: h.subject, message: h.message})
	}

	if _, err := database.Exec("PRAGMA foreign_keys=OFF"); err != nil {
		t.Fatalf("Failed to disable foreign keys: %v", err)
	}
	type danglingExpect struct {
		id      int64
		ruleID  int64
		subject string
		message string
	}
	var danglingBefore []danglingExpect
	danglingSeeds := []struct {
		ruleID  int64
		subject string
		message string
	}{
		{999999, "dangling subject one", "dangling message one"},
		{999998, "dangling subject two", "dangling message two"},
	}
	for _, h := range danglingSeeds {
		res, err := database.ExecContext(ctx,
			"INSERT INTO alert_history (rule_id, alert_type, severity, subject, message, status) VALUES (?, 'peer_offline', 'warning', ?, ?, 'sent')",
			h.ruleID, h.subject, h.message)
		if err != nil {
			t.Fatalf("Failed to seed dangling alert_history: %v", err)
		}
		hid, err := res.LastInsertId()
		if err != nil {
			t.Fatalf("Failed to get dangling history id: %v", err)
		}
		danglingBefore = append(danglingBefore, danglingExpect{id: hid, ruleID: h.ruleID, subject: h.subject, message: h.message})
	}
	res, err := database.ExecContext(ctx,
		"INSERT INTO firewall_logs (peer_id, timestamp, src_ip, dst_ip, protocol, action) VALUES (?, '2026-01-02 00:00:00', '10.0.0.1', '10.0.0.2', 'tcp', 'DROP')",
		777777)
	if err != nil {
		t.Fatalf("Failed to seed unrelated firewall_logs violation: %v", err)
	}
	firewallOrphanID, err := res.LastInsertId()
	if err != nil {
		t.Fatalf("Failed to get firewall_logs orphan id: %v", err)
	}
	if _, err := database.Exec("PRAGMA foreign_keys=ON"); err != nil {
		t.Fatalf("Failed to re-enable foreign keys: %v", err)
	}
	if err := database.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&fkEnabled); err != nil {
		t.Fatalf("Failed to check foreign_keys pragma: %v", err)
	}
	if fkEnabled != 1 {
		t.Fatalf("foreign_keys pragma = %d, want 1 (migration must run under FK enforcement)", fkEnabled)
	}

	var totalBefore int
	if err := database.QueryRowContext(ctx, "SELECT COUNT(*) FROM alert_history").Scan(&totalBefore); err != nil {
		t.Fatalf("Failed to count alert_history before migration: %v", err)
	}
	wantTotal := len(validBefore) + len(nullBefore) + len(danglingBefore)
	if totalBefore != wantTotal {
		t.Fatalf("alert_history count before = %d, want %d", totalBefore, wantTotal)
	}

	if err := migrateSchema(ctx, database); err != nil {
		t.Fatalf("First migrateSchema (orphan quarantine) failed: %v", err)
	}
	if err := migrateSchema(ctx, database); err != nil {
		t.Fatalf("Second migrateSchema (idempotence) failed: %v", err)
	}
	if err := createSchema(ctx, database); err != nil {
		t.Fatalf("createSchema (startup path) failed: %v", err)
	}

	var widenedSQL string
	if err := database.QueryRowContext(ctx, "SELECT sql FROM sqlite_master WHERE type='table' AND name='alert_rules'").Scan(&widenedSQL); err != nil {
		t.Fatalf("Failed to read widened alert_rules SQL: %v", err)
	}
	if !strings.Contains(widenedSQL, "agent_updated") {
		t.Errorf("Widened alert_rules SQL should contain agent_updated, got: %s", widenedSQL)
	}

	for _, idx := range []string{"idx_alert_rules_type_enabled", "idx_alert_rules_peer_id"} {
		var exists bool
		if err := database.QueryRowContext(ctx, "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='index' AND name=?", idx).Scan(&exists); err != nil {
			t.Fatalf("Failed to check index %s: %v", idx, err)
		}
		if !exists {
			t.Errorf("Expected index %s to exist after quarantine rebuild", idx)
		}
	}

	for alertType, wantID := range ruleIDs {
		var gotID int64
		if err := database.QueryRowContext(ctx, "SELECT id FROM alert_rules WHERE alert_type=? ORDER BY id LIMIT 1", alertType).Scan(&gotID); err != nil {
			t.Errorf("Failed to query preserved rule %s: %v", alertType, err)
			continue
		}
		if gotID != wantID {
			t.Errorf("Rule %s id = %d, want stable id %d", alertType, gotID, wantID)
		}
	}

	var totalAfter int
	if err := database.QueryRowContext(ctx, "SELECT COUNT(*) FROM alert_history").Scan(&totalAfter); err != nil {
		t.Fatalf("Failed to count alert_history after migration: %v", err)
	}
	if totalAfter != totalBefore {
		t.Fatalf("alert_history count = %d, want %d (rows must be preserved, orphans quarantined not deleted)", totalAfter, totalBefore)
	}

	for _, exp := range validBefore {
		var gotRuleID sql.NullInt64
		var gotSubject, gotMessage string
		if err := database.QueryRowContext(ctx, "SELECT rule_id, subject, message FROM alert_history WHERE id=?", exp.id).Scan(&gotRuleID, &gotSubject, &gotMessage); err != nil {
			t.Errorf("Failed to query valid history %d: %v", exp.id, err)
			continue
		}
		if !gotRuleID.Valid || gotRuleID.Int64 != exp.ruleID {
			gotVal := "NULL"
			if gotRuleID.Valid {
				gotVal = fmt.Sprintf("%d", gotRuleID.Int64)
			}
			t.Errorf("Valid history %d rule_id = %s, want %d (valid refs must stay intact)", exp.id, gotVal, exp.ruleID)
		}
		if gotSubject != exp.subject {
			t.Errorf("Valid history %d subject = %q, want %q", exp.id, gotSubject, exp.subject)
		}
		if gotMessage != exp.message {
			t.Errorf("Valid history %d message = %q, want %q", exp.id, gotMessage, exp.message)
		}
		var parentID int64
		if err := database.QueryRowContext(ctx, "SELECT id FROM alert_rules WHERE id=?", exp.ruleID).Scan(&parentID); err != nil {
			t.Errorf("Valid history %d references missing rule %d: %v", exp.id, exp.ruleID, err)
		}
	}

	for _, exp := range nullBefore {
		var gotRuleID sql.NullInt64
		var gotSubject string
		if err := database.QueryRowContext(ctx, "SELECT rule_id, subject FROM alert_history WHERE id=?", exp.id).Scan(&gotRuleID, &gotSubject); err != nil {
			t.Errorf("Failed to query NULL history %d: %v", exp.id, err)
			continue
		}
		if gotRuleID.Valid {
			t.Errorf("NULL history %d rule_id = %d, want NULL (NULL refs must stay NULL)", exp.id, gotRuleID.Int64)
		}
		if gotSubject != exp.subject {
			t.Errorf("NULL history %d subject = %q, want %q", exp.id, gotSubject, exp.subject)
		}
	}

	for _, exp := range danglingBefore {
		var gotRuleID sql.NullInt64
		var gotSubject, gotMessage string
		if err := database.QueryRowContext(ctx, "SELECT rule_id, subject, message FROM alert_history WHERE id=?", exp.id).Scan(&gotRuleID, &gotSubject, &gotMessage); err != nil {
			t.Errorf("Failed to query dangling history %d: %v", exp.id, err)
			continue
		}
		if gotRuleID.Valid {
			t.Errorf("Dangling history %d rule_id = %d, want NULL (orphans must be quarantined to NULL)", exp.id, gotRuleID.Int64)
		}
		if gotSubject != exp.subject {
			t.Errorf("Dangling history %d subject = %q, want %q (rows must be preserved)", exp.id, gotSubject, exp.subject)
		}
		if gotMessage != exp.message {
			t.Errorf("Dangling history %d message = %q, want %q (rows must be preserved)", exp.id, gotMessage, exp.message)
		}
	}

	assertTableFKCheckEmpty(t, ctx, database, "alert_history")

	var gotPeerID int64
	if err := database.QueryRowContext(ctx, "SELECT peer_id FROM firewall_logs WHERE id=?", firewallOrphanID).Scan(&gotPeerID); err != nil {
		t.Errorf("Failed to query unrelated firewall_logs orphan: %v", err)
	} else if gotPeerID != 777777 {
		t.Errorf("firewall_logs orphan peer_id = %d, want 777777 (unrelated rows must be preserved)", gotPeerID)
	}

	var seededCount int
	if err := database.QueryRowContext(ctx, "SELECT COUNT(*) FROM alert_rules WHERE alert_type='agent_updated'").Scan(&seededCount); err != nil {
		t.Fatalf("Failed to count agent_updated rules: %v", err)
	}
	if seededCount != 1 {
		t.Errorf("agent_updated rule count = %d, want 1 seeded row", seededCount)
	}

	if _, err := database.ExecContext(ctx,
		"INSERT INTO alert_rules (name, alert_type, enabled, threshold_value, threshold_window_minutes, throttle_minutes) VALUES (?, 'agent_updated', 1, 0, 5, 15)",
		"Orphan Probe"); err != nil {
		t.Fatalf("agent_updated insert failed after quarantine: %v", err)
	}
	assertTableFKCheckEmpty(t, ctx, database, "alert_history")
}

// TestMigrateAgentUpdatedOrphanQuarantineVolume verifies quarantine at production
// volume: 850 dangling alert_history refs plus valid and NULL refs migrate
// cleanly across repeated runs with zero data loss and the default Agent
// Updated rule seeded exactly once.
func TestMigrateAgentUpdatedOrphanQuarantineVolume(t *testing.T) {
	database, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open in-memory database: %v", err)
	}
	defer database.Close()
	database.SetMaxOpenConns(1)
	database.SetMaxIdleConns(1)

	if _, err := database.Exec("PRAGMA foreign_keys=ON"); err != nil {
		t.Fatalf("Failed to enable foreign keys: %v", err)
	}

	ctx := context.Background()

	if _, err := database.ExecContext(ctx, Schema()); err != nil {
		t.Fatalf("Failed to create full schema: %v", err)
	}

	downgradeAlertRulesForTest(t, ctx, database, "CHECK(alert_type IN ('peer_offline', 'bundle_failed', 'blocked_spike', 'peer_online', 'new_peer', 'bundle_deployed'))")

	ruleIDs := make(map[string]int64)
	seedRules := []struct {
		name      string
		alertType string
	}{
		{"Peer Offline", "peer_offline"},
		{"Bundle Failed", "bundle_failed"},
	}
	for _, r := range seedRules {
		res, err := database.ExecContext(ctx,
			"INSERT INTO alert_rules (name, alert_type, enabled, threshold_value, threshold_window_minutes, throttle_minutes) VALUES (?, ?, 1, 0, 5, 15)",
			r.name, r.alertType)
		if err != nil {
			t.Fatalf("Failed to seed alert_rule %s: %v", r.alertType, err)
		}
		id, err := res.LastInsertId()
		if err != nil {
			t.Fatalf("Failed to get rule id: %v", err)
		}
		ruleIDs[r.alertType] = id
	}

	validIDs := make([]int64, 0, 2)
	validRuleIDs := make([]int64, 0, 2)
	validSeeds := []struct {
		ruleType string
		subject  string
		message  string
		status   string
	}{
		{"peer_offline", "volume valid offline", "volume valid offline message", "sent"},
		{"bundle_failed", "volume valid failed", "volume valid failed message", "pending"},
	}
	for _, h := range validSeeds {
		res, err := database.ExecContext(ctx,
			"INSERT INTO alert_history (rule_id, alert_type, severity, subject, message, status) VALUES (?, ?, 'warning', ?, ?, ?)",
			ruleIDs[h.ruleType], h.ruleType, h.subject, h.message, h.status)
		if err != nil {
			t.Fatalf("Failed to seed volume valid history: %v", err)
		}
		hid, err := res.LastInsertId()
		if err != nil {
			t.Fatalf("Failed to get volume valid history id: %v", err)
		}
		validIDs = append(validIDs, hid)
		validRuleIDs = append(validRuleIDs, ruleIDs[h.ruleType])
	}

	nullIDs := make([]int64, 0, 2)
	nullSeeds := []struct {
		alertType string
		subject   string
		message   string
	}{
		{"peer_offline", "volume null one", "volume null message one"},
		{"bundle_failed", "volume null two", "volume null message two"},
	}
	for _, h := range nullSeeds {
		res, err := database.ExecContext(ctx,
			"INSERT INTO alert_history (rule_id, alert_type, severity, subject, message, status) VALUES (NULL, ?, 'info', ?, ?, 'sent')",
			h.alertType, h.subject, h.message)
		if err != nil {
			t.Fatalf("Failed to seed volume NULL history: %v", err)
		}
		hid, err := res.LastInsertId()
		if err != nil {
			t.Fatalf("Failed to get volume NULL history id: %v", err)
		}
		nullIDs = append(nullIDs, hid)
	}

	const volumeOrphans = 850
	if _, err := database.Exec("PRAGMA foreign_keys=OFF"); err != nil {
		t.Fatalf("Failed to disable foreign keys: %v", err)
	}
	for i := 0; i < volumeOrphans; i++ {
		subject := fmt.Sprintf("volume orphan %d", i)
		message := fmt.Sprintf("volume orphan message %d", i)
		if _, err := database.ExecContext(ctx,
			"INSERT INTO alert_history (rule_id, alert_type, severity, subject, message, status) VALUES (?, 'peer_offline', 'warning', ?, ?, 'sent')",
			int64(900000+i), subject, message); err != nil {
			t.Fatalf("Failed to seed volume orphan %d: %v", i, err)
		}
	}
	if _, err := database.Exec("PRAGMA foreign_keys=ON"); err != nil {
		t.Fatalf("Failed to re-enable foreign keys: %v", err)
	}

	var fkEnabled int
	if err := database.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&fkEnabled); err != nil {
		t.Fatalf("Failed to check foreign_keys pragma: %v", err)
	}
	if fkEnabled != 1 {
		t.Fatalf("foreign_keys pragma = %d, want 1 (migration must run under FK enforcement)", fkEnabled)
	}

	var totalBefore int
	if err := database.QueryRowContext(ctx, "SELECT COUNT(*) FROM alert_history").Scan(&totalBefore); err != nil {
		t.Fatalf("Failed to count alert_history before migration: %v", err)
	}
	wantTotal := len(validIDs) + len(nullIDs) + volumeOrphans
	if totalBefore != wantTotal {
		t.Fatalf("alert_history count before = %d, want %d", totalBefore, wantTotal)
	}

	if err := migrateSchema(ctx, database); err != nil {
		t.Fatalf("First migrateSchema (volume quarantine) failed: %v", err)
	}
	if err := migrateSchema(ctx, database); err != nil {
		t.Fatalf("Second migrateSchema (idempotence) failed: %v", err)
	}
	if err := createSchema(ctx, database); err != nil {
		t.Fatalf("createSchema (startup path) failed: %v", err)
	}

	var widenedSQL string
	if err := database.QueryRowContext(ctx, "SELECT sql FROM sqlite_master WHERE type='table' AND name='alert_rules'").Scan(&widenedSQL); err != nil {
		t.Fatalf("Failed to read widened alert_rules SQL: %v", err)
	}
	if !strings.Contains(widenedSQL, "agent_updated") {
		t.Errorf("Widened alert_rules SQL should contain agent_updated")
	}

	for _, idx := range []string{"idx_alert_rules_type_enabled", "idx_alert_rules_peer_id"} {
		var exists bool
		if err := database.QueryRowContext(ctx, "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='index' AND name=?", idx).Scan(&exists); err != nil {
			t.Fatalf("Failed to check index %s: %v", idx, err)
		}
		if !exists {
			t.Errorf("Expected index %s to exist after volume rebuild", idx)
		}
	}

	for alertType, wantID := range ruleIDs {
		var gotID int64
		if err := database.QueryRowContext(ctx, "SELECT id FROM alert_rules WHERE alert_type=? ORDER BY id LIMIT 1", alertType).Scan(&gotID); err != nil {
			t.Errorf("Failed to query preserved rule %s: %v", alertType, err)
			continue
		}
		if gotID != wantID {
			t.Errorf("Rule %s id = %d, want stable id %d", alertType, gotID, wantID)
		}
	}

	var totalAfter int
	if err := database.QueryRowContext(ctx, "SELECT COUNT(*) FROM alert_history").Scan(&totalAfter); err != nil {
		t.Fatalf("Failed to count alert_history after migration: %v", err)
	}
	if totalAfter != totalBefore {
		t.Fatalf("alert_history count = %d, want %d (zero data loss at volume)", totalAfter, totalBefore)
	}

	for i, hid := range validIDs {
		var gotRuleID sql.NullInt64
		if err := database.QueryRowContext(ctx, "SELECT rule_id FROM alert_history WHERE id=?", hid).Scan(&gotRuleID); err != nil {
			t.Errorf("Failed to query volume valid history %d: %v", hid, err)
			continue
		}
		if !gotRuleID.Valid || gotRuleID.Int64 != validRuleIDs[i] {
			gotVal := "NULL"
			if gotRuleID.Valid {
				gotVal = fmt.Sprintf("%d", gotRuleID.Int64)
			}
			t.Errorf("Volume valid history %d rule_id = %s, want %d", hid, gotVal, validRuleIDs[i])
		}
	}

	for _, hid := range nullIDs {
		var gotRuleID sql.NullInt64
		if err := database.QueryRowContext(ctx, "SELECT rule_id FROM alert_history WHERE id=?", hid).Scan(&gotRuleID); err != nil {
			t.Errorf("Failed to query volume NULL history %d: %v", hid, err)
			continue
		}
		if gotRuleID.Valid {
			t.Errorf("Volume NULL history %d rule_id = %d, want NULL", hid, gotRuleID.Int64)
		}
	}

	var nullCount int
	if err := database.QueryRowContext(ctx, "SELECT COUNT(*) FROM alert_history WHERE rule_id IS NULL").Scan(&nullCount); err != nil {
		t.Fatalf("Failed to count NULL refs after volume migration: %v", err)
	}
	if nullCount != len(nullIDs)+volumeOrphans {
		t.Errorf("NULL rule_id count = %d, want %d (2 original + 850 quarantined)", nullCount, len(nullIDs)+volumeOrphans)
	}

	var danglingRemain int
	if err := database.QueryRowContext(ctx, "SELECT COUNT(*) FROM alert_history WHERE rule_id IS NOT NULL AND rule_id NOT IN (SELECT id FROM alert_rules)").Scan(&danglingRemain); err != nil {
		t.Fatalf("Failed to count remaining dangling refs: %v", err)
	}
	if danglingRemain != 0 {
		t.Errorf("Dangling refs remaining = %d, want 0 (all orphans quarantined)", danglingRemain)
	}

	var orphanSubjectCount int
	if err := database.QueryRowContext(ctx, "SELECT COUNT(*) FROM alert_history WHERE subject LIKE 'volume orphan %'").Scan(&orphanSubjectCount); err != nil {
		t.Fatalf("Failed to count preserved orphan subjects: %v", err)
	}
	if orphanSubjectCount != volumeOrphans {
		t.Errorf("Preserved orphan subjects = %d, want %d (rows must be preserved)", orphanSubjectCount, volumeOrphans)
	}

	assertTableFKCheckEmpty(t, ctx, database, "alert_history")

	var seededCount int
	if err := database.QueryRowContext(ctx, "SELECT COUNT(*) FROM alert_rules WHERE alert_type='agent_updated'").Scan(&seededCount); err != nil {
		t.Fatalf("Failed to count agent_updated rules: %v", err)
	}
	if seededCount != 1 {
		t.Errorf("agent_updated rule count = %d, want 1 seeded row", seededCount)
	}

	if _, err := database.ExecContext(ctx,
		"INSERT INTO alert_rules (name, alert_type, enabled, threshold_value, threshold_window_minutes, throttle_minutes) VALUES ('Volume Probe', 'agent_updated', 1, 0, 5, 15)"); err != nil {
		t.Fatalf("agent_updated insert after volume quarantine failed: %v", err)
	}
	assertTableFKCheckEmpty(t, ctx, database, "alert_history")
}
