// Package db provides database test helpers.
// This file provides shared test setup utilities for the db package.
package db

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func SetupTestDB(tb testing.TB) (*sql.DB, func()) {
	tb.Helper()
	f, err := os.CreateTemp("", "runic-test-*.db")
	if err != nil {
		tb.Fatal(err)
	}
	dbPath := f.Name()
	if cErr := f.Close(); cErr != nil {
		tb.Logf("Failed to close temp file: %v", cErr)
	}

	database, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		if rErr := os.Remove(dbPath); rErr != nil {
			tb.Logf("Failed to remove db: %v", rErr)
		}
		tb.Fatal(err)
	}

	database.SetMaxOpenConns(10)
	database.SetMaxIdleConns(5)

	// Enable foreign keys
	if _, err := database.Exec("PRAGMA foreign_keys=ON"); err != nil {
		database.Close()
		os.Remove(dbPath)
		tb.Fatal(err)
	}

	if _, err := database.Exec(Schema()); err != nil {
		if cErr := database.Close(); cErr != nil {
			tb.Logf("Failed to close database: %v", cErr)
		}
		if rErr := os.Remove(dbPath); rErr != nil {
			tb.Logf("Failed to remove db: %v", rErr)
		}
		tb.Fatal(err)
	}

	if err := database.Ping(); err != nil {
		if cErr := database.Close(); cErr != nil {
			tb.Logf("Failed to close database: %v", cErr)
		}
		if rErr := os.Remove(dbPath); rErr != nil {
			tb.Logf("Failed to remove db: %v", rErr)
		}
		tb.Fatal(err)
	}

	cleanup := func() {
		if cErr := database.Close(); cErr != nil {
			tb.Logf("Failed to close database: %v", cErr)
		}
		if rErr := os.Remove(dbPath); rErr != nil {
			tb.Logf("Failed to remove db: %v", rErr)
		}
	}
	return database, cleanup
}

func TestSchema(t *testing.T) {
	schema := Schema()
	if schema == "" {
		t.Fatal("Schema() returned empty string")
	}

	// Verify schema contains expected table definitions
	expectedTables := []string{
		"CREATE TABLE",
		"users",
		"peers",
		"services",
		"groups",
	}

	for _, expected := range expectedTables {
		if !strings.Contains(schema, expected) {
			t.Errorf("Schema() missing expected content: %s", expected)
		}
	}
}

func TestNewDatabaseWrapper(t *testing.T) {
	db, cleanup := SetupTestDB(t)
	defer cleanup()

	// Test New() wrapper
	database := New(db)
	if database == nil {
		t.Fatal("New() returned nil")
	}

	// Verify underlying DB is accessible
	if database.DB == nil {
		t.Error("Database.DB is nil")
	}

	// Test UnderlyingDB() returns the original DB
	underlying := database.UnderlyingDB()
	if underlying != db {
		t.Error("UnderlyingDB() did not return the original *sql.DB")
	}

	// Verify the wrapper embeds the sql.DB correctly
	if err := database.DB.Ping(); err != nil {
		t.Errorf("Failed to ping through wrapper: %v", err)
	}
}

func TestAllowedTables(t *testing.T) {
	tests := []struct {
		tableName string
		expected  bool
	}{
		{"users", true},
		{"peers", true},
		{"services", true},
		{"groups", true},
		{"policies", true},
		{"revoked_tokens", true},
		{"rule_bundles", true},
		{"firewall_logs", true},
		{"group_members", true},
		{"special_targets", true},
		{"system_config", true},
		{"registration_tokens", true},
		{"pending_changes", true},
		{"pending_bundle_previews", true},
		// Invalid table names should not be in the whitelist
		{"invalid_table", false},
		{"admin", false},
		{"; DROP TABLE users; --", false},
	}

	for _, tc := range tests {
		t.Run(tc.tableName, func(t *testing.T) {
			result := allowedTables[tc.tableName]
			if result != tc.expected {
				t.Errorf("allowedTables[%q] = %v, want %v", tc.tableName, result, tc.expected)
			}
		})
	}
}

func TestDatabaseWrapperImplementsInterface(t *testing.T) {
	db, cleanup := SetupTestDB(t)
	defer cleanup()

	database := New(db)

	// Verify we can call sql.DB methods through the wrapper
	err := database.Ping()
	if err != nil {
		t.Errorf("Failed to ping through Database wrapper: %v", err)
	}

	// Test stats (basic method from sql.DB)
	stats := database.Stats()
	if stats.MaxOpenConnections != 10 {
		t.Errorf("Expected MaxOpenConnections = 10, got %d", stats.MaxOpenConnections)
	}
}

func TestSchemaNotEmpty(t *testing.T) {
	schema := Schema()

	if len(schema) < 1000 {
		t.Errorf("Schema() seems too short (%d bytes), may be incomplete", len(schema))
	}

	// Verify key tables are present
	importantTables := []string{
		"users",
		"peers",
		"services",
		"groups",
		"policies",
	}

	for _, table := range importantTables {
		if !strings.Contains(schema, table) {
			t.Errorf("Schema missing table: %s", table)
		}
	}
}

// busyCodeError is a cgo-free stand-in for the cgo driver error. It carries
// SQLite result codes as plain ints via the sqliteCoder interface so the
// code-based IsBusyError path is testable with CGO_ENABLED=0.
type busyCodeError struct {
	code int
	ext  int
	msg  string
}

func (e busyCodeError) Error() string { return e.msg }
func (e busyCodeError) Code() int     { return e.code }
func (e busyCodeError) ExtendedCode() int {
	return e.ext
}

func TestIsBusyError(t *testing.T) {
	busyCode := busyCodeError{code: 5, ext: 261, msg: "code-only busy without message match"}
	wrappedBusyCode := fmt.Errorf("update peer heartbeat: %w", busyCodeError{code: 6, ext: 262, msg: "code-only locked"})
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"database is locked", errors.New("database is locked"), true},
		{"database is locked uppercase", errors.New("DATABASE IS LOCKED"), true},
		{"database table is locked", errors.New("database table is locked"), true},
		{"database is busy", errors.New("database is busy"), true},
		{"sqlite busy uppercase", errors.New("SQLITE_BUSY: database is locked"), true},
		{"sqlite locked", errors.New("SQLITE_LOCKED: table is locked"), true},
		{"busy recovery", errors.New("sqlite3: busy recovery, database is locked"), true},
		{"busy snapshot", errors.New("sqlite3: busy snapshot"), true},
		{"wrapped locked string", fmt.Errorf("update peer heartbeat: %w", errors.New("database is locked")), true},
		{"wrapped busy string", fmt.Errorf("insert peer IP: %w", errors.New("database is busy")), true},
		{"code-only busy", busyCode, true},
		{"wrapped code-only locked", wrappedBusyCode, true},
		{"extended snapshot code-only", busyCodeError{code: 0, ext: 517, msg: "unrelated message"}, true},
		{"extended timeout code-only", busyCodeError{code: 0, ext: 773, msg: "unrelated message"}, true},
		{"primary mask future variant", busyCodeError{code: 0, ext: 5 | (9 << 8), msg: "unrelated message"}, true},
		{"non-busy unique", errors.New("UNIQUE constraint failed: users.username"), false},
		{"non-busy foreign key", errors.New("FOREIGN KEY constraint failed"), false},
		{"non-busy generic", errors.New("something else went wrong"), false},
		{"non-busy code", busyCodeError{code: 19, ext: 2067, msg: "UNIQUE constraint failed"}, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsBusyError(tc.err); got != tc.want {
				t.Errorf("IsBusyError(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}
