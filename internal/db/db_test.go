// Package db provides database test helpers.
// This file provides shared test setup utilities for the db package.
package db

import (
	"database/sql"
	"os"
	"strings"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

// SetupTestDB creates a temporary test database with the full schema.
func SetupTestDB(t *testing.T) (*sql.DB, func()) {
	t.Helper()
	f, err := os.CreateTemp("", "runic-test-*.db")
	if err != nil {
		t.Fatal(err)
	}
	dbPath := f.Name()
	if cErr := f.Close(); cErr != nil {
		t.Logf("Failed to close temp file: %v", cErr)
	}

	database, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		if rErr := os.Remove(dbPath); rErr != nil {
			t.Logf("Failed to remove db: %v", rErr)
		}
		t.Fatal(err)
	}

	database.SetMaxOpenConns(10)
	database.SetMaxIdleConns(5)

	// Enable foreign keys
	if _, err := database.Exec("PRAGMA foreign_keys=ON"); err != nil {
		database.Close()
		os.Remove(dbPath)
		t.Fatal(err)
	}

	if _, err := database.Exec(Schema()); err != nil {
		if cErr := database.Close(); cErr != nil {
			t.Logf("Failed to close database: %v", cErr)
		}
		if rErr := os.Remove(dbPath); rErr != nil {
			t.Logf("Failed to remove db: %v", rErr)
		}
		t.Fatal(err)
	}

	if err := database.Ping(); err != nil {
		if cErr := database.Close(); cErr != nil {
			t.Logf("Failed to close database: %v", cErr)
		}
		if rErr := os.Remove(dbPath); rErr != nil {
			t.Logf("Failed to remove db: %v", rErr)
		}
		t.Fatal(err)
	}

	cleanup := func() {
		if cErr := database.Close(); cErr != nil {
			t.Logf("Failed to close database: %v", cErr)
		}
		if rErr := os.Remove(dbPath); rErr != nil {
			t.Logf("Failed to remove db: %v", rErr)
		}
	}
	return database, cleanup
}

// TestSchema tests that Schema() returns non-empty SQL.
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
		if !contains(schema, expected) {
			t.Errorf("Schema() missing expected content: %s", expected)
		}
	}
}

// TestNewDatabaseWrapper tests that New() creates a proper Database wrapper.
func TestNewDatabaseWrapper(t *testing.T) {
	// Create a test database connection
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

// TestAllowedTables tests the allowedTables whitelist.
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

// TestDatabaseWrapperImplementsInterface tests that Database embeds *sql.DB correctly.
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

// TestSchemaNotEmpty tests that schema contains specific important tables.
func TestSchemaNotEmpty(t *testing.T) {
	schema := Schema()

	// Check for minimum length (schema should be substantial)
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
		if !contains(schema, table) {
			t.Errorf("Schema missing table: %s", table)
		}
	}
}

// contains is a helper function to check if a string contains a substring.
func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}
