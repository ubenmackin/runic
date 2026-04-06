// Package testutil provides test utilities.
package testutil

import (
	"database/sql"
	"os"
	"testing"

	"runic/internal/db"

	_ "github.com/mattn/go-sqlite3"
)

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

	// Set connection pool settings to prevent issues during cleanup
	database.SetMaxOpenConns(1)
	database.SetMaxIdleConns(1)

	if _, err := database.Exec(db.Schema()); err != nil {
		if cErr := database.Close(); cErr != nil {
			t.Logf("Failed to close database: %v", cErr)
		}
		if rErr := os.Remove(dbPath); rErr != nil {
			t.Logf("Failed to remove db: %v", rErr)
		}
		t.Fatal(err)
	}

	// Pre-warm the connection to ensure it works
	if err := database.Ping(); err != nil {
		if cErr := database.Close(); cErr != nil {
			t.Logf("Failed to close database: %v", cErr)
		}
		if rErr := os.Remove(dbPath); rErr != nil {
			t.Logf("Failed to remove db: %v", rErr)
		}
		t.Fatal(err)
	}

	// Return cleanup function but DON'T register it here
	// Caller is responsible for cleanup order
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
