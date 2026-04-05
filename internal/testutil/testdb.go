package testutil

import (
	"database/sql"
	"os"
	"testing"

	_ "github.com/mattn/go-sqlite3"
	"runic/internal/db"
)

func SetupTestDB(t *testing.T) (*sql.DB, func()) {
	t.Helper()
	f, err := os.CreateTemp("", "runic-test-*.db")
	if err != nil {
		t.Fatal(err)
	}
	dbPath := f.Name()
	f.Close()

	database, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		os.Remove(dbPath)
		t.Fatal(err)
	}

	// Set connection pool settings to prevent issues during cleanup
	database.SetMaxOpenConns(1)
	database.SetMaxIdleConns(1)

	if _, err := database.Exec(db.Schema()); err != nil {
		database.Close()
		os.Remove(dbPath)
		t.Fatal(err)
	}

	// Pre-warm the connection to ensure it works
	if err := database.Ping(); err != nil {
		database.Close()
		os.Remove(dbPath)
		t.Fatal(err)
	}

	// Return cleanup function but DON'T register it here
	// Caller is responsible for cleanup order
	cleanup := func() {
		database.Close()
		os.Remove(dbPath)
	}
	return database, cleanup
}
