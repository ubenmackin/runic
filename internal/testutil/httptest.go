// Package testutil provides test utilities.
package testutil

import (
	"database/sql"
	"net/http"
	"testing"

	"github.com/gorilla/mux"

	_ "github.com/mattn/go-sqlite3"
)

// MuxVars is commonly needed in handler tests that extract path parameters.
func MuxVars(r *http.Request, vars map[string]string) *http.Request {
	return mux.SetURLVars(r, vars)
}

// SetupTestDBWithSecret is required for tests that verify agent authentication.
func SetupTestDBWithSecret(t *testing.T) (*sql.DB, func()) {
	db, cleanup := SetupTestDB(t)

	_, err := db.Exec(
		"INSERT INTO system_config (key, value) VALUES (?, ?)",
		"agent_jwt_secret",
		"test-secret-key-for-agent-jwt-256-bits!!",
	)
	if err != nil {
		cleanup()
		t.Fatalf("failed to insert agent_jwt_secret: %v", err)
	}

	return db, cleanup
}

// SetupTestDBWithSecretAndLogs sets up both databases with the agent JWT secret configured.
// This is required for tests that need both databases (e.g., agents, logs, dashboard handlers).
func SetupTestDBWithSecretAndLogs(t *testing.T) (*sql.DB, *sql.DB, func()) {
	// Call SetupTestDB (not SetupTestDBWithSecret) and insert secret manually
	mainDB, mainCleanup := SetupTestDB(t)
	logsDB, logsCleanup := SetupTestLogsDB(t)

	_, err := mainDB.Exec(
		"INSERT INTO system_config (key, value) VALUES (?, ?)",
		"agent_jwt_secret",
		"test-secret-key-for-agent-jwt-256-bits!!",
	)
	if err != nil {
		logsCleanup()
		mainCleanup()
		t.Fatalf("failed to insert agent_jwt_secret: %v", err)
	}

	cleanup := func() {
		logsCleanup()
		mainCleanup()
	}
	return mainDB, logsDB, cleanup
}
