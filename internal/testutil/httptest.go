// Package testutil provides test utilities.
package testutil

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"

	_ "github.com/mattn/go-sqlite3"
)

// MuxVars is a helper to set gorilla/mux URL variables.
// This is commonly needed in handler tests that extract path parameters.
func MuxVars(r *http.Request, vars map[string]string) *http.Request {
	return mux.SetURLVars(r, vars)
}

// NewTestResponseRecorder returns a new httptest.ResponseRecorder.
// This is a convenience helper to reduce boilerplate in test files.
func NewTestResponseRecorder() *httptest.ResponseRecorder {
	return httptest.NewRecorder()
}

// SetupTestDBWithSecret sets up a test database with the agent JWT secret configured.
// This is required for tests that verify agent authentication.
func SetupTestDBWithSecret(t *testing.T) (*sql.DB, func()) {
	db, cleanup := SetupTestDB(t)

	// Insert the agent JWT secret
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

// SetupTestDBWithSecretAndLogs sets up both a main database and a logs database
// with the agent JWT secret configured. This is required for tests that need
// both databases (e.g., agents, logs, dashboard handlers).
func SetupTestDBWithSecretAndLogs(t *testing.T) (*sql.DB, *sql.DB, func()) {
	// Call SetupTestDB (not SetupTestDBWithSecret) and insert secret manually
	mainDB, mainCleanup := SetupTestDB(t)
	logsDB, logsCleanup := SetupTestLogsDB(t)

	// Insert the agent JWT secret (only once)
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

// SetupTestDBWithTestData sets up a test database with common test data:
// - A test service
// - A test peer
// - A test group
// This is useful for tests that require these entities to exist.
func SetupTestDBWithTestData(t *testing.T) (*sql.DB, func()) {
	db, cleanup := SetupTestDB(t)

	// Insert required service
	_, err := db.Exec(
		"INSERT INTO services (name, ports, protocol) VALUES (?, ?, ?)",
		"test-service", "8080", "tcp",
	)
	if err != nil {
		cleanup()
		t.Fatalf("failed to insert service: %v", err)
	}

	// Insert required peer
	_, err = db.Exec(
		"INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)",
		"test-peer", "10.0.0.1", "agent-key-123", "hmac-key-123",
	)
	if err != nil {
		cleanup()
		t.Fatalf("failed to insert peer: %v", err)
	}

	// Insert required group
	_, err = db.Exec(
		"INSERT INTO groups (name) VALUES (?)",
		"test-group",
	)
	if err != nil {
		cleanup()
		t.Fatalf("failed to insert group: %v", err)
	}

	return db, cleanup
}
