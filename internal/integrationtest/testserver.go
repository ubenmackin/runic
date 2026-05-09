// Package integrationtest provides integration tests.
package integrationtest

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/gorilla/mux"

	"runic/internal/api"
	"runic/internal/auth"
	"runic/internal/db"
	"runic/internal/engine"
	"runic/internal/store"
)

// NewTestAPIServer initializes the JWT key for authentication.
//
// IMPORTANT: Callers MUST call Server.Close() BEFORE calling the returned
// cleanup function to avoid race conditions with in-flight requests.
//
// Usage:
//
//	server, cleanup := NewTestAPIServer(t)
//	defer cleanup()
//	defer server.Close()
func NewTestAPIServer(t *testing.T) (*httptest.Server, func()) {
	t.Helper()

	f, err := os.CreateTemp("", "runic-test-*.db")
	if err != nil {
		t.Fatal(err)
	}
	dbPath := f.Name()
	if err := f.Close(); err != nil {
		t.Log(err)
	}

	// Open the database
	database, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		if rErr := os.Remove(dbPath); rErr != nil {
			t.Log(rErr)
		}
		t.Fatal(err)
	}

	database.SetMaxOpenConns(25)
	database.SetMaxIdleConns(5)

	// Enable WAL mode and busy timeout to match production configuration
	// and prevent "database is locked" errors in concurrent tests.
	if _, err := database.Exec("PRAGMA journal_mode=WAL"); err != nil {
		t.Log(err)
	}
	if _, err := database.Exec("PRAGMA busy_timeout=5000"); err != nil {
		t.Log(err)
	}

	// Execute schema
	if _, err := database.Exec(db.Schema()); err != nil {
		if err := database.Close(); err != nil {
			t.Log(err)
		}
		if rErr := os.Remove(dbPath); rErr != nil {
			t.Log(rErr)
		}
		t.Fatal(err)
	}

	if _, err := database.Exec(`
		CREATE TABLE IF NOT EXISTS pending_changes (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			peer_id INTEGER NOT NULL REFERENCES peers(id),
			change_type TEXT NOT NULL CHECK (change_type IN ('policy', 'group', 'service')),
			change_id INTEGER NOT NULL,
			change_action TEXT NOT NULL CHECK (change_action IN ('create', 'update', 'delete')),
			change_summary TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	`); err != nil {
		if err := database.Close(); err != nil {
			t.Log(err)
		}
		if rErr := os.Remove(dbPath); rErr != nil {
			t.Log(rErr)
		}
		t.Fatal(err)
	}

	if _, err := database.Exec("CREATE INDEX IF NOT EXISTS idx_pending_changes_peer ON pending_changes(peer_id)"); err != nil {
		if err := database.Close(); err != nil {
			t.Log(err)
		}
		if rErr := os.Remove(dbPath); rErr != nil {
			t.Log(rErr)
		}
		t.Fatal(err)
	}

	// Initialize JWT key using the package's init function
	// This avoids the DB query issue by generating a random key directly
	ctx := context.Background()
	if err := auth.InitJwtKey(ctx, database); err != nil {
		// If it fails, the package should have generated a random key anyway
		// Continue - auth.InitJwtKey generates a fallback key on error
		t.Logf("InitJwtKey fallback utilized: %v", err)
	}

	// Set the global TokenStore for auth.Middleware revocation checks
	auth.SetTokenStore(store.NewTokenStore(database))

	compiler := engine.NewTestCompiler(database)

	logsDB, err := db.InitLogsDB(":memory:")
	if err != nil {
		t.Fatalf("Failed to initialize logs database: %v", err)
	}
	testAPI := api.NewAPI(database, compiler, logsDB, ":memory:", nil, nil)

	router := mux.NewRouter()
	testAPI.RegisterRoutes(router, "")

	server := httptest.NewServer(router)

	// Cleanup function - NOTE: caller should call server.Close() FIRST
	cleanup := func() {
		if cErr := database.Close(); cErr != nil {
			t.Log(cErr)
		}
		if cErr := logsDB.Close(); cErr != nil {
			t.Log(cErr)
		}
		if rErr := os.Remove(dbPath); rErr != nil {
			t.Log(rErr)
		}
	}

	return server, cleanup
}

// AuthenticatedRequest automatically generates a valid token for the given username and role.
func AuthenticatedRequest(t *testing.T, server *httptest.Server, method, url string, body interface{}, username, role string) *http.Request {
	t.Helper()

	var reqBody *bytes.Buffer
	if body != nil {
		jsonBytes, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("failed to marshal request body: %v", err)
		}
		reqBody = bytes.NewBuffer(jsonBytes)
	} else {
		reqBody = bytes.NewBuffer(nil)
	}

	req, err := http.NewRequest(method, server.URL+url, reqBody)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	token, err := auth.GenerateToken(username, role, 24*time.Hour)
	if err != nil {
		t.Fatalf("failed to generate auth token: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	return req
}

// JSONRequest is a helper function for common GET/POST/PUT/DELETE operations.
func JSONRequest(t *testing.T, server *httptest.Server, method, url string, body interface{}, username, role string) *http.Response {
	t.Helper()
	req := AuthenticatedRequest(t, server, method, url, body, username, role)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("failed to execute request: %v", err)
	}
	return resp
}
