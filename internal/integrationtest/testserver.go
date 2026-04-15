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
)

// NewTestAPIServer creates an httptest.Server with a fully configured API
// for testing purposes. The server uses an in-memory test database and
// initializes the JWT key for authentication.
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

	// Create a temporary database file
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

	// Set connection pool settings
	database.SetMaxOpenConns(25)
	database.SetMaxIdleConns(5)

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

	// Create pending_changes table if it doesn't exist (needed for policy changes)
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

	// Create index for pending_changes
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

	// Create compiler for rule compilation
	compiler := engine.NewCompiler(database)

	// Create API instance with in-memory logs DB (pass nil for alert service and encryptor in tests)
	testAPI := api.NewAPI(database, compiler, ":memory:", nil, nil)

	// Create router and register routes
	router := mux.NewRouter()
	testAPI.RegisterRoutes(router, "")

	server := httptest.NewServer(router)

	// Cleanup function - NOTE: caller should call server.Close() FIRST
	cleanup := func() {
		if cErr := database.Close(); cErr != nil {
			t.Log(cErr)
		}
		if rErr := os.Remove(dbPath); rErr != nil {
			t.Log(rErr)
		}
	}

	return server, cleanup
}

// AuthenticatedRequest makes an HTTP request with JWT authentication.
// It automatically generates a valid token for the given username and role.
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

	// Set content type for JSON requests
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	// Generate and set auth token
	token, err := auth.GenerateToken(username, role, 24*time.Hour)
	if err != nil {
		t.Fatalf("failed to generate auth token: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	return req
}

// JSONRequest makes an authenticated JSON request and returns the response.
// Helper function for common GET/POST/PUT/DELETE operations.
func JSONRequest(t *testing.T, server *httptest.Server, method, url string, body interface{}, username, role string) *http.Response {
	t.Helper()
	req := AuthenticatedRequest(t, server, method, url, body, username, role)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("failed to execute request: %v", err)
	}
	return resp
}
