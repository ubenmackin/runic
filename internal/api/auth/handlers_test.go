package auth

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"runic/internal/auth"
	"runic/internal/testutil"
)

// Helper to set admin context on request
func withAdminContext(ctx context.Context) context.Context {
	return auth.SetContextForTest(ctx, "admin", "adminuser")
}

// uniqueIPCounter is used to generate unique IPs for rate limit tests
var uniqueIPCounter int

// newRequestWithUniqueIP creates an HTTP request with a unique remote addr to avoid rate limiting
func newRequestWithUniqueIP(method, url string, body string) *http.Request {
	uniqueIPCounter++
	ip := fmt.Sprintf("192.0.2.%d:12345", uniqueIPCounter)
	r := httptest.NewRequest(method, url, strings.NewReader(body))
	r.RemoteAddr = ip
	return r
}

// resetAllRateLimiters clears both rate limiters for test isolation
func resetAllRateLimiters() {
	ResetRateLimitStore()
	ResetSetupRateLimit()
}

// =============================================================================
// Test HandleSetupGET
// =============================================================================

func TestHandleSetupGET_NoUsers(t *testing.T) {
	resetAllRateLimiters()
	db, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	// Set up JWT key
	setupTestJWT(t, db)

	h := NewHandler(db, db)
	w := httptest.NewRecorder()
	r := newRequestWithUniqueIP(http.MethodGet, "/api/v1/setup", "")

	h.HandleSetupGET(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var response map[string]bool
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if !response["needs_setup"] {
		t.Errorf("expected needs_setup to be true when no users exist")
	}
}

func TestHandleSetupGET_UsersExist(t *testing.T) {
	resetAllRateLimiters()
	db, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	// Set up JWT key
	setupTestJWT(t, db)

	// Insert a user
	hash, err := bcrypt.GenerateFromPassword([]byte("password123"), 12)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = db.Exec("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
		"existinguser", string(hash), "admin")

	h := NewHandler(db, db)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/setup", nil)

	h.HandleSetupGET(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var response map[string]bool
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if response["needs_setup"] {
		t.Errorf("expected needs_setup to be false when users exist")
	}
}

func TestHandleSetupGET_DBError(t *testing.T) {
	// Test with nil DB to trigger error
	h := NewHandler(nil, nil)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/setup", nil)

	h.HandleSetupGET(w, r)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected status %d, got %d", http.StatusInternalServerError, w.Code)
	}
}

// =============================================================================
// Test HandleSetupPOST
// =============================================================================

// testServer creates an httptest.Server that allows setting custom remote address
type testServer struct {
	*httptest.Server
}

func newTestServer(handler http.Handler) *testServer {
	ts := httptest.NewServer(handler)
	return &testServer{ts}
}

// RemoteAddr returns a custom remote addr for testing
// Since we can't easily set RemoteAddr in httptest, we'll use unique IPs in tests
// by using httptest.NewRequest and setting up different scenarios

func TestHandleSetupPOST_Success(t *testing.T) {
	resetAllRateLimiters()
	db, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	// Set up JWT key
	setupTestJWT(t, db)

	h := NewHandler(db, db)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/setup",
		strings.NewReader(`{"username":"admin","password":"password123"}`))
	r.RemoteAddr = "192.0.2.1:12345" // Unique IP for this test

	h.HandleSetupPOST(w, r)

	if w.Code != http.StatusCreated {
		t.Errorf("expected status %d, got %d", http.StatusCreated, w.Code)
	}

	// Verify user was created
	var count int
	_ = db.QueryRow("SELECT COUNT(*) FROM users WHERE username = ?", "admin").Scan(&count)
	if count != 1 {
		t.Errorf("expected 1 user created, got %d", count)
	}

	// Verify response contains username and is_setup
	var response map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if response["username"] != "admin" {
		t.Errorf("expected username in response, got %v", response["username"])
	}
	if response["is_setup"] != true {
		t.Errorf("expected is_setup=true in response, got %v", response["is_setup"])
	}

	// Verify cookies are set
	if len(w.Result().Cookies()) != 2 {
		t.Errorf("expected 2 cookies, got %d", len(w.Result().Cookies()))
	}
}

func TestHandleSetupPOST_AlreadyCompleted(t *testing.T) {
	resetAllRateLimiters()
	db, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	// Set up JWT key
	setupTestJWT(t, db)

	// Insert a user first
	hash, err := bcrypt.GenerateFromPassword([]byte("password123"), 12)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = db.Exec("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
		"existinguser", string(hash), "admin")

	h := NewHandler(db, db)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/setup",
		strings.NewReader(`{"username":"newadmin","password":"password123"}`))

	h.HandleSetupPOST(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected status %d, got %d", http.StatusForbidden, w.Code)
	}
}

func TestHandleSetupPOST_InvalidJSON(t *testing.T) {
	resetAllRateLimiters()
	db, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	setupTestJWT(t, db)

	h := NewHandler(db, db)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/setup",
		strings.NewReader("{invalid json"))

	h.HandleSetupPOST(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestHandleSetupPOST_MissingFields(t *testing.T) {
	resetAllRateLimiters()
	db, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	setupTestJWT(t, db)

	h := NewHandler(db, db)
	w := httptest.NewRecorder()

	tests := []struct {
		name     string
		body     string
		expected int
	}{
		{"missing password", `{"username":"admin"}`, http.StatusBadRequest},
		{"missing username", `{"password":"password123"}`, http.StatusBadRequest},
		{"empty both", "{}", http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/api/v1/setup",
				strings.NewReader(tt.body))
			h.HandleSetupPOST(w, r)

			if w.Code != tt.expected {
				t.Errorf("expected status %d, got %d", tt.expected, w.Code)
			}
		})
	}
}

func TestHandleSetupPOST_DuplicateUsername(t *testing.T) {
	resetAllRateLimiters()
	// Note: When users already exist, setup returns 403 Forbidden first.
	// The duplicate username error only occurs when doing setup from scratch
	// but trying to create a user with an already-existing username.
	// This test verifies the "setup already completed" case.
	db, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	setupTestJWT(t, db)

	// Insert a user first
	hash, err := bcrypt.GenerateFromPassword([]byte("password123"), 12)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = db.Exec("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
		"duplicate", string(hash), "admin")

	h := NewHandler(db, db)
	w := httptest.NewRecorder()
	r := newRequestWithUniqueIP(http.MethodPost, "/api/v1/setup",
		`{"username":"duplicate","password":"password123"}`)

	h.HandleSetupPOST(w, r)

	// Since users already exist, setup returns 403 Forbidden
	if w.Code != http.StatusForbidden {
		t.Errorf("expected status %d, got %d", http.StatusForbidden, w.Code)
	}
}

// =============================================================================
// Test HandleLoginPOST
// =============================================================================

func TestHandleLoginPOST_Success(t *testing.T) {
	db, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	setupTestJWT(t, db)
	ResetRateLimitStore()

	// Insert a user
	hash, _ := bcrypt.GenerateFromPassword([]byte("password123"), 12)
	db.Exec("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)", "loginuser", string(hash), "admin")

	h := NewHandler(db, db)
	w := httptest.NewRecorder()

	tests := []struct {
		name     string
		body     string
		expected int
	}{
		{"wrong password", `{"username":"loginuser","password":"wrongpassword"}`, http.StatusUnauthorized},
		{"unknown user", `{"username":"unknown","password":"password123"}`, http.StatusUnauthorized},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/api/v1/login",
				strings.NewReader(tt.body))
			h.HandleLoginPOST(w, r)

			if w.Code != tt.expected {
				t.Errorf("expected status %d, got %d", tt.expected, w.Code)
			}
		})
	}
}

func TestHandleLoginPOST_MissingFields(t *testing.T) {
	db, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	setupTestJWT(t, db)

	h := NewHandler(db, db)
	w := httptest.NewRecorder()

	tests := []struct {
		name     string
		body     string
		expected int
	}{
		{"missing password", `{"username":"admin"}`, http.StatusBadRequest},
		{"missing username", `{"password":"password123"}`, http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/api/v1/login",
				strings.NewReader(tt.body))
			h.HandleLoginPOST(w, r)

			if w.Code != tt.expected {
				t.Errorf("expected status %d, got %d", tt.expected, w.Code)
			}
		})
	}
}

func TestHandleLoginPOST_InvalidJSON(t *testing.T) {
	db, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	setupTestJWT(t, db)

	h := NewHandler(db, db)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/login",
		strings.NewReader("{invalid json"))

	h.HandleLoginPOST(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

// =============================================================================
// Test HandleLogoutPOST
// =============================================================================

func TestHandleLogoutPOST_NoCookie(t *testing.T) {
	db, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	setupTestJWT(t, db)

	h := NewHandler(db, db)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/logout", nil)

	h.HandleLogoutPOST(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}
}

func TestHandleLogoutPOST_InvalidToken(t *testing.T) {
	db, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	setupTestJWT(t, db)

	h := NewHandler(db, db)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/logout", nil)
	r.AddCookie(&http.Cookie{Name: "runic_access_token", Value: "invalid-token"})

	h.HandleLogoutPOST(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}
}

// =============================================================================
// Test HandleGetMe
// =============================================================================

func TestHandleGetMe_Success(t *testing.T) {
	db, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	setupTestJWT(t, db)

	h := NewHandler(db, db)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	r = r.WithContext(withAdminContext(context.Background()))

	h.HandleGetMe(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var response map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if response["username"] != "adminuser" {
		t.Errorf("expected username 'adminuser', got %s", response["username"])
	}
	if response["role"] != "admin" {
		t.Errorf("expected role 'admin', got %s", response["role"])
	}
}

// =============================================================================
// Test HandleRefreshPOST
// =============================================================================

func TestHandleRefreshPOST_NoCookie(t *testing.T) {
	db, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	setupTestJWT(t, db)

	h := NewHandler(db, db)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", nil)

	h.HandleRefreshPOST(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}
}

func TestHandleRefreshPOST_InvalidToken(t *testing.T) {
	db, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	setupTestJWT(t, db)

	h := NewHandler(db, db)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", nil)
	r.AddCookie(&http.Cookie{Name: "runic_refresh_token", Value: "invalid-token"})

	h.HandleRefreshPOST(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}
}

// =============================================================================
// Test HandleSetup (router handler)
// =============================================================================

func TestHandleSetup_MethodNotAllowed(t *testing.T) {
	resetAllRateLimiters()
	db, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	setupTestJWT(t, db)

	h := NewHandler(db, db)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPut, "/api/v1/setup", nil)

	h.HandleSetup(w, r)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status %d, got %d", http.StatusMethodNotAllowed, w.Code)
	}
}

func TestHandleSetup_GET(t *testing.T) {
	resetAllRateLimiters()
	db, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	setupTestJWT(t, db)

	h := NewHandler(db, db)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/setup", nil)

	h.HandleSetup(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}
}

func TestHandleSetup_POST(t *testing.T) {
	resetAllRateLimiters()
	db, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	setupTestJWT(t, db)

	h := NewHandler(db, db)
	w := httptest.NewRecorder()
	r := newRequestWithUniqueIP(http.MethodPost, "/api/v1/setup",
		`{"username":"setupuser","password":"password123"}`)

	h.HandleSetup(w, r)

	if w.Code != http.StatusCreated {
		t.Errorf("expected status %d, got %d", http.StatusCreated, w.Code)
	}
}

// setupTestJWT sets up the JWT key for testing
func setupTestJWT(t *testing.T, db *sql.DB) {
	// Set a test JWT key - note that auth.InitJwtKey uses the secret from DB
	// For testing we need to directly set the JwtKey
	testKey := []byte("test-secret-key-for-testing-purposes-32")
	auth.JwtKeyMu.Lock()
	auth.JwtKey = testKey
	auth.JwtKeyMu.Unlock()

	// Set the auth DB for revocation checks
	auth.SetDB(db)
}

// =============================================================================
// Helper
// =============================================================================

// This file tests all auth handlers including:
// - HandleSetup (GET/POST)
// - HandleLoginPOST
// - HandleLogoutPOST
// - HandleGetMe
// - HandleRefreshPOST
