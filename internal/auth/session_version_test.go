package auth

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"runic/internal/store"
	"runic/internal/testutil"
)

// sessionTestServer wires the token store and the session user lookup against
// a fresh test database and returns an OK-handler wrapped by Middleware.
func sessionTestServer(t *testing.T) (*sql.DB, http.Handler) {
	t.Helper()
	db, cleanup := testutil.SetupTestDB(t)
	t.Cleanup(cleanup)
	SetTokenStore(store.NewTokenStore(db))
	SetSessionUserStore(store.NewUserStore(db))
	t.Cleanup(func() { SetSessionUserStore(nil) })

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	return db, Middleware(handler)
}

func insertSessionTestUser(t *testing.T, db *sql.DB, username, role string) {
	t.Helper()
	if _, err := db.Exec(
		"INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
		username, "bcrypt_hash", role); err != nil {
		t.Fatalf("insert user %q: %v", username, err)
	}
}

func serveBearerToken(handler http.Handler, token string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/protected", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	handler.ServeHTTP(w, r)
	return w
}

func TestMiddlewareAcceptsCurrentTokenVersion(t *testing.T) {
	db, handler := sessionTestServer(t)
	insertSessionTestUser(t, db, "currentuser", "viewer")

	token, err := GenerateTokenWithVersion("currentuser", "viewer", TokenTypeAccess, 1, time.Hour)
	if err != nil {
		t.Fatalf("GenerateTokenWithVersion failed: %v", err)
	}

	w := serveBearerToken(handler, token)
	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d: %s", http.StatusOK, w.Code, w.Body.String())
	}
}

func TestMiddlewareRejectsStaleTokenVersion(t *testing.T) {
	db, handler := sessionTestServer(t)
	insertSessionTestUser(t, db, "staleuser", "admin")

	token, err := GenerateTokenWithVersion("staleuser", "admin", TokenTypeAccess, 1, time.Hour)
	if err != nil {
		t.Fatalf("GenerateTokenWithVersion failed: %v", err)
	}

	// Password change: version advances, token stays at the old epoch.
	if _, err := db.Exec("UPDATE users SET token_version = token_version + 1 WHERE username = ?", "staleuser"); err != nil {
		t.Fatal(err)
	}

	w := serveBearerToken(handler, token)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d for a stale token version, got %d: %s", http.StatusUnauthorized, w.Code, w.Body.String())
	}
}

func TestMiddlewareRejectsVersionedTokenForDeletedUser(t *testing.T) {
	db, handler := sessionTestServer(t)
	insertSessionTestUser(t, db, "goneuser", "admin")

	token, err := GenerateTokenWithVersion("goneuser", "admin", TokenTypeAccess, 1, time.Hour)
	if err != nil {
		t.Fatalf("GenerateTokenWithVersion failed: %v", err)
	}

	if _, err := db.Exec("DELETE FROM users WHERE username = ?", "goneuser"); err != nil {
		t.Fatal(err)
	}

	w := serveBearerToken(handler, token)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d for a deleted user, got %d: %s", http.StatusUnauthorized, w.Code, w.Body.String())
	}
}

func TestMiddlewareRejectsVersionedTokenWhenStoreUnwired(t *testing.T) {
	// The signing key is provided by TestMain and revocation is wired, so the
	// only missing piece is the session user lookup. A versioned token must
	// fail closed rather than skip the token-version check.
	db, cleanup := testutil.SetupTestDB(t)
	t.Cleanup(cleanup)
	SetTokenStore(store.NewTokenStore(db))
	SetSessionUserStore(nil)

	token, err := GenerateTokenWithVersion("unwireduser", "admin", TokenTypeAccess, 1, time.Hour)
	if err != nil {
		t.Fatalf("GenerateTokenWithVersion failed: %v", err)
	}

	w := serveBearerToken(Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})), token)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d when the session store is unwired, got %d: %s", http.StatusUnauthorized, w.Code, w.Body.String())
	}
}

func TestGenerateTokenWithVersionEmbedsVersion(t *testing.T) {
	token, err := GenerateTokenWithVersion("epoch", "editor", TokenTypeRefresh, 7, time.Hour)
	if err != nil {
		t.Fatalf("GenerateTokenWithVersion failed: %v", err)
	}

	claims, err := ValidateToken(token)
	if err != nil || claims == nil {
		t.Fatalf("ValidateToken failed: %v", err)
	}
	if claims.TokenVersion != 7 {
		t.Errorf("expected token version 7, got %d", claims.TokenVersion)
	}
	if claims.TokenType != TokenTypeRefresh {
		t.Errorf("expected token type %q, got %q", TokenTypeRefresh, claims.TokenType)
	}
}

// Ensure the legacy wrapper still compiles/behaves as a version-less token so
// pre-upgrade sessions remain readable (they are bounded by their TTL and can
// never be refreshed because the refresh handler requires an exact match).
func TestGenerateTokenIsVersionless(t *testing.T) {
	token, err := GenerateToken("legacy", "viewer", TokenTypeAccess, time.Hour)
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}
	claims, err := ValidateToken(token)
	if err != nil || claims == nil {
		t.Fatalf("ValidateToken failed: %v", err)
	}
	if claims.TokenVersion != 0 {
		t.Errorf("expected legacy token version 0, got %d", claims.TokenVersion)
	}
}
