package users

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"runic/internal/auth"
	"runic/internal/store"
	"runic/internal/testutil"
)

func newTestTokenHandler(db *sql.DB) *TokenHandler {
	return NewTokenHandler(store.NewUserTokenStore(db), store.NewUserStore(db))
}

func insertTokenTestUser(t *testing.T, db *sql.DB, username, role string) int {
	t.Helper()
	result, err := db.Exec(
		"INSERT INTO users (username, password_hash, email, role) VALUES (?, ?, ?, ?)",
		username, "bcrypt_hash", username+"@test.com", role)
	if err != nil {
		t.Fatalf("insert user %q: %v", username, err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("last insert id: %v", err)
	}
	return int(id)
}

func withUserContext(role, username string) func(r *http.Request) *http.Request {
	return func(r *http.Request) *http.Request {
		return r.WithContext(auth.SetContextForTest(r.Context(), role, username, "test-unique-id"))
	}
}

type createTokenResponse struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"`
	Prefix    string `json:"prefix"`
	FullToken string `json:"full_token"`
	ExpiresAt string `json:"expires_at"`
}

func TestCreateToken_SelfSuccess(t *testing.T) {
	db, cleanup := testutil.SetupTestDB(t)
	defer cleanup()
	insertTokenTestUser(t, db, "alice", "editor")

	h := newTestTokenHandler(db)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/users/tokens", strings.NewReader(`{"name":"ci"}`))
	r = withUserContext("editor", "alice")(r)

	h.CreateToken(w, r)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected status %d, got %d: %s", http.StatusCreated, w.Code, w.Body.String())
	}
	var resp createTokenResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}
	if resp.ID <= 0 {
		t.Error("expected a token id")
	}
	if !strings.HasPrefix(resp.FullToken, "runic_pat_") {
		t.Errorf("full_token missing PAT marker: %q", resp.FullToken)
	}
	if !strings.HasPrefix(resp.FullToken, resp.Prefix) || resp.Prefix == "" {
		t.Errorf("prefix %q is not a prefix of the full token", resp.Prefix)
	}
	if resp.ExpiresAt != "" {
		t.Errorf("expected no expiry, got %q", resp.ExpiresAt)
	}

	// The stored credential must resolve by hash.
	ts := store.NewUserTokenStore(db)
	got, err := ts.LookupByHash(r.Context(), store.HashPATToken(resp.FullToken))
	if err != nil {
		t.Fatalf("LookupByHash: %v", err)
	}
	if got.ID != resp.ID {
		t.Errorf("lookup id = %d, want %d", got.ID, resp.ID)
	}
}

func TestCreateToken_WithExpiry(t *testing.T) {
	db, cleanup := testutil.SetupTestDB(t)
	defer cleanup()
	insertTokenTestUser(t, db, "alice", "viewer")

	h := newTestTokenHandler(db)
	future := time.Now().Add(48 * time.Hour).UTC().Format(time.RFC3339)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/users/tokens",
		strings.NewReader(`{"name":"short-lived","expires_at":"`+future+`"}`))
	r = withUserContext("viewer", "alice")(r)

	h.CreateToken(w, r)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected status %d, got %d: %s", http.StatusCreated, w.Code, w.Body.String())
	}
	var resp createTokenResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}
	if resp.ExpiresAt == "" {
		t.Error("expected expires_at to be echoed")
	}
}

func TestCreateToken_Validation(t *testing.T) {
	db, cleanup := testutil.SetupTestDB(t)
	defer cleanup()
	insertTokenTestUser(t, db, "alice", "editor")

	h := newTestTokenHandler(db)
	past := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	tests := []struct {
		name       string
		body       string
		wantStatus int
	}{
		{"missing name", `{}`, http.StatusBadRequest},
		{"blank name", `{"name":"  "}`, http.StatusBadRequest},
		{"name too long", `{"name":"` + strings.Repeat("a", 101) + `"}`, http.StatusBadRequest},
		{"invalid json", `{`, http.StatusBadRequest},
		{"bad expiry format", `{"name":"x","expires_at":"tomorrow"}`, http.StatusBadRequest},
		{"past expiry", `{"name":"x","expires_at":"` + past + `"}`, http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, "/api/v1/users/tokens", strings.NewReader(tt.body))
			r = withUserContext("editor", "alice")(r)
			h.CreateToken(w, r)
			if w.Code != tt.wantStatus {
				t.Errorf("expected status %d, got %d: %s", tt.wantStatus, w.Code, w.Body.String())
			}
		})
	}
}

func TestCreateToken_BodyTooLarge(t *testing.T) {
	db, cleanup := testutil.SetupTestDB(t)
	defer cleanup()
	insertTokenTestUser(t, db, "alice", "editor")

	h := newTestTokenHandler(db)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/users/tokens",
		strings.NewReader(`{"name":"`+strings.Repeat("a", 2<<20)+`"}`))
	r = withUserContext("editor", "alice")(r)

	h.CreateToken(w, r)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("expected status %d, got %d", http.StatusRequestEntityTooLarge, w.Code)
	}
}

func TestCreateToken_Unauthenticated(t *testing.T) {
	db, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	h := newTestTokenHandler(db)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/users/tokens", strings.NewReader(`{"name":"x"}`))

	h.CreateToken(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}
}

func TestCreateToken_AdminForOtherUser(t *testing.T) {
	db, cleanup := testutil.SetupTestDB(t)
	defer cleanup()
	insertTokenTestUser(t, db, "root", "admin")
	insertTokenTestUser(t, db, "bob", "viewer")

	var bobID int
	if err := db.QueryRow("SELECT id FROM users WHERE username = 'bob'").Scan(&bobID); err != nil {
		t.Fatalf("select bob id: %v", err)
	}

	h := newTestTokenHandler(db)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/users/tokens", strings.NewReader(`{"name":"for-bob"}`))
	r = withUserContext("admin", "root")(r)
	r = muxVars(r, map[string]string{"id": strconv.Itoa(bobID)})

	h.CreateToken(w, r)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected status %d, got %d: %s", http.StatusCreated, w.Code, w.Body.String())
	}
	var resp createTokenResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !strings.HasPrefix(resp.FullToken, "runic_pat_") {
		t.Errorf("full_token missing PAT marker: %q", resp.FullToken)
	}

	// The token belongs to bob.
	ts := store.NewUserTokenStore(db)
	got, err := ts.LookupByHash(r.Context(), store.HashPATToken(resp.FullToken))
	if err != nil {
		t.Fatalf("LookupByHash: %v", err)
	}
	if got.UserID != bobID {
		t.Errorf("token owner = %d, want %d", got.UserID, bobID)
	}
}

func TestCreateToken_NonAdminForOtherUserForbidden(t *testing.T) {
	db, cleanup := testutil.SetupTestDB(t)
	defer cleanup()
	insertTokenTestUser(t, db, "alice", "editor")
	insertTokenTestUser(t, db, "bob", "viewer")

	var bobID int
	if err := db.QueryRow("SELECT id FROM users WHERE username = 'bob'").Scan(&bobID); err != nil {
		t.Fatalf("select bob id: %v", err)
	}

	h := newTestTokenHandler(db)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/users/tokens", strings.NewReader(`{"name":"x"}`))
	r = withUserContext("editor", "alice")(r)
	r = muxVars(r, map[string]string{"id": strconv.Itoa(bobID)})

	h.CreateToken(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected status %d, got %d: %s", http.StatusForbidden, w.Code, w.Body.String())
	}
}

func TestListTokens_Masked(t *testing.T) {
	db, cleanup := testutil.SetupTestDB(t)
	defer cleanup()
	insertTokenTestUser(t, db, "alice", "viewer")

	h := newTestTokenHandler(db)

	// Create two tokens through the handler (single full display each).
	var raws []string
	for _, name := range []string{"one", "two"} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/api/v1/users/tokens",
			strings.NewReader(`{"name":"`+name+`"}`))
		r = withUserContext("viewer", "alice")(r)
		h.CreateToken(w, r)
		if w.Code != http.StatusCreated {
			t.Fatalf("create %s: got %d", name, w.Code)
		}
		var resp createTokenResponse
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		raws = append(raws, resp.FullToken)
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/users/tokens", nil)
	r = withUserContext("viewer", "alice")(r)
	h.ListTokens(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, w.Code)
	}
	var items []map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &items); err != nil {
		t.Fatalf("unmarshal list: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("expected 2 tokens, got %d", len(items))
	}
	for _, item := range items {
		for _, secret := range []string{"full_token", "token_hash", "tokenHash"} {
			if _, ok := item[secret]; ok {
				t.Errorf("list view must not expose %q", secret)
			}
		}
		display, _ := item["display"].(string)
		prefix, _ := item["prefix"].(string)
		if prefix == "" || display != prefix+"..." {
			t.Errorf("display %q is not the masked prefix form", display)
		}
		for _, raw := range raws {
			if display == raw {
				t.Error("list view must never contain the raw token")
			}
		}
	}
}

func TestRevokeToken(t *testing.T) {
	db, cleanup := testutil.SetupTestDB(t)
	defer cleanup()
	insertTokenTestUser(t, db, "alice", "viewer")

	h := newTestTokenHandler(db)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/users/tokens", strings.NewReader(`{"name":"doomed"}`))
	r = withUserContext("viewer", "alice")(r)
	h.CreateToken(w, r)
	if w.Code != http.StatusCreated {
		t.Fatalf("create: got %d: %s", w.Code, w.Body.String())
	}
	var created createTokenResponse
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// Revoke → 204.
	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodDelete, "/api/v1/users/tokens/1", nil)
	r = withUserContext("viewer", "alice")(r)
	r = muxVars(r, map[string]string{"token_id": strconv.FormatInt(created.ID, 10)})
	h.RevokeToken(w, r)
	if w.Code != http.StatusNoContent {
		t.Fatalf("expected status %d, got %d: %s", http.StatusNoContent, w.Code, w.Body.String())
	}

	// The credential no longer resolves.
	ts := store.NewUserTokenStore(db)
	if _, err := ts.LookupByHash(r.Context(), store.HashPATToken(created.FullToken)); err == nil {
		t.Error("revoked token still resolves")
	}

	// Second revoke → 404.
	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodDelete, "/api/v1/users/tokens/1", nil)
	r = withUserContext("viewer", "alice")(r)
	r = muxVars(r, map[string]string{"token_id": strconv.FormatInt(created.ID, 10)})
	h.RevokeToken(w, r)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected status %d, got %d", http.StatusNotFound, w.Code)
	}

	// Unknown token → 404.
	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodDelete, "/api/v1/users/tokens/9999", nil)
	r = withUserContext("viewer", "alice")(r)
	r = muxVars(r, map[string]string{"token_id": "9999"})
	h.RevokeToken(w, r)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected status %d, got %d", http.StatusNotFound, w.Code)
	}

	// Invalid token id → 400.
	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodDelete, "/api/v1/users/tokens/x", nil)
	r = withUserContext("viewer", "alice")(r)
	r = muxVars(r, map[string]string{"token_id": "x"})
	h.RevokeToken(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestRevokeToken_OtherUsersTokenNotFound(t *testing.T) {
	db, cleanup := testutil.SetupTestDB(t)
	defer cleanup()
	insertTokenTestUser(t, db, "alice", "viewer")
	insertTokenTestUser(t, db, "bob", "viewer")

	h := newTestTokenHandler(db)

	// Alice creates a token.
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/users/tokens", strings.NewReader(`{"name":"alice-tok"}`))
	r = withUserContext("viewer", "alice")(r)
	h.CreateToken(w, r)
	if w.Code != http.StatusCreated {
		t.Fatalf("create: got %d: %s", w.Code, w.Body.String())
	}
	var created createTokenResponse
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// Bob cannot revoke it (scoped to the owner → 404, no existence leak).
	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodDelete, "/api/v1/users/tokens/1", nil)
	r = withUserContext("viewer", "bob")(r)
	r = muxVars(r, map[string]string{"token_id": strconv.FormatInt(created.ID, 10)})
	h.RevokeToken(w, r)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected status %d, got %d", http.StatusNotFound, w.Code)
	}
}
