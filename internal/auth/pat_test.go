package auth

import (
	"context"
	"crypto/rand"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"runic/internal/store"
	"runic/internal/testutil"
)

// setupPATTestDB wires a real database plus the PAT stores into the auth
// package globals. Callers must defer the returned cleanup to reset globals
// and the revocation cache so tests stay isolated (token row IDs restart at 1
// per database while the cache is process-global).
func setupPATTestDB(t *testing.T) (*store.UserTokenStore, *store.UserStore, *sql.DB, func()) {
	t.Helper()
	db, cleanup := testutil.SetupTestDB(t)
	SetTokenStore(store.NewTokenStore(db))
	ts := store.NewUserTokenStore(db)
	us := store.NewUserStore(db)
	SetPATStore(ts)
	SetPATUserStore(us)
	SetSettingsStore(store.NewSettingsStore(db, nil))
	return ts, us, db, func() {
		SetPATStore(nil)
		SetPATUserStore(nil)
		SetSettingsStore(nil)
		clearRevocationCache()
		cleanup()
	}
}

func insertPATUser(t *testing.T, db *sql.DB, username, role string) int {
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

func createPAT(t *testing.T, ts *store.UserTokenStore, userID int, expires *time.Time) (raw string, id int64) {
	t.Helper()
	raw, hash, prefix, err := store.GeneratePAT()
	if err != nil {
		t.Fatalf("GeneratePAT: %v", err)
	}
	id, err = ts.CreateToken(context.Background(), userID, "test-token", hash, prefix, expires)
	if err != nil {
		t.Fatalf("CreateToken: %v", err)
	}
	return raw, id
}

func serveWithBearer(t *testing.T, bearer string) (code int, username, role, uniqueID string) {
	t.Helper()
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username = UsernameFromContext(r.Context())
		role = RoleFromContext(r.Context())
		uniqueID = UniqueIDFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/peers", nil)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	w := httptest.NewRecorder()
	Middleware(next).ServeHTTP(w, req)
	return w.Code, username, role, uniqueID
}

func TestPATMiddleware_Success(t *testing.T) {
	ts, _, db, cleanup := setupPATTestDB(t)
	defer cleanup()
	userID := insertPATUser(t, db, "alice", "viewer")
	raw, id := createPAT(t, ts, userID, nil)

	code, username, role, uniqueID := serveWithBearer(t, raw)

	if code != http.StatusOK {
		t.Fatalf("expected 200, got %d", code)
	}
	if username != "alice" || role != "viewer" {
		t.Errorf("context = %q/%q, want alice/viewer", username, role)
	}
	if want := patUniqueID(id); uniqueID != want {
		t.Errorf("uniqueID = %q, want %q", uniqueID, want)
	}
}

func TestPATMiddleware_UnknownToken(t *testing.T) {
	_, _, _, cleanup := setupPATTestDB(t)
	defer cleanup()

	raw, _, _, err := store.GeneratePAT()
	if err != nil {
		t.Fatalf("GeneratePAT: %v", err)
	}
	code, _, _, _ := serveWithBearer(t, raw)
	if code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", code)
	}
}

func TestPATMiddleware_NonPATBearerStillUnauthorized(t *testing.T) {
	_, _, _, cleanup := setupPATTestDB(t)
	defer cleanup()

	code, _, _, _ := serveWithBearer(t, "not-a-pat")
	if code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", code)
	}
}

func TestPATMiddleware_MissingHeader(t *testing.T) {
	_, _, _, cleanup := setupPATTestDB(t)
	defer cleanup()

	code, _, _, _ := serveWithBearer(t, "")
	if code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", code)
	}
}

func TestPATMiddleware_Revoked(t *testing.T) {
	ts, _, db, cleanup := setupPATTestDB(t)
	defer cleanup()
	userID := insertPATUser(t, db, "alice", "editor")
	raw, id := createPAT(t, ts, userID, nil)

	if code, _, _, _ := serveWithBearer(t, raw); code != http.StatusOK {
		t.Fatalf("pre-revoke: expected 200, got %d", code)
	}

	revoked, err := ts.RevokeToken(context.Background(), id, userID)
	if err != nil || !revoked {
		t.Fatalf("RevokeToken = %v, %v", revoked, err)
	}
	CachePATRevocation(id)

	if code, _, _, _ := serveWithBearer(t, raw); code != http.StatusUnauthorized {
		t.Errorf("post-revoke: expected 401, got %d", code)
	}
}

func TestPATMiddleware_RevokedWithoutCache(t *testing.T) {
	ts, _, db, cleanup := setupPATTestDB(t)
	defer cleanup()
	userID := insertPATUser(t, db, "alice", "editor")
	raw, id := createPAT(t, ts, userID, nil)

	// Revoke in the store only; the DB flag alone must reject the token.
	if revoked, err := ts.RevokeToken(context.Background(), id, userID); err != nil || !revoked {
		t.Fatalf("RevokeToken = %v, %v", revoked, err)
	}
	if code, _, _, _ := serveWithBearer(t, raw); code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", code)
	}
}

func TestPATMiddleware_Expired(t *testing.T) {
	ts, _, db, cleanup := setupPATTestDB(t)
	defer cleanup()
	userID := insertPATUser(t, db, "alice", "viewer")
	past := time.Now().Add(-time.Hour)
	raw, _ := createPAT(t, ts, userID, &past)

	if code, _, _, _ := serveWithBearer(t, raw); code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", code)
	}
}

func TestPATMiddleware_LiveRoleLoad(t *testing.T) {
	ts, _, db, cleanup := setupPATTestDB(t)
	defer cleanup()
	userID := insertPATUser(t, db, "alice", "viewer")
	raw, _ := createPAT(t, ts, userID, nil)

	if _, _, role, _ := serveWithBearer(t, raw); role != "viewer" {
		t.Fatalf("role = %q, want viewer", role)
	}
	if _, err := db.Exec("UPDATE users SET role = 'editor' WHERE id = ?", userID); err != nil {
		t.Fatalf("update role: %v", err)
	}
	if code, _, role, _ := serveWithBearer(t, raw); code != http.StatusOK || role != "editor" {
		t.Errorf("after demotion change: code = %d, role = %q; want 200/editor", code, role)
	}
}

func TestPATMiddleware_TouchLastUsed(t *testing.T) {
	ts, _, db, cleanup := setupPATTestDB(t)
	defer cleanup()
	userID := insertPATUser(t, db, "alice", "viewer")
	raw, id := createPAT(t, ts, userID, nil)

	if code, _, _, _ := serveWithBearer(t, raw); code != http.StatusOK {
		t.Fatalf("expected 200, got %d", code)
	}
	// TouchLastUsed runs fire-and-forget off the request path, so poll
	// briefly for the write instead of asserting synchronously.
	deadline := time.Now().Add(2 * time.Second)
	var lastUsed sql.NullString
	for {
		if err := db.QueryRow("SELECT last_used_at FROM user_api_tokens WHERE id = ?", id).Scan(&lastUsed); err != nil {
			t.Fatalf("select last_used_at: %v", err)
		}
		if lastUsed.Valid && lastUsed.String != "" {
			break
		}
		if time.Now().After(deadline) {
			t.Error("expected last_used_at to be recorded")
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestPATMiddleware_JWTRotationKeepsPAT(t *testing.T) {
	ts, _, db, cleanup := setupPATTestDB(t)
	defer cleanup()
	if err := InitJwtKey(context.Background(), db); err != nil {
		t.Fatalf("InitJwtKey: %v", err)
	}
	userID := insertPATUser(t, db, "alice", "admin")
	raw, _ := createPAT(t, ts, userID, nil)

	jwtToken, err := GenerateToken("alice", "admin", TokenTypeAccess, time.Hour)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}

	// Rotate the JWT signing key; PATs must be unaffected.
	JwtKeyMu.RLock()
	oldKey := append([]byte(nil), JwtKey...)
	JwtKeyMu.RUnlock()
	newKey := make([]byte, 32)
	if _, err := rand.Read(newKey); err != nil {
		t.Fatalf("rand: %v", err)
	}
	if err := RotateJwtKey(context.Background(), newKey); err != nil {
		t.Fatalf("RotateJwtKey: %v", err)
	}
	defer func() {
		JwtKeyMu.Lock()
		JwtKey = oldKey
		JwtPrevKey = nil
		JwtKeyMu.Unlock()
	}()

	if code, _, _, _ := serveWithBearer(t, raw); code != http.StatusOK {
		t.Errorf("PAT after rotation: expected 200, got %d", code)
	}
	// The pre-rotation JWT remains valid through the rotation window.
	if code, _, _, _ := serveWithBearer(t, jwtToken); code != http.StatusOK {
		t.Errorf("JWT after rotation: expected 200, got %d", code)
	}
}

func TestCachePATRevocation(t *testing.T) {
	clearRevocationCache()
	defer clearRevocationCache()
	CachePATRevocation(42)
	entry, ok := revocationCacheGet(patUniqueID(42))
	if !ok || !entry.revoked {
		t.Error("expected cached revocation for pat:42")
	}
}

func TestPATMiddleware_DisabledWithoutStores(t *testing.T) {
	_, _, _, cleanup := setupPATTestDB(t)
	defer cleanup()
	// Unwire PAT stores: the middleware must fall through to 401, preserving
	// existing behavior for deployments that never configure PATs.
	SetPATStore(nil)
	SetPATUserStore(nil)

	raw, _, _, err := store.GeneratePAT()
	if err != nil {
		t.Fatalf("GeneratePAT: %v", err)
	}
	if code, _, _, _ := serveWithBearer(t, raw); code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", code)
	}
}
