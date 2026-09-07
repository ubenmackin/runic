package store

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"runic/internal/db"

	_ "github.com/mattn/go-sqlite3"
)

func setupUserTokenStoreTestDB(t *testing.T) (*UserTokenStore, *UserStore, *sql.DB, func()) {
	t.Helper()
	f, err := os.CreateTemp("", "runic-user-token-store-test-*.db")
	if err != nil {
		t.Fatal(err)
	}
	dbPath := f.Name()
	if cErr := f.Close(); cErr != nil {
		t.Logf("Failed to close temp file: %v", cErr)
	}

	database, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		os.Remove(dbPath)
		t.Fatal(err)
	}

	// Single connection so PRAGMA foreign_keys=ON applies to every query
	// (PRAGMAs are per-connection in SQLite).
	database.SetMaxOpenConns(1)
	database.SetMaxIdleConns(1)

	if _, err := database.Exec("PRAGMA foreign_keys=ON"); err != nil {
		database.Close()
		os.Remove(dbPath)
		t.Fatal(err)
	}

	if _, err := database.Exec(db.Schema()); err != nil {
		database.Close()
		os.Remove(dbPath)
		t.Fatal(err)
	}

	tokenStore := NewUserTokenStore(db.New(database))
	userStore := NewUserStore(db.New(database))
	cleanup := func() {
		database.Close()
		os.Remove(dbPath)
	}
	return tokenStore, userStore, database, cleanup
}

func insertPATTestUser(t *testing.T, dbConn *sql.DB, username, role string) int {
	t.Helper()
	result, err := dbConn.Exec(
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

func TestGeneratePAT_Format(t *testing.T) {
	raw, hash, prefix, err := GeneratePAT()
	if err != nil {
		t.Fatalf("GeneratePAT: %v", err)
	}
	if !strings.HasPrefix(raw, PATTokenPrefix) {
		t.Errorf("raw token missing prefix: %q", raw)
	}
	if len(raw) != len(PATTokenPrefix)+64 {
		t.Errorf("raw token length = %d, want %d", len(raw), len(PATTokenPrefix)+64)
	}
	if len(hash) != 64 {
		t.Errorf("hash length = %d, want 64", len(hash))
	}
	if hash != HashPATToken(raw) {
		t.Error("HashPATToken mismatch")
	}
	if prefix != PrefixForPAT(raw) {
		t.Error("PrefixForPAT mismatch")
	}
	if !strings.HasPrefix(prefix, PATTokenPrefix) {
		t.Errorf("prefix missing marker: %q", prefix)
	}
	// Uniqueness.
	raw2, _, _, err := GeneratePAT()
	if err != nil {
		t.Fatalf("GeneratePAT: %v", err)
	}
	if raw == raw2 {
		t.Error("GeneratePAT returned duplicate token")
	}
}

func TestUserTokenStore_CreateAndLookupRoundtrip(t *testing.T) {
	ts, _, dbConn, cleanup := setupUserTokenStoreTestDB(t)
	defer cleanup()
	ctx := context.Background()

	userID := insertPATTestUser(t, dbConn, "alice", "editor")
	_, hash, prefix, err := GeneratePAT()
	if err != nil {
		t.Fatalf("GeneratePAT: %v", err)
	}
	expires := time.Now().Add(24 * time.Hour)
	id, err := ts.CreateToken(ctx, userID, "ci-token", hash, prefix, &expires)
	if err != nil {
		t.Fatalf("CreateToken: %v", err)
	}
	if id <= 0 {
		t.Fatalf("CreateToken returned invalid id %d", id)
	}

	got, err := ts.LookupByHash(ctx, hash)
	if err != nil {
		t.Fatalf("LookupByHash: %v", err)
	}
	if got.ID != id || got.UserID != userID || got.Name != "ci-token" {
		t.Errorf("lookup mismatch: %+v", got)
	}
	if got.TokenHash != hash || got.Prefix != prefix {
		t.Errorf("hash/prefix mismatch: %+v", got)
	}
	if got.IsRevoked {
		t.Error("new token must not be revoked")
	}
}

func TestUserTokenStore_HashOnlyPersisted(t *testing.T) {
	ts, _, dbConn, cleanup := setupUserTokenStoreTestDB(t)
	defer cleanup()
	ctx := context.Background()

	userID := insertPATTestUser(t, dbConn, "alice", "viewer")
	raw, hash, prefix, err := GeneratePAT()
	if err != nil {
		t.Fatalf("GeneratePAT: %v", err)
	}
	if _, err := ts.CreateToken(ctx, userID, "n", hash, prefix, nil); err != nil {
		t.Fatalf("CreateToken: %v", err)
	}

	var storedHash, storedPrefix, storedName string
	err = dbConn.QueryRowContext(ctx,
		"SELECT token_hash, prefix, name FROM user_api_tokens WHERE user_id = ?", userID,
	).Scan(&storedHash, &storedPrefix, &storedName)
	if err != nil {
		t.Fatalf("select: %v", err)
	}
	if storedHash != hash {
		t.Error("stored hash mismatch")
	}
	for _, v := range []string{storedHash, storedPrefix, storedName} {
		if v == raw {
			t.Error("raw token must never be persisted")
		}
	}
}

func TestUserTokenStore_LookupUnknown(t *testing.T) {
	ts, _, _, cleanup := setupUserTokenStoreTestDB(t)
	defer cleanup()

	_, err := ts.LookupByHash(context.Background(), HashPATToken(PATTokenPrefix+"doesnotexist"))
	if !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("expected sql.ErrNoRows, got %v", err)
	}
}

func TestUserTokenStore_Revoke(t *testing.T) {
	ts, _, dbConn, cleanup := setupUserTokenStoreTestDB(t)
	defer cleanup()
	ctx := context.Background()

	alice := insertPATTestUser(t, dbConn, "alice", "editor")
	bob := insertPATTestUser(t, dbConn, "bob", "viewer")
	_, hash, prefix, err := GeneratePAT()
	if err != nil {
		t.Fatalf("GeneratePAT: %v", err)
	}
	id, err := ts.CreateToken(ctx, alice, "n", hash, prefix, nil)
	if err != nil {
		t.Fatalf("CreateToken: %v", err)
	}

	// Another user cannot revoke it.
	if revoked, err := ts.RevokeToken(ctx, id, bob); err != nil || revoked {
		t.Errorf("cross-user revoke = %v, %v; want false, nil", revoked, err)
	}
	// Owner revokes.
	if revoked, err := ts.RevokeToken(ctx, id, alice); err != nil || !revoked {
		t.Fatalf("owner revoke = %v, %v; want true, nil", revoked, err)
	}
	// Second revoke is a no-op.
	if revoked, err := ts.RevokeToken(ctx, id, alice); err != nil || revoked {
		t.Errorf("second revoke = %v, %v; want false, nil", revoked, err)
	}
	// Revoked tokens do not resolve.
	if _, err := ts.LookupByHash(ctx, hash); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("revoked lookup: expected sql.ErrNoRows, got %v", err)
	}
}

func TestUserTokenStore_Expiry(t *testing.T) {
	ts, _, dbConn, cleanup := setupUserTokenStoreTestDB(t)
	defer cleanup()
	ctx := context.Background()

	userID := insertPATTestUser(t, dbConn, "alice", "viewer")
	_, expiredHash, expiredPrefix, err := GeneratePAT()
	if err != nil {
		t.Fatalf("GeneratePAT: %v", err)
	}
	past := time.Now().Add(-time.Hour)
	if _, err := ts.CreateToken(ctx, userID, "old", expiredHash, expiredPrefix, &past); err != nil {
		t.Fatalf("CreateToken: %v", err)
	}
	if _, err := ts.LookupByHash(ctx, expiredHash); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("expired lookup: expected sql.ErrNoRows, got %v", err)
	}

	_, liveHash, livePrefix, err := GeneratePAT()
	if err != nil {
		t.Fatalf("GeneratePAT: %v", err)
	}
	future := time.Now().Add(time.Hour)
	if _, err := ts.CreateToken(ctx, userID, "live", liveHash, livePrefix, &future); err != nil {
		t.Fatalf("CreateToken: %v", err)
	}
	if _, err := ts.LookupByHash(ctx, liveHash); err != nil {
		t.Errorf("live lookup: %v", err)
	}
}

func TestUserTokenStore_ListMasked(t *testing.T) {
	ts, _, dbConn, cleanup := setupUserTokenStoreTestDB(t)
	defer cleanup()
	ctx := context.Background()

	userID := insertPATTestUser(t, dbConn, "alice", "viewer")
	for _, name := range []string{"first", "second"} {
		_, hash, prefix, err := GeneratePAT()
		if err != nil {
			t.Fatalf("GeneratePAT: %v", err)
		}
		if _, err := ts.CreateToken(ctx, userID, name, hash, prefix, nil); err != nil {
			t.Fatalf("CreateToken: %v", err)
		}
	}

	tokens, err := ts.ListTokens(ctx, userID)
	if err != nil {
		t.Fatalf("ListTokens: %v", err)
	}
	if len(tokens) != 2 {
		t.Fatalf("ListTokens = %d tokens, want 2", len(tokens))
	}
	if tokens[0].Name != "second" {
		t.Errorf("expected newest first, got %q", tokens[0].Name)
	}
	for _, tok := range tokens {
		if tok.Display != tok.Prefix+"..." {
			t.Errorf("display %q is not masked prefix form", tok.Display)
		}
		if tok.Prefix == "" {
			t.Error("prefix must be exposed for display")
		}
	}

	other := insertPATTestUser(t, dbConn, "bob", "viewer")
	empty, err := ts.ListTokens(ctx, other)
	if err != nil {
		t.Fatalf("ListTokens: %v", err)
	}
	if len(empty) != 0 {
		t.Errorf("expected empty list, got %d", len(empty))
	}
}

func TestUserTokenStore_CleanupExpired(t *testing.T) {
	ts, _, dbConn, cleanup := setupUserTokenStoreTestDB(t)
	defer cleanup()
	ctx := context.Background()

	userID := insertPATTestUser(t, dbConn, "alice", "viewer")
	past := time.Now().Add(-time.Hour)
	future := time.Now().Add(time.Hour)
	cases := []struct {
		name    string
		expires *time.Time
	}{
		{"expired", &past},
		{"live", &future},
		{"forever", nil},
	}
	for _, c := range cases {
		_, hash, prefix, err := GeneratePAT()
		if err != nil {
			t.Fatalf("GeneratePAT: %v", err)
		}
		if _, err := ts.CreateToken(ctx, userID, c.name, hash, prefix, c.expires); err != nil {
			t.Fatalf("CreateToken: %v", err)
		}
	}

	if err := ts.CleanupExpiredTokens(ctx); err != nil {
		t.Fatalf("CleanupExpiredTokens: %v", err)
	}
	tokens, err := ts.ListTokens(ctx, userID)
	if err != nil {
		t.Fatalf("ListTokens: %v", err)
	}
	if len(tokens) != 2 {
		t.Fatalf("after cleanup: %d tokens, want 2", len(tokens))
	}
	for _, tok := range tokens {
		if tok.Name == "expired" {
			t.Error("expired token survived cleanup")
		}
	}
}

func TestUserTokenStore_TouchLastUsed(t *testing.T) {
	ts, _, dbConn, cleanup := setupUserTokenStoreTestDB(t)
	defer cleanup()
	ctx := context.Background()

	userID := insertPATTestUser(t, dbConn, "alice", "viewer")
	_, hash, prefix, err := GeneratePAT()
	if err != nil {
		t.Fatalf("GeneratePAT: %v", err)
	}
	id, err := ts.CreateToken(ctx, userID, "n", hash, prefix, nil)
	if err != nil {
		t.Fatalf("CreateToken: %v", err)
	}
	got, err := ts.LookupByHash(ctx, hash)
	if err != nil {
		t.Fatalf("LookupByHash: %v", err)
	}
	if got.LastUsedAt.Valid {
		t.Fatal("last_used_at should start NULL")
	}
	if err := ts.TouchLastUsed(ctx, id); err != nil {
		t.Fatalf("TouchLastUsed: %v", err)
	}
	got, err = ts.LookupByHash(ctx, hash)
	if err != nil {
		t.Fatalf("LookupByHash: %v", err)
	}
	if !got.LastUsedAt.Valid || got.LastUsedAt.String == "" {
		t.Error("last_used_at was not recorded")
	}
}

func TestUserTokenStore_DeleteUserCascades(t *testing.T) {
	ts, us, dbConn, cleanup := setupUserTokenStoreTestDB(t)
	defer cleanup()
	ctx := context.Background()

	userID := insertPATTestUser(t, dbConn, "alice", "viewer")
	_, hash, prefix, err := GeneratePAT()
	if err != nil {
		t.Fatalf("GeneratePAT: %v", err)
	}
	if _, err := ts.CreateToken(ctx, userID, "n", hash, prefix, nil); err != nil {
		t.Fatalf("CreateToken: %v", err)
	}

	if err := us.DeleteUser(ctx, userID); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	if _, err := ts.LookupByHash(ctx, hash); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("after user delete: expected sql.ErrNoRows, got %v", err)
	}
	tokens, err := ts.ListTokens(ctx, userID)
	if err != nil {
		t.Fatalf("ListTokens: %v", err)
	}
	if len(tokens) != 0 {
		t.Errorf("expected cascade to remove tokens, got %d", len(tokens))
	}
}
