package store

import (
	"context"
	"testing"
	"time"

	"runic/internal/testutil"
)

func TestStoreTokenRevocation_UsesTokenExpiry(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	tokenStore := NewTokenStore(database)
	ctx := context.Background()

	// Long-lived legacy access tokens outlast the default access-token TTL, so
	// the revocation must be stored until the token's own expiry; clamping it
	// to a shorter TTL would let a stolen token validate again after cleanup.
	tokenExpiry := time.Now().Add(8 * time.Hour).UTC().Truncate(time.Second)
	if err := tokenStore.RevokeToken(ctx, "long-lived-token", tokenExpiry, "access"); err != nil {
		t.Fatalf("RevokeToken: %v", err)
	}

	var storedExpiry string
	if err := database.QueryRow(
		"SELECT expires_at FROM revoked_tokens WHERE unique_id = ?", "long-lived-token").Scan(&storedExpiry); err != nil {
		t.Fatalf("read stored expires_at: %v", err)
	}
	if want := tokenExpiry.Format(time.RFC3339); storedExpiry != want {
		t.Errorf("stored expires_at = %q, want token expiry %q", storedExpiry, want)
	}

	if err := tokenStore.CleanupExpiredTokens(ctx); err != nil {
		t.Fatalf("CleanupExpiredTokens: %v", err)
	}
	revoked, err := tokenStore.IsTokenRevoked(ctx, "long-lived-token")
	if err != nil {
		t.Fatalf("IsTokenRevoked: %v", err)
	}
	if !revoked {
		t.Fatal("expected the revocation to survive cleanup until the token's expiry")
	}

	// A revocation whose token has already expired is still pruned.
	expiredAt := time.Now().Add(-time.Minute).UTC().Truncate(time.Second)
	if err := tokenStore.RevokeToken(ctx, "expired-token", expiredAt, "access"); err != nil {
		t.Fatalf("RevokeToken expired: %v", err)
	}
	if err := tokenStore.CleanupExpiredTokens(ctx); err != nil {
		t.Fatalf("CleanupExpiredTokens after expired insert: %v", err)
	}
	revoked, err = tokenStore.IsTokenRevoked(ctx, "expired-token")
	if err != nil {
		t.Fatalf("IsTokenRevoked expired: %v", err)
	}
	if revoked {
		t.Error("expected the expired token's revocation to be cleaned up")
	}
}
