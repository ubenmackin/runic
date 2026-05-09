package store

import (
	"context"
	"fmt"
	"time"

	"runic/internal/db"
)

// TokenStore provides data access for token revocation queries.
type TokenStore struct {
	db db.Querier
}

// NewTokenStore creates a new TokenStore.
func NewTokenStore(database db.Querier) *TokenStore {
	return &TokenStore{db: database}
}

// RevokeToken inserts a token revocation entry. Uses INSERT OR IGNORE to
// handle duplicate revocations gracefully.
func (s *TokenStore) RevokeToken(ctx context.Context, uniqueID string, expiresAt time.Time, tokenType string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT OR IGNORE INTO revoked_tokens (unique_id, expires_at, token_type) VALUES (?, ?, ?)`,
		uniqueID, expiresAt.UTC().Format(time.RFC3339), tokenType)
	if err != nil {
		return fmt.Errorf("revoke token %q: %w", uniqueID, err)
	}
	return nil
}

// IsTokenRevoked returns true if the token with the given uniqueID has been revoked.
func (s *TokenStore) IsTokenRevoked(ctx context.Context, uniqueID string) (bool, error) {
	var count int
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM revoked_tokens WHERE unique_id = ?`, uniqueID).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("check token revoked %q: %w", uniqueID, err)
	}
	return count > 0, nil
}

// CleanupExpiredTokens removes expired token revocation entries.
// Should be called periodically (e.g. every hour).
func (s *TokenStore) CleanupExpiredTokens(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM revoked_tokens WHERE datetime(expires_at) < datetime('now')`)
	if err != nil {
		return fmt.Errorf("cleanup expired tokens: %w", err)
	}
	return nil
}
