package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"

	ic "runic/internal/common"
	"runic/internal/db"
)

// PAT (personal access token) constants. Raw tokens use crypto/rand 32 bytes
// hex-encoded, exactly like registration tokens, prefixed with PATTokenPrefix
// so the auth middleware can route them to the PAT fallback without attempting
// JWT validation.
const (
	// PATTokenPrefix marks a raw token as a personal access token.
	PATTokenPrefix = "runic_pat_"
	// patRandomBytes is the entropy per token (32 bytes, hex-encoded to 64 chars).
	patRandomBytes = 32
	// patPrefixChars is the number of random hex chars embedded in the stored
	// prefix for display and indexed lookup.
	patPrefixChars = 8
)

// UserAPIToken is the canonical row representation of a personal access token.
// TokenHash is the SHA256 hex digest; the raw token is never persisted.
type UserAPIToken struct {
	ID         int64
	UserID     int
	Name       string
	TokenHash  string
	Prefix     string
	ExpiresAt  sql.NullString
	LastUsedAt sql.NullString
	IsRevoked  bool
	CreatedAt  sql.NullString
}

// UserAPITokenView is the masked list representation of a personal access
// token. It never exposes the token hash (and the raw token is unrecoverable
// by design); Display carries the prefix-based masked form.
type UserAPITokenView struct {
	ID         int64  `json:"id"`
	Name       string `json:"name"`
	Prefix     string `json:"prefix"`
	Display    string `json:"display"`
	ExpiresAt  string `json:"expires_at,omitempty"`
	LastUsedAt string `json:"last_used_at,omitempty"`
	IsRevoked  bool   `json:"is_revoked"`
	CreatedAt  string `json:"created_at"`
}

// UserTokenStore provides data access for user API (PAT) tokens.
type UserTokenStore struct {
	db db.Querier
}

// NewUserTokenStore creates a new UserTokenStore.
func NewUserTokenStore(database db.Querier) *UserTokenStore {
	return &UserTokenStore{db: database}
}

// GeneratePAT creates a new raw personal access token and derives its SHA256
// hex digest and display prefix. Only the digest and prefix are persisted;
// the raw token must be shown to the caller exactly once.
func GeneratePAT() (rawToken, tokenHash, prefix string, err error) {
	tokenBytes := make([]byte, patRandomBytes)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", "", "", fmt.Errorf("generate PAT entropy: %w", err)
	}
	rawToken = PATTokenPrefix + hex.EncodeToString(tokenBytes)
	return rawToken, HashPATToken(rawToken), PrefixForPAT(rawToken), nil
}

// HashPATToken returns the SHA256 hex digest of a raw PAT. Digests (never raw
// tokens) are what the database stores and what the middleware compares.
func HashPATToken(rawToken string) string {
	sum := sha256.Sum256([]byte(rawToken))
	return hex.EncodeToString(sum[:])
}

// PrefixForPAT derives the stored display/lookup prefix from a raw PAT.
func PrefixForPAT(rawToken string) string {
	if len(rawToken) <= len(PATTokenPrefix)+patPrefixChars {
		return rawToken
	}
	return rawToken[:len(PATTokenPrefix)+patPrefixChars]
}

// MaskPATDisplay returns the masked display form of a stored prefix. The full
// token is unrecoverable after creation, so list views show the prefix plus an
// ellipsis. This delegates to the shared internal/common masking helper so
// PAT display stays consistent with the registration-token masking convention.
func MaskPATDisplay(prefix string) string {
	return ic.MaskTokenPrefix(prefix)
}

// CreateToken persists a new token, storing only the hash and prefix. The
// caller must have generated the raw token (see GeneratePAT) and is
// responsible for displaying it once. A nil expiresAt means the token never
// expires.
func (s *UserTokenStore) CreateToken(ctx context.Context, userID int, name, tokenHash, prefix string, expiresAt *time.Time) (int64, error) {
	var expiresVal interface{}
	if expiresAt != nil {
		expiresVal = expiresAt.UTC().Format(time.RFC3339)
	}
	result, err := s.db.ExecContext(ctx,
		`INSERT INTO user_api_tokens (user_id, name, token_hash, prefix, expires_at) VALUES (?, ?, ?, ?, ?)`,
		userID, name, tokenHash, prefix, expiresVal)
	if err != nil {
		return 0, fmt.Errorf("insert user api token: %w", err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("get insert id: %w", err)
	}
	return id, nil
}

// ListTokens returns the masked token list for a user, newest first. The
// token hash is never selected so digests cannot leak through list views.
func (s *UserTokenStore) ListTokens(ctx context.Context, userID int) ([]UserAPITokenView, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, name, prefix, expires_at, last_used_at, is_revoked, created_at
		 FROM user_api_tokens WHERE user_id = ? ORDER BY id DESC`, userID)
	if err != nil {
		return nil, fmt.Errorf("list user api tokens: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var tokens []UserAPITokenView
	for rows.Next() {
		var t UserAPITokenView
		var expiresAt, lastUsedAt, createdAt sql.NullString
		var isRevoked int
		if err := rows.Scan(&t.ID, &t.Name, &t.Prefix, &expiresAt, &lastUsedAt, &isRevoked, &createdAt); err != nil {
			return nil, fmt.Errorf("scan user api token: %w", err)
		}
		t.Display = MaskPATDisplay(t.Prefix)
		t.ExpiresAt = ic.FormatSQLiteDatetime(expiresAt.String)
		t.LastUsedAt = ic.FormatSQLiteDatetime(lastUsedAt.String)
		t.IsRevoked = isRevoked == 1
		t.CreatedAt = ic.FormatSQLiteDatetime(createdAt.String)
		tokens = append(tokens, t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows error user api tokens: %w", err)
	}
	return ic.EnsureSlice(tokens), nil
}

// RevokeToken marks a token revoked, scoped to its owning user so callers can
// only revoke their own tokens (admins resolve the target user first).
// Returns false if the token was not found, belongs to another user, or is
// already revoked.
func (s *UserTokenStore) RevokeToken(ctx context.Context, id int64, userID int) (bool, error) {
	result, err := s.db.ExecContext(ctx,
		`UPDATE user_api_tokens SET is_revoked = 1 WHERE id = ? AND user_id = ? AND is_revoked = 0`,
		id, userID)
	if err != nil {
		return false, fmt.Errorf("revoke user api token: %w", err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("rows affected: %w", err)
	}
	return rowsAffected > 0, nil
}

// LookupByHash resolves a token by its SHA256 hex digest, enforcing the
// revoked flag and expiry in SQL. The stored digest is additionally verified
// with a constant-time comparison so digest equality never depends on
// short-circuit string comparison. Expired or revoked tokens (and unknown
// digests) surface as sql.ErrNoRows so callers can use errors.Is.
func (s *UserTokenStore) LookupByHash(ctx context.Context, tokenHash string) (UserAPIToken, error) {
	var t UserAPIToken
	var isRevoked int
	err := s.db.QueryRowContext(ctx,
		`SELECT id, user_id, name, token_hash, prefix, expires_at, last_used_at, is_revoked, created_at
		 FROM user_api_tokens
		 WHERE token_hash = ? AND is_revoked = 0
		   AND (expires_at IS NULL OR datetime(expires_at) > datetime('now'))`,
		tokenHash,
	).Scan(&t.ID, &t.UserID, &t.Name, &t.TokenHash, &t.Prefix, &t.ExpiresAt, &t.LastUsedAt, &isRevoked, &t.CreatedAt)
	if err != nil {
		return UserAPIToken{}, fmt.Errorf("lookup user api token: %w", err)
	}
	if subtle.ConstantTimeCompare([]byte(t.TokenHash), []byte(tokenHash)) != 1 {
		return UserAPIToken{}, fmt.Errorf("lookup user api token: %w", sql.ErrNoRows)
	}
	// Defense in depth: re-check expiry in Go in case the stored timestamp
	// uses a format SQLite's datetime() could not compare.
	if t.ExpiresAt.Valid && t.ExpiresAt.String != "" {
		if exp, err := time.Parse(time.RFC3339, t.ExpiresAt.String); err == nil {
			if !exp.After(time.Now()) {
				return UserAPIToken{}, fmt.Errorf("lookup user api token: %w", sql.ErrNoRows)
			}
		} else if exp, err := time.Parse("2006-01-02 15:04:05", t.ExpiresAt.String); err == nil {
			if !exp.After(time.Now().UTC()) {
				return UserAPIToken{}, fmt.Errorf("lookup user api token: %w", sql.ErrNoRows)
			}
		}
	}
	t.IsRevoked = isRevoked == 1
	return t, nil
}

// CleanupExpiredTokens permanently removes expired tokens. Should be called
// periodically alongside the JWT revocation cleanup.
func (s *UserTokenStore) CleanupExpiredTokens(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM user_api_tokens WHERE expires_at IS NOT NULL AND datetime(expires_at) < datetime('now')`)
	if err != nil {
		return fmt.Errorf("cleanup expired user api tokens: %w", err)
	}
	return nil
}

// TouchLastUsed records token activity. Callers treat this as best-effort and
// ignore its error so a slow write path can never block authentication.
func (s *UserTokenStore) TouchLastUsed(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE user_api_tokens SET last_used_at = CURRENT_TIMESTAMP WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("touch user api token last used: %w", err)
	}
	return nil
}
