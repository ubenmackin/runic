// Package auth provides authentication utilities.
package auth

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"runic/internal/common/log"
	"runic/internal/db"
	"runic/internal/store"
)

// preventing collisions with keys from other packages.
type contextKey string

const (
	ctxKeyUsername contextKey = "username"
	ctxKeyUniqueID contextKey = "unique_id"
	ctxKeyRole     contextKey = "role"
)

var (
	JwtKey   []byte
	JwtKeyMu sync.RWMutex

	// JwtPrevKey holds the previous signing key during key rotation.
	// Tokens signed with the old key are still accepted for verification
	// until the rotation window expires.
	JwtPrevKey []byte

	// JwtKeyRotationAt records when the key was last rotated.
	JwtKeyRotationAt time.Time

	// tokenStore is the store used for token revocation queries.
	tokenStore *store.TokenStore

	// settingsStore is the store used for persisting JWT key rotation.
	settingsStore *store.SettingsStore
)

// Token type constants used for access vs refresh token differentiation.
const (
	TokenTypeAccess  = "access"
	TokenTypeRefresh = "refresh"
)

// SetTokenStore sets the TokenStore used for token revocation operations.
func SetTokenStore(ts *store.TokenStore) {
	tokenStore = ts
}

// SetSettingsStore sets the SettingsStore used for persisting JWT key rotation.
func SetSettingsStore(ss *store.SettingsStore) {
	settingsStore = ss
}

// InitJwtKey initializes the JWT key. Must be called after database initialization.
func InitJwtKey(ctx context.Context, database db.Querier) error {
	settings := store.NewSettingsStore(database, nil)
	secret, err := settings.GetSystemConfig(ctx, "jwt_secret")
	if err == nil && secret != "" {
		JwtKeyMu.Lock()
		JwtKey = []byte(secret)
		JwtKeyMu.Unlock()
	} else if err != nil && !errors.Is(err, sql.ErrNoRows) {
		log.Warn("Failed to query jwt_secret from database", "error", err)
	}

	// Load the previous key if it exists (from a prior rotation).
	prevSecret, err := settings.GetSystemConfig(ctx, "jwt_prev_secret")
	if err == nil && prevSecret != "" {
		JwtKeyMu.Lock()
		JwtPrevKey = []byte(prevSecret)
		JwtKeyMu.Unlock()
	}

	if JwtKey == nil {
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return fmt.Errorf("failed to generate random JWT key: %w", err)
		}
		JwtKeyMu.Lock()
		JwtKey = key
		JwtKeyMu.Unlock()
		log.Warn("Using random JWT key (no jwt_secret found in database)")
	}
	return nil
}

type Claims struct {
	Username  string `json:"username"`
	UniqueID  string `json:"unique_id"`
	Role      string `json:"role"`
	TokenType string `json:"token_type"`
	jwt.RegisteredClaims
}

func GenerateToken(username string, role string, tokenType string, duration time.Duration) (string, error) {
	now := time.Now()
	expirationTime := now.Add(duration)

	uniqueBytes := make([]byte, 8)
	if _, err := rand.Read(uniqueBytes); err != nil {
		return "", fmt.Errorf("failed to generate unique ID: %w", err)
	}
	uniqueID := hex.EncodeToString(uniqueBytes)

	claims := &Claims{
		Username:  username,
		UniqueID:  uniqueID,
		Role:      role,
		TokenType: tokenType,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(now),
			Issuer:    "runic",
			Audience:  jwt.ClaimStrings{"runic"},
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	JwtKeyMu.RLock()
	defer JwtKeyMu.RUnlock()
	return token.SignedString(JwtKey)
}

// RotateJwtKey rotates the JWT signing key. The current key is retained as
// the previous key so that tokens signed before the rotation remain valid
// for verification during the overlapping rotation window.
// Both the new key and the old key are persisted to the database via the
// settings store so they survive a restart.
func RotateJwtKey(ctx context.Context, newKey []byte) error {
	JwtKeyMu.Lock()
	oldKey := JwtKey
	JwtPrevKey = oldKey
	JwtKey = newKey
	JwtKeyRotationAt = time.Now()
	JwtKeyMu.Unlock()

	if settingsStore != nil {
		if err := settingsStore.SetSystemConfig(ctx, "jwt_secret", string(newKey)); err != nil {
			return fmt.Errorf("failed to persist new JWT key: %w", err)
		}
		if oldKey != nil {
			if err := settingsStore.SetSystemConfig(ctx, "jwt_prev_secret", string(oldKey)); err != nil {
				return fmt.Errorf("failed to persist previous JWT key: %w", err)
			}
		}
	}
	return nil
}

func ValidateToken(tokenString string) (*Claims, error) {
	claims := &Claims{}
	JwtKeyMu.RLock()
	key := JwtKey
	prevKey := JwtPrevKey
	JwtKeyMu.RUnlock()

	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		// Verify the signing algorithm to prevent algorithm confusion attacks.
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return key, nil
	}, jwt.WithIssuer("runic"), jwt.WithAudience("runic"))

	// If validation fails with the primary key, try the previous key (rotation window).
	if err != nil && prevKey != nil {
		claims = &Claims{}
		token, err = jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return prevKey, nil
		}, jwt.WithIssuer("runic"), jwt.WithAudience("runic"))
	}

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, jwt.ErrSignatureInvalid
	}

	return claims, nil
}

// --- Token Revocation ---

func RevokeToken(ctx context.Context, uniqueID string, expiresAt time.Time, tokenType string) error {
	if tokenStore == nil {
		return fmt.Errorf("auth token store not initialized")
	}
	return tokenStore.RevokeToken(ctx, uniqueID, expiresAt, tokenType)
}

func IsRevoked(ctx context.Context, uniqueID string) bool {
	if tokenStore == nil {
		// No token store means we cannot verify revocation status.
		// Assume revoked to be safe rather than silently allowing potentially revoked tokens.
		return true
	}
	revoked, err := tokenStore.IsTokenRevoked(ctx, uniqueID)
	if err != nil {
		log.WarnContext(ctx, "failed to check token revocation, assuming revoked", "error", err)
		return true
	}
	return revoked
}

// CleanupExpiredTokens removes expired token revocation entries. Should be called periodically (e.g. every hour).
func CleanupExpiredTokens(ctx context.Context) error {
	if tokenStore == nil {
		return nil
	}
	return tokenStore.CleanupExpiredTokens(ctx)
}

// --- Middleware ---

func writeUnauthorizedJSON(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	if err := json.NewEncoder(w).Encode(map[string]string{"error": message}); err != nil {
		log.Warn("Failed to encode unauthorized response", "error", err)
	}
}

func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var tokenStr string
		// Try cookie first (web UI)
		if c, err := r.Cookie("runic_access_token"); err == nil && c.Value != "" {
			tokenStr = c.Value
		} else {
			// Fall back to Bearer header (agent)
			// Per RFC 7235, the Authorization scheme is case-insensitive. Handle
			// "Bearer", "bearer", "BEARER", etc.
			authHeader := r.Header.Get("Authorization")
			tokenStr = ExtractBearerToken(authHeader)
			if tokenStr == "" {
				writeUnauthorizedJSON(w, "Unauthorized")
				return
			}
		}

		claims, err := ValidateToken(tokenStr)
		if err != nil || claims == nil {
			writeUnauthorizedJSON(w, "Unauthorized")
			return
		}

		revCtx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if IsRevoked(revCtx, claims.UniqueID) {
			writeUnauthorizedJSON(w, "Unauthorized: token revoked")
			return
		}

		ctx := context.WithValue(r.Context(), ctxKeyUsername, claims.Username)
		ctx = context.WithValue(ctx, ctxKeyUniqueID, claims.UniqueID)
		ctx = context.WithValue(ctx, ctxKeyRole, claims.Role)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func UsernameFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(ctxKeyUsername).(string); ok {
		return v
	}
	return ""
}

func UniqueIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(ctxKeyUniqueID).(string); ok {
		return v
	}
	return ""
}

func RoleFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(ctxKeyRole).(string); ok {
		return v
	}
	return ""
}

// SetContextForTest sets auth context values for testing. This is needed because the context keys are unexported and can't be directly
// accessed from other packages.
func SetContextForTest(ctx context.Context, role, username, uniqueID string) context.Context {
	ctx = context.WithValue(ctx, ctxKeyRole, role)
	ctx = context.WithValue(ctx, ctxKeyUsername, username)
	ctx = context.WithValue(ctx, ctxKeyUniqueID, uniqueID)
	return ctx
}

// ExtractBearerToken extracts the token value from an Authorization header value.
// Per RFC 7235, the auth-scheme token is case-insensitive, so we accept
// "Bearer", "bearer", "BEARER", and any other casing variant.
// Returns the token string, or "" if the header does not contain a Bearer token.
func ExtractBearerToken(authHeader string) string {
	const bearerLen = len("Bearer ")
	if len(authHeader) <= bearerLen {
		return ""
	}
	// Case-insensitive prefix check per RFC 7235
	if !strings.EqualFold(authHeader[:bearerLen], "Bearer ") {
		return ""
	}
	return authHeader[bearerLen:]
}
