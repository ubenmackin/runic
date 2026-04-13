// Package auth provides authentication utilities.
package auth

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"runic/internal/common/log"
	"runic/internal/db"
)

// contextKey is an unexported type for context keys in this package,
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
)

// InitJwtKey initializes the JWT key from the database or generates a random one.
// Must be called after database initialization.
func InitJwtKey(ctx context.Context, database *sql.DB) error {
	secret, err := db.GetSecret(ctx, database, "jwt_secret")
	if err == nil && secret != "" {
		JwtKeyMu.Lock()
		JwtKey = []byte(secret)
		JwtKeyMu.Unlock()
		return nil
	}

	// Generate random key as fallback
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return fmt.Errorf("failed to generate random JWT key: %w", err)
	}
	JwtKeyMu.Lock()
	JwtKey = key
	JwtKeyMu.Unlock()
	log.Warn("Using random JWT key (no jwt_secret found in database)")
	return nil
}

type Claims struct {
	Username string `json:"username"`
	UniqueID string `json:"unique_id"`
	Role     string `json:"role"`
	jwt.RegisteredClaims
}

func GenerateToken(username string, role string, duration time.Duration) (string, error) {
	now := time.Now()
	expirationTime := now.Add(duration)

	// Generate a unique ID to ensure each token is different
	uniqueBytes := make([]byte, 8)
	if _, err := rand.Read(uniqueBytes); err != nil {
		return "", fmt.Errorf("failed to generate unique ID: %w", err)
	}
	uniqueID := hex.EncodeToString(uniqueBytes)

	claims := &Claims{
		Username: username,
		UniqueID: uniqueID,
		Role:     role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	JwtKeyMu.RLock()
	defer JwtKeyMu.RUnlock()
	return token.SignedString(JwtKey)
}

func ValidateToken(tokenString string) (*Claims, error) {
	claims := &Claims{}
	JwtKeyMu.RLock()
	defer JwtKeyMu.RUnlock()
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		// Verify the signing algorithm to prevent algorithm confusion attacks.
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return JwtKey, nil
	})

	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			return nil, err
		}
		return nil, err
	}

	if !token.Valid {
		return nil, jwt.ErrSignatureInvalid
	}

	return claims, nil
}

// --- Token Revocation ---

// db holds the database connection for revocation queries.
// Set via SetDB during server startup.
var authDB *sql.DB

// SetDB sets the database connection used for token revocation checks.
func SetDB(database *sql.DB) {
	authDB = database
}

// RevokeToken marks a token's unique ID as revoked in the database.
func RevokeToken(ctx context.Context, uniqueID string, expiresAt time.Time, tokenType string) error {
	if authDB == nil {
		return fmt.Errorf("auth database not initialized")
	}
	_, err := authDB.ExecContext(ctx,
		`INSERT OR IGNORE INTO revoked_tokens (unique_id, expires_at, token_type) VALUES (?, ?, ?)`,
		uniqueID, expiresAt.UTC().Format(time.RFC3339), tokenType)
	return err
}

// IsRevoked checks whether a token's unique ID has been revoked.
func IsRevoked(ctx context.Context, uniqueID string) bool {
	if authDB == nil {
		return false
	}
	var count int
	err := authDB.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM revoked_tokens WHERE unique_id = ?`, uniqueID).Scan(&count)
	if err != nil {
		return false
	}
	return count > 0
}

// CleanupExpiredTokens removes revoked token entries whose original tokens have expired.
// Should be called periodically (e.g. every hour).
func CleanupExpiredTokens(ctx context.Context) error {
	if authDB == nil {
		return nil
	}
	_, err := authDB.ExecContext(ctx,
		`DELETE FROM revoked_tokens WHERE datetime(expires_at) < datetime('now')`)
	return err
}

// --- Middleware ---

func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var tokenStr string
		// Try cookie first (web UI)
		if c, err := r.Cookie("runic_access_token"); err == nil && c.Value != "" {
			tokenStr = c.Value
		} else {
			// Fall back to Bearer header (agent)
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			tokenStr = strings.TrimPrefix(authHeader, "Bearer ")
		}

		claims, err := ValidateToken(tokenStr)
		if err != nil || claims == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Check if the token has been revoked (with timeout for DB safety)
		revCtx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if IsRevoked(revCtx, claims.UniqueID) {
			http.Error(w, "Unauthorized: token revoked", http.StatusUnauthorized)
			return
		}

		// Add claims to context using typed keys to prevent collisions
		ctx := context.WithValue(r.Context(), ctxKeyUsername, claims.Username)
		ctx = context.WithValue(ctx, ctxKeyUniqueID, claims.UniqueID)
		ctx = context.WithValue(ctx, ctxKeyRole, claims.Role)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// UsernameFromContext extracts the authenticated username from the request context.
func UsernameFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(ctxKeyUsername).(string); ok {
		return v
	}
	return ""
}

// UniqueIDFromContext extracts the token's unique ID from the request context.
func UniqueIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(ctxKeyUniqueID).(string); ok {
		return v
	}
	return ""
}

// RoleFromContext extracts the user's role from the request context.
func RoleFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(ctxKeyRole).(string); ok {
		return v
	}
	return ""
}

// SetContextForTest sets role and username in context for testing purposes.
// This is needed because the context keys are unexported and can't be directly
// accessed from other packages.
func SetContextForTest(ctx context.Context, role, username string) context.Context {
	ctx = context.WithValue(ctx, ctxKeyRole, role)
	ctx = context.WithValue(ctx, ctxKeyUsername, username)
	return ctx
}
