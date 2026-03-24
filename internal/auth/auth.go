package auth

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// contextKey is an unexported type for context keys in this package,
// preventing collisions with keys from other packages.
type contextKey string

const (
	ctxKeyUsername contextKey = "username"
	ctxKeyUniqueID contextKey = "unique_id"
)

var JwtKey []byte

func init() {
	envKey := os.Getenv("RUNIC_JWT_SECRET")
	if envKey != "" {
		JwtKey = []byte(envKey)
	} else if os.Getenv("ENV") == "production" {
		log.Fatal("RUNIC_JWT_SECRET must be set in production")
	} else {
		// Generate a random key for development instead of a hardcoded constant.
		// This means tokens don't survive server restarts in dev mode, which is acceptable.
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			log.Fatal("failed to generate random dev JWT key")
		}
		JwtKey = key
		log.Println("WARNING: using random JWT key in development mode (tokens will not persist across restarts)")
	}
}

type Claims struct {
	Username string `json:"username"`
	UniqueID string `json:"unique_id"`
	jwt.RegisteredClaims
}

func GenerateToken(username string) (string, error) {
	now := time.Now()
	expirationTime := now.Add(24 * time.Hour)

	// Generate a unique ID to ensure each token is different
	uniqueBytes := make([]byte, 8)
	rand.Read(uniqueBytes)
	uniqueID := hex.EncodeToString(uniqueBytes)

	claims := &Claims{
		Username: username,
		UniqueID: uniqueID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(JwtKey)
}

func ValidateToken(tokenString string) (*Claims, error) {
	claims := &Claims{}
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
func RevokeToken(ctx context.Context, uniqueID string, expiresAt time.Time) error {
	if authDB == nil {
		return fmt.Errorf("auth database not initialized")
	}
	_, err := authDB.ExecContext(ctx,
		`INSERT OR IGNORE INTO revoked_tokens (unique_id, expires_at) VALUES (?, ?)`,
		uniqueID, expiresAt.UTC().Format(time.RFC3339))
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
		`DELETE FROM revoked_tokens WHERE expires_at < datetime('now')`)
	return err
}

// --- Middleware ---

func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
		claims, err := ValidateToken(tokenStr)
		if err != nil || claims == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Check if the token has been revoked
		if IsRevoked(r.Context(), claims.UniqueID) {
			http.Error(w, "Unauthorized: token revoked", http.StatusUnauthorized)
			return
		}

		// Add claims to context using typed keys to prevent collisions
		ctx := context.WithValue(r.Context(), ctxKeyUsername, claims.Username)
		ctx = context.WithValue(ctx, ctxKeyUniqueID, claims.UniqueID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// LogoutHandler handles POST /logout by revoking the caller's current token.
func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
	claims, err := ValidateToken(tokenStr)
	if err != nil || claims == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	expiresAt := claims.ExpiresAt.Time
	if err := RevokeToken(r.Context(), claims.UniqueID, expiresAt); err != nil {
		http.Error(w, "Failed to revoke token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"logged_out"}`))
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

