// Package auth provides authentication utilities.
package auth

import (
	"container/list"
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
	"golang.org/x/sync/singleflight"

	"runic/internal/common/constants"
	"runic/internal/common/log"
	"runic/internal/db"
	"runic/internal/store"
)

// contextKey is an unexported named-int type so that values of it cannot
// collide with context keys defined in other packages (a Go idiom for
// safe context.WithValue use).
type contextKey int

const (
	ctxKeyUsername contextKey = iota
	ctxKeyUniqueID
	ctxKeyRole
)

var (
	JwtKey   []byte
	JwtKeyMu sync.RWMutex

	// JwtPrevKey holds the previous signing key during key rotation.
	// Tokens signed with the old key are still accepted for verification
	// until the rotation window expires.
	JwtPrevKey []byte

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

// revocationCacheTTL bounds how long a positive revocation lookup is cached.
// Negative results (revoked=false) are never cached so a token revoked via
// the database, a direct store write, or a peer instance is observed on the
// next request instead of being accepted for up to the TTL.
const revocationCacheTTL = 30 * time.Second

// maxRevocationCacheEntries bounds the number of cached revocations so the
// cache cannot grow without limit.
const maxRevocationCacheEntries = 10000

type revocationCacheEntry struct {
	revoked   bool
	expiresAt time.Time
}

type revocationCacheItem struct {
	key   string
	entry revocationCacheEntry
}

var (
	revocationCacheMu sync.Mutex
	revocationCache   = make(map[string]*list.Element)
	revocationLRU     = list.New()
	// revocationFlight deduplicates concurrent revocation DB lookups for the
	// same token so a burst of cache misses does not thundering-herd the DB.
	revocationFlight singleflight.Group
)

func revocationCacheGet(key string) (revocationCacheEntry, bool) {
	revocationCacheMu.Lock()
	defer revocationCacheMu.Unlock()
	elem, ok := revocationCache[key]
	if !ok {
		return revocationCacheEntry{}, false
	}
	item, ok := elem.Value.(revocationCacheItem)
	if !ok {
		revocationLRU.Remove(elem)
		delete(revocationCache, key)
		return revocationCacheEntry{}, false
	}
	if time.Now().After(item.entry.expiresAt) {
		revocationLRU.Remove(elem)
		delete(revocationCache, key)
		return revocationCacheEntry{}, false
	}
	revocationLRU.MoveToFront(elem)
	return item.entry, true
}

func revocationCacheAdd(key string, entry revocationCacheEntry) {
	revocationCacheMu.Lock()
	defer revocationCacheMu.Unlock()
	if elem, ok := revocationCache[key]; ok {
		elem.Value = revocationCacheItem{key: key, entry: entry}
		revocationLRU.MoveToFront(elem)
		return
	}
	if revocationLRU.Len() >= maxRevocationCacheEntries {
		if back := revocationLRU.Back(); back != nil {
			if item, ok := back.Value.(revocationCacheItem); ok {
				delete(revocationCache, item.key)
			}
			revocationLRU.Remove(back)
		}
	}
	elem := revocationLRU.PushFront(revocationCacheItem{key: key, entry: entry})
	revocationCache[key] = elem
}

func clearRevocationCache() {
	revocationCacheMu.Lock()
	defer revocationCacheMu.Unlock()
	revocationCache = make(map[string]*list.Element)
	revocationLRU.Init()
}

// SetTokenStore sets the TokenStore used for token revocation operations.
func SetTokenStore(ts *store.TokenStore) {
	tokenStore = ts
	clearRevocationCache()
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

	JwtKeyMu.RLock()
	needsNewKey := JwtKey == nil
	JwtKeyMu.RUnlock()
	if needsNewKey {
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return fmt.Errorf("failed to generate random JWT key: %w", err)
		}
		JwtKeyMu.Lock()
		// Re-check under the write lock: another goroutine may have populated
		// JwtKey while we were deriving a random one. If so, discard ours.
		if JwtKey == nil {
			JwtKey = key
		}
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
		primaryErr := err
		claims = &Claims{}
		token, err = jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return prevKey, nil
		}, jwt.WithIssuer("runic"), jwt.WithAudience("runic"))
		// If the rotation-window attempt also failed, surface both errors so
		// operators can tell that the primary key was tried first.
		if err != nil {
			err = fmt.Errorf("%w (primary key error: %v)", err, primaryErr)
		}
	}

	if err != nil {
		return nil, fmt.Errorf("validate token: %w", err)
	}

	if !token.Valid {
		return nil, errors.New("token reported as invalid by parser")
	}

	return claims, nil
}

// --- Token Revocation ---

func RevokeToken(ctx context.Context, uniqueID string, expiresAt time.Time, tokenType string) error {
	if tokenStore == nil {
		return fmt.Errorf("auth token store not initialized")
	}
	if err := tokenStore.RevokeToken(ctx, uniqueID, expiresAt, tokenType); err != nil {
		return fmt.Errorf("revoke token: %w", err)
	}
	revocationCacheAdd(uniqueID, revocationCacheEntry{revoked: true, expiresAt: time.Now().Add(revocationCacheTTL)})
	return nil
}

func IsRevoked(ctx context.Context, uniqueID string) bool {
	if tokenStore == nil {
		// No token store means we cannot verify revocation status.
		// Assume revoked to be safe rather than silently allowing potentially revoked tokens.
		return true
	}
	if entry, ok := revocationCacheGet(uniqueID); ok {
		return entry.revoked
	}
	v, err, _ := revocationFlight.Do(uniqueID, func() (interface{}, error) {
		lookupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), constants.RevocationCheckTimeout)
		defer cancel()
		return tokenStore.IsTokenRevoked(lookupCtx, uniqueID)
	})
	if err != nil {
		log.WarnContext(ctx, "failed to check token revocation, assuming revoked", "error", err)
		return true
	}
	revoked, ok := v.(bool)
	if !ok {
		log.WarnContext(ctx, "unexpected revocation lookup result, assuming revoked")
		return true
	}
	if revoked {
		revocationCacheAdd(uniqueID, revocationCacheEntry{revoked: true, expiresAt: time.Now().Add(revocationCacheTTL)})
	}
	return revoked
}

// CleanupExpiredTokens removes expired token revocation entries. Should be called periodically (e.g. every hour).
func CleanupExpiredTokens(ctx context.Context) error {
	if tokenStore == nil {
		return nil
	}
	if err := tokenStore.CleanupExpiredTokens(ctx); err != nil {
		return fmt.Errorf("cleanup expired tokens: %w", err)
	}
	clearRevocationCache()
	return nil
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
			log.WarnContext(r.Context(), "JWT verification failed", "error", err)
			writeUnauthorizedJSON(w, "Unauthorized")
			return
		}

		revCtx, cancel := context.WithTimeout(r.Context(), constants.RevocationCheckTimeout)
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
