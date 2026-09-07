// Package auth provides authentication utilities.
package auth

import (
	"container/list"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/sync/singleflight"

	"runic/internal/common/constants"
	"runic/internal/common/log"
	"runic/internal/db"
	"runic/internal/models"
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

	// authStoresMu guards tokenStore, settingsStore, patStore, and
	// patUserLookup. Setters take the write lock while readers take the
	// read lock so concurrent Middleware/authenticatePAT/IsRevoked requests
	// cannot race with wiring.
	authStoresMu sync.RWMutex

	// tokenStore is the store used for token revocation queries.
	tokenStore *store.TokenStore

	// settingsStore is the store used for persisting JWT key rotation.
	settingsStore *store.SettingsStore

	// patStore resolves personal access tokens by their SHA256 hex digest.
	// patUserLookup loads the live user record (username + role) for a PAT.
	// Both are nil until wired via SetPATStore/SetPATUserStore; while nil,
	// PAT authentication is disabled and the middleware falls through to 401.
	patStore      patTokenStore
	patUserLookup patUserStore
)

// patTokenPrefix marks a Bearer token as a personal access token. PATs bypass
// JWT validation entirely so rotation of jwt_secret never invalidates them.
const patTokenPrefix = "runic_pat_"

// patTokenStore is the subset of *store.UserTokenStore used for PAT auth.
type patTokenStore interface {
	LookupByHash(ctx context.Context, tokenHash string) (store.UserAPIToken, error)
	TouchLastUsed(ctx context.Context, id int64) error
}

// patUserStore is the subset of *store.UserStore used for live role lookup.
type patUserStore interface {
	GetUserByID(ctx context.Context, id int) (models.UserRow, error)
}

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
	authStoresMu.Lock()
	tokenStore = ts
	authStoresMu.Unlock()
	clearRevocationCache()
}

// SetSettingsStore sets the SettingsStore used for persisting JWT key rotation.
func SetSettingsStore(ss *store.SettingsStore) {
	authStoresMu.Lock()
	settingsStore = ss
	authStoresMu.Unlock()
}

// SetPATStore sets the store used to resolve personal access tokens.
// Until set, PAT authentication is disabled.
func SetPATStore(s patTokenStore) {
	authStoresMu.Lock()
	patStore = s
	authStoresMu.Unlock()
}

// SetPATUserStore sets the store used for live PAT role lookup.
// Until set, PAT authentication is disabled.
func SetPATUserStore(s patUserStore) {
	authStoresMu.Lock()
	patUserLookup = s
	authStoresMu.Unlock()
}

// patUniqueID returns the context unique ID for a PAT row ID. PATs carry no
// JWT claims, so the row ID namespaced with the "pat:" prefix identifies the
// credential in request context, logs, and the revocation cache.
func patUniqueID(tokenID int64) string {
	return "pat:" + strconv.FormatInt(tokenID, 10)
}

// CachePATRevocation records a PAT revocation in the shared revocation cache
// so in-flight credentials are rejected without waiting for a DB round trip.
// Callers invoke this immediately after marking a token revoked in the store.
// It only touches in-memory state and never logs token material.
func CachePATRevocation(tokenID int64) {
	revocationCacheAdd(patUniqueID(tokenID), revocationCacheEntry{revoked: true, expiresAt: time.Now().Add(revocationCacheTTL)})
}

// authenticatePAT authenticates a `Bearer runic_pat_*` personal access token
// from the Authorization header. It hashes the presented token (SHA256 hex,
// matching what the store persists), resolves it with expiry/revocation
// enforcement, honors the shared revocation cache, loads the live user role
// from the database, and records last use on a best-effort basis.
// The raw token is never logged. Returns username, role, uniqueID, ok.
func authenticatePAT(r *http.Request) (string, string, string, bool) {
	raw := ExtractBearerToken(r.Header.Get("Authorization"))
	if raw == "" || !strings.HasPrefix(raw, patTokenPrefix) {
		return "", "", "", false
	}
	authStoresMu.RLock()
	storeSnap := patStore
	lookupSnap := patUserLookup
	authStoresMu.RUnlock()
	if storeSnap == nil || lookupSnap == nil {
		return "", "", "", false
	}
	// Only the digest ever touches the database or comparisons.
	sum := sha256.Sum256([]byte(raw))
	tokenHash := hex.EncodeToString(sum[:])

	ctx, cancel := context.WithTimeout(r.Context(), constants.RevocationCheckTimeout)
	defer cancel()

	tok, err := storeSnap.LookupByHash(ctx, tokenHash)
	if err != nil {
		return "", "", "", false
	}
	// Defense in depth: constant-time verification of the stored digest.
	if subtle.ConstantTimeCompare([]byte(tok.TokenHash), []byte(tokenHash)) != 1 {
		return "", "", "", false
	}
	uniqueID := patUniqueID(tok.ID)
	// Honor the shared revocation cache populated at revoke time.
	if entry, ok := revocationCacheGet(uniqueID); ok && entry.revoked {
		return "", "", "", false
	}
	// IsRevoked is fail-closed when the JWT store is unwired, so it must run
	// unconditionally here; guarding on tokenStore would let PATs bypass
	// revocation entirely.
	if IsRevoked(ctx, uniqueID) {
		return "", "", "", false
	}
	// Live role load so role changes apply to existing PATs immediately.
	user, err := lookupSnap.GetUserByID(ctx, tok.UserID)
	if err != nil {
		return "", "", "", false
	}
	if user.Role != "admin" && user.Role != "editor" && user.Role != "viewer" {
		log.WarnContext(ctx, "PAT authentication rejected for unknown role")
		return "", "", "", false
	}
	// Best-effort activity tracking on a detached context so a slow write
	// never blocks authentication on the request path.
	touchStore := storeSnap
	touchID := tok.ID
	go func() {
		touchCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), constants.RevocationCheckTimeout)
		defer cancel()
		_ = touchStore.TouchLastUsed(touchCtx, touchID)
	}()
	return user.Username, user.Role, uniqueID, true
}

// AuthenticatePATToken authenticates a raw personal access token string
// through the same PAT core as the HTTP middleware (digest lookup,
// revocation cache with fail-closed IsRevoked, live role load, best-effort
// last-used tracking). It exists for transports that extract the candidate
// token from somewhere other than the Authorization header — e.g. the
// WebSocket Sec-WebSocket-Protocol header or cookie in MakeLogsStreamHandler.
// The raw token is never logged. Returns username, role, uniqueID, ok.
func AuthenticatePATToken(r *http.Request, rawToken string) (string, string, string, bool) {
	if rawToken == "" {
		return "", "", "", false
	}
	cloned := r.Clone(r.Context())
	cloned.Header.Set("Authorization", "Bearer "+rawToken)
	return authenticatePAT(cloned)
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

	authStoresMu.RLock()
	ss := settingsStore
	authStoresMu.RUnlock()
	if ss != nil {
		if err := ss.SetSystemConfig(ctx, "jwt_secret", string(newKey)); err != nil {
			return fmt.Errorf("failed to persist new JWT key: %w", err)
		}
		if oldKey != nil {
			if err := ss.SetSystemConfig(ctx, "jwt_prev_secret", string(oldKey)); err != nil {
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
	authStoresMu.RLock()
	ts := tokenStore
	authStoresMu.RUnlock()
	if ts == nil {
		return fmt.Errorf("auth token store not initialized")
	}
	if err := ts.RevokeToken(ctx, uniqueID, expiresAt, tokenType); err != nil {
		return fmt.Errorf("revoke token: %w", err)
	}
	revocationCacheAdd(uniqueID, revocationCacheEntry{revoked: true, expiresAt: time.Now().Add(revocationCacheTTL)})
	return nil
}

func IsRevoked(ctx context.Context, uniqueID string) bool {
	authStoresMu.RLock()
	ts := tokenStore
	authStoresMu.RUnlock()
	if ts == nil {
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
		return ts.IsTokenRevoked(lookupCtx, uniqueID)
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
	authStoresMu.RLock()
	ts := tokenStore
	authStoresMu.RUnlock()
	if ts == nil {
		return nil
	}
	if err := ts.CleanupExpiredTokens(ctx); err != nil {
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
		if err == nil && claims != nil {
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
			return
		}

		// JWT failed: fall back to personal access tokens presented as
		// `Bearer runic_pat_*` on the Authorization header (never cookies).
		// PATs are validated against their SHA256 digest, not the JWT key.
		if username, role, uniqueID, ok := authenticatePAT(r); ok {
			ctx := context.WithValue(r.Context(), ctxKeyUsername, username)
			ctx = context.WithValue(ctx, ctxKeyUniqueID, uniqueID)
			ctx = context.WithValue(ctx, ctxKeyRole, role)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		if err != nil {
			log.WarnContext(r.Context(), "JWT verification failed", "error", err)
		} else {
			log.WarnContext(r.Context(), "PAT authentication failed")
		}
		writeUnauthorizedJSON(w, "Unauthorized")
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
