// Package auth provides authentication handlers.
package auth

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"

	"runic/internal/api/common"
	"runic/internal/auth"
	runiccommon "runic/internal/common"
	"runic/internal/common/log"
	"runic/internal/db"
	"runic/internal/models"
	"runic/internal/store"
)

// maxRequestBodyBytes caps the size of request bodies decoded from JSON. 1 MiB
// is comfortably above the largest legitimate auth payload (a username +
// password is typically <100 bytes) and well below the limit at which
// pathological clients can pin server resources.
const maxRequestBodyBytes = 1 << 20

// credentialsRequest is the request body shared by the setup and login
// endpoints. Both endpoints accept only a username and password, so a single
// type avoids a redundant pair of structurally identical structs.
type credentialsRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

var (
	isProduction   bool
	isProductionMu sync.Once

	// errSetupAlreadyCompleted is returned inside the setup transaction when users already exist.
	errSetupAlreadyCompleted = errors.New("setup already completed")
)

// UserStore is defined as an interface here for testability.
type UserStore interface {
	CountUsers(ctx context.Context) (int, error)
	CountUsersTx(ctx context.Context, q db.Querier) (int, error)
	CreateUser(ctx context.Context, q db.Querier, username, passwordHash, email, role string) (int64, error)
	GetCredentials(ctx context.Context, username string) (models.UserCredentials, error)
	GetUserByUsername(ctx context.Context, username string) (models.UserRow, error)
}

type Handler struct {
	UserStore  UserStore
	TokenStore *store.TokenStore // For token revocation checks
	DBBeginner db.Beginner       // For transaction support in HandleSetupPOST
}

func NewHandler(userStore UserStore, tokenStore *store.TokenStore, dbBeginner db.Beginner) *Handler {
	return &Handler{UserStore: userStore, TokenStore: tokenStore, DBBeginner: dbBeginner}
}

// getIsProduction returns whether the app is running in production mode.
// Uses lazy initialization via sync.Once to avoid init()-order issues.
func getIsProduction() bool {
	isProductionMu.Do(func() {
		isProduction = os.Getenv("GO_ENV") != "development"
	})
	return isProduction
}

// expireRefreshCookieAtPath removes a refresh cookie scoped to path. A browser
// keeps one cookie per name and path, so every path the cookie was ever issued
// under must be expired explicitly; otherwise the stale value survives and can
// shadow the current cookie on requests.
func expireRefreshCookieAtPath(w http.ResponseWriter, path string) {
	http.SetCookie(w, &http.Cookie{
		Name:     RefreshTokenCookieName,
		Value:    "",
		Path:     path,
		HttpOnly: true,
		Secure:   getIsProduction(),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

func setAuthCookies(w http.ResponseWriter, access, refresh string) {
	// Expire the legacy path before issuing the current cookie so browsers
	// drop the old value instead of sending it alongside the new one. The
	// access token cookie uses SameSite=Strict to defend against CSRF on
	// state-changing API requests. The refresh token cookie keeps SameSite=Lax
	// because the refresh endpoint is reachable cross-tab and the refresh
	// token is opaque (no JWT claims) — a full double-submit / token-binding
	// scheme is out of scope here.
	expireRefreshCookieAtPath(w, legacyRefreshTokenCookiePath)
	http.SetCookie(w, &http.Cookie{
		Name:     "runic_access_token",
		Value:    access,
		Path:     "/",
		HttpOnly: true,
		Secure:   getIsProduction(),
		SameSite: http.SameSiteStrictMode,
		MaxAge:   AccessTokenCookieMaxAge,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     RefreshTokenCookieName,
		Value:    refresh,
		Path:     RefreshTokenCookiePath,
		HttpOnly: true,
		Secure:   getIsProduction(),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   RefreshTokenCookieMaxAge,
	})
}

func clearAuthCookies(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     "runic_access_token",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   getIsProduction(),
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
	// Expire the legacy path first so the canonical path is the last refresh
	// cookie in the response.
	expireRefreshCookieAtPath(w, legacyRefreshTokenCookiePath)
	expireRefreshCookieAtPath(w, RefreshTokenCookiePath)
}

// HandleSetupGET handles the setup check. Returns {"needs_setup": true} if no users exist, false otherwise.
func (h *Handler) HandleSetupGET(w http.ResponseWriter, r *http.Request) {
	if h.UserStore == nil {
		common.RespondError(w, http.StatusInternalServerError, "database not initialized")
		return
	}

	// Rate limit check keyed on RemoteAddrIP (TCP peer, port-stripped),
	// ignoring X-Forwarded-For/X-Real-IP so header rotation cannot bypass
	// the per-IP limit on direct exposure. See common.RemoteAddrIP.
	if err := CheckSetupGetRateLimit(common.RemoteAddrIP(r)); err != nil {
		common.RespondError(w, http.StatusTooManyRequests, err.Error())
		return
	}

	ctx, cancel := runiccommon.WithHandlerTimeout(r.Context())
	defer cancel()

	count, err := h.UserStore.CountUsers(ctx)
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "failed to check setup status")
		return
	}

	common.RespondJSON(w, http.StatusOK, map[string]bool{"needs_setup": count == 0})
}

// isLoopbackRemote reports whether the request's TCP peer is a loopback
// address. First-run setup uses it to keep the bootstrap administrator on the
// server's own loopback until an account exists.
func isLoopbackRemote(r *http.Request) bool {
	ip := net.ParseIP(common.RemoteAddrIP(r))
	return ip != nil && ip.IsLoopback()
}

// HandleSetupPOST handles the initial setup. Returns 403 if users already exist.
func (h *Handler) HandleSetupPOST(w http.ResponseWriter, r *http.Request) {
	if h.UserStore == nil {
		common.RespondError(w, http.StatusInternalServerError, "database not initialized")
		return
	}

	// Rate limit check keyed on RemoteAddrIP (TCP peer, port-stripped) to
	// prevent enumeration/abuse. X-Forwarded-For/X-Real-IP are ignored so
	// header rotation cannot bypass the limit on direct exposure.
	// POST has a stricter limit than GET since it creates an admin user.
	if err := CheckSetupPostRateLimit(common.RemoteAddrIP(r)); err != nil {
		common.RespondError(w, http.StatusTooManyRequests, err.Error())
		return
	}

	// Bound the request body to defend against slow-loris / memory-exhaustion
	// attacks where an attacker streams a huge payload. The reader will return
	// an error from Decode once the cap is hit.
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)

	var body credentialsRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if body.Username == "" || body.Password == "" {
		common.RespondError(w, http.StatusBadRequest, "username and password are required")
		return
	}
	// bcrypt silently truncates input above 72 bytes; rejecting explicitly is
	// cheaper and avoids a misleading hash that does not match the password
	// the user actually submitted.
	if len(body.Password) > 72 {
		common.RespondError(w, http.StatusBadRequest, "password must be 72 bytes or fewer")
		return
	}

	ctx, cancel := runiccommon.WithHandlerTimeout(r.Context())
	defer cancel()

	// Before the first user exists, a single unauthenticated POST here mints a
	// full administrator. Reject non-loopback callers so a remote attacker
	// racing the operator to the endpoint cannot claim the instance. Once an
	// account exists the transaction below rejects setup regardless of origin.
	if !isLoopbackRemote(r) {
		count, err := h.UserStore.CountUsers(ctx)
		if err != nil {
			common.RespondError(w, http.StatusInternalServerError, "failed to check setup status")
			return
		}
		if count == 0 {
			log.WarnContext(ctx, "setup rejected from non-loopback caller before first user", "remote_addr", common.RemoteAddrIP(r))
			common.RespondError(w, http.StatusForbidden, "Setup must be completed from the server's loopback interface")
			return
		}
	}

	// Hash password
	hash, err := bcrypt.GenerateFromPassword([]byte(body.Password), 12)
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "failed to hash password")
		return
	}

	if err := db.RunInTx(ctx, h.DBBeginner, func(ctx context.Context, tx *sql.Tx) error {
		count, countErr := h.UserStore.CountUsersTx(ctx, tx)
		if countErr != nil {
			return countErr
		}
		if count > 0 {
			return errSetupAlreadyCompleted
		}
		_, createErr := h.UserStore.CreateUser(ctx, tx, body.Username, string(hash), "", "admin")
		if createErr != nil {
			var sqliteErr sqlite3.Error
			if errors.As(createErr, &sqliteErr) && sqliteErr.ExtendedCode == sqlite3.ErrConstraintUnique {
				return errSetupAlreadyCompleted
			}
			return createErr
		}
		return nil
	}); err != nil {
		if errors.Is(err, errSetupAlreadyCompleted) {
			common.RespondError(w, http.StatusForbidden, "Setup already completed")
			return
		}
		log.ErrorContext(r.Context(), "failed to complete setup", "error", err)
		common.RespondError(w, http.StatusInternalServerError, "failed to complete setup")
		return
	}

	log.InfoContext(r.Context(), "user created", "username", body.Username, "remote_addr", common.RemoteAddrIP(r))

	accessToken, refreshToken, err := h.GenerateTokenPair(ctx, body.Username)
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "failed to generate tokens")
		return
	}

	h.RespondWithTokens(w, http.StatusCreated, accessToken, refreshToken, body.Username, true)
}

func (h *Handler) HandleLoginPOST(w http.ResponseWriter, r *http.Request) {
	if h.UserStore == nil {
		common.RespondError(w, http.StatusInternalServerError, "database not initialized")
		return
	}

	// Bound the request body to defend against slow-loris / memory-exhaustion
	// attacks. See HandleSetupPOST for details.
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)

	var body credentialsRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if body.Username == "" || body.Password == "" {
		common.RespondError(w, http.StatusBadRequest, "username and password are required")
		return
	}
	// bcrypt silently truncates input above 72 bytes; rejecting explicitly
	// avoids both a misleading hash and an attacker burning CPU on a huge
	// payload before we ever call bcrypt.
	if len(body.Password) > 72 {
		common.RespondError(w, http.StatusBadRequest, "password must be 72 bytes or fewer")
		return
	}

	// Rate limit check keyed on the TCP peer IP (RemoteAddrIP, port-stripped)
	// combined with the username inside CheckAndRecordFailure. Proxy headers
	// are deliberately ignored so rotating X-Forwarded-For/X-Real-IP per
	// guess cannot yield a fresh username:IP bucket and bypass the
	// 5-attempt/15-minute lockout on direct exposure. See common.RemoteAddrIP.
	if err := CheckAndRecordFailure(r.Context(), body.Username, common.RemoteAddrIP(r)); err != nil {
		common.RespondError(w, http.StatusTooManyRequests, err.Error())
		return
	}

	ctx, cancel := runiccommon.WithHandlerTimeout(r.Context())
	defer cancel()

	creds, err := h.UserStore.GetCredentials(ctx, body.Username)
	if err != nil {
		log.WarnContext(r.Context(), "login failed - unknown user", "username", body.Username, "remote_addr", common.RemoteAddrIP(r))
		common.RespondError(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(creds.PasswordHash), []byte(body.Password)); err != nil {
		log.WarnContext(r.Context(), "login failed - invalid password", "username", body.Username, "remote_addr", common.RemoteAddrIP(r))
		common.RespondError(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}

	RecordSuccess(body.Username)
	log.InfoContext(r.Context(), "user authenticated", "username", body.Username, "remote_addr", common.RemoteAddrIP(r))

	accessToken, refreshToken, err := h.GenerateTokenPair(ctx, body.Username)
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "failed to generate tokens")
		return
	}

	h.RespondWithTokens(w, http.StatusOK, accessToken, refreshToken, body.Username, true)
}

func (h *Handler) HandleLogoutPOST(w http.ResponseWriter, r *http.Request) {
	// Apply the standard handler timeout so a slow revocation store cannot
	// keep the request open indefinitely.
	ctx, cancel := runiccommon.WithHandlerTimeout(r.Context())
	defer cancel()

	// The refresh cookie is scoped to the auth surface so browsers now send it
	// to logout; its jti must be recorded as revoked even when the access token
	// is already expired and absent from the request context, otherwise a
	// copied refresh token could keep minting sessions after the client-side
	// cookie is cleared. A browser can send both the legacy-path and current
	// cookies, and Request.Cookie returns only the first, so revoke every
	// valid refresh value on the request.
	for _, refreshToken := range refreshTokenCookieValues(r) {
		refreshClaims, err := auth.ValidateToken(refreshToken)
		if err != nil || refreshClaims == nil || refreshClaims.TokenType != auth.TokenTypeRefresh {
			continue
		}
		if err := h.TokenStore.RevokeToken(ctx, refreshClaims.UniqueID, refreshClaims.ExpiresAt.Time, "refresh"); err != nil {
			log.WarnContext(ctx, "failed to revoke refresh token on logout", "error", err)
		}
	}

	// A valid access token is revoked whenever one is present. The public
	// logout route has no auth middleware, so validate the access cookie and
	// Bearer header here and revoke every token found (a stale cookie must not
	// hide a live Bearer token). Each validated token contributes its own
	// expiry, so the hourly cleanup cannot drop a revocation while a
	// long-lived legacy token is still valid.
	refs := accessTokenRefs(r)
	if len(refs) == 0 {
		// No valid access token — treat logout as an idempotent no-op.
		// Clear any stale auth cookies and return success so clients never
		// enter a refresh loop via this endpoint.
		clearAuthCookies(w)
		common.RespondJSON(w, http.StatusOK, map[string]string{"status": "logged_out"})
		return
	}

	// Revoke each access token until its own expiry. A fixed TTL shorter than
	// the token's lifetime would let the hourly cleanup drop the entry while a
	// long-lived legacy token is still valid.
	for _, ref := range refs {
		if err := h.TokenStore.RevokeToken(ctx, ref.uniqueID, ref.expiresAt, "access"); err != nil {
			common.RespondError(w, http.StatusInternalServerError, "Failed to revoke token")
			return
		}
	}

	clearAuthCookies(w)

	common.RespondJSON(w, http.StatusOK, map[string]string{"status": "logged_out"})
}

// refreshTokenCookieValues returns every refresh token cookie value on the
// request. A cookie path change leaves browsers holding the same cookie name
// under multiple paths, and Request.Cookie returns only the first, so callers
// must consider all values and ignore stale ones.
func refreshTokenCookieValues(r *http.Request) []string {
	var values []string
	for _, cookie := range r.Cookies() {
		if cookie.Name == RefreshTokenCookieName && cookie.Value != "" {
			values = append(values, cookie.Value)
		}
	}
	return values
}

// accessTokenRef pairs a validated access token's unique ID with the expiry
// its revocation entry must outlive.
type accessTokenRef struct {
	uniqueID  string
	expiresAt time.Time
}

// accessTokenRefs returns every valid access token presented on the access
// cookie or Authorization header, along with the expiry taken from its
// claims. Logout is reachable without the auth middleware, so it validates
// the tokens itself; both sources are checked because a stale cookie must not
// hide a live Bearer token.
func accessTokenRefs(r *http.Request) []accessTokenRef {
	var refs []accessTokenRef
	seen := make(map[string]struct{}, 2)
	add := func(tokenStr string) {
		if tokenStr == "" {
			return
		}
		claims, err := auth.ValidateToken(tokenStr)
		if err != nil || claims == nil || claims.TokenType != auth.TokenTypeAccess || claims.UniqueID == "" {
			return
		}
		if _, ok := seen[claims.UniqueID]; ok {
			return
		}
		seen[claims.UniqueID] = struct{}{}
		refs = append(refs, accessTokenRef{uniqueID: claims.UniqueID, expiresAt: claims.ExpiresAt.Time})
	}
	if cookie, err := r.Cookie("runic_access_token"); err == nil {
		add(cookie.Value)
	}
	add(auth.ExtractBearerToken(r.Header.Get("Authorization")))
	return refs
}

func (h *Handler) HandleGetMe(w http.ResponseWriter, r *http.Request) {
	common.RespondJSON(w, http.StatusOK, map[string]string{
		"username": auth.UsernameFromContext(r.Context()),
		"role":     auth.RoleFromContext(r.Context()),
	})
}

// HandleRefreshPOST handles token refresh. It validates the refresh token from
// the refresh cookie(s) and issues a new access token if valid.
func (h *Handler) HandleRefreshPOST(w http.ResponseWriter, r *http.Request) {
	if h.UserStore == nil {
		common.RespondError(w, http.StatusInternalServerError, "database not initialized")
		return
	}

	// Apply the standard handler timeout so a slow revocation lookup cannot
	// stall the request.
	ctx, cancel := runiccommon.WithHandlerTimeout(r.Context())
	defer cancel()

	tokens := refreshTokenCookieValues(r)
	if len(tokens) == 0 {
		common.RespondError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	// A browser can present both the legacy-path and current refresh cookies,
	// with the stale one first. Select the first value that passes the full
	// validation chain so an unusable legacy cookie cannot shadow a valid one.
	var (
		claims *auth.Claims
		user   models.UserRow
	)
	for _, refreshToken := range tokens {
		candidateClaims, err := auth.ValidateToken(refreshToken)
		if err != nil || candidateClaims == nil || candidateClaims.TokenType != auth.TokenTypeRefresh {
			continue
		}

		if revoked, err := h.TokenStore.IsTokenRevoked(ctx, candidateClaims.UniqueID); err != nil || revoked {
			continue
		}

		// Resolve the live user before minting anything. A deleted account must
		// not be able to exchange a still-valid refresh JWT for a fresh session,
		// and a password change bumps token_version, which invalidates refresh
		// tokens minted under the previous credential epoch.
		candidateUser, err := h.UserStore.GetUserByUsername(ctx, candidateClaims.Username)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				log.WarnContext(ctx, "refresh rejected - user no longer exists", "username", candidateClaims.Username)
				continue
			}
			log.ErrorContext(ctx, "refresh rejected - user lookup failed", "username", candidateClaims.Username, "error", err)
			common.RespondError(w, http.StatusInternalServerError, "failed to refresh session")
			return
		}
		if candidateUser.TokenVersion != candidateClaims.TokenVersion {
			log.WarnContext(ctx, "refresh rejected - token version revoked", "username", candidateClaims.Username)
			continue
		}

		claims = candidateClaims
		user = candidateUser
		break
	}
	if claims == nil {
		common.RespondError(w, http.StatusUnauthorized, "Invalid refresh token")
		return
	}

	accessToken, refreshToken, err := h.generateTokenPairForUser(&user)
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "failed to generate tokens")
		return
	}

	// Revoke the old refresh token (rotation).
	// If revoking the old token fails, we still issue the new tokens to avoid
	// disrupting the user's session, but we log at CRITICAL level so operators
	// are aware that an old refresh token remains valid.
	if err := h.TokenStore.RevokeToken(ctx, claims.UniqueID, claims.ExpiresAt.Time, "refresh"); err != nil {
		log.ErrorContext(ctx, "CRITICAL: failed to revoke old refresh token during rotation; the old token remains valid", "error", err)
		// Continue anyway - the new tokens are still valid
	}

	log.InfoContext(ctx, "token refreshed", "username", claims.Username)

	setAuthCookies(w, accessToken, refreshToken)
	common.RespondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *Handler) RegisterRoutes(r *mux.Router) {
	r.HandleFunc("/me", h.HandleGetMe).Methods("GET")
}
