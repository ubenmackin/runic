package auth

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"runic/internal/api/common"
	"runic/internal/auth"
	"runic/internal/common/log"
	"runic/internal/models"
)

// Token TTL constants.
const (
	AccessTokenTTL  = time.Hour          // 1 hour
	RefreshTokenTTL = 7 * 24 * time.Hour // 7 days

	// AccessTokenCookieMaxAge matches AccessTokenTTL expressed in seconds. The
	// cookie's MaxAge must equal the JWT TTL: if MaxAge is shorter the cookie
	// expires before the token it carries; if longer the cookie lingers past
	// token validity and clients may present a "valid-looking" cookie that
	// contains an already-expired JWT.
	AccessTokenCookieMaxAge = int(time.Hour / time.Second)

	// RefreshTokenCookieMaxAge matches RefreshTokenTTL expressed in seconds.
	// See AccessTokenCookieMaxAge for the rationale.
	RefreshTokenCookieMaxAge = int((7 * 24 * time.Hour) / time.Second)
)

// RefreshTokenCookieName is the refresh token cookie read by both the refresh
// and logout handlers.
const RefreshTokenCookieName = "runic_refresh_token"

// RefreshTokenCookiePath scopes the refresh token cookie to the whole auth
// surface. Browsers only send a cookie to endpoints under its Path, and
// logout must receive the refresh token to revoke its jti, so the scope must
// cover both /api/v1/auth/refresh and /api/v1/auth/logout.
const RefreshTokenCookiePath = "/api/v1/auth"

// legacyRefreshTokenCookiePath is the narrower path used before the refresh
// cookie was widened to the whole auth surface. Browsers key cookies by name
// and path, so they can hold the old cookie alongside the current one; every
// cookie write expires this path and refresh/logout scan past its value.
const legacyRefreshTokenCookiePath = "/api/v1/auth/refresh"

// API route suffixes for the endpoints that consume the refresh token. They
// live beside RefreshTokenCookiePath so the cookie scope cannot drift away
// from the routes it must cover.
const (
	RefreshRoutePath = "/auth/refresh"
	LogoutRoutePath  = "/auth/logout"
)

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// GenerateTokenPair mints an access/refresh pair for an existing user. It
// fails closed when the user cannot be loaded: issuing a token without a live
// user row (or with a guessed role) would keep deleted users authenticated and
// would detach tokens from the user's token_version epoch.
func (h *Handler) GenerateTokenPair(ctx context.Context, username string) (accessToken string, refreshToken string, err error) {
	user, err := h.UserStore.GetUserByUsername(ctx, username)
	if err != nil {
		log.WarnContext(ctx, "failed to load user for token generation", "username", username, "error", err)
		return "", "", fmt.Errorf("load user %q for token generation: %w", username, err)
	}
	return h.generateTokenPairForUser(&user)
}

// generateTokenPairForUser mints tokens bound to the user's live role and
// token_version. Callers that already resolved the user (login, refresh) use
// this to avoid a redundant lookup and to keep role/version consistent with
// the row they validated.
func (h *Handler) generateTokenPairForUser(user *models.UserRow) (accessToken string, refreshToken string, err error) {
	accessToken, err = auth.GenerateTokenWithVersion(user.Username, user.Role, auth.TokenTypeAccess, user.TokenVersion, AccessTokenTTL)
	if err != nil {
		return "", "", err
	}
	refreshToken, err = auth.GenerateTokenWithVersion(user.Username, user.Role, auth.TokenTypeRefresh, user.TokenVersion, RefreshTokenTTL)
	if err != nil {
		return "", "", err
	}
	return accessToken, refreshToken, nil
}

// RespondWithTokens sets auth cookies and returns a JSON response with username and setup status.
// Tokens are set as cookies; only username and is_setup are returned in JSON.
func (h *Handler) RespondWithTokens(w http.ResponseWriter, status int, accessToken, refreshToken, username string, isSetup bool) {
	setAuthCookies(w, accessToken, refreshToken)
	common.RespondJSON(w, status, map[string]interface{}{
		"username": username,
		"is_setup": isSetup,
	})
}
