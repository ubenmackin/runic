package auth

import (
	"context"
	"net/http"
	"time"

	"runic/internal/api/common"
	"runic/internal/auth"
	"runic/internal/common/log"
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

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

func (h *Handler) GenerateTokenPair(ctx context.Context, username string) (accessToken string, refreshToken string, err error) {
	// token generation always succeeds even if the DB is temporarily unavailable.
	role := "viewer"
	if user, lookupErr := h.UserStore.GetUserByUsername(ctx, username); lookupErr == nil {
		role = user.Role
	} else {
		log.WarnContext(ctx, "failed to look up role, defaulting to viewer", "username", username, "error", lookupErr)
	}

	accessToken, err = auth.GenerateToken(username, role, auth.TokenTypeAccess, AccessTokenTTL)
	if err != nil {
		return "", "", err
	}
	refreshToken, err = auth.GenerateToken(username, role, auth.TokenTypeRefresh, RefreshTokenTTL)
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
