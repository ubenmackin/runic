package auth

import (
	"net/http"
	"time"

	"runic/internal/api/common"
	"runic/internal/auth"
)

// Token TTL constants.
const (
	AccessTokenTTL  = time.Hour          // 1 hour
	RefreshTokenTTL = 7 * 24 * time.Hour // 7 days
)

// TokenResponse represents the standard token response.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// GenerateTokenPair generates an access token (1h TTL) and refresh token (7d TTL).
func GenerateTokenPair(username string) (accessToken string, refreshToken string, err error) {
	accessToken, err = auth.GenerateToken(username, AccessTokenTTL)
	if err != nil {
		return "", "", err
	}
	refreshToken, err = auth.GenerateToken(username, RefreshTokenTTL)
	if err != nil {
		return "", "", err
	}
	return accessToken, refreshToken, nil
}

// RespondWithTokens responds with the standard token JSON response.
// If includeUsername is true, adds the username field to the response.
func RespondWithTokens(w http.ResponseWriter, status int, accessToken, refreshToken, username string, includeUsername bool) {
	resp := map[string]string{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	}
	if includeUsername {
		resp["username"] = username
	}
	common.RespondJSON(w, status, resp)
}
