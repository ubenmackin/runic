package auth

import (
	"log"
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
func (h *Handler) GenerateTokenPair(username string) (accessToken string, refreshToken string, err error) {
	// Look up user's role from database
	var role string
	err = h.DB.QueryRow("SELECT role FROM users WHERE username = ?", username).Scan(&role)
	if err != nil {
		log.Printf("WARNING: failed to look up role for %s, defaulting to viewer: %v", username, err)
		role = "viewer"
	}

	accessToken, err = auth.GenerateToken(username, role, AccessTokenTTL)
	if err != nil {
		return "", "", err
	}
	refreshToken, err = auth.GenerateToken(username, role, RefreshTokenTTL)
	if err != nil {
		return "", "", err
	}
	return accessToken, refreshToken, nil
}

// RespondWithTokens responds with the standard token response via httpOnly cookies.
// Tokens are set as cookies; only username and is_setup are returned in JSON.
func (h *Handler) RespondWithTokens(w http.ResponseWriter, status int, accessToken, refreshToken, username string, isSetup bool) {
	setAuthCookies(w, accessToken, refreshToken)
	common.RespondJSON(w, status, map[string]interface{}{
		"username": username,
		"is_setup": isSetup,
	})
}
