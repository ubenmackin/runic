package auth

import (
	"log"
	"net/http"
	"time"

	"runic/internal/api/common"
	"runic/internal/auth"
	"runic/internal/db"
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
	// Look up user's role from database
	var role string
	err = db.DB.QueryRow("SELECT role FROM users WHERE username = ?", username).Scan(&role)
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
