package auth

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"

	"github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"

	"runic/internal/api/common"
	"runic/internal/auth"
	runiccommon "runic/internal/common"
	"runic/internal/db"
)

// setupRequest is the request body for first-time setup.
type setupRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// loginRequest is the request body for login.
type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// HandleSetup handles both GET and POST /api/v1/setup requests
func HandleSetup(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		HandleSetupGET(w, r)
	case http.MethodPost:
		HandleSetupPOST(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// HandleSetupGET checks whether any users exist in the database.
// Returns {"needs_setup": true} if no users exist, false otherwise.
func HandleSetupGET(w http.ResponseWriter, r *http.Request) {
	if db.DB == nil {
		common.RespondError(w, http.StatusInternalServerError, "database not initialized")
		return
	}

	// Rate limit check based on IP to prevent enumeration
	if err := CheckSetupRateLimit(r.RemoteAddr); err != nil {
		common.RespondError(w, http.StatusTooManyRequests, err.Error())
		return
	}

	ctx, cancel := runiccommon.WithHandlerTimeout(r.Context())
	defer cancel()

	var count int
	err := db.DB.QueryRowContext(ctx, "SELECT COUNT(*) FROM users").Scan(&count)
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "failed to check setup status")
		return
	}

	common.RespondJSON(w, http.StatusOK, map[string]bool{"needs_setup": count == 0})
}

// HandleSetupPOST creates the first admin user during initial setup.
// Returns 403 if users already exist.
func HandleSetupPOST(w http.ResponseWriter, r *http.Request) {
	if db.DB == nil {
		common.RespondError(w, http.StatusInternalServerError, "database not initialized")
		return
	}

	// Rate limit check based on IP to prevent enumeration/abuse
	if err := CheckSetupRateLimit(r.RemoteAddr); err != nil {
		common.RespondError(w, http.StatusTooManyRequests, err.Error())
		return
	}

	var body setupRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if body.Username == "" || body.Password == "" {
		common.RespondError(w, http.StatusBadRequest, "username and password are required")
		return
	}

	ctx, cancel := runiccommon.WithHandlerTimeout(r.Context())
	defer cancel()

	// Begin transaction
	tx, err := db.DB.BeginTx(ctx, nil)
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "failed to start transaction")
		return
	}
	defer tx.Rollback()

	// Check if any users already exist
	var count int
	err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM users").Scan(&count)
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "failed to check setup status")
		return
	}
	if count > 0 {
		common.RespondError(w, http.StatusForbidden, "Setup already completed")
		return
	}

	// Hash password
	hash, err := bcrypt.GenerateFromPassword([]byte(body.Password), bcrypt.DefaultCost)
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "failed to hash password")
		return
	}

	// Insert user
	_, err = tx.ExecContext(ctx,
		"INSERT INTO users (username, password_hash) VALUES (?, ?)",
		body.Username, string(hash))
	if err != nil {
		var sqliteErr sqlite3.Error
		if errors.As(err, &sqliteErr) && sqliteErr.ExtendedCode == sqlite3.ErrConstraintUnique {
			common.RespondError(w, http.StatusConflict, "username already exists")
			return
		}
		common.RespondError(w, http.StatusInternalServerError, "failed to create user")
		return
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		common.RespondError(w, http.StatusInternalServerError, "failed to commit transaction")
		return
	}

	// Log successful user creation
	log.Printf("AUTH SETUP: User '%s' created (IP: %s)", body.Username, r.RemoteAddr)

	// Generate tokens
	accessToken, refreshToken, err := GenerateTokenPair(body.Username)
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "failed to generate tokens")
		return
	}

	RespondWithTokens(w, http.StatusCreated, accessToken, refreshToken, body.Username, true)
}

// HandleLoginPOST authenticates an existing user with username and password.
func HandleLoginPOST(w http.ResponseWriter, r *http.Request) {
	if db.DB == nil {
		common.RespondError(w, http.StatusInternalServerError, "database not initialized")
		return
	}

	var body loginRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if body.Username == "" || body.Password == "" {
		common.RespondError(w, http.StatusBadRequest, "username and password are required")
		return
	}

	// Rate limit check
	if err := CheckAndRecordFailure(body.Username, r.RemoteAddr); err != nil {
		common.RespondError(w, http.StatusTooManyRequests, err.Error())
		return
	}

	ctx, cancel := runiccommon.WithHandlerTimeout(r.Context())
	defer cancel()

	// Look up user
	var id int
	var storedHash string
	err := db.DB.QueryRowContext(ctx,
		"SELECT id, password_hash FROM users WHERE username = ?",
		body.Username).Scan(&id, &storedHash)
	if err != nil {
		log.Printf("AUTH LOGIN FAIL: Unknown user '%s' (IP: %s)", body.Username, r.RemoteAddr)
		common.RespondError(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(body.Password)); err != nil {
		log.Printf("AUTH LOGIN FAIL: Invalid password for user '%s' (IP: %s)", body.Username, r.RemoteAddr)
		common.RespondError(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}

	// Record successful login
	RecordSuccess(body.Username)
	log.Printf("AUTH LOGIN: User '%s' authenticated (IP: %s)", body.Username, r.RemoteAddr)

	// Generate tokens
	accessToken, refreshToken, err := GenerateTokenPair(body.Username)
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "failed to generate tokens")
		return
	}

	RespondWithTokens(w, http.StatusOK, accessToken, refreshToken, body.Username, true)
}

// HandleLogoutPOST handles POST /api/v1/auth/logout by revoking the caller's current token.
func HandleLogoutPOST(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		common.RespondError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
	claims, err := auth.ValidateToken(tokenStr)
	if err != nil || claims == nil {
		common.RespondError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	expiresAt := claims.ExpiresAt.Time
	if err := auth.RevokeToken(r.Context(), claims.UniqueID, expiresAt); err != nil {
		common.RespondError(w, http.StatusInternalServerError, "Failed to revoke token")
		return
	}

	common.RespondJSON(w, http.StatusOK, map[string]string{"status": "logged_out"})
}

// refreshRequest is the request body for token refresh.
type refreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// HandleRefreshPOST handles POST /api/v1/auth/refresh to refresh an access token.
// It validates the refresh token and issues a new access token if valid.
func HandleRefreshPOST(w http.ResponseWriter, r *http.Request) {
	if db.DB == nil {
		common.RespondError(w, http.StatusInternalServerError, "database not initialized")
		return
	}

	var body refreshRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if body.RefreshToken == "" {
		common.RespondError(w, http.StatusBadRequest, "refresh_token is required")
		return
	}

	// Validate the refresh token
	claims, err := auth.ValidateToken(body.RefreshToken)
	if err != nil || claims == nil {
		common.RespondError(w, http.StatusUnauthorized, "Invalid refresh token")
		return
	}

	// Check if the token has been revoked
	if auth.IsRevoked(r.Context(), claims.UniqueID) {
		common.RespondError(w, http.StatusUnauthorized, "Token has been revoked")
		return
	}

	// Generate new tokens (rotation for security)
	accessToken, refreshToken, err := GenerateTokenPair(claims.Username)
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "failed to generate tokens")
		return
	}

	// Revoke the old refresh token (rotation)
	if err := auth.RevokeToken(r.Context(), claims.UniqueID, claims.ExpiresAt.Time); err != nil {
		log.Printf("Warning: failed to revoke old refresh token: %v", err)
		// Continue anyway - the new tokens are still valid
	}

	log.Printf("AUTH REFRESH: Token refreshed for user '%s'", claims.Username)

	RespondWithTokens(w, http.StatusOK, accessToken, refreshToken, "", false)
}
