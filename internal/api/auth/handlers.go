// Package auth provides authentication handlers.
package auth

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"

	"github.com/gorilla/mux"
	"github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"

	"runic/internal/api/common"
	"runic/internal/auth"
	runiccommon "runic/internal/common"
	"runic/internal/common/log"
	"runic/internal/db"
)

// Handler provides HTTP handlers for auth endpoints with dependency injection.
type Handler struct {
	DB         db.Querier
	DBBeginner db.Beginner // For transaction support (same underlying *sql.DB in production)
}

// NewHandler creates a new auth handler with the given database connection.
func NewHandler(db db.Querier, dbBeginner db.Beginner) *Handler {
	return &Handler{DB: db, DBBeginner: dbBeginner}
}

var isProduction bool

func init() {
	isProduction = os.Getenv("GO_ENV") != "development"
}

// setAuthCookies sets httpOnly cookies for access and refresh tokens.
func setAuthCookies(w http.ResponseWriter, access, refresh string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "runic_access_token",
		Value:    access,
		Path:     "/",
		HttpOnly: true,
		Secure:   isProduction,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   900, // 15 minutes
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "runic_refresh_token",
		Value:    refresh,
		Path:     "/",
		HttpOnly: true,
		Secure:   isProduction,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   604800, // 7 days
	})
}

// clearAuthCookies clears the auth cookies by setting them with MaxAge=-1.
func clearAuthCookies(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     "runic_access_token",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   isProduction,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "runic_refresh_token",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   isProduction,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

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
func (h *Handler) HandleSetup(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.HandleSetupGET(w, r)
	case http.MethodPost:
		h.HandleSetupPOST(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// HandleSetupGET checks whether any users exist in the database.
// Returns {"needs_setup": true} if no users exist, false otherwise.
func (h *Handler) HandleSetupGET(w http.ResponseWriter, r *http.Request) {
	if h.DB == nil {
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
	err := h.DB.QueryRowContext(ctx, "SELECT COUNT(*) FROM users").Scan(&count)
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "failed to check setup status")
		return
	}

	common.RespondJSON(w, http.StatusOK, map[string]bool{"needs_setup": count == 0})
}

// HandleSetupPOST creates the first admin user during initial setup.
// Returns 403 if users already exist.
func (h *Handler) HandleSetupPOST(w http.ResponseWriter, r *http.Request) {
	if h.DB == nil {
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
	tx, err := h.DBBeginner.BeginTx(ctx, nil)
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "failed to start transaction")
		return
	}
	committed := false
	defer func() {
		if !committed {
			if err := tx.Rollback(); err != nil {
				log.Warn("rollback err", "err", err)
			}
		}
	}()

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
	hash, err := bcrypt.GenerateFromPassword([]byte(body.Password), 12)
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "failed to hash password")
		return
	}

	// Insert user
	_, err = tx.ExecContext(ctx,
		"INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'admin')",
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

	if err := tx.Commit(); err != nil {
		common.RespondError(w, http.StatusInternalServerError, "failed to commit transaction")
		return
	}
	committed = true

	log.InfoContext(r.Context(), "user created", "username", body.Username, "remote_addr", r.RemoteAddr)

	accessToken, refreshToken, err := h.GenerateTokenPair(body.Username)
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "failed to generate tokens")
		return
	}

	h.RespondWithTokens(w, http.StatusCreated, accessToken, refreshToken, body.Username, true)
}

// HandleLoginPOST authenticates an existing user with username and password.
func (h *Handler) HandleLoginPOST(w http.ResponseWriter, r *http.Request) {
	if h.DB == nil {
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
	err := h.DB.QueryRowContext(ctx,
		"SELECT id, password_hash FROM users WHERE username = ?",
		body.Username).Scan(&id, &storedHash)
	if err != nil {
		log.WarnContext(r.Context(), "login failed - unknown user", "username", body.Username, "remote_addr", r.RemoteAddr)
		common.RespondError(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(body.Password)); err != nil {
		log.WarnContext(r.Context(), "login failed - invalid password", "username", body.Username, "remote_addr", r.RemoteAddr)
		common.RespondError(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}

	RecordSuccess(body.Username)
	log.InfoContext(r.Context(), "user authenticated", "username", body.Username, "remote_addr", r.RemoteAddr)

	accessToken, refreshToken, err := h.GenerateTokenPair(body.Username)
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "failed to generate tokens")
		return
	}

	h.RespondWithTokens(w, http.StatusOK, accessToken, refreshToken, body.Username, true)
}

// HandleLogoutPOST handles POST /api/v1/auth/logout by revoking the caller's current token.
func (h *Handler) HandleLogoutPOST(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("runic_access_token")
	if err != nil || cookie.Value == "" {
		common.RespondError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	tokenStr := cookie.Value
	claims, err := auth.ValidateToken(tokenStr)
	if err != nil || claims == nil {
		common.RespondError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	expiresAt := claims.ExpiresAt.Time
	if err := auth.RevokeToken(r.Context(), claims.UniqueID, expiresAt, "access"); err != nil {
		common.RespondError(w, http.StatusInternalServerError, "Failed to revoke token")
		return
	}

	// Also revoke the refresh token if present
	if refreshCookie, err := r.Cookie("runic_refresh_token"); err == nil && refreshCookie.Value != "" {
		if refreshClaims, err := auth.ValidateToken(refreshCookie.Value); err == nil && refreshClaims != nil {
			if err := auth.RevokeToken(r.Context(), refreshClaims.UniqueID, refreshClaims.ExpiresAt.Time, "refresh"); err != nil {
				log.WarnContext(r.Context(), "failed to revoke refresh token on logout", "error", err)
			}
		}
	}

	clearAuthCookies(w)

	common.RespondJSON(w, http.StatusOK, map[string]string{"status": "logged_out"})
}

// HandleGetMe returns the authenticated user's profile.
func (h *Handler) HandleGetMe(w http.ResponseWriter, r *http.Request) {
	common.RespondJSON(w, http.StatusOK, map[string]string{
		"username": auth.UsernameFromContext(r.Context()),
		"role":     auth.RoleFromContext(r.Context()),
	})
}

// HandleRefreshPOST handles POST /api/v1/auth/refresh to refresh an access token.
// It validates the refresh token from cookie and issues a new access token if valid.
func (h *Handler) HandleRefreshPOST(w http.ResponseWriter, r *http.Request) {
	if h.DB == nil {
		common.RespondError(w, http.StatusInternalServerError, "database not initialized")
		return
	}

	cookie, err := r.Cookie("runic_refresh_token")
	if err != nil || cookie.Value == "" {
		common.RespondError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}
	refreshToken := cookie.Value

	// Validate the refresh token
	claims, err := auth.ValidateToken(refreshToken)
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
	accessToken, refreshToken, err := h.GenerateTokenPair(claims.Username)
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "failed to generate tokens")
		return
	}

	// Revoke the old refresh token (rotation)
	if err := auth.RevokeToken(r.Context(), claims.UniqueID, claims.ExpiresAt.Time, "refresh"); err != nil {
		log.WarnContext(r.Context(), "failed to revoke old refresh token", "error", err)
		// Continue anyway - the new tokens are still valid
	}

	log.InfoContext(r.Context(), "token refreshed", "username", claims.Username)

	setAuthCookies(w, accessToken, refreshToken)
	common.RespondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// RegisterRoutes adds auth routes to the given router.
func (h *Handler) RegisterRoutes(r *mux.Router) {
	r.HandleFunc("/me", h.HandleGetMe).Methods("GET")
}
