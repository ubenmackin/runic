// Package auth provides authentication handlers.
package auth

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
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

func setAuthCookies(w http.ResponseWriter, access, refresh string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "runic_access_token",
		Value:    access,
		Path:     "/",
		HttpOnly: true,
		Secure:   getIsProduction(),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   900, // 15 minutes
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "runic_refresh_token",
		Value:    refresh,
		Path:     "/api/v1/auth/refresh",
		HttpOnly: true,
		Secure:   getIsProduction(),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   604800, // 7 days
	})
}

func clearAuthCookies(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     "runic_access_token",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   getIsProduction(),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "runic_refresh_token",
		Value:    "",
		Path:     "/api/v1/auth/refresh",
		HttpOnly: true,
		Secure:   getIsProduction(),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

type setupRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

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

// HandleSetupGET handles the setup check. Returns {"needs_setup": true} if no users exist, false otherwise.
func (h *Handler) HandleSetupGET(w http.ResponseWriter, r *http.Request) {
	if h.UserStore == nil {
		common.RespondError(w, http.StatusInternalServerError, "database not initialized")
		return
	}

	// Rate limit check based on IP to prevent enumeration
	if err := CheckSetupGetRateLimit(common.GetClientIP(r)); err != nil {
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

// HandleSetupPOST handles the initial setup. Returns 403 if users already exist.
func (h *Handler) HandleSetupPOST(w http.ResponseWriter, r *http.Request) {
	if h.UserStore == nil {
		common.RespondError(w, http.StatusInternalServerError, "database not initialized")
		return
	}

	// Rate limit check based on IP to prevent enumeration/abuse
	// POST has a stricter limit than GET since it creates an admin user.
	if err := CheckSetupPostRateLimit(common.GetClientIP(r)); err != nil {
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

	// Hash password
	hash, err := bcrypt.GenerateFromPassword([]byte(body.Password), 12)
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "failed to hash password")
		return
	}

	if err := store.RunInTx(ctx, h.DBBeginner, func(tx *sql.Tx) error {
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

	log.InfoContext(r.Context(), "user created", "username", body.Username, "remote_addr", common.GetClientIP(r))

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
	if err := CheckAndRecordFailure(body.Username, common.GetClientIP(r)); err != nil {
		common.RespondError(w, http.StatusTooManyRequests, err.Error())
		return
	}

	ctx, cancel := runiccommon.WithHandlerTimeout(r.Context())
	defer cancel()

	creds, err := h.UserStore.GetCredentials(ctx, body.Username)
	if err != nil {
		log.WarnContext(r.Context(), "login failed - unknown user", "username", body.Username, "remote_addr", common.GetClientIP(r))
		common.RespondError(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(creds.PasswordHash), []byte(body.Password)); err != nil {
		log.WarnContext(r.Context(), "login failed - invalid password", "username", body.Username, "remote_addr", common.GetClientIP(r))
		common.RespondError(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}

	RecordSuccess(body.Username)
	log.InfoContext(r.Context(), "user authenticated", "username", body.Username, "remote_addr", common.GetClientIP(r))

	accessToken, refreshToken, err := h.GenerateTokenPair(ctx, body.Username)
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "failed to generate tokens")
		return
	}

	h.RespondWithTokens(w, http.StatusOK, accessToken, refreshToken, body.Username, true)
}

func (h *Handler) HandleLogoutPOST(w http.ResponseWriter, r *http.Request) {
	// The auth.Middleware has already validated the token and populated the context.
	// Use context values instead of re-parsing the JWT.
	uniqueID := auth.UniqueIDFromContext(r.Context())
	if uniqueID == "" {
		common.RespondError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	// Revoke the access token using its stored unique_id.
	// We use the token's original expiry as the TTL for the revocation entry.
	// Since we don't have the original expiry from context, we use the default
	// access token lifetime (15 minutes) as a safe upper bound.
	expiresAt := time.Now().Add(15 * time.Minute)
	if err := h.TokenStore.RevokeToken(r.Context(), uniqueID, expiresAt, "access"); err != nil {
		common.RespondError(w, http.StatusInternalServerError, "Failed to revoke token")
		return
	}

	// Also revoke the refresh token if present
	if refreshCookie, err := r.Cookie("runic_refresh_token"); err == nil && refreshCookie.Value != "" {
		if refreshClaims, err := auth.ValidateToken(refreshCookie.Value); err == nil && refreshClaims != nil {
			if err := h.TokenStore.RevokeToken(r.Context(), refreshClaims.UniqueID, refreshClaims.ExpiresAt.Time, "refresh"); err != nil {
				log.WarnContext(r.Context(), "failed to revoke refresh token on logout", "error", err)
			}
		}
	}

	clearAuthCookies(w)

	common.RespondJSON(w, http.StatusOK, map[string]string{"status": "logged_out"})
}

func (h *Handler) HandleGetMe(w http.ResponseWriter, r *http.Request) {
	common.RespondJSON(w, http.StatusOK, map[string]string{
		"username": auth.UsernameFromContext(r.Context()),
		"role":     auth.RoleFromContext(r.Context()),
	})
}

// HandleRefreshPOST handles token refresh. It validates the refresh token from cookie and issues a new access token if valid.
func (h *Handler) HandleRefreshPOST(w http.ResponseWriter, r *http.Request) {
	if h.UserStore == nil {
		common.RespondError(w, http.StatusInternalServerError, "database not initialized")
		return
	}

	cookie, err := r.Cookie("runic_refresh_token")
	if err != nil || cookie.Value == "" {
		common.RespondError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}
	refreshToken := cookie.Value

	claims, err := auth.ValidateToken(refreshToken)
	if err != nil || claims == nil {
		common.RespondError(w, http.StatusUnauthorized, "Invalid refresh token")
		return
	}

	if revoked, err := h.TokenStore.IsTokenRevoked(r.Context(), claims.UniqueID); err != nil || revoked {
		common.RespondError(w, http.StatusUnauthorized, "Token has been revoked")
		return
	}

	accessToken, refreshToken, err := h.GenerateTokenPair(r.Context(), claims.Username)
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "failed to generate tokens")
		return
	}

	// Revoke the old refresh token (rotation).
	// If revoking the old token fails, we still issue the new tokens to avoid
	// disrupting the user's session, but we log at CRITICAL level so operators
	// are aware that an old refresh token remains valid.
	if err := h.TokenStore.RevokeToken(r.Context(), claims.UniqueID, claims.ExpiresAt.Time, "refresh"); err != nil {
		log.ErrorContext(r.Context(), "CRITICAL: failed to revoke old refresh token during rotation; the old token remains valid", "error", err)
		// Continue anyway - the new tokens are still valid
	}

	log.InfoContext(r.Context(), "token refreshed", "username", claims.Username)

	setAuthCookies(w, accessToken, refreshToken)
	common.RespondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *Handler) RegisterRoutes(r *mux.Router) {
	r.HandleFunc("/me", h.HandleGetMe).Methods("GET")
}
