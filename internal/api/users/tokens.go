package users

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"

	"runic/internal/api/common"
	"runic/internal/auth"
	runiccommon "runic/internal/common"
	"runic/internal/common/log"
	"runic/internal/models"
	"runic/internal/store"
)

// User API token (PAT) endpoints. Intended routes (wired by the API layer):
//
// Self-service on the protected subrouter (any role for their own tokens):
//
//	POST   /users/me/tokens              — create a token for the caller
//	GET    /users/me/tokens              — list the caller's tokens (masked)
//	DELETE /users/me/tokens/{id}         — revoke one of the caller's tokens
//
// Legacy aliases (same handlers, same self semantics):
//
//	POST   /users/tokens
//	GET    /users/tokens
//	DELETE /users/tokens/{token_id}
//
// Admins may pass a numeric {id} path parameter to manage another user's
// tokens (for example the automation user `llm_agent`):
//
//	POST   /users/{id}/tokens
//	GET    /users/{id}/tokens
//	DELETE /users/{id}/tokens/{token_id}
//
// Creation is rate-limited like login (see the token limiter in api.go).
// Authentication for these endpoints uses the standard auth middleware; the
// issued tokens themselves authenticate via `Authorization: Bearer runic_pat_*`
// and flow through the existing RequireRole RBAC unchanged, so a viewer PAT
// stays GET-only exactly like a viewer JWT.

// maxTokenRequestBytes caps PAT request bodies. Payloads are tiny (a name plus
// an optional expiry); 1 MiB matches every other JSON endpoint.
const maxTokenRequestBytes = 1 << 20

// maxTokenNameLength bounds the operator-supplied token label.
const maxTokenNameLength = 100

// Bounds for the expires_in_days creation field. Zero means the token never
// expires; 1-365 caps the lifetime to a year. Values outside 0-365 are
// rejected with 400.
const (
	minTokenExpiresDays = 1
	maxTokenExpiresDays = 365
)

// UserTokenStore is the subset of *store.UserTokenStore used by the PAT
// handlers, defined as an interface here for testability.
type UserTokenStore interface {
	CreateToken(ctx context.Context, userID int, name, tokenHash, prefix string, expiresAt *time.Time) (int64, error)
	ListTokens(ctx context.Context, userID int) ([]store.UserAPITokenView, error)
	RevokeToken(ctx context.Context, id int64, userID int) (bool, error)
}

// tokenUserStore resolves users for PAT ownership checks, defined as an
// interface here for testability. *store.UserStore satisfies it.
type tokenUserStore interface {
	GetUserByID(ctx context.Context, id int) (models.UserRow, error)
	GetUserByUsername(ctx context.Context, username string) (models.UserRow, error)
}

// TokenHandler manages personal access tokens for users.
type TokenHandler struct {
	Tokens UserTokenStore
	Users  tokenUserStore
}

// NewTokenHandler creates a new TokenHandler.
func NewTokenHandler(tokens UserTokenStore, users tokenUserStore) *TokenHandler {
	return &TokenHandler{Tokens: tokens, Users: users}
}

// CreateTokenRequest is the request body for PAT creation. ExpiresAt is an
// optional RFC3339 timestamp; empty means the token never expires.
// ExpiresInDays is an alternative relative expiry: 0 means never expires,
// 1-365 sets expiry to now plus that many days. Only one of ExpiresAt and
// ExpiresInDays may be set.
type CreateTokenRequest struct {
	Name          string `json:"name"`
	ExpiresAt     string `json:"expires_at"`
	ExpiresInDays *int   `json:"expires_in_days"`
}

// CreateTokenResponse carries the newly issued credential. FullToken is shown
// exactly once here; it is unrecoverable afterwards (only its SHA256 digest
// is persisted).
type CreateTokenResponse struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"`
	Prefix    string `json:"prefix"`
	FullToken string `json:"full_token"`
	ExpiresAt string `json:"expires_at,omitempty"`
}

// tokenIDFromRequest extracts the token row ID from the request. Admin routes
// name it {token_id} while the self-service DELETE names it {id}
// (DELETE /users/me/tokens/{id}); {token_id} is preferred and {id} is the
// fallback so either route template resolves to the same handler.
func tokenIDFromRequest(r *http.Request) (int64, bool) {
	vars := mux.Vars(r)
	raw := strings.TrimSpace(vars["token_id"])
	if raw == "" {
		raw = strings.TrimSpace(vars["id"])
	}
	if raw == "" {
		return 0, false
	}
	tokenID, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || tokenID <= 0 {
		return 0, false
	}
	return tokenID, true
}

// resolveTargetUserID maps the request to the user whose tokens are managed.
// Without an {id} path parameter the caller manages their own tokens. With
// {id}, only admins may target another user. Self-service routes under
// /users/me/tokens always resolve to the caller, even though the DELETE
// variant carries the token ID in {id}.
func (h *TokenHandler) resolveTargetUserID(r *http.Request) (int, *common.HTTPError) {
	ctx := r.Context()
	callerRole := auth.RoleFromContext(ctx)
	callerUsername := auth.UsernameFromContext(ctx)
	if callerUsername == "" {
		return 0, common.NewHTTPError(http.StatusUnauthorized, "Unauthorized")
	}

	// Self-service paths always operate on the caller. Check first because
	// DELETE /users/me/tokens/{id} reuses {id} for the token ID.
	if strings.Contains(r.URL.Path, "/users/me/tokens") {
		caller, err := h.Users.GetUserByUsername(ctx, callerUsername)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return 0, common.NewHTTPError(http.StatusUnauthorized, "Unauthorized")
			}
			return 0, common.NewHTTPError(http.StatusInternalServerError, "internal server error")
		}
		return caller.ID, nil
	}

	vars := mux.Vars(r)
	rawID, hasID := vars["id"]
	if !hasID || strings.TrimSpace(rawID) == "" || strings.EqualFold(strings.TrimSpace(rawID), "me") {
		caller, err := h.Users.GetUserByUsername(ctx, callerUsername)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return 0, common.NewHTTPError(http.StatusUnauthorized, "Unauthorized")
			}
			return 0, common.NewHTTPError(http.StatusInternalServerError, "internal server error")
		}
		return caller.ID, nil
	}

	targetID, err := strconv.Atoi(strings.TrimSpace(rawID))
	if err != nil || targetID <= 0 {
		return 0, common.NewHTTPError(http.StatusBadRequest, "Invalid user ID")
	}
	caller, err := h.Users.GetUserByUsername(ctx, callerUsername)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, common.NewHTTPError(http.StatusUnauthorized, "Unauthorized")
		}
		return 0, common.NewHTTPError(http.StatusInternalServerError, "internal server error")
	}
	if targetID != caller.ID && callerRole != "admin" {
		return 0, common.NewHTTPError(http.StatusForbidden, "forbidden")
	}
	return targetID, nil
}

// CreateToken issues a new personal access token. The raw token is generated
// with crypto/rand (32 bytes, hex) and returned once in FullToken; only its
// SHA256 digest and display prefix are stored.
func (h *TokenHandler) CreateToken(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := runiccommon.WithHandlerTimeout(r.Context())
	defer cancel()

	r.Body = http.MaxBytesReader(w, r.Body, maxTokenRequestBytes)

	var req CreateTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			common.RespondError(w, http.StatusRequestEntityTooLarge, "request body too large")
			return
		}
		common.RespondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		common.RespondError(w, http.StatusBadRequest, "Token name is required")
		return
	}
	if len(req.Name) > maxTokenNameLength {
		common.RespondError(w, http.StatusBadRequest, "Token name must be 100 characters or fewer")
		return
	}

	var expiresAt *time.Time
	var expiresOut string
	hasExpiresAt := strings.TrimSpace(req.ExpiresAt) != ""
	hasExpiresInDays := req.ExpiresInDays != nil
	if hasExpiresAt && hasExpiresInDays {
		common.RespondError(w, http.StatusBadRequest, "only one of expires_at and expires_in_days may be set")
		return
	}
	if hasExpiresAt {
		exp, err := time.Parse(time.RFC3339, strings.TrimSpace(req.ExpiresAt))
		if err != nil {
			common.RespondError(w, http.StatusBadRequest, "expires_at must be RFC3339 format")
			return
		}
		if !exp.After(time.Now()) {
			common.RespondError(w, http.StatusBadRequest, "expires_at must be in the future")
			return
		}
		expiresAt = &exp
		expiresOut = exp.UTC().Format(time.RFC3339)
	} else if hasExpiresInDays {
		days := *req.ExpiresInDays
		if days != 0 && (days < minTokenExpiresDays || days > maxTokenExpiresDays) {
			common.RespondError(w, http.StatusBadRequest, "expires_in_days must be between 0 and 365")
			return
		}
		if days == 0 {
			// Never expires. Allowed so automation users such as llm_agent
			// can hold long-lived credentials when policy permits.
		} else {
			exp := time.Now().Add(time.Duration(days) * 24 * time.Hour)
			expiresAt = &exp
			expiresOut = exp.UTC().Format(time.RFC3339)
		}
	}

	targetID, httpErr := h.resolveTargetUserID(r.WithContext(ctx))
	if httpErr != nil {
		common.RespondError(w, httpErr.StatusCode, httpErr.Message)
		return
	}

	if _, err := h.Users.GetUserByID(ctx, targetID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			common.RespondError(w, http.StatusNotFound, "User not found")
			return
		}
		log.ErrorContext(r.Context(), "failed to get token owner", "error", err)
		common.InternalError(w)
		return
	}

	rawToken, tokenHash, prefix, err := store.GeneratePAT()
	if err != nil {
		log.ErrorContext(r.Context(), "failed to generate token entropy", "error", err)
		common.InternalError(w)
		return
	}

	id, err := h.Tokens.CreateToken(ctx, targetID, req.Name, tokenHash, prefix, expiresAt)
	if err != nil {
		log.ErrorContext(r.Context(), "failed to store token", "error", err)
		common.InternalError(w)
		return
	}

	callerUsername := auth.UsernameFromContext(ctx)
	if callerUsername == "" {
		callerUsername = auth.UsernameFromContext(r.Context())
	}
	log.InfoContext(r.Context(), "user API token created", "username", callerUsername, "user_id", targetID, "token_id", id, "name", req.Name)

	common.RespondJSON(w, http.StatusCreated, CreateTokenResponse{
		ID:        id,
		Name:      req.Name,
		Prefix:    prefix,
		FullToken: rawToken,
		ExpiresAt: expiresOut,
	})
}

// ListTokens returns the caller's (or, for admins with {id}, another user's)
// tokens in masked form. Digests are never selected and the raw token is
// unrecoverable, so only the prefix-based display is exposed.
func (h *TokenHandler) ListTokens(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := runiccommon.WithHandlerTimeout(r.Context())
	defer cancel()

	targetID, httpErr := h.resolveTargetUserID(r.WithContext(ctx))
	if httpErr != nil {
		common.RespondError(w, httpErr.StatusCode, httpErr.Message)
		return
	}

	if _, err := h.Users.GetUserByID(ctx, targetID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			common.RespondError(w, http.StatusNotFound, "User not found")
			return
		}
		log.ErrorContext(r.Context(), "failed to get token owner", "error", err)
		common.InternalError(w)
		return
	}

	tokens, err := h.Tokens.ListTokens(ctx, targetID)
	if err != nil {
		log.ErrorContext(r.Context(), "failed to list tokens", "error", err)
		common.InternalError(w)
		return
	}

	common.RespondJSON(w, http.StatusOK, tokens)
}

// RevokeToken revokes a single token (DELETE semantics → 204). The revocation
// is recorded in the shared auth revocation cache immediately so in-flight
// credentials are rejected without waiting for cache expiry.
func (h *TokenHandler) RevokeToken(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := runiccommon.WithHandlerTimeout(r.Context())
	defer cancel()

	tokenID, ok := tokenIDFromRequest(r)
	if !ok {
		common.RespondError(w, http.StatusBadRequest, "Invalid token ID")
		return
	}

	targetID, httpErr := h.resolveTargetUserID(r.WithContext(ctx))
	if httpErr != nil {
		common.RespondError(w, httpErr.StatusCode, httpErr.Message)
		return
	}

	revoked, err := h.Tokens.RevokeToken(ctx, tokenID, targetID)
	if err != nil {
		log.ErrorContext(r.Context(), "failed to revoke token", "error", err)
		common.InternalError(w)
		return
	}
	if !revoked {
		common.RespondError(w, http.StatusNotFound, "token not found or already revoked")
		return
	}

	auth.CachePATRevocation(tokenID)

	callerUsername := auth.UsernameFromContext(ctx)
	if callerUsername == "" {
		callerUsername = auth.UsernameFromContext(r.Context())
	}
	log.InfoContext(r.Context(), "user API token revoked", "username", callerUsername, "user_id", targetID, "token_id", tokenID)

	w.WriteHeader(http.StatusNoContent)
}
