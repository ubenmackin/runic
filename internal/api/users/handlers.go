// Package users provides user management handlers.
package users

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"

	"golang.org/x/crypto/bcrypt"

	"runic/internal/api/common"
	"runic/internal/auth"
	runiccommon "runic/internal/common"
	"runic/internal/common/log"
	"runic/internal/db"
	"runic/internal/models"
	"runic/internal/store"
)

// UserStore is defined as an interface here for testability.
type UserStore interface {
	ListUsers(ctx context.Context) ([]models.UserRow, error)
	UserExists(ctx context.Context, username string) (bool, error)
	CreateUser(ctx context.Context, q db.Querier, username, passwordHash, email, role string) (int64, error)
	GetUserByID(ctx context.Context, id int) (models.UserRow, error)
	UpdateUser(ctx context.Context, id int, fields store.UpdateUserFields) error
	DeleteUser(ctx context.Context, id int) error
}

type Handler struct {
	Store UserStore
}

func NewHandler(s UserStore) *Handler {
	return &Handler{Store: s}
}

var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)

func (h *Handler) ListUsers(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := runiccommon.WithHandlerTimeout(r.Context())
	defer cancel()

	users, err := h.Store.ListUsers(ctx)
	if err != nil {
		log.ErrorContext(r.Context(), "failed to list users", "error", err)
		common.InternalError(w)
		return
	}

	common.RespondJSON(w, http.StatusOK, users)
}

type CreateUserRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Email    string `json:"email"`
	Role     string `json:"role"`
}

func (h *Handler) CreateUser(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := runiccommon.WithHandlerTimeout(r.Context())
	defer cancel()

	var req CreateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		common.RespondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	req.Username = strings.TrimSpace(req.Username)
	if req.Username == "" {
		common.RespondError(w, http.StatusBadRequest, "Username is required")
		return
	}

	req.Email = strings.TrimSpace(req.Email)

	if req.Password == "" {
		common.RespondError(w, http.StatusBadRequest, "Password is required")
		return
	}
	if len(req.Password) < 8 {
		common.RespondError(w, http.StatusBadRequest, "Password must be at least 8 characters")
		return
	}

	req.Role = strings.TrimSpace(req.Role)
	if req.Role == "" {
		req.Role = "viewer"
	}
	if req.Role != "admin" && req.Role != "editor" && req.Role != "viewer" {
		common.RespondError(w, http.StatusBadRequest, "Role must be 'admin', 'editor', or 'viewer'")
		return
	}

	callerRole := auth.RoleFromContext(r.Context())
	if callerRole != "admin" && (req.Role == "admin" || req.Role == "editor") {
		common.RespondError(w, http.StatusForbidden, "Only admins can create admin or editor users")
		return
	}

	exists, err := h.Store.UserExists(ctx, req.Username)
	if err != nil {
		log.ErrorContext(r.Context(), "failed to check user existence", "error", err)
		common.InternalError(w)
		return
	}
	if exists {
		common.RespondError(w, http.StatusConflict, "Username already exists")
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), 12)
	if err != nil {
		log.ErrorContext(r.Context(), "failed to hash password", "error", err)
		common.InternalError(w)
		return
	}

	id, err := h.Store.CreateUser(ctx, nil, req.Username, string(hash), req.Email, req.Role)
	if err != nil {
		log.ErrorContext(r.Context(), "failed to create user", "error", err)
		common.InternalError(w)
		return
	}

	log.InfoContext(r.Context(), "user created", "username", req.Username, "role", req.Role)

	common.RespondJSON(w, http.StatusCreated, models.UserRow{
		ID:       int(id),
		Username: req.Username,
		Email:    req.Email,
		Role:     req.Role,
	})
}

func (h *Handler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	id, err := common.ParseIDParam(r, "id")
	if err != nil {
		common.RespondError(w, http.StatusBadRequest, "Invalid user ID")
		return
	}

	ctx, cancel := runiccommon.WithHandlerTimeout(r.Context())
	defer cancel()

	authUsername := auth.UsernameFromContext(r.Context())

	callerRole := auth.RoleFromContext(r.Context())
	if callerRole != "admin" {
		common.RespondError(w, http.StatusForbidden, "Only admins can delete users")
		return
	}

	user, err := h.Store.GetUserByID(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		common.RespondError(w, http.StatusNotFound, "User not found")
		return
	}
	if err != nil {
		log.ErrorContext(r.Context(), "failed to get user", "error", err)
		common.InternalError(w)
		return
	}

	if user.Username == authUsername {
		common.RespondError(w, http.StatusBadRequest, "Cannot delete your own account")
		return
	}

	if err := h.Store.DeleteUser(ctx, id); err != nil {
		log.ErrorContext(r.Context(), "failed to delete user", "error", err)
		common.InternalError(w)
		return
	}

	log.InfoContext(r.Context(), "user deleted", "username", user.Username, "deleted_by", authUsername)
	common.RespondJSON(w, http.StatusOK, map[string]string{"message": "User deleted"})
}

type UpdateUserRequest struct {
	Email    string `json:"email"`
	Role     string `json:"role"`
	Password string `json:"password"`
}

func (h *Handler) UpdateUser(w http.ResponseWriter, r *http.Request) {
	id, err := common.ParseIDParam(r, "id")
	if err != nil {
		common.RespondError(w, http.StatusBadRequest, "Invalid user ID")
		return
	}

	ctx, cancel := runiccommon.WithHandlerTimeout(r.Context())
	defer cancel()

	var req UpdateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		common.RespondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	req.Email = strings.TrimSpace(req.Email)
	if req.Email != "" && !emailRegex.MatchString(req.Email) {
		common.RespondError(w, http.StatusBadRequest, "Invalid email format")
		return
	}

	req.Role = strings.TrimSpace(req.Role)
	if req.Role != "" && req.Role != "admin" && req.Role != "editor" && req.Role != "viewer" {
		common.RespondError(w, http.StatusBadRequest, "Role must be 'admin', 'editor', or 'viewer'")
		return
	}

	user, err := h.Store.GetUserByID(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		common.RespondError(w, http.StatusNotFound, "User not found")
		return
	}
	if err != nil {
		log.ErrorContext(r.Context(), "failed to get user", "error", err)
		common.InternalError(w)
		return
	}

	if req.Role != "" {
		callerRole := auth.RoleFromContext(r.Context())
		if callerRole != "admin" {
			common.RespondError(w, http.StatusForbidden, "Only admins can change user roles")
			return
		}
	}

	fields := store.UpdateUserFields{
		Email: req.Email,
		Role:  req.Role,
	}

	if req.Password != "" {
		if len(req.Password) < 8 {
			common.RespondError(w, http.StatusBadRequest, "Password must be at least 8 characters")
			return
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), 12)
		if err != nil {
			log.ErrorContext(r.Context(), "failed to hash password", "error", err)
			common.InternalError(w)
			return
		}
		fields.PasswordHash = string(hash)
	}

	if err := h.Store.UpdateUser(ctx, id, fields); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			common.RespondError(w, http.StatusNotFound, "User not found")
			return
		}
		log.ErrorContext(r.Context(), "failed to update user", "error", err)
		common.InternalError(w)
		return
	}

	log.InfoContext(r.Context(), "user updated", "username", user.Username, "user_id", id)
	common.RespondJSON(w, http.StatusOK, map[string]string{"message": "User updated"})
}
