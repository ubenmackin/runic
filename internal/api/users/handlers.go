// Package users provides user management handlers.
package users

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
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
	ListUsers(ctx context.Context, page, perPage int) ([]models.UserRow, int, error)
	UserExists(ctx context.Context, username string) (bool, error)
	CreateUser(ctx context.Context, q db.Querier, username, passwordHash, email, role string) (int64, error)
	GetUserByID(ctx context.Context, id int) (models.UserRow, error)
	UpdateUser(ctx context.Context, id int, fields store.UpdateUserFields) error
	DeleteUser(ctx context.Context, id int) error
	CountAdmins(ctx context.Context) (int, error)
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

	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	perPage, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
	if perPage < 1 || perPage > 100 {
		perPage = 50
	}

	users, total, err := h.Store.ListUsers(ctx, page, perPage)
	if err != nil {
		log.ErrorContext(r.Context(), "failed to list users", "error", err)
		common.InternalError(w)
		return
	}

	common.RespondJSON(w, http.StatusOK, map[string]interface{}{
		"users":    users,
		"total":    total,
		"page":     page,
		"per_page": perPage,
	})
}

type CreateUserRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Email    string `json:"email"`
	Role     string `json:"role"`
}

func validateCreateUserRequest(req *CreateUserRequest) error {
	req.Username = strings.TrimSpace(req.Username)
	if req.Username == "" {
		return common.NewHTTPError(http.StatusBadRequest, "Username is required")
	}
	if req.Password == "" {
		return common.NewHTTPError(http.StatusBadRequest, "Password is required")
	}
	if len(req.Password) < 8 {
		return common.NewHTTPError(http.StatusBadRequest, "Password must be at least 8 characters")
	}
	req.Role = strings.TrimSpace(req.Role)
	if req.Role == "" {
		req.Role = "viewer"
	}
	if req.Role != "admin" && req.Role != "editor" && req.Role != "viewer" {
		return common.NewHTTPError(http.StatusBadRequest, "Role must be 'admin', 'editor', or 'viewer'")
	}
	callerRole := auth.RoleFromContext(context.Background())
	if callerRole != "admin" && (req.Role == "admin" || req.Role == "editor") {
		return common.NewHTTPError(http.StatusForbidden, "Only admins can create admin or editor users")
	}
	return nil
}

func hashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	if err != nil {
		return "", fmt.Errorf("failed to hash password: %w", err)
	}
	return string(hash), nil
}

func (h *Handler) CreateUser(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := runiccommon.WithHandlerTimeout(r.Context())
	defer cancel()

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1MB limit

	var req CreateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			common.RespondError(w, http.StatusRequestEntityTooLarge, "request body too large")
			return
		}
		common.RespondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if err := validateCreateUserRequest(&req); err != nil {
		var httpErr *common.HTTPError
		if errors.As(err, &httpErr) {
			common.RespondError(w, httpErr.StatusCode, httpErr.Message)
			return
		}
		common.RespondError(w, http.StatusBadRequest, err.Error())
		return
	}

	req.Email = strings.TrimSpace(req.Email)

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

	hash, err := hashPassword(req.Password)
	if err != nil {
		log.ErrorContext(r.Context(), "failed to hash password", "error", err)
		common.InternalError(w)
		return
	}

	id, err := h.Store.CreateUser(ctx, nil, req.Username, hash, req.Email, req.Role)
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

	// Prevent deleting the last admin account — would orphan the system
	if user.Role == "admin" {
		adminCount, err := h.Store.CountAdmins(ctx)
		if err != nil {
			log.ErrorContext(r.Context(), "failed to count admins", "error", err)
			common.InternalError(w)
			return
		}
		if adminCount <= 1 {
			common.RespondError(w, http.StatusBadRequest, "Cannot delete the last admin user")
			return
		}
	}

	if err := h.Store.DeleteUser(ctx, id); err != nil {
		log.ErrorContext(r.Context(), "failed to delete user", "error", err)
		common.InternalError(w)
		return
	}

	log.InfoContext(r.Context(), "user deleted", "username", user.Username, "deleted_by", authUsername)
	w.WriteHeader(http.StatusNoContent)
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

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1MB limit

	var req UpdateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			common.RespondError(w, http.StatusRequestEntityTooLarge, "request body too large")
			return
		}
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
