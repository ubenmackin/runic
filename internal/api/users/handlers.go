package users

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"runic/internal/api/common"
	"runic/internal/auth"
	runiccommon "runic/internal/common"
	"runic/internal/db"
)

// emailRegex is a basic pattern for email validation
var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)

// UserResponse is the user data returned in API responses (no password_hash)
type UserResponse struct {
	ID        int       `json:"id"`
	Username  string    `json:"username"`
	Email     string    `json:"email"`
	Role      string    `json:"role"`
	CreatedAt time.Time `json:"created_at"`
}

// ListUsers handles GET /api/v1/users
func ListUsers(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := runiccommon.WithHandlerTimeout(r.Context())
	defer cancel()

	rows, err := db.DB.QueryContext(ctx, "SELECT id, username, email, role, created_at FROM users ORDER BY id")
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "Failed to query users")
		return
	}
	defer rows.Close()

	var users []UserResponse
	for rows.Next() {
		var u UserResponse
		if err := rows.Scan(&u.ID, &u.Username, &u.Email, &u.Role, &u.CreatedAt); err != nil {
			common.RespondError(w, http.StatusInternalServerError, "Failed to scan user")
			return
		}
		users = append(users, u)
	}
	if err := rows.Err(); err != nil {
		common.RespondError(w, http.StatusInternalServerError, "Error iterating users")
		return
	}

	users = common.EnsureSlice(users)

	common.RespondJSON(w, http.StatusOK, users)
}

// CreateUserRequest is the request body for creating a user
type CreateUserRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Email    string `json:"email"`
	Role     string `json:"role"`
}

// CreateUser handles POST /api/v1/users
func CreateUser(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := runiccommon.WithHandlerTimeout(r.Context())
	defer cancel()

	var req CreateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		common.RespondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Validate username
	req.Username = strings.TrimSpace(req.Username)
	if req.Username == "" {
		common.RespondError(w, http.StatusBadRequest, "Username is required")
		return
	}

	req.Email = strings.TrimSpace(req.Email)

	// Validate password
	if req.Password == "" {
		common.RespondError(w, http.StatusBadRequest, "Password is required")
		return
	}
	if len(req.Password) < 8 {
		common.RespondError(w, http.StatusBadRequest, "Password must be at least 8 characters")
		return
	}

	// Validate role
	req.Role = strings.TrimSpace(req.Role)
	if req.Role == "" {
		req.Role = "viewer"
	}
	if req.Role != "admin" && req.Role != "editor" && req.Role != "viewer" {
		common.RespondError(w, http.StatusBadRequest, "Role must be 'admin', 'editor', or 'viewer'")
		return
	}

	// Only admins can create users with elevated roles
	callerRole := auth.RoleFromContext(r.Context())
	if callerRole != "admin" && (req.Role == "admin" || req.Role == "editor") {
		common.RespondError(w, http.StatusForbidden, "Only admins can create admin or editor users")
		return
	}

	// Check if username exists
	var exists bool
	err := db.DB.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM users WHERE username = ?)", req.Username).Scan(&exists)
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "Database error")
		return
	}
	if exists {
		common.RespondError(w, http.StatusConflict, "Username already exists")
		return
	}

	// Hash password
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), 12)
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "Failed to hash password")
		return
	}

	// Insert user
	result, err := db.DB.ExecContext(ctx,
		"INSERT INTO users (username, password_hash, email, role) VALUES (?, ?, ?, ?)",
		req.Username, string(hash), req.Email, req.Role,
	)
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "Failed to create user")
		return
	}

	id, err := result.LastInsertId()
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "Failed to get user ID")
		return
	}

	log.Printf("USERS CREATE: User '%s' created (role: %s)", req.Username, req.Role)

	common.RespondJSON(w, http.StatusCreated, UserResponse{
		ID:       int(id),
		Username: req.Username,
		Email:    req.Email,
		Role:     req.Role,
	})
}

// DeleteUser handles DELETE /api/v1/users/{id}
func DeleteUser(w http.ResponseWriter, r *http.Request) {
	id, err := common.ParseIDParam(r, "id")
	if err != nil {
		common.RespondError(w, http.StatusBadRequest, "Invalid user ID")
		return
	}

	ctx, cancel := runiccommon.WithHandlerTimeout(r.Context())
	defer cancel()

	// Get authenticated username from context
	authUsername := auth.UsernameFromContext(r.Context())

	// Only admins can delete users
	callerRole := auth.RoleFromContext(r.Context())
	if callerRole != "admin" {
		common.RespondError(w, http.StatusForbidden, "Only admins can delete users")
		return
	}

	// Check if user exists and get username
	var username string
	err = db.DB.QueryRowContext(ctx, "SELECT username FROM users WHERE id = ?", id).Scan(&username)
	if err == sql.ErrNoRows {
		common.RespondError(w, http.StatusNotFound, "User not found")
		return
	}
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "Database error")
		return
	}

	// Prevent deleting yourself
	if username == authUsername {
		common.RespondError(w, http.StatusBadRequest, "Cannot delete your own account")
		return
	}

	// Delete user
	_, err = db.DB.ExecContext(ctx, "DELETE FROM users WHERE id = ?", id)
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "Failed to delete user")
		return
	}

	log.Printf("USERS DELETE: User '%s' deleted by '%s'", username, authUsername)

	common.RespondJSON(w, http.StatusOK, map[string]string{"message": "User deleted"})
}

// UpdateUserRequest is the request body for updating a user
type UpdateUserRequest struct {
	Email    string `json:"email"`
	Role     string `json:"role"`
	Password string `json:"password"`
}

// UpdateUser handles PUT /api/v1/users/{id}
func UpdateUser(w http.ResponseWriter, r *http.Request) {
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

	// Validate email if provided
	req.Email = strings.TrimSpace(req.Email)
	if req.Email != "" && !emailRegex.MatchString(req.Email) {
		common.RespondError(w, http.StatusBadRequest, "Invalid email format")
		return
	}

	// Validate role if provided
	req.Role = strings.TrimSpace(req.Role)
	if req.Role != "" && req.Role != "admin" && req.Role != "editor" && req.Role != "viewer" {
		common.RespondError(w, http.StatusBadRequest, "Role must be 'admin', 'editor', or 'viewer'")
		return
	}

	// Check if user exists
	var username string
	err = db.DB.QueryRowContext(ctx, "SELECT username FROM users WHERE id = ?", id).Scan(&username)
	if err == sql.ErrNoRows {
		common.RespondError(w, http.StatusNotFound, "User not found")
		return
	}
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "Database error")
		return
	}

	// Only admins can change user roles
	if req.Role != "" {
		callerRole := auth.RoleFromContext(r.Context())
		if callerRole != "admin" {
			common.RespondError(w, http.StatusForbidden, "Only admins can change user roles")
			return
		}
	}

	// Build update query dynamically - only update fields that are provided
	var setClauses []string
	var args []interface{}

	if req.Email != "" {
		setClauses = append(setClauses, "email = ?")
		args = append(args, req.Email)
	}

	if req.Role != "" {
		setClauses = append(setClauses, "role = ?")
		args = append(args, req.Role)
	}

	// Handle password separately since it needs validation and hashing
	if req.Password != "" {
		if len(req.Password) < 8 {
			common.RespondError(w, http.StatusBadRequest, "Password must be at least 8 characters")
			return
		}

		hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), 12)
		if err != nil {
			common.RespondError(w, http.StatusInternalServerError, "Failed to hash password")
			return
		}

		setClauses = append(setClauses, "password_hash = ?")
		args = append(args, string(hash))
	}

	// If no fields to update, return early
	if len(setClauses) == 0 {
		common.RespondJSON(w, http.StatusOK, map[string]string{"message": "No changes to update"})
		return
	}

	// Build and execute the query
	query := "UPDATE users SET " + strings.Join(setClauses, ", ") + " WHERE id = ?"
	args = append(args, id)

	_, err = db.DB.ExecContext(ctx, query, args...)
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "Failed to update user")
		return
	}

	log.Printf("USERS UPDATE: User '%s' (id=%d) updated by admin", username, id)

	common.RespondJSON(w, http.StatusOK, map[string]string{"message": "User updated"})
}
