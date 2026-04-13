package users

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"runic/internal/auth"
	"runic/internal/testutil"
)

// muxVars is a helper to set gorilla/mux URL variables
var muxVars = testutil.MuxVars

// Helper to set admin context on request
func withAdminContext(ctx context.Context) context.Context {
	return auth.SetContextForTest(ctx, "admin", "admin")
}

// Helper to set editor context on request
func withEditorContext(ctx context.Context) context.Context {
	return auth.SetContextForTest(ctx, "editor", "editor")
}

// Helper to set viewer context on request
func withViewerContext(ctx context.Context) context.Context {
	return auth.SetContextForTest(ctx, "viewer", "viewer")
}

// Helper to set role context with custom role and username
func withRoleContext(ctx context.Context, role, username string) context.Context {
	return auth.SetContextForTest(ctx, role, username)
}

// =============================================================================
// Test ListUsers
// =============================================================================

func TestListUsers_EmptyTable(t *testing.T) {
	db, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	h := NewHandler(db)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)

	h.ListUsers(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var users []UserResponse
	if err := json.Unmarshal(w.Body.Bytes(), &users); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if len(users) != 0 {
		t.Errorf("expected empty users list, got %d users", len(users))
	}
}

func TestListUsers_MultipleUsers(t *testing.T) {
	db, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	// Insert test users
	hash1, _ := bcrypt.GenerateFromPassword([]byte("password123"), 12)
	hash2, _ := bcrypt.GenerateFromPassword([]byte("password123"), 12)
	hash3, _ := bcrypt.GenerateFromPassword([]byte("password123"), 12)

	db.Exec("INSERT INTO users (username, password_hash, email, role) VALUES (?, ?, ?, ?)",
		"user1", string(hash1), "user1@test.com", "admin")
	db.Exec("INSERT INTO users (username, password_hash, email, role) VALUES (?, ?, ?, ?)",
		"user2", string(hash2), "user2@test.com", "editor")
	db.Exec("INSERT INTO users (username, password_hash, email, role) VALUES (?, ?, ?, ?)",
		"user3", string(hash3), "user3@test.com", "viewer")

	h := NewHandler(db)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)

	h.ListUsers(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var users []UserResponse
	if err := json.Unmarshal(w.Body.Bytes(), &users); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if len(users) != 3 {
		t.Errorf("expected 3 users, got %d", len(users))
	}
}

// =============================================================================
// Test CreateUser
// =============================================================================

func TestCreateUser_InvalidJSON(t *testing.T) {
	db, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	h := NewHandler(db)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/users", strings.NewReader("{invalid json"))
	r = r.WithContext(withAdminContext(context.Background()))

	h.CreateUser(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestCreateUser_MissingUsername(t *testing.T) {
	db, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	h := NewHandler(db)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/users", strings.NewReader(`{"password":"password123"}`))
	r = r.WithContext(withAdminContext(context.Background()))

	h.CreateUser(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestCreateUser_MissingPassword(t *testing.T) {
	db, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	h := NewHandler(db)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/users", strings.NewReader(`{"username":"testuser"}`))
	r = r.WithContext(withAdminContext(context.Background()))

	h.CreateUser(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestCreateUser_PasswordTooShort(t *testing.T) {
	db, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	h := NewHandler(db)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/users", strings.NewReader(`{"username":"testuser","password":"short"}`))
	r = r.WithContext(withAdminContext(context.Background()))

	h.CreateUser(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestCreateUser_InvalidRole(t *testing.T) {
	db, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	h := NewHandler(db)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/users", strings.NewReader(`{"username":"testuser","password":"password123","role":"superuser"}`))
	r = r.WithContext(withAdminContext(context.Background()))

	h.CreateUser(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestCreateUser_NonAdminCreatingElevatedRole(t *testing.T) {
	db, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	h := NewHandler(db)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/users", strings.NewReader(`{"username":"newadmin","password":"password123","role":"admin"}`))
	r = r.WithContext(withEditorContext(context.Background()))

	h.CreateUser(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected status %d, got %d", http.StatusForbidden, w.Code)
	}
}

func TestCreateUser_UsernameExists(t *testing.T) {
	db, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	// Insert existing user
	hash, _ := bcrypt.GenerateFromPassword([]byte("password123"), 12)
	db.Exec("INSERT INTO users (username, password_hash, email, role) VALUES (?, ?, ?, ?)",
		"existinguser", string(hash), "test@test.com", "viewer")

	h := NewHandler(db)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/users", strings.NewReader(`{"username":"existinguser","password":"password123"}`))
	r = r.WithContext(withAdminContext(context.Background()))

	h.CreateUser(w, r)

	if w.Code != http.StatusConflict {
		t.Errorf("expected status %d, got %d", http.StatusConflict, w.Code)
	}
}

func TestCreateUser_ValidCreation(t *testing.T) {
	db, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	h := NewHandler(db)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/users", strings.NewReader(`{"username":"newuser","password":"password123","email":"newuser@test.com","role":"viewer"}`))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	r = r.WithContext(withAdminContext(ctx))

	h.CreateUser(w, r)

	if w.Code != http.StatusCreated {
		t.Errorf("expected status %d, got %d", http.StatusCreated, w.Code)
	}

	var user UserResponse
	if err := json.Unmarshal(w.Body.Bytes(), &user); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if user.Username != "newuser" {
		t.Errorf("expected username 'newuser', got '%s'", user.Username)
	}
	if user.Role != "viewer" {
		t.Errorf("expected role 'viewer', got '%s'", user.Role)
	}
}

// =============================================================================
// Test DeleteUser
// =============================================================================

func TestDeleteUser_InvalidID(t *testing.T) {
	db, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	h := NewHandler(db)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/api/v1/users/invalid", nil)
	r = muxVars(r, map[string]string{"id": "invalid"})
	r = r.WithContext(withAdminContext(context.Background()))

	h.DeleteUser(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestDeleteUser_UserNotFound(t *testing.T) {
	db, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	h := NewHandler(db)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/api/v1/users/9999", nil)
	r = muxVars(r, map[string]string{"id": "9999"})
	r = r.WithContext(withAdminContext(r.Context()))

	h.DeleteUser(w, r)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status %d, got %d", http.StatusNotFound, w.Code)
	}
}

func TestDeleteUser_NonAdmin(t *testing.T) {
	db, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	// Insert test user
	hash, _ := bcrypt.GenerateFromPassword([]byte("password123"), 12)
	db.Exec("INSERT INTO users (username, password_hash, email, role) VALUES (?, ?, ?, ?)",
		"testuser", string(hash), "test@test.com", "viewer")

	h := NewHandler(db)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/api/v1/users/1", nil)
	r = muxVars(r, map[string]string{"id": "1"})
	r = r.WithContext(withEditorContext(r.Context()))

	h.DeleteUser(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected status %d, got %d", http.StatusForbidden, w.Code)
	}
}

func TestDeleteUser_CannotDeleteYourself(t *testing.T) {
	db, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	// Insert admin user
	hash, _ := bcrypt.GenerateFromPassword([]byte("password123"), 12)
	db.Exec("INSERT INTO users (username, password_hash, email, role) VALUES (?, ?, ?, ?)",
		"admin", string(hash), "admin@test.com", "admin")

	h := NewHandler(db)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/api/v1/users/1", nil)
	r = muxVars(r, map[string]string{"id": "1"})
	r = r.WithContext(withRoleContext(context.Background(), "admin", "admin"))

	h.DeleteUser(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestDeleteUser_ValidDelete(t *testing.T) {
	db, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	// Insert test users
	hash, _ := bcrypt.GenerateFromPassword([]byte("password123"), 12)
	db.Exec("INSERT INTO users (username, password_hash, email, role) VALUES (?, ?, ?, ?)",
		"admin", string(hash), "admin@test.com", "admin")
	db.Exec("INSERT INTO users (username, password_hash, email, role) VALUES (?, ?, ?, ?)",
		"todelete", string(hash), "delete@test.com", "viewer")

	h := NewHandler(db)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/api/v1/users/2", nil)
	r = muxVars(r, map[string]string{"id": "2"})
	r = r.WithContext(withRoleContext(r.Context(), "admin", "admin"))

	h.DeleteUser(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	// Verify user was deleted
	var count int
	db.QueryRow("SELECT COUNT(*) FROM users WHERE id = 2").Scan(&count)
	if count != 0 {
		t.Error("expected user to be deleted")
	}
}

// =============================================================================
// Test UpdateUser
// =============================================================================

func TestUpdateUser_InvalidID(t *testing.T) {
	db, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	h := NewHandler(db)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPut, "/api/v1/users/invalid", strings.NewReader(`{"email":"test@test.com"}`))
	r = muxVars(r, map[string]string{"id": "invalid"})
	r = r.WithContext(withAdminContext(context.Background()))

	h.UpdateUser(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestUpdateUser_InvalidJSON(t *testing.T) {
	db, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	h := NewHandler(db)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPut, "/api/v1/users/1", strings.NewReader("{invalid json"))
	r = muxVars(r, map[string]string{"id": "1"})
	r = r.WithContext(withAdminContext(context.Background()))

	h.UpdateUser(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestUpdateUser_InvalidEmailFormat(t *testing.T) {
	db, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	hash, _ := bcrypt.GenerateFromPassword([]byte("password123"), 12)
	db.Exec("INSERT INTO users (username, password_hash, email, role) VALUES (?, ?, ?, ?)",
		"testuser", string(hash), "test@test.com", "viewer")

	h := NewHandler(db)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPut, "/api/v1/users/1", strings.NewReader(`{"email":"notanemail"}`))
	r = muxVars(r, map[string]string{"id": "1"})
	r = r.WithContext(withAdminContext(context.Background()))

	h.UpdateUser(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestUpdateUser_InvalidRole(t *testing.T) {
	db, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	hash, _ := bcrypt.GenerateFromPassword([]byte("password123"), 12)
	db.Exec("INSERT INTO users (username, password_hash, email, role) VALUES (?, ?, ?, ?)",
		"testuser", string(hash), "test@test.com", "viewer")

	h := NewHandler(db)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPut, "/api/v1/users/1", strings.NewReader(`{"role":"superuser"}`))
	r = muxVars(r, map[string]string{"id": "1"})
	r = r.WithContext(withAdminContext(context.Background()))

	h.UpdateUser(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestUpdateUser_UserNotFound(t *testing.T) {
	db, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	h := NewHandler(db)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPut, "/api/v1/users/9999", strings.NewReader(`{"email":"test@test.com"}`))
	r = muxVars(r, map[string]string{"id": "9999"})
	r = r.WithContext(withAdminContext(r.Context()))

	h.UpdateUser(w, r)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status %d, got %d", http.StatusNotFound, w.Code)
	}
}

func TestUpdateUser_NonAdminChangingRole(t *testing.T) {
	db, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	hash, _ := bcrypt.GenerateFromPassword([]byte("password123"), 12)
	db.Exec("INSERT INTO users (username, password_hash, email, role) VALUES (?, ?, ?, ?)",
		"testuser", string(hash), "test@test.com", "viewer")

	h := NewHandler(db)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPut, "/api/v1/users/1", strings.NewReader(`{"role":"admin"}`))
	r = muxVars(r, map[string]string{"id": "1"})
	r = r.WithContext(withEditorContext(r.Context()))

	h.UpdateUser(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected status %d, got %d", http.StatusForbidden, w.Code)
	}
}

func TestUpdateUser_PasswordTooShort(t *testing.T) {
	db, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	hash, _ := bcrypt.GenerateFromPassword([]byte("password123"), 12)
	db.Exec("INSERT INTO users (username, password_hash, email, role) VALUES (?, ?, ?, ?)",
		"testuser", string(hash), "test@test.com", "viewer")

	h := NewHandler(db)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPut, "/api/v1/users/1", strings.NewReader(`{"password":"short"}`))
	r = muxVars(r, map[string]string{"id": "1"})
	r = r.WithContext(withAdminContext(context.Background()))

	h.UpdateUser(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestUpdateUser_ValidUpdate(t *testing.T) {
	db, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	hash, _ := bcrypt.GenerateFromPassword([]byte("password123"), 12)
	db.Exec("INSERT INTO users (username, password_hash, email, role) VALUES (?, ?, ?, ?)",
		"testuser", string(hash), "old@test.com", "viewer")

	h := NewHandler(db)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPut, "/api/v1/users/1", strings.NewReader(`{"email":"new@test.com"}`))
	r = muxVars(r, map[string]string{"id": "1"})
	r = r.WithContext(withAdminContext(r.Context()))

	h.UpdateUser(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	// Verify email was updated
	var email string
	db.QueryRow("SELECT email FROM users WHERE id = 1").Scan(&email)
	if email != "new@test.com" {
		t.Errorf("expected email 'new@test.com', got '%s'", email)
	}
}
