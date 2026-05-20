package store

import (
	"context"
	"database/sql"
	"os"
	"testing"

	"runic/internal/db"

	_ "github.com/mattn/go-sqlite3"
)

func setupUserStoreTestDB(t *testing.T) (*UserStore, *sql.DB, func()) {
	t.Helper()
	f, err := os.CreateTemp("", "runic-user-store-test-*.db")
	if err != nil {
		t.Fatal(err)
	}
	dbPath := f.Name()
	if cErr := f.Close(); cErr != nil {
		t.Logf("Failed to close temp file: %v", cErr)
	}

	database, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		os.Remove(dbPath)
		t.Fatal(err)
	}

	if _, err := database.Exec("PRAGMA foreign_keys=ON"); err != nil {
		database.Close()
		os.Remove(dbPath)
		t.Fatal(err)
	}

	if _, err := database.Exec(db.Schema()); err != nil {
		database.Close()
		os.Remove(dbPath)
		t.Fatal(err)
	}

	store := NewUserStore(db.New(database))
	cleanup := func() {
		database.Close()
		os.Remove(dbPath)
	}
	return store, database, cleanup
}

func insertTestUser(t *testing.T, dbConn *sql.DB, username, email, role string) int64 {
	t.Helper()
	ctx := context.Background()
	result, err := dbConn.ExecContext(ctx,
		"INSERT INTO users (username, password_hash, email, role) VALUES (?, ?, ?, ?)",
		username, "bcrypt_hash", email, role)
	if err != nil {
		t.Fatalf("insert user %q: %v", username, err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("last insert id for user %q: %v", username, err)
	}
	return id
}

func TestUserStore_CreateUser(t *testing.T) {
	store, _, cleanup := setupUserStoreTestDB(t)
	defer cleanup()
	ctx := context.Background()

	id, err := store.CreateUser(ctx, nil, "testuser", "bcrypt_hash", "test@example.com", "admin")
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}
	if id == 0 {
		t.Error("expected non-zero user ID")
	}
}

func TestUserStore_GetUserByID(t *testing.T) {
	store, _, cleanup := setupUserStoreTestDB(t)
	defer cleanup()
	ctx := context.Background()

	id, err := store.CreateUser(ctx, nil, "getuser", "hash", "get@example.com", "viewer")
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	user, err := store.GetUserByID(ctx, int(id))
	if err != nil {
		t.Fatalf("GetUserByID failed: %v", err)
	}
	if user.Username != "getuser" {
		t.Errorf("expected username %q, got %q", "getuser", user.Username)
	}
	if user.Email != "get@example.com" {
		t.Errorf("expected email %q, got %q", "get@example.com", user.Email)
	}
	if user.Role != "viewer" {
		t.Errorf("expected role %q, got %q", "viewer", user.Role)
	}
}

func TestUserStore_GetUserByID_NotFound(t *testing.T) {
	store, _, cleanup := setupUserStoreTestDB(t)
	defer cleanup()
	ctx := context.Background()

	_, err := store.GetUserByID(ctx, 99999)
	if err == nil {
		t.Error("expected error for non-existent user, got nil")
	}
}

func TestUserStore_GetUserByUsername(t *testing.T) {
	store, _, cleanup := setupUserStoreTestDB(t)
	defer cleanup()
	ctx := context.Background()

	_, err := store.CreateUser(ctx, nil, "findme", "hash", "find@example.com", "editor")
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	user, err := store.GetUserByUsername(ctx, "findme")
	if err != nil {
		t.Fatalf("GetUserByUsername failed: %v", err)
	}
	if user.Username != "findme" {
		t.Errorf("expected username %q, got %q", "findme", user.Username)
	}
	if user.Role != "editor" {
		t.Errorf("expected role %q, got %q", "editor", user.Role)
	}
}

func TestUserStore_GetUserByUsername_NotFound(t *testing.T) {
	store, _, cleanup := setupUserStoreTestDB(t)
	defer cleanup()
	ctx := context.Background()

	_, err := store.GetUserByUsername(ctx, "nonexistent")
	if err == nil {
		t.Error("expected error for non-existent username, got nil")
	}
}

func TestUserStore_ListUsers(t *testing.T) {
	store, _, cleanup := setupUserStoreTestDB(t)
	defer cleanup()
	ctx := context.Background()

	// Initially empty
	users, total, err := store.ListUsers(ctx, 1, 10)
	if err != nil {
		t.Fatalf("ListUsers failed: %v", err)
	}
	if total != 0 {
		t.Errorf("expected total 0, got %d", total)
	}
	if len(users) != 0 {
		t.Errorf("expected 0 users, got %d", len(users))
	}

	// Create users
	for i := 0; i < 5; i++ {
		_, err := store.CreateUser(ctx, nil, "user"+string(rune('a'+i)), "hash", "", "viewer")
		if err != nil {
			t.Fatalf("CreateUser %d failed: %v", i, err)
		}
	}

	users, total, err = store.ListUsers(ctx, 1, 10)
	if err != nil {
		t.Fatalf("ListUsers failed: %v", err)
	}
	if total != 5 {
		t.Errorf("expected total 5, got %d", total)
	}
	if len(users) != 5 {
		t.Errorf("expected 5 users, got %d", len(users))
	}
}

func TestUserStore_ListUsers_Pagination(t *testing.T) {
	store, _, cleanup := setupUserStoreTestDB(t)
	defer cleanup()
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		_, err := store.CreateUser(ctx, nil, "puser"+string(rune('a'+i)), "hash", "", "viewer")
		if err != nil {
			t.Fatalf("CreateUser %d failed: %v", i, err)
		}
	}

	// Page 1 with perPage=2
	users, total, err := store.ListUsers(ctx, 1, 2)
	if err != nil {
		t.Fatalf("ListUsers page 1 failed: %v", err)
	}
	if total != 5 {
		t.Errorf("expected total 5, got %d", total)
	}
	if len(users) != 2 {
		t.Errorf("expected 2 users on page 1, got %d", len(users))
	}

	// Page 3 with perPage=2 — should get 1 user
	users, total, err = store.ListUsers(ctx, 3, 2)
	if err != nil {
		t.Fatalf("ListUsers page 3 failed: %v", err)
	}
	if total != 5 {
		t.Errorf("expected total 5, got %d", total)
	}
	if len(users) != 1 {
		t.Errorf("expected 1 user on page 3, got %d", len(users))
	}
}

func TestUserStore_UserExists(t *testing.T) {
	store, _, cleanup := setupUserStoreTestDB(t)
	defer cleanup()
	ctx := context.Background()

	_, err := store.CreateUser(ctx, nil, "existing", "hash", "", "viewer")
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	exists, err := store.UserExists(ctx, "existing")
	if err != nil {
		t.Fatalf("UserExists failed: %v", err)
	}
	if !exists {
		t.Error("expected user to exist")
	}

	exists, err = store.UserExists(ctx, "nonexistent")
	if err != nil {
		t.Fatalf("UserExists failed: %v", err)
	}
	if exists {
		t.Error("expected user to not exist")
	}
}

func TestUserStore_CountUsers(t *testing.T) {
	store, _, cleanup := setupUserStoreTestDB(t)
	defer cleanup()
	ctx := context.Background()

	count, err := store.CountUsers(ctx)
	if err != nil {
		t.Fatalf("CountUsers failed: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 users, got %d", count)
	}

	for i := 0; i < 3; i++ {
		_, err := store.CreateUser(ctx, nil, "cntuser"+string(rune('a'+i)), "hash", "", "viewer")
		if err != nil {
			t.Fatalf("CreateUser %d failed: %v", i, err)
		}
	}

	count, err = store.CountUsers(ctx)
	if err != nil {
		t.Fatalf("CountUsers failed: %v", err)
	}
	if count != 3 {
		t.Errorf("expected 3 users, got %d", count)
	}
}

func TestUserStore_CountAdmins(t *testing.T) {
	store, _, cleanup := setupUserStoreTestDB(t)
	defer cleanup()
	ctx := context.Background()

	count, err := store.CountAdmins(ctx)
	if err != nil {
		t.Fatalf("CountAdmins failed: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 admins, got %d", count)
	}

	_, err = store.CreateUser(ctx, nil, "admin1", "hash", "", "admin")
	if err != nil {
		t.Fatalf("CreateUser admin1 failed: %v", err)
	}
	_, err = store.CreateUser(ctx, nil, "viewer1", "hash", "", "viewer")
	if err != nil {
		t.Fatalf("CreateUser viewer1 failed: %v", err)
	}
	_, err = store.CreateUser(ctx, nil, "admin2", "hash", "", "admin")
	if err != nil {
		t.Fatalf("CreateUser admin2 failed: %v", err)
	}

	count, err = store.CountAdmins(ctx)
	if err != nil {
		t.Fatalf("CountAdmins failed: %v", err)
	}
	if count != 2 {
		t.Errorf("expected 2 admins, got %d", count)
	}
}

func TestUserStore_GetCredentials(t *testing.T) {
	store, _, cleanup := setupUserStoreTestDB(t)
	defer cleanup()
	ctx := context.Background()

	_, err := store.CreateUser(ctx, nil, "creduser", "bcrypt_hash_123", "", "admin")
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	creds, err := store.GetCredentials(ctx, "creduser")
	if err != nil {
		t.Fatalf("GetCredentials failed: %v", err)
	}
	if creds.Username != "creduser" {
		t.Errorf("expected username %q, got %q", "creduser", creds.Username)
	}
	if creds.PasswordHash != "bcrypt_hash_123" {
		t.Errorf("expected password_hash %q, got %q", "bcrypt_hash_123", creds.PasswordHash)
	}
}

func TestUserStore_GetCredentials_NotFound(t *testing.T) {
	store, _, cleanup := setupUserStoreTestDB(t)
	defer cleanup()
	ctx := context.Background()

	_, err := store.GetCredentials(ctx, "nobody")
	if err == nil {
		t.Error("expected error for non-existent username, got nil")
	}
}

func TestUserStore_UpdateUser(t *testing.T) {
	store, _, cleanup := setupUserStoreTestDB(t)
	defer cleanup()
	ctx := context.Background()

	id, err := store.CreateUser(ctx, nil, "upuser", "hash", "old@example.com", "viewer")
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	// Update email and role
	err = store.UpdateUser(ctx, int(id), UpdateUserFields{
		Email: "new@example.com",
		Role:  "editor",
	})
	if err != nil {
		t.Fatalf("UpdateUser failed: %v", err)
	}

	user, err := store.GetUserByID(ctx, int(id))
	if err != nil {
		t.Fatalf("GetUserByID failed: %v", err)
	}
	if user.Email != "new@example.com" {
		t.Errorf("expected email %q, got %q", "new@example.com", user.Email)
	}
	if user.Role != "editor" {
		t.Errorf("expected role %q, got %q", "editor", user.Role)
	}
}

func TestUserStore_UpdateUser_PasswordOnly(t *testing.T) {
	store, _, cleanup := setupUserStoreTestDB(t)
	defer cleanup()
	ctx := context.Background()

	id, err := store.CreateUser(ctx, nil, "pwduser", "old_hash", "pwd@example.com", "viewer")
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	err = store.UpdateUser(ctx, int(id), UpdateUserFields{
		PasswordHash: "new_hash",
	})
	if err != nil {
		t.Fatalf("UpdateUser failed: %v", err)
	}

	creds, err := store.GetCredentials(ctx, "pwduser")
	if err != nil {
		t.Fatalf("GetCredentials failed: %v", err)
	}
	if creds.PasswordHash != "new_hash" {
		t.Errorf("expected password_hash %q, got %q", "new_hash", creds.PasswordHash)
	}

	// Other fields should remain unchanged
	user, err := store.GetUserByID(ctx, int(id))
	if err != nil {
		t.Fatalf("GetUserByID failed: %v", err)
	}
	if user.Email != "pwd@example.com" {
		t.Errorf("expected email unchanged, got %q", user.Email)
	}
	if user.Role != "viewer" {
		t.Errorf("expected role unchanged, got %q", user.Role)
	}
}

func TestUserStore_UpdateUser_NoFields(t *testing.T) {
	store, _, cleanup := setupUserStoreTestDB(t)
	defer cleanup()
	ctx := context.Background()

	id, err := store.CreateUser(ctx, nil, "nofielduser", "hash", "", "viewer")
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	// Empty fields — should return nil (nothing to update)
	err = store.UpdateUser(ctx, int(id), UpdateUserFields{})
	if err != nil {
		t.Errorf("expected nil for empty update, got %v", err)
	}
}

func TestUserStore_UpdateUser_NotFound(t *testing.T) {
	store, _, cleanup := setupUserStoreTestDB(t)
	defer cleanup()
	ctx := context.Background()

	err := store.UpdateUser(ctx, 99999, UpdateUserFields{Email: "x@x.com"})
	if err == nil {
		t.Error("expected error for updating non-existent user, got nil")
	}
	if err != sql.ErrNoRows {
		t.Errorf("expected sql.ErrNoRows, got %v", err)
	}
}

func TestUserStore_DeleteUser(t *testing.T) {
	store, _, cleanup := setupUserStoreTestDB(t)
	defer cleanup()
	ctx := context.Background()

	id, err := store.CreateUser(ctx, nil, "deluser", "hash", "", "viewer")
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	err = store.DeleteUser(ctx, int(id))
	if err != nil {
		t.Fatalf("DeleteUser failed: %v", err)
	}

	_, err = store.GetUserByID(ctx, int(id))
	if err == nil {
		t.Error("expected error after deletion, got nil")
	}
}

func TestUserStore_DeleteUser_NotFound(t *testing.T) {
	store, _, cleanup := setupUserStoreTestDB(t)
	defer cleanup()
	ctx := context.Background()

	err := store.DeleteUser(ctx, 99999)
	if err == nil {
		t.Error("expected error for deleting non-existent user, got nil")
	}
	if err != sql.ErrNoRows {
		t.Errorf("expected sql.ErrNoRows, got %v", err)
	}
}
