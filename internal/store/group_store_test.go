package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"testing"

	"runic/internal/db"

	_ "github.com/mattn/go-sqlite3"
)

func setupGroupStoreTestDB(t *testing.T) (*GroupStore, *sql.DB, func()) {
	t.Helper()
	f, err := os.CreateTemp("", "runic-group-store-test-*.db")
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

	store := NewGroupStore(db.New(database))
	cleanup := func() {
		database.Close()
		os.Remove(dbPath)
	}
	return store, database, cleanup
}

func TestGroupStore_CreateGroup(t *testing.T) {
	store, _, cleanup := setupGroupStoreTestDB(t)
	defer cleanup()
	ctx := context.Background()

	id, err := store.CreateGroup(ctx, "test-group", "a test group")
	if err != nil {
		t.Fatalf("CreateGroup failed: %v", err)
	}
	if id == 0 {
		t.Error("expected non-zero group ID")
	}
}

func TestGroupStore_CreateGroup_EmptyName(t *testing.T) {
	store, _, cleanup := setupGroupStoreTestDB(t)
	defer cleanup()
	ctx := context.Background()

	_, err := store.CreateGroup(ctx, "", "description")
	if err == nil {
		t.Error("expected error for empty group name, got nil")
	}
}

func TestGroupStore_GetNameByID(t *testing.T) {
	store, _, cleanup := setupGroupStoreTestDB(t)
	defer cleanup()
	ctx := context.Background()

	id, err := store.CreateGroup(ctx, "my-group", "description")
	if err != nil {
		t.Fatalf("CreateGroup failed: %v", err)
	}

	name, err := store.GetNameByID(ctx, int(id))
	if err != nil {
		t.Fatalf("GetNameByID failed: %v", err)
	}
	if name != "my-group" {
		t.Errorf("expected name %q, got %q", "my-group", name)
	}
}

func TestGroupStore_GetNameByID_NotFound(t *testing.T) {
	store, _, cleanup := setupGroupStoreTestDB(t)
	defer cleanup()
	ctx := context.Background()

	_, err := store.GetNameByID(ctx, 99999)
	if err == nil {
		t.Error("expected error for non-existent group, got nil")
	}
	if !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("expected error wrapping sql.ErrNoRows, got %v", err)
	}
}

func TestGroupStore_ListGroups(t *testing.T) {
	store, _, cleanup := setupGroupStoreTestDB(t)
	defer cleanup()
	ctx := context.Background()

	// Initially empty
	groups, err := store.ListGroups(ctx)
	if err != nil {
		t.Fatalf("ListGroups failed: %v", err)
	}
	if len(groups) != 0 {
		t.Errorf("expected 0 groups, got %d", len(groups))
	}

	// Create groups
	for i := 0; i < 3; i++ {
		_, err := store.CreateGroup(ctx, fmt.Sprintf("group-%d", i), "")
		if err != nil {
			t.Fatalf("CreateGroup %d failed: %v", i, err)
		}
	}

	groups, err = store.ListGroups(ctx)
	if err != nil {
		t.Fatalf("ListGroups failed: %v", err)
	}
	if len(groups) != 3 {
		t.Errorf("expected 3 groups, got %d", len(groups))
	}
}

func TestGroupStore_GetGroup(t *testing.T) {
	store, _, cleanup := setupGroupStoreTestDB(t)
	defer cleanup()
	ctx := context.Background()

	id, err := store.CreateGroup(ctx, "get-group", "test description")
	if err != nil {
		t.Fatalf("CreateGroup failed: %v", err)
	}

	group, err := store.GetGroup(ctx, int(id))
	if err != nil {
		t.Fatalf("GetGroup failed: %v", err)
	}
	if group.Name != "get-group" {
		t.Errorf("expected name %q, got %q", "get-group", group.Name)
	}
	if group.Description != "test description" {
		t.Errorf("expected description %q, got %q", "test description", group.Description)
	}
}

func TestGroupStore_UpdateGroup(t *testing.T) {
	store, _, cleanup := setupGroupStoreTestDB(t)
	defer cleanup()
	ctx := context.Background()

	id, err := store.CreateGroup(ctx, "original", "original desc")
	if err != nil {
		t.Fatalf("CreateGroup failed: %v", err)
	}

	err = store.UpdateGroup(ctx, int(id), "updated", "updated desc")
	if err != nil {
		t.Fatalf("UpdateGroup failed: %v", err)
	}

	group, err := store.GetGroup(ctx, int(id))
	if err != nil {
		t.Fatalf("GetGroup failed: %v", err)
	}
	if group.Name != "updated" {
		t.Errorf("expected name %q, got %q", "updated", group.Name)
	}
	if group.Description != "updated desc" {
		t.Errorf("expected description %q, got %q", "updated desc", group.Description)
	}
}

func TestGroupStore_UpdateGroup_NotFound(t *testing.T) {
	store, _, cleanup := setupGroupStoreTestDB(t)
	defer cleanup()
	ctx := context.Background()

	err := store.UpdateGroup(ctx, 99999, "name", "desc")
	if err == nil {
		t.Error("expected error for updating non-existent group, got nil")
	}
	if err != ErrGroupNotFound {
		t.Errorf("expected ErrGroupNotFound, got %v", err)
	}
}

func TestGroupStore_SoftDeleteGroup(t *testing.T) {
	store, _, cleanup := setupGroupStoreTestDB(t)
	defer cleanup()
	ctx := context.Background()

	id, err := store.CreateGroup(ctx, "to-delete", "description")
	if err != nil {
		t.Fatalf("CreateGroup failed: %v", err)
	}

	err = store.SoftDeleteGroup(ctx, int(id))
	if err != nil {
		t.Fatalf("SoftDeleteGroup failed: %v", err)
	}

	// Soft-deleted group should not be returned by GetGroup (filters is_pending_delete=0)
	_, err = store.GetGroup(ctx, int(id))
	if err == nil {
		t.Error("expected error for soft-deleted group, got nil")
	}
}

func TestGroupStore_SoftDeleteGroup_NotFound(t *testing.T) {
	store, _, cleanup := setupGroupStoreTestDB(t)
	defer cleanup()
	ctx := context.Background()

	err := store.SoftDeleteGroup(ctx, 99999)
	if err == nil {
		t.Error("expected error for deleting non-existent group, got nil")
	}
	if err != ErrGroupNotFound {
		t.Errorf("expected ErrGroupNotFound, got %v", err)
	}
}

func TestGroupStore_AddAndDeleteGroupMember(t *testing.T) {
	store, dbConn, cleanup := setupGroupStoreTestDB(t)
	defer cleanup()
	ctx := context.Background()

	// Create a peer
	peerResult, err := dbConn.ExecContext(ctx,
		"INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, is_manual) VALUES (?, ?, ?, ?, 1)",
		"testpeer", "10.0.0.1", "agent-key", "hmac-key")
	if err != nil {
		t.Fatalf("insert peer failed: %v", err)
	}
	peerID, _ := peerResult.LastInsertId()

	groupID, err := store.CreateGroup(ctx, "member-group", "")
	if err != nil {
		t.Fatalf("CreateGroup failed: %v", err)
	}

	// Add member
	memberID, err := store.AddGroupMember(ctx, int(groupID), int(peerID))
	if err != nil {
		t.Fatalf("AddGroupMember failed: %v", err)
	}
	if memberID == 0 {
		t.Error("expected non-zero member ID")
	}

	// List members
	members, err := store.ListGroupMembers(ctx, int(groupID))
	if err != nil {
		t.Fatalf("ListGroupMembers failed: %v", err)
	}
	if len(members) != 1 {
		t.Errorf("expected 1 member, got %d", len(members))
	}
	if members[0].Hostname != "testpeer" {
		t.Errorf("expected hostname %q, got %q", "testpeer", members[0].Hostname)
	}

	// Delete member
	err = store.DeleteGroupMember(ctx, int(groupID), int(peerID))
	if err != nil {
		t.Fatalf("DeleteGroupMember failed: %v", err)
	}

	members, err = store.ListGroupMembers(ctx, int(groupID))
	if err != nil {
		t.Fatalf("ListGroupMembers failed: %v", err)
	}
	if len(members) != 0 {
		t.Errorf("expected 0 members after delete, got %d", len(members))
	}
}

func TestGroupStore_CheckDeleteConstraints_NoPolicies(t *testing.T) {
	store, _, cleanup := setupGroupStoreTestDB(t)
	defer cleanup()
	ctx := context.Background()

	id, err := store.CreateGroup(ctx, "free-group", "")
	if err != nil {
		t.Fatalf("CreateGroup failed: %v", err)
	}

	err = store.CheckDeleteConstraints(ctx, int(id))
	if err != nil {
		t.Errorf("expected no constraint error for group with no policies, got %v", err)
	}
}

func TestGroupStore_GetGroupSystemStatus(t *testing.T) {
	store, _, cleanup := setupGroupStoreTestDB(t)
	defer cleanup()
	ctx := context.Background()

	id, err := store.CreateGroup(ctx, "normal-group", "")
	if err != nil {
		t.Fatalf("CreateGroup failed: %v", err)
	}

	isSystem, err := store.GetGroupSystemStatus(ctx, int(id))
	if err != nil {
		t.Fatalf("GetGroupSystemStatus failed: %v", err)
	}
	if isSystem {
		t.Error("expected is_system=false for regular group")
	}
}
