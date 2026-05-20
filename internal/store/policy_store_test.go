package store

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"

	"runic/internal/db"
	"runic/internal/models"

	_ "github.com/mattn/go-sqlite3"
)

func setupPolicyStoreTestDB(t *testing.T) (*PolicyStore, *sql.DB, func()) {
	t.Helper()
	f, err := os.CreateTemp("", "runic-policy-store-test-*.db")
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

	store := NewPolicyStore(db.New(database))
	cleanup := func() {
		database.Close()
		os.Remove(dbPath)
	}
	return store, database, cleanup
}

func insertPolicyDependencies(t *testing.T, dbConn *sql.DB) (groupID, peerID, serviceID int) {
	t.Helper()
	ctx := context.Background()

	// Insert service
	svcResult, err := dbConn.ExecContext(ctx,
		"INSERT INTO services (name, ports, protocol) VALUES (?, ?, ?)",
		"test-svc", "80,443", "tcp")
	if err != nil {
		t.Fatalf("insert service: %v", err)
	}
	sid, _ := svcResult.LastInsertId()
	serviceID = int(sid)

	// Insert group
	grpResult, err := dbConn.ExecContext(ctx,
		"INSERT INTO groups (name) VALUES (?)", "test-group")
	if err != nil {
		t.Fatalf("insert group: %v", err)
	}
	gid, _ := grpResult.LastInsertId()
	groupID = int(gid)

	// Insert peer
	peerResult, err := dbConn.ExecContext(ctx,
		"INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, is_manual) VALUES (?, ?, ?, ?, 1)",
		"testpeer", "10.0.0.1", "agent-key", "hmac-key")
	if err != nil {
		t.Fatalf("insert peer: %v", err)
	}
	pid, _ := peerResult.LastInsertId()
	peerID = int(pid)

	return groupID, peerID, serviceID
}

func TestPolicyStore_CreatePolicy(t *testing.T) {
	store, dbConn, cleanup := setupPolicyStoreTestDB(t)
	defer cleanup()
	ctx := context.Background()

	groupID, peerID, serviceID := insertPolicyDependencies(t, dbConn)

	policy := &models.PolicyRow{
		Name:        "test-policy",
		Description: "a test policy",
		SourceID:    groupID,
		SourceType:  "group",
		ServiceID:   serviceID,
		TargetID:    peerID,
		TargetType:  "peer",
		Action:      "ACCEPT",
		Priority:    100,
		Enabled:     true,
		TargetScope: "both",
		Direction:   "both",
	}

	id, err := store.CreatePolicy(ctx, policy)
	if err != nil {
		t.Fatalf("CreatePolicy failed: %v", err)
	}
	if id == 0 {
		t.Error("expected non-zero policy ID")
	}
}

func TestPolicyStore_GetPolicy(t *testing.T) {
	store, dbConn, cleanup := setupPolicyStoreTestDB(t)
	defer cleanup()
	ctx := context.Background()

	groupID, peerID, serviceID := insertPolicyDependencies(t, dbConn)

	policy := &models.PolicyRow{
		Name:        "get-policy",
		SourceID:    groupID,
		SourceType:  "group",
		ServiceID:   serviceID,
		TargetID:    peerID,
		TargetType:  "peer",
		Action:      "DROP",
		Priority:    200,
		Enabled:     true,
		TargetScope: "both",
		Direction:   "forward",
	}
	id, err := store.CreatePolicy(ctx, policy)
	if err != nil {
		t.Fatalf("CreatePolicy failed: %v", err)
	}

	got, err := store.GetPolicy(ctx, int(id))
	if err != nil {
		t.Fatalf("GetPolicy failed: %v", err)
	}
	if got.Name != "get-policy" {
		t.Errorf("expected name %q, got %q", "get-policy", got.Name)
	}
	if got.Action != "DROP" {
		t.Errorf("expected action %q, got %q", "DROP", got.Action)
	}
	if got.Priority != 200 {
		t.Errorf("expected priority 200, got %d", got.Priority)
	}
}

func TestPolicyStore_GetPolicy_NotFound(t *testing.T) {
	store, _, cleanup := setupPolicyStoreTestDB(t)
	defer cleanup()
	ctx := context.Background()

	_, err := store.GetPolicy(ctx, 99999)
	if err == nil {
		t.Error("expected error for non-existent policy, got nil")
	}
}

func TestPolicyStore_ListPolicies(t *testing.T) {
	store, dbConn, cleanup := setupPolicyStoreTestDB(t)
	defer cleanup()
	ctx := context.Background()

	groupID, peerID, serviceID := insertPolicyDependencies(t, dbConn)

	// Initially empty
	policies, err := store.ListPolicies(ctx)
	if err != nil {
		t.Fatalf("ListPolicies failed: %v", err)
	}
	if len(policies) != 0 {
		t.Errorf("expected 0 policies, got %d", len(policies))
	}

	// Create policies
	for i := 0; i < 3; i++ {
		policy := &models.PolicyRow{
			Name:        fmt.Sprintf("policy-%d", i),
			SourceID:    groupID,
			SourceType:  "group",
			ServiceID:   serviceID,
			TargetID:    peerID,
			TargetType:  "peer",
			Action:      "ACCEPT",
			Priority:    (i + 1) * 100,
			Enabled:     true,
			TargetScope: "both",
			Direction:   "both",
		}
		if _, err := store.CreatePolicy(ctx, policy); err != nil {
			t.Fatalf("CreatePolicy %d failed: %v", i, err)
		}
	}

	policies, err = store.ListPolicies(ctx)
	if err != nil {
		t.Fatalf("ListPolicies failed: %v", err)
	}
	if len(policies) != 3 {
		t.Errorf("expected 3 policies, got %d", len(policies))
	}

	// Verify sorted by priority ASC
	if policies[0].Priority > policies[1].Priority {
		t.Errorf("policies not sorted by priority ASC: %d > %d", policies[0].Priority, policies[1].Priority)
	}
}

func TestPolicyStore_UpdatePolicy(t *testing.T) {
	store, dbConn, cleanup := setupPolicyStoreTestDB(t)
	defer cleanup()
	ctx := context.Background()

	groupID, peerID, serviceID := insertPolicyDependencies(t, dbConn)

	policy := &models.PolicyRow{
		Name:        "update-policy",
		SourceID:    groupID,
		SourceType:  "group",
		ServiceID:   serviceID,
		TargetID:    peerID,
		TargetType:  "peer",
		Action:      "ACCEPT",
		Priority:    100,
		Enabled:     true,
		TargetScope: "both",
		Direction:   "both",
	}
	id, err := store.CreatePolicy(ctx, policy)
	if err != nil {
		t.Fatalf("CreatePolicy failed: %v", err)
	}

	policy.ID = int(id)
	policy.Name = "updated-policy"
	policy.Action = "DROP"
	policy.Enabled = false

	err = store.UpdatePolicy(ctx, policy)
	if err != nil {
		t.Fatalf("UpdatePolicy failed: %v", err)
	}

	got, err := store.GetPolicy(ctx, int(id))
	if err != nil {
		t.Fatalf("GetPolicy failed: %v", err)
	}
	if got.Name != "updated-policy" {
		t.Errorf("expected name %q, got %q", "updated-policy", got.Name)
	}
	if got.Action != "DROP" {
		t.Errorf("expected action DROP, got %q", got.Action)
	}
	if got.Enabled != false {
		t.Error("expected enabled=false after update")
	}
}

func TestPolicyStore_UpdatePolicy_NotFound(t *testing.T) {
	store, _, cleanup := setupPolicyStoreTestDB(t)
	defer cleanup()
	ctx := context.Background()

	policy := &models.PolicyRow{ID: 99999, Name: "ghost"}

	err := store.UpdatePolicy(ctx, policy)
	if err == nil {
		t.Error("expected error for updating non-existent policy, got nil")
	}
	if err != ErrPolicyNotFound {
		t.Errorf("expected ErrPolicyNotFound, got %v", err)
	}
}

func TestPolicyStore_PatchPolicyEnabled(t *testing.T) {
	store, dbConn, cleanup := setupPolicyStoreTestDB(t)
	defer cleanup()
	ctx := context.Background()

	groupID, peerID, serviceID := insertPolicyDependencies(t, dbConn)

	policy := &models.PolicyRow{
		Name:        "patch-policy",
		SourceID:    groupID,
		SourceType:  "group",
		ServiceID:   serviceID,
		TargetID:    peerID,
		TargetType:  "peer",
		Action:      "ACCEPT",
		Priority:    100,
		Enabled:     true,
		TargetScope: "both",
		Direction:   "both",
	}
	id, err := store.CreatePolicy(ctx, policy)
	if err != nil {
		t.Fatalf("CreatePolicy failed: %v", err)
	}

	err = store.PatchPolicyEnabled(ctx, int(id), false)
	if err != nil {
		t.Fatalf("PatchPolicyEnabled failed: %v", err)
	}

	got, err := store.GetPolicy(ctx, int(id))
	if err != nil {
		t.Fatalf("GetPolicy failed: %v", err)
	}
	if got.Enabled {
		t.Error("expected enabled=false after patch")
	}
}

func TestPolicyStore_SoftDeletePolicy(t *testing.T) {
	store, dbConn, cleanup := setupPolicyStoreTestDB(t)
	defer cleanup()
	ctx := context.Background()

	groupID, peerID, serviceID := insertPolicyDependencies(t, dbConn)

	policy := &models.PolicyRow{
		Name:        "delete-policy",
		SourceID:    groupID,
		SourceType:  "group",
		ServiceID:   serviceID,
		TargetID:    peerID,
		TargetType:  "peer",
		Action:      "ACCEPT",
		Priority:    100,
		Enabled:     true,
		TargetScope: "both",
		Direction:   "both",
	}
	id, err := store.CreatePolicy(ctx, policy)
	if err != nil {
		t.Fatalf("CreatePolicy failed: %v", err)
	}

	err = store.SoftDeletePolicy(ctx, int(id))
	if err != nil {
		t.Fatalf("SoftDeletePolicy failed: %v", err)
	}

	// Soft-deleted policy should not be returned by GetPolicy
	_, err = store.GetPolicy(ctx, int(id))
	if err == nil {
		t.Error("expected error for soft-deleted policy, got nil")
	}
}

func TestPolicyStore_SoftDeletePolicy_NotFound(t *testing.T) {
	store, _, cleanup := setupPolicyStoreTestDB(t)
	defer cleanup()
	ctx := context.Background()

	err := store.SoftDeletePolicy(ctx, 99999)
	if err == nil {
		t.Error("expected error for deleting non-existent policy, got nil")
	}
	if err != ErrPolicyNotFound {
		t.Errorf("expected ErrPolicyNotFound, got %v", err)
	}
}

func TestPolicyStore_GetPolicyName(t *testing.T) {
	store, dbConn, cleanup := setupPolicyStoreTestDB(t)
	defer cleanup()
	ctx := context.Background()

	groupID, peerID, serviceID := insertPolicyDependencies(t, dbConn)

	policy := &models.PolicyRow{
		Name:        "named-policy",
		SourceID:    groupID,
		SourceType:  "group",
		ServiceID:   serviceID,
		TargetID:    peerID,
		TargetType:  "peer",
		Action:      "ACCEPT",
		Priority:    100,
		Enabled:     true,
		TargetScope: "both",
		Direction:   "both",
	}
	id, err := store.CreatePolicy(ctx, policy)
	if err != nil {
		t.Fatalf("CreatePolicy failed: %v", err)
	}

	name, err := store.GetPolicyName(ctx, int(id))
	if err != nil {
		t.Fatalf("GetPolicyName failed: %v", err)
	}
	if name != "named-policy" {
		t.Errorf("expected name %q, got %q", "named-policy", name)
	}
}

func TestPolicyStore_CheckDeleteConstraints(t *testing.T) {
	store, _, cleanup := setupPolicyStoreTestDB(t)
	defer cleanup()
	ctx := context.Background()

	// Policies have no foreign-key constraints — always returns nil
	err := store.CheckDeleteConstraints(ctx, 1)
	if err != nil {
		t.Errorf("expected nil for policy delete constraints, got %v", err)
	}
}

func TestPolicyStore_ListSpecialTargets(t *testing.T) {
	store, _, cleanup := setupPolicyStoreTestDB(t)
	defer cleanup()
	ctx := context.Background()

	targets, err := store.ListSpecialTargets(ctx)
	if err != nil {
		t.Fatalf("ListSpecialTargets failed: %v", err)
	}
	// The schema seeds special targets, so we expect at least 1
	if len(targets) == 0 {
		t.Error("expected at least 1 special target from schema seeds")
	}
}
