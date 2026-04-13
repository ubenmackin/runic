package db

import (
	"context"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func TestSeedSystemServices(t *testing.T) {
	db, cleanup := SetupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	// First call - creates services
	err := seedSystemServices(ctx, db)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Count system services
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM services WHERE is_system = 1").Scan(&count)
	if err != nil {
		t.Fatal(err)
	}
	if count == 0 {
		t.Error("expected system services to be created")
	}

	// Second call - should be idempotent
	err = seedSystemServices(ctx, db)
	if err != nil {
		t.Fatalf("unexpected error on second call: %v", err)
	}

	var count2 int
	db.QueryRow("SELECT COUNT(*) FROM services WHERE is_system = 1").Scan(&count2)
	if count != count2 {
		t.Errorf("idempotency failed: count changed from %d to %d", count, count2)
	}
}

func TestSeedSystemServices_SystemFlag(t *testing.T) {
	db, cleanup := SetupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	err := seedSystemServices(ctx, db)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify all seeded services have is_system = 1
	rows, err := db.Query("SELECT name, is_system FROM services")
	if err != nil {
		t.Fatalf("failed to query services: %v", err)
	}
	defer rows.Close()

	for rows.Next() {
		var name string
		var isSystem bool
		if err := rows.Scan(&name, &isSystem); err != nil {
			t.Fatalf("failed to scan row: %v", err)
		}
		if !isSystem {
			t.Errorf("service %s: expected is_system = true, got %v", name, isSystem)
		}
	}
}

func TestSeedSystemServices_NoConntrackFlag(t *testing.T) {
	db, cleanup := SetupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	err := seedSystemServices(ctx, db)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify no_conntrack flag is set correctly per service
	// Services that should have no_conntrack = 1: IGMP, Multicast, mDNS, Subnet Broadcast, Limited Broadcast, VRRP
	// Services that should have no_conntrack = 0: ICMP
	expectedNoConntrack := map[string]bool{
		"ICMP":              false,
		"IGMP":              true,
		"Multicast":         true,
		"mDNS":              true,
		"Subnet Broadcast":  true,
		"Limited Broadcast": true,
		"VRRP":              true,
	}

	for name, expected := range expectedNoConntrack {
		var noConntrack bool
		err := db.QueryRow("SELECT no_conntrack FROM services WHERE name = ?", name).Scan(&noConntrack)
		if err != nil {
			t.Fatalf("failed to query service %s: %v", name, err)
		}
		if noConntrack != expected {
			t.Errorf("service %s: expected no_conntrack = %v, got %v", name, expected, noConntrack)
		}
	}
}

func TestSeedSystemServices_ExistingServiceUpdate(t *testing.T) {
	db, cleanup := SetupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	// Insert an existing service with same name but is_system = 0
	_, err := db.Exec(`
		INSERT INTO services (name, ports, source_ports, protocol, description, is_system, no_conntrack)
		VALUES ('ICMP', '8', '', 'icmp', 'Existing ICMP service', 0, 0)
	`)
	if err != nil {
		t.Fatalf("failed to insert existing service: %v", err)
	}

	// Call seedSystemServices
	err = seedSystemServices(ctx, db)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify the existing service was updated to is_system = true
	var isSystem bool
	err = db.QueryRow("SELECT is_system FROM services WHERE name = 'ICMP'").Scan(&isSystem)
	if err != nil {
		t.Fatalf("failed to query service: %v", err)
	}
	if !isSystem {
		t.Errorf("expected is_system = true after update, got %v", isSystem)
	}

	// Verify no_conntrack was also updated to the correct value (0 for ICMP)
	var noConntrack bool
	err = db.QueryRow("SELECT no_conntrack FROM services WHERE name = 'ICMP'").Scan(&noConntrack)
	if err != nil {
		t.Fatalf("failed to query no_conntrack: %v", err)
	}
	if noConntrack != false {
		t.Errorf("expected no_conntrack = false for ICMP, got %v", noConntrack)
	}
}

func TestSeedSystemGroups(t *testing.T) {
	db, cleanup := SetupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	// First call - creates groups
	err := seedSystemGroups(ctx, db)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Count system groups
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM groups WHERE is_system = 1").Scan(&count)
	if err != nil {
		t.Fatal(err)
	}
	if count == 0 {
		t.Error("expected system groups to be created")
	}

	// Second call - should be idempotent
	err = seedSystemGroups(ctx, db)
	if err != nil {
		t.Fatalf("unexpected error on second call: %v", err)
	}

	var count2 int
	db.QueryRow("SELECT COUNT(*) FROM groups WHERE is_system = 1").Scan(&count2)
	if count != count2 {
		t.Errorf("idempotency failed: count changed from %d to %d", count, count2)
	}
}

func TestSeedSystemGroups_SystemFlag(t *testing.T) {
	db, cleanup := SetupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	err := seedSystemGroups(ctx, db)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify all seeded groups have is_system = 1
	rows, err := db.Query("SELECT name, is_system FROM groups")
	if err != nil {
		t.Fatalf("failed to query groups: %v", err)
	}
	defer rows.Close()

	for rows.Next() {
		var name string
		var isSystem bool
		if err := rows.Scan(&name, &isSystem); err != nil {
			t.Fatalf("failed to scan row: %v", err)
		}
		if !isSystem {
			t.Errorf("group %s: expected is_system = true, got %v", name, isSystem)
		}
	}
}

func TestSeedSystemGroups_ExistingGroupUpdate(t *testing.T) {
	db, cleanup := SetupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	// Insert an existing group with same name but is_system = 0
	_, err := db.Exec(`
		INSERT INTO groups (name, description, is_system)
		VALUES ('localhost', 'Existing localhost group', 0)
	`)
	if err != nil {
		t.Fatalf("failed to insert existing group: %v", err)
	}

	// Call seedSystemGroups
	err = seedSystemGroups(ctx, db)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify the existing group was updated to is_system = true
	var isSystem bool
	err = db.QueryRow("SELECT is_system FROM groups WHERE name = 'localhost'").Scan(&isSystem)
	if err != nil {
		t.Fatalf("failed to query group: %v", err)
	}
	if !isSystem {
		t.Errorf("expected is_system = true after update, got %v", isSystem)
	}
}

func TestSeedSystemServices_AllServicesCreated(t *testing.T) {
	db, cleanup := SetupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	err := seedSystemServices(ctx, db)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify all expected services are created
	expectedServices := []string{
		"ICMP",
		"IGMP",
		"Multicast",
		"mDNS",
		"Subnet Broadcast",
		"Limited Broadcast",
		"VRRP",
	}

	for _, name := range expectedServices {
		var exists int
		err := db.QueryRow("SELECT COUNT(*) FROM services WHERE name = ? AND is_system = 1", name).Scan(&exists)
		if err != nil {
			t.Fatalf("failed to query service %s: %v", name, err)
		}
		if exists != 1 {
			t.Errorf("expected system service %s to exist, but count = %d", name, exists)
		}
	}
}

func TestSeedSystemGroups_AllGroupsCreated(t *testing.T) {
	db, cleanup := SetupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	err := seedSystemGroups(ctx, db)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify the localhost group is created
	var exists int
	err = db.QueryRow("SELECT COUNT(*) FROM groups WHERE name = 'localhost' AND is_system = 1").Scan(&exists)
	if err != nil {
		t.Fatalf("failed to query localhost group: %v", err)
	}
	if exists != 1 {
		t.Errorf("expected system group 'localhost' to exist, but count = %d", exists)
	}
}
