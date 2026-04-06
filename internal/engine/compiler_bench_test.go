package engine

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"

	"runic/internal/db"

	_ "github.com/mattn/go-sqlite3"
)

// BenchmarkCompileSmall tests compilation with ~5 peers and ~5 policies.
// This represents a small-scale deployment typical of a small office or home network.
func BenchmarkCompileSmall(b *testing.B) {
	database, cleanup := setupBenchmarkDB(b)
	defer cleanup()

	// Create 5 peers (with required NOT NULL fields)
	for i := 1; i <= 5; i++ {
		_, err := database.Exec("INSERT INTO peers (hostname, ip_address, has_docker, agent_key, hmac_key) VALUES (?, ?, ?, ?, ?)",
			"peer-"+string(rune('a'+i-1)), "10.0."+string(rune('0'+i))+".10/32", false, "key-"+string(rune('a'+i-1)), "hmac-"+string(rune('a'+i-1)))
		if err != nil {
			b.Fatal(err)
		}
	}

	// Create a group with 3 peers
	database.Exec("INSERT INTO groups (name) VALUES (?)", "test-group")
	for i := 1; i <= 3; i++ {
		database.Exec("INSERT INTO group_members (group_id, peer_id) VALUES (1, ?)", i)
	}

	// Create a service
	database.Exec("INSERT INTO services (name, ports, protocol) VALUES (?, ?, ?)", "http", "80,443", "tcp")

	// Create 5 policies (mix of peer-to-peer and group-to-peer)
	policies := []struct {
		sourceType string
		sourceID   int
		targetType string
		targetID   int
		action     string
	}{
		{"peer", 1, "peer", 2, "ACCEPT"},
		{"peer", 2, "peer", 3, "ACCEPT"},
		{"peer", 3, "group", 1, "ACCEPT"},
		{"group", 1, "peer", 4, "ACCEPT"},
		{"peer", 5, "peer", 1, "DROP"},
	}
	for i, p := range policies {
		_, err := database.Exec(`INSERT INTO policies (name, source_type, source_id, target_type, target_id, service_id, action, enabled, direction, target_scope)
			VALUES (?, ?, ?, ?, ?, 1, ?, 1, 'both', 'both')`,
			"policy-"+string(rune('a'+i)), p.sourceType, p.sourceID, p.targetType, p.targetID, p.action)
		if err != nil {
			b.Fatal(err)
		}
	}

	compiler := NewCompiler(database)
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := compiler.Compile(ctx, 1)
		if err != nil {
			b.Fatalf("Compile failed: %v", err)
		}
	}
}

// BenchmarkCompileLarge tests compilation with ~50 peers and ~20 policies.
// This represents a medium-scale enterprise deployment.
func BenchmarkCompileLarge(b *testing.B) {
	database, cleanup := setupBenchmarkDB(b)
	defer cleanup()

	// Create 50 peers
	for i := 1; i <= 50; i++ {
		hostname := fmt.Sprintf("peer-%d", i)
		ipAddr := fmt.Sprintf("10.0.%d.%d/32", i/10, i%10)
		_, err := database.Exec("INSERT INTO peers (hostname, ip_address, has_docker, agent_key, hmac_key) VALUES (?, ?, ?, ?, ?)",
			hostname, ipAddr, i%3 == 0, fmt.Sprintf("key-%d", i), fmt.Sprintf("hmac-%d", i))
		if err != nil {
			b.Fatal(err)
		}
	}

	// Create 5 groups with 10 peers each
	for g := 1; g <= 5; g++ {
		database.Exec("INSERT INTO groups (name) VALUES (?)", "group-"+string(rune('a'+g-1)))
		for p := 1; p <= 10; p++ {
			peerID := (g-1)*10 + p
			database.Exec("INSERT INTO group_members (group_id, peer_id) VALUES (?, ?)", g, peerID)
		}
	}

	// Create 3 services
	services := []struct {
		name  string
		ports string
		proto string
	}{
		{"http", "80,443", "tcp"},
		{"ssh", "22", "tcp"},
		{"dns", "53", "udp"},
	}
	for i, s := range services {
		database.Exec("INSERT INTO services (name, ports, protocol) VALUES (?, ?, ?)", s.name, s.ports, s.proto)
		_ = i // use services variable
	}

	// Create 20 policies: mix of peer->peer, peer->group, group->peer, group->group
	policies := []struct {
		sourceType string
		sourceID   int
		targetType string
		targetID   int
		action     string
		serviceID  int
	}{
		{"peer", 1, "peer", 2, "ACCEPT", 1},
		{"peer", 3, "peer", 4, "ACCEPT", 1},
		{"peer", 5, "group", 1, "ACCEPT", 1},
		{"group", 1, "peer", 6, "ACCEPT", 2},
		{"group", 2, "peer", 7, "ACCEPT", 1},
		{"peer", 8, "group", 3, "ACCEPT", 2},
		{"peer", 9, "peer", 10, "ACCEPT", 1},
		{"peer", 11, "peer", 12, "ACCEPT", 3},
		{"group", 1, "group", 2, "ACCEPT", 1},
		{"group", 3, "group", 4, "ACCEPT", 2},
		{"peer", 13, "peer", 14, "DROP", 1},
		{"peer", 15, "peer", 16, "DROP", 2},
		{"peer", 17, "group", 4, "DROP", 1},
		{"group", 4, "peer", 18, "DROP", 2},
		{"peer", 19, "peer", 20, "LOG_DROP", 1},
		{"peer", 21, "peer", 22, "ACCEPT", 1},
		{"peer", 23, "peer", 24, "ACCEPT", 2},
		{"peer", 25, "group", 5, "ACCEPT", 3},
		{"group", 5, "peer", 26, "ACCEPT", 1},
		{"peer", 27, "peer", 28, "ACCEPT", 1},
	}
	for i, p := range policies {
		_, err := database.Exec(`INSERT INTO policies (name, source_type, source_id, target_type, target_id, service_id, action, enabled, direction, target_scope)
			VALUES (?, ?, ?, ?, ?, ?, ?, 1, 'both', 'both')`,
			"policy-"+string(rune('a'+i)), p.sourceType, p.sourceID, p.targetType, p.targetID, p.serviceID, p.action)
		if err != nil {
			b.Fatal(err)
		}
	}

	compiler := NewCompiler(database)
	ctx := context.Background()

	// Benchmark compile for first peer (member of multiple groups)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := compiler.Compile(ctx, 1)
		if err != nil {
			b.Fatalf("Compile failed: %v", err)
		}
	}
}

// BenchmarkCompileAndStore benchmarks the full compile-and-store cycle.
func BenchmarkCompileAndStore(b *testing.B) {
	database, cleanup := setupBenchmarkDB(b)
	defer cleanup()

	// Create 10 peers
	for i := 1; i <= 10; i++ {
		hostname := fmt.Sprintf("peer-%s", string(rune('a'+i-1)))
		ipAddr := fmt.Sprintf("10.0.%d.10/32", i)
		_, err := database.Exec("INSERT INTO peers (hostname, ip_address, has_docker, agent_key, hmac_key) VALUES (?, ?, ?, ?, ?)",
			hostname, ipAddr, false, "key-"+string(rune('a'+i-1)), "test-key-"+string(rune('a'+i-1)))
		if err != nil {
			b.Fatal(err)
		}
	}

	// Create a group with 5 peers
	database.Exec("INSERT INTO groups (name) VALUES (?)", "test-group")
	for i := 1; i <= 5; i++ {
		database.Exec("INSERT INTO group_members (group_id, peer_id) VALUES (1, ?)", i)
	}

	// Create services
	database.Exec("INSERT INTO services (name, ports, protocol) VALUES (?, ?, ?)", "http", "80,443", "tcp")
	database.Exec("INSERT INTO services (name, ports, protocol) VALUES (?, ?, ?)", "ssh", "22", "tcp")

	// Create 5 policies
	policies := []struct {
		sourceType string
		sourceID   int
		targetType string
		targetID   int
		action     string
		serviceID  int
	}{
		{"peer", 1, "peer", 2, "ACCEPT", 1},
		{"peer", 2, "peer", 3, "ACCEPT", 1},
		{"peer", 3, "group", 1, "ACCEPT", 2},
		{"group", 1, "peer", 4, "ACCEPT", 1},
		{"peer", 5, "peer", 1, "DROP", 2},
	}
	for i, p := range policies {
		_, err := database.Exec(`INSERT INTO policies (name, source_type, source_id, target_type, target_id, service_id, action, enabled, direction, target_scope)
			VALUES (?, ?, ?, ?, ?, ?, ?, 1, 'both', 'both')`,
			"policy-"+string(rune('a'+i)), p.sourceType, p.sourceID, p.targetType, p.targetID, p.serviceID, p.action)
		if err != nil {
			b.Fatal(err)
		}
	}

	compiler := NewCompiler(database)
	ctx := context.Background()

	// Run once to create initial bundle, then benchmark subsequent compilations that will fail due to unique constraint
	// So we run only 1 iteration for this benchmark
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if i > 0 {
			// Clear previous bundles to avoid unique constraint
			database.Exec("DELETE FROM rule_bundles WHERE peer_id = 1")
		}
		_, err := compiler.CompileAndStore(ctx, 1)
		if err != nil {
			b.Fatalf("CompileAndStore failed: %v", err)
		}
	}
}

// setupBenchmarkDB creates a temporary test database for benchmarking.
func setupBenchmarkDB(b *testing.B) (*sql.DB, func()) {
	f, err := os.CreateTemp("", "runic-bench-*.db")
	if err != nil {
		b.Fatal(err)
	}
	dbPath := f.Name()
	f.Close()

	database, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		os.Remove(dbPath)
		b.Fatal(err)
	}

	if _, err := database.Exec(db.Schema()); err != nil {
		database.Close()
		os.Remove(dbPath)
		b.Fatal(err)
	}

	cleanup := func() {
		database.Close()
		os.Remove(dbPath)
	}
	return database, cleanup
}
