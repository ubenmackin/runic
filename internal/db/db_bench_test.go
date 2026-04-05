package db

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

// BenchmarkGetPeer benchmarks fetching a single peer by ID.
func BenchmarkGetPeer(b *testing.B) {
	database, cleanup := setupBenchmarkDB(b)
	defer cleanup()

	// Insert test peer (with all required NOT NULL fields)
	database.Exec(`INSERT INTO peers (hostname, ip_address, os_type, arch, has_docker, agent_key, hmac_key, agent_token, agent_version, is_manual, bundle_version, status)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"test-peer", "192.168.1.100", "linux", "x86_64", true, "key123", "hmac123", "token123", "v1.0", 1, "v1", "online")

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := GetPeer(ctx, database, 1)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkListPeers benchmarks listing all peers.
func BenchmarkListPeers(b *testing.B) {
	database, cleanup := setupBenchmarkDB(b)
	defer cleanup()

	// Insert 100 peers (with unique hostnames and keys)
	for i := 1; i <= 100; i++ {
		database.Exec(`INSERT INTO peers (hostname, ip_address, os_type, arch, has_docker, agent_key, hmac_key, agent_token, agent_version, is_manual, bundle_version, status)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			fmt.Sprintf("peer-%d", i), fmt.Sprintf("10.0.0.%d", i), "linux", "x86_64", i%3 == 0, fmt.Sprintf("key-%d", i), fmt.Sprintf("hmac-%d", i), "token", "v1.0", 1, "v1", "online")
	}

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rows, err := database.QueryContext(ctx, "SELECT id, hostname, ip_address FROM peers")
		if err != nil {
			b.Fatal(err)
		}
		count := 0
		for rows.Next() {
			count++
		}
		rows.Close()
		if count != 100 {
			b.Fatalf("expected 100 peers, got %d", count)
		}
	}
}

// BenchmarkGetPolicy benchmarks fetching a single policy by ID.
func BenchmarkGetPolicy(b *testing.B) {
	database, cleanup := setupBenchmarkDB(b)
	defer cleanup()

	// Insert test service first
	database.Exec("INSERT INTO services (name, ports, protocol) VALUES (?, ?, ?)", "http", "80,443", "tcp")

	// Insert test policy
	database.Exec(`INSERT INTO policies (name, source_type, source_id, target_type, target_id, service_id, action, priority, enabled, direction, target_scope)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"test-policy", "peer", 1, "peer", 2, 1, "ACCEPT", 1, 1, "both", "both")

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		row := database.QueryRowContext(ctx, "SELECT id, name, source_type, source_id, target_type, target_id, service_id, action, priority, enabled, direction, target_scope FROM policies WHERE id = ?", 1)
		var id, sourceID, targetID, serviceID, priority int
		var name, sourceType, targetType, action, direction, targetScope string
		var enabled bool
		if err := row.Scan(&id, &name, &sourceType, &sourceID, &targetType, &targetID, &serviceID, &action, &priority, &enabled, &direction, &targetScope); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkListEnabledPolicies benchmarks listing policies for a peer.
func BenchmarkListEnabledPolicies(b *testing.B) {
	database, cleanup := setupBenchmarkDB(b)
	defer cleanup()

	// Insert 10 peers (with required NOT NULL fields)
	for i := 1; i <= 10; i++ {
		database.Exec("INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)", fmt.Sprintf("peer-%d", i), fmt.Sprintf("10.0.0.%d", i), fmt.Sprintf("key-%d", i), fmt.Sprintf("hmac-%d", i))
	}

	// Insert a group with 5 peers
	database.Exec("INSERT INTO groups (name) VALUES (?)", "test-group")
	for i := 1; i <= 5; i++ {
		database.Exec("INSERT INTO group_members (group_id, peer_id) VALUES (?, ?)", 1, i)
	}

	// Insert services
	database.Exec("INSERT INTO services (name, ports, protocol) VALUES (?, ?, ?)", "http", "80", "tcp")
	database.Exec("INSERT INTO services (name, ports, protocol) VALUES (?, ?, ?)", "ssh", "22", "tcp")

	// Insert 20 policies: direct peer targets and group targets
	policies := []struct {
		targetType string
		targetID   int
	}{
		{"peer", 1}, {"peer", 2}, {"peer", 3}, {"peer", 4}, {"peer", 5},
		{"peer", 6}, {"peer", 7}, {"peer", 8}, {"peer", 9}, {"peer", 10},
		{"group", 1}, {"group", 1}, {"group", 1}, {"group", 1}, {"group", 1},
		{"peer", 1}, {"peer", 2}, {"peer", 3}, {"peer", 4}, {"peer", 5},
	}
	for i, p := range policies {
		action := "ACCEPT"
		if i%3 == 0 {
			action = "DROP"
		}
		serviceID := 1
		if i%2 == 0 {
			serviceID = 2
		}
		database.Exec(`INSERT INTO policies (name, source_type, source_id, target_type, target_id, service_id, action, priority, enabled, direction, target_scope)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			"policy-"+string(rune('a'+i)), "peer", 1, p.targetType, p.targetID, serviceID, action, i+1, 1, "both", "both")
	}

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rows, err := database.QueryContext(ctx, `SELECT DISTINCT p.id, p.name, p.source_id, p.source_type, p.service_id, p.target_id, p.target_type, 
			p.action, p.priority, p.target_scope, COALESCE(p.direction, 'both')
		FROM policies p
		LEFT JOIN group_members gm ON p.target_type = 'group' AND p.target_id = gm.group_id
		WHERE p.enabled = 1 AND (
			(p.target_type = 'peer' AND p.target_id = ?) OR
			(p.target_type = 'group' AND gm.peer_id = ?)
		)
		ORDER BY p.priority ASC`, 1, 1)
		if err != nil {
			b.Fatal(err)
		}
		count := 0
		for rows.Next() {
			count++
		}
		rows.Close()
		if count == 0 {
			b.Fatal("expected policies, got none")
		}
	}
}

// BenchmarkGetGroup benchmarks fetching a group by ID.
func BenchmarkGetGroup(b *testing.B) {
	database, cleanup := setupBenchmarkDB(b)
	defer cleanup()

	// Insert test group
	database.Exec("INSERT INTO groups (name, description) VALUES (?, ?)", "test-group", "Test group description")

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := GetGroup(ctx, database, 1)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkListGroupMembers benchmarks listing group members.
func BenchmarkListGroupMembers(b *testing.B) {
	database, cleanup := setupBenchmarkDB(b)
	defer cleanup()

	// Insert test group
	database.Exec("INSERT INTO groups (name) VALUES (?)", "test-group")

	// Insert 50 peers and add to group
	for i := 1; i <= 50; i++ {
		database.Exec("INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)", fmt.Sprintf("peer-%d", i), fmt.Sprintf("10.0.0.%d", i), fmt.Sprintf("key-%d", i), fmt.Sprintf("hmac-%d", i))
		database.Exec("INSERT INTO group_members (group_id, peer_id) VALUES (?, ?)", 1, i)
	}

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ListGroupMembers(ctx, database, 1)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkGetService benchmarks fetching a service by ID.
func BenchmarkGetService(b *testing.B) {
	database, cleanup := setupBenchmarkDB(b)
	defer cleanup()

	// Insert test service
	database.Exec("INSERT INTO services (name, ports, source_ports, protocol) VALUES (?, ?, ?, ?)", "http", "80,443", "1024:65535", "tcp")

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := GetService(ctx, database, 1)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkResolveGroup benchmarks resolving a group to its peer IPs.
func BenchmarkResolveGroup(b *testing.B) {
	database, cleanup := setupBenchmarkDB(b)
	defer cleanup()

	// Insert test group
	database.Exec("INSERT INTO groups (name) VALUES (?)", "test-group")

	// Insert 50 peers and add to group
	for i := 1; i <= 50; i++ {
		database.Exec("INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)", fmt.Sprintf("peer-%d", i), fmt.Sprintf("10.0.0.%d", i), fmt.Sprintf("key-%d", i), fmt.Sprintf("hmac-%d", i))
		database.Exec("INSERT INTO group_members (group_id, peer_id) VALUES (?, ?)", 1, i)
	}

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rows, err := database.QueryContext(ctx, `
			SELECT p.ip_address
			FROM group_members gm
			JOIN peers p ON gm.peer_id = p.id
			WHERE gm.group_id = ?`, 1)
		if err != nil {
			b.Fatal(err)
		}
		count := 0
		var ip string
		for rows.Next() {
			if err := rows.Scan(&ip); err != nil {
				rows.Close()
				b.Fatal(err)
			}
			count++
		}
		rows.Close()
		if count != 50 {
			b.Fatalf("expected 50 members, got %d", count)
		}
	}
}

// BenchmarkGetBundle benchmarks fetching the latest bundle for a peer.
func BenchmarkGetBundle(b *testing.B) {
	database, cleanup := setupBenchmarkDB(b)
	defer cleanup()

	// Insert test peer (with required NOT NULL fields)
	database.Exec("INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)", "test-peer", "192.168.1.100", "key1", "test-key")

	// Insert multiple bundles with unique versions (version is unique per peer)
	for i := 1; i <= 10; i++ {
		database.Exec("INSERT INTO rule_bundles (peer_id, version, version_number, rules_content, hmac) VALUES (?, ?, ?, ?, ?)",
			1, fmt.Sprintf("v1.%d", i), i, "*filter\n:INPUT DROP\nCOMMIT\n", fmt.Sprintf("sig-%d", i))
	}

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		row := database.QueryRowContext(ctx, "SELECT id, version, version_number, rules_content, hmac, created_at FROM rule_bundles WHERE peer_id = ? ORDER BY version_number DESC LIMIT 1", 1)
		var id, versionNumber int
		var version, rulesContent, hmac string
		var createdAt interface{}
		if err := row.Scan(&id, &version, &versionNumber, &rulesContent, &hmac, &createdAt); err != nil {
			b.Fatal(err)
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

	if _, err := database.Exec(Schema()); err != nil {
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
