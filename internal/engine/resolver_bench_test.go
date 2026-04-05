package engine

import (
	"context"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

// BenchmarkResolveEntityPeer benchmarks resolving a peer entity to CIDR.
func BenchmarkResolveEntityPeer(b *testing.B) {
	database, cleanup := setupBenchmarkDB(b)
	defer cleanup()

	// Insert test peers (with required NOT NULL fields)
	database.Exec("INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)", "test-peer", "192.168.1.100", "key1", "hmac1")
	database.Exec("INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)", "test-peer-cidr", "192.168.2.0/24", "key2", "hmac2")

	resolver := &Resolver{db: database}
	ctx := context.Background()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := resolver.ResolveEntity(ctx, "peer", 1)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkResolveEntityGroup benchmarks resolving a group with multiple peers.
func BenchmarkResolveEntityGroup(b *testing.B) {
	database, cleanup := setupBenchmarkDB(b)
	defer cleanup()

	// Create a group
	database.Exec("INSERT INTO groups (name) VALUES (?)", "test-group")

	// Add 50 peers to the group
	for i := 1; i <= 50; i++ {
		database.Exec("INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)", "peer-"+string(rune('a'+i-1)), "10.0."+string(rune('0'+i/10))+"."+string(rune('0'+i%10)), "key-"+string(rune('a'+i-1)), "hmac-"+string(rune('a'+i-1)))
		database.Exec("INSERT INTO group_members (group_id, peer_id) VALUES (1, ?)", i)
	}

	resolver := &Resolver{db: database}
	ctx := context.Background()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := resolver.ResolveEntity(ctx, "group", 1)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkResolveEntityGroupWithCIDR benchmarks resolving a group with CIDR peers.
func BenchmarkResolveEntityGroupWithCIDR(b *testing.B) {
	database, cleanup := setupBenchmarkDB(b)
	defer cleanup()

	// Create a group with CIDR peers (simulates container networks)
	database.Exec("INSERT INTO groups (name) VALUES (?)", "cidr-group")

	// Add 20 CIDR peers
	cidrs := []string{
		"172.16.0.0/24", "172.16.1.0/24", "172.16.2.0/24", "172.16.3.0/24",
		"172.17.0.0/24", "172.17.1.0/24", "172.17.2.0/24", "172.17.3.0/24",
		"10.8.0.0/24", "10.8.1.0/24", "10.8.2.0/24", "10.8.3.0/24",
		"192.168.100.0/24", "192.168.101.0/24", "192.168.102.0/24", "192.168.103.0/24",
		"172.20.0.0/24", "172.20.1.0/24", "172.20.2.0/24", "172.20.3.0/24",
	}
	for i, cidr := range cidrs {
		database.Exec("INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)", "cidr-peer-"+string(rune('a'+i)), cidr, "key-"+string(rune('a'+i)), "hmac-"+string(rune('a'+i)))
		database.Exec("INSERT INTO group_members (group_id, peer_id) VALUES (1, ?)", i+1)
	}

	resolver := &Resolver{db: database}
	ctx := context.Background()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := resolver.ResolveEntity(ctx, "group", 1)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkResolveSpecialTarget benchmarks resolving various special targets.
func BenchmarkResolveSpecialTarget(b *testing.B) {
	database, cleanup := setupBenchmarkDB(b)
	defer cleanup()

	// Insert test peer for subnet_broadcast
	database.Exec("INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)", "test-peer", "192.168.1.100", "key1", "hmac1")

	// Add some peers for __all_peers__
	for i := 1; i <= 10; i++ {
		database.Exec("INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)", "peer-"+string(rune('a'+i-1)), "10.0.0."+string(rune('0'+i)), "key-"+string(rune('a'+i-1)), "hmac-"+string(rune('a'+i-1)))
	}

	resolver := &Resolver{db: database}
	ctx := context.Background()

	// Benchmark each special target
	specials := []struct {
		name      string
		specialID int
		peerIP    string
	}{
		{"subnet_broadcast", 1, "192.168.1.100"},
		{"limited_broadcast", 2, ""},
		{"all_hosts", 3, ""},
		{"mdns", 4, ""},
		{"loopback", 5, ""},
		{"any_ip", 6, ""},
		{"all_peers", 7, ""},
	}

	for _, tc := range specials {
		b.Run(tc.name, func(b *testing.B) {
			peerIP := tc.peerIP
			if peerIP == "" {
				peerIP = "192.168.1.100" // default for ones that don't need it
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := resolver.ResolveSpecialTarget(ctx, tc.specialID, peerIP)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkExpandPorts benchmarks port expansion with various port strings.
func BenchmarkExpandPorts(b *testing.B) {
	// Test cases covering typical port string formats
	cases := []struct {
		name     string
		dstPorts string
		srcPorts string
		protocol string
	}{
		{"single_port", "80", "", "tcp"},
		{"multiport", "80,443,8080,8443", "", "tcp"},
		{"port_range", "1:1024", "", "tcp"},
		{"with_source_ports", "80", "1024:65535", "tcp"},
		{"both_multiport", "80,443", "1024:65535", "tcp"},
		{"udp_single", "53", "", "udp"},
		{"tcp_both_protocol", "80,443", "1024:65535", "both"},
		{"many_ports", "80,443,8080,8443,9000,9090,3000,4000", "", "tcp"},
	}

	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := ExpandPorts(tc.dstPorts, tc.srcPorts, tc.protocol)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkExpandPortsSequential runs port expansion sequentially (non-parallel).
func BenchmarkExpandPortsSequential(b *testing.B) {
	dstPorts := "80,443,8080,8443,9000,9090,3000,4000,5000,6000"
	protocol := "tcp"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ExpandPorts(dstPorts, "", protocol)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkSanitizeForIpset benchmarks the ipset name sanitization function.
func BenchmarkSanitizeForIpset(b *testing.B) {
	names := []string{
		"Web Servers",
		"DB-Clusters-Prod",
		"API_Gateway_v2",
		"k8s-workers-01",
		"very_long_group_name_that_exceeds_normal_limits_for_ipset_compatibility",
		"group-with-dashes-and_underscores",
		"MixedCaseGROUP123",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, name := range names {
			_ = sanitizeForIpset(name)
		}
	}
}

// BenchmarkValidatePorts benchmarks port validation.
func BenchmarkValidatePorts(b *testing.B) {
	ports := []string{
		"80",
		"80,443",
		"80,443,8080,8443",
		"1:65535",
		"1,2,3,4,5,6,7,8,9,10",
		"1024:65535",
		"",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, port := range ports {
			_ = ValidatePorts(port)
		}
	}
}
