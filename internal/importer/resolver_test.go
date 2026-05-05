package importer

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	_ "github.com/mattn/go-sqlite3"

	"runic/internal/iptparse"
	"runic/internal/testutil"
)

// insertTestPeer inserts a test peer and returns its ID.
func insertTestPeer(t *testing.T, database *sql.DB, hostname, ip string, hasDocker bool) int64 {
	t.Helper()
	result, err := database.Exec(
		`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, has_docker) VALUES (?, ?, ?, ?, ?)`,
		hostname, ip, "key-"+hostname, "test-hmac-key", hasDocker)
	if err != nil {
		t.Fatalf("insert peer: %v", err)
	}
	id, _ := result.LastInsertId()
	return id
}

// insertSystemService inserts a system service and returns its ID.
func insertSystemService(t *testing.T, database *sql.DB, name, ports, protocol, description string, noConntrack bool) int64 {
	t.Helper()
	nc := 0
	if noConntrack {
		nc = 1
	}
	result, err := database.Exec(
		`INSERT INTO services (name, ports, protocol, description, is_system, no_conntrack) VALUES (?, ?, ?, ?, 1, ?)`,
		name, ports, protocol, description, nc)
	if err != nil {
		t.Fatalf("insert system service %s: %v", name, err)
	}
	id, _ := result.LastInsertId()
	return id
}

// insertTestService inserts a regular (non-system) service and returns its ID.
func insertTestService(t *testing.T, database *sql.DB, name, ports, protocol string) int64 {
	t.Helper()
	result, err := database.Exec(
		`INSERT INTO services (name, ports, protocol) VALUES (?, ?, ?)`,
		name, ports, protocol)
	if err != nil {
		t.Fatalf("insert service %s: %v", name, err)
	}
	id, _ := result.LastInsertId()
	return id
}

// insertTestManualPeer inserts a test peer with is_manual=1 and returns its ID.
func insertTestManualPeer(t *testing.T, database *sql.DB, hostname, ip string) int64 {
	t.Helper()
	result, err := database.Exec(
		`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, is_manual) VALUES (?, ?, ?, ?, 1)`,
		hostname, ip, "manual-"+hostname, "test-hmac-key")
	if err != nil {
		t.Fatalf("insert manual peer: %v", err)
	}
	id, _ := result.LastInsertId()
	return id
}

// --- isBroadcastDest tests ---

func TestIsBroadcastDest_LimitedBroadcast(t *testing.T) {
	rule := iptparse.ParsedRule{DestIP: "255.255.255.255"}
	if isBroadcastDest(&rule, "INPUT", nil) != specialTargetLimitedBroadcast {
		t.Errorf("expected isBroadcastDest to return specialTargetLimitedBroadcast (%d) for 255.255.255.255 on INPUT chain", specialTargetLimitedBroadcast)
	}
}

func TestIsBroadcastDest_OutputChain(t *testing.T) {
	rule := iptparse.ParsedRule{DestIP: "255.255.255.255"}
	if isBroadcastDest(&rule, "OUTPUT", nil) != 0 {
		t.Error("expected isBroadcastDest to return 0 for OUTPUT chain")
	}
}

func TestIsBroadcastDest_EmptyDestIP(t *testing.T) {
	rule := iptparse.ParsedRule{DestIP: ""}
	if isBroadcastDest(&rule, "INPUT", nil) != 0 {
		t.Error("expected isBroadcastDest to return 0 for empty DestIP on INPUT chain")
	}
}

func TestIsBroadcastDest_NormalIP(t *testing.T) {
	rule := iptparse.ParsedRule{DestIP: "192.168.1.1"}
	if isBroadcastDest(&rule, "INPUT", []string{"10.100.5.36"}) != 0 {
		t.Error("expected isBroadcastDest to return 0 for normal IP on INPUT chain")
	}
}

func TestIsBroadcastDest_DockerUserChain(t *testing.T) {
	rule := iptparse.ParsedRule{DestIP: "255.255.255.255"}
	if isBroadcastDest(&rule, "DOCKER-USER", nil) != specialTargetLimitedBroadcast {
		t.Errorf("expected isBroadcastDest to return specialTargetLimitedBroadcast (%d) for 255.255.255.255 on DOCKER-USER chain", specialTargetLimitedBroadcast)
	}
}

func TestIsBroadcastDest_CIDRNotation(t *testing.T) {
	rule := iptparse.ParsedRule{DestIP: "255.255.255.255/32"}
	if isBroadcastDest(&rule, "INPUT", nil) != specialTargetLimitedBroadcast {
		t.Errorf("expected isBroadcastDest to return specialTargetLimitedBroadcast (%d) for 255.255.255.255/32 on INPUT chain (normalizeIP should strip /32)", specialTargetLimitedBroadcast)
	}
}

func TestIsBroadcastDest_SubnetBroadcast(t *testing.T) {
	rule := iptparse.ParsedRule{DestIP: "10.100.5.255/32"}
	if isBroadcastDest(&rule, "INPUT", []string{"10.100.5.36"}) != specialTargetSubnetBroadcast {
		t.Errorf("expected isBroadcastDest to return specialTargetSubnetBroadcast (%d) for 10.100.5.255/32 on INPUT chain with peer IP 10.100.5.36", specialTargetSubnetBroadcast)
	}
}

func TestIsBroadcastDest_SubnetBroadcast_DifferentSubnet(t *testing.T) {
	rule := iptparse.ParsedRule{DestIP: "192.168.1.255/32"}
	if isBroadcastDest(&rule, "INPUT", []string{"10.100.5.36"}) != 0 {
		t.Error("expected isBroadcastDest to return 0 for 192.168.1.255/32 when peer IP is on a different subnet (10.100.5.36)")
	}
}

func TestIsBroadcastDest_SubnetBroadcast_MultiplePeerIPs(t *testing.T) {
	rule := iptparse.ParsedRule{DestIP: "192.168.1.255/32"}
	if isBroadcastDest(&rule, "INPUT", []string{"10.100.5.36", "192.168.1.10"}) != specialTargetSubnetBroadcast {
		t.Errorf("expected isBroadcastDest to return specialTargetSubnetBroadcast (%d) for 192.168.1.255/32 when second peer IP (192.168.1.10) is on matching subnet", specialTargetSubnetBroadcast)
	}
}

func TestIsBroadcastDest_SubnetBroadcast_WithoutCIDR(t *testing.T) {
	rule := iptparse.ParsedRule{DestIP: "10.100.5.255"}
	if isBroadcastDest(&rule, "INPUT", []string{"10.100.5.36"}) != specialTargetSubnetBroadcast {
		t.Errorf("expected isBroadcastDest to return specialTargetSubnetBroadcast (%d) for 10.100.5.255 without CIDR on INPUT chain", specialTargetSubnetBroadcast)
	}
}

func TestIsBroadcastDest_SubnetBroadcast_CIDRPeerIP(t *testing.T) {
	// peerIPs may contain CIDR-prefixed IPs (e.g., from peer_ips table with /24)
	// parseIPPart should strip the suffix before broadcast computation
	rule := iptparse.ParsedRule{DestIP: "10.100.5.255/32"}
	if isBroadcastDest(&rule, "INPUT", []string{"10.100.5.36/24"}) != specialTargetSubnetBroadcast {
		t.Errorf("expected isBroadcastDest to return specialTargetSubnetBroadcast (%d) for 10.100.5.255/32 with CIDR-prefixed peer IP 10.100.5.36/24", specialTargetSubnetBroadcast)
	}
}

func TestIsBroadcastDest_SubnetBroadcast_EmptyPeerIPs(t *testing.T) {
	// With no peer IPs, a subnet-broadcast-like DestIP should not match
	rule := iptparse.ParsedRule{DestIP: "10.100.5.255/32"}
	if isBroadcastDest(&rule, "INPUT", nil) != 0 {
		t.Error("expected isBroadcastDest to return 0 for subnet-broadcast-like DestIP when peerIPs is nil")
	}
	if isBroadcastDest(&rule, "INPUT", []string{}) != 0 {
		t.Error("expected isBroadcastDest to return 0 for subnet-broadcast-like DestIP when peerIPs is empty")
	}
}

// --- resolveBroadcastService tests ---

func TestResolveBroadcastService_LimitedBroadcast(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()
	database.Exec("PRAGMA foreign_keys=OFF")

	limitedBroadcastID := insertSystemService(t, database, "Limited Broadcast", "", "udp", "Limited broadcast", true)

	ctx := context.Background()
	serviceID, err := resolveBroadcastService(ctx, database, specialTargetLimitedBroadcast)
	if err != nil {
		t.Fatalf("resolveBroadcastService returned error: %v", err)
	}
	if serviceID == 0 {
		t.Fatal("expected non-zero service ID")
	}
	if serviceID != limitedBroadcastID {
		t.Errorf("expected service ID %d, got %d", limitedBroadcastID, serviceID)
	}

	// Verify by querying the service name
	var name string
	err = database.QueryRow("SELECT name FROM services WHERE id = ?", serviceID).Scan(&name)
	if err != nil {
		t.Fatalf("failed to query service name: %v", err)
	}
	if name != "Limited Broadcast" {
		t.Errorf("expected service name 'Limited Broadcast', got %q", name)
	}
}

func TestResolveBroadcastService_SubnetBroadcast(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()
	database.Exec("PRAGMA foreign_keys=OFF")

	subnetBroadcastID := insertSystemService(t, database, "Subnet Broadcast", "", "udp", "Subnet broadcast", true)

	ctx := context.Background()
	serviceID, err := resolveBroadcastService(ctx, database, specialTargetSubnetBroadcast)
	if err != nil {
		t.Fatalf("resolveBroadcastService returned error: %v", err)
	}
	if serviceID == 0 {
		t.Fatal("expected non-zero service ID")
	}
	if serviceID != subnetBroadcastID {
		t.Errorf("expected service ID %d, got %d", subnetBroadcastID, serviceID)
	}

	var name string
	err = database.QueryRow("SELECT name FROM services WHERE id = ?", serviceID).Scan(&name)
	if err != nil {
		t.Fatalf("failed to query service name: %v", err)
	}
	if name != "Subnet Broadcast" {
		t.Errorf("expected service name 'Subnet Broadcast', got %q", name)
	}
}

func TestResolveBroadcastService_InvalidID(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()
	database.Exec("PRAGMA foreign_keys=OFF")

	ctx := context.Background()
	_, err := resolveBroadcastService(ctx, database, 99)
	if err == nil {
		t.Fatal("expected error for invalid broadcast special ID, got nil")
	}
	if !strings.Contains(err.Error(), "unknown broadcast special ID") {
		t.Errorf("expected error to contain 'unknown broadcast special ID', got %q", err.Error())
	}
}

func TestResolveBroadcastService_NotMulticast(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()
	database.Exec("PRAGMA foreign_keys=OFF")

	// Insert both Multicast and Limited Broadcast system services
	// This tests Bug #2 — ensure broadcast resolves to the correct service, not Multicast
	multicastID := insertSystemService(t, database, "Multicast", "", "udp", "Multicast", true)
	limitedBroadcastID := insertSystemService(t, database, "Limited Broadcast", "", "udp", "Limited broadcast", true)

	ctx := context.Background()
	serviceID, err := resolveBroadcastService(ctx, database, specialTargetLimitedBroadcast)
	if err != nil {
		t.Fatalf("resolveBroadcastService returned error: %v", err)
	}
	if serviceID == 0 {
		t.Fatal("expected non-zero service ID")
	}

	// The returned service must be "Limited Broadcast", NOT "Multicast"
	if serviceID == multicastID {
		t.Error("resolveBroadcastService returned Multicast service ID — Bug #2: broadcast should resolve to Limited Broadcast, not Multicast")
	}
	if serviceID != limitedBroadcastID {
		t.Errorf("expected Limited Broadcast service ID %d, got %d", limitedBroadcastID, serviceID)
	}

	var name string
	err = database.QueryRow("SELECT name FROM services WHERE id = ?", serviceID).Scan(&name)
	if err != nil {
		t.Fatalf("failed to query service name: %v", err)
	}
	if name != "Limited Broadcast" {
		t.Errorf("expected service name 'Limited Broadcast', got %q", name)
	}
}

// --- resolveBroadcastRule tests ---

func TestResolveBroadcastRule_LimitedBroadcast(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()
	database.Exec("PRAGMA foreign_keys=OFF")

	// Insert a peer
	peerID := insertTestPeer(t, database, "test-peer", "10.0.0.1", false)

	// Insert Limited Broadcast system service
	limitedBroadcastServiceID := insertSystemService(t, database, "Limited Broadcast", "", "udp", "Limited broadcast", true)

	// Create an import session for the peer
	result, err := database.Exec("INSERT INTO import_sessions (peer_id, status, raw_backup) VALUES (?, 'parsed', 'test')", peerID)
	if err != nil {
		t.Fatalf("insert session: %v", err)
	}
	sessionID, _ := result.LastInsertId()

	// Insert an import_rule with broadcast destination
	result, err = database.Exec(
		`INSERT INTO import_rules (session_id, chain, rule_order, raw_rule, status, action, priority, direction, target_scope, policy_name)
		 VALUES (?, 'INPUT', 1, '-d 255.255.255.255/32 -p udp -j ACCEPT', 'pending', 'ACCEPT', 100, 'both', 'both', 'test-policy')`,
		sessionID)
	if err != nil {
		t.Fatalf("insert rule: %v", err)
	}
	ruleID, _ := result.LastInsertId()

	// Create a ParsedRule representing the broadcast rule
	rule := iptparse.ParsedRule{
		DestIP:   "255.255.255.255/32",
		Protocol: "udp",
		Target:   "ACCEPT",
	}

	ctx := context.Background()
	err = resolveBroadcastRule(ctx, database, sessionID, ruleID, peerID, specialTargetLimitedBroadcast, &rule)
	if err != nil {
		t.Fatalf("resolveBroadcastRule returned error: %v", err)
	}

	// Query the import_rule to verify the resolved mappings
	var sourceType, targetType, direction, status string
	var sourceID, targetID, serviceID int64
	err = database.QueryRow(
		"SELECT source_type, source_id, target_type, target_id, service_id, direction, status FROM import_rules WHERE id = ?",
		ruleID,
	).Scan(&sourceType, &sourceID, &targetType, &targetID, &serviceID, &direction, &status)
	if err != nil {
		t.Fatalf("query rule: %v", err)
	}

	if sourceType != "special" {
		t.Errorf("expected source_type='special', got %q", sourceType)
	}
	if sourceID != specialTargetLimitedBroadcast {
		t.Errorf("expected source_id=%d (limited_broadcast), got %d", specialTargetLimitedBroadcast, sourceID)
	}
	if targetType != "peer" {
		t.Errorf("expected target_type='peer', got %q", targetType)
	}
	if targetID != peerID {
		t.Errorf("expected target_id=%d (peer), got %d", peerID, targetID)
	}
	if serviceID != limitedBroadcastServiceID {
		t.Errorf("expected service_id=%d (Limited Broadcast), got %d", limitedBroadcastServiceID, serviceID)
	}
	if direction != "both" {
		t.Errorf("expected direction='both', got %q", direction)
	}
	if status != "resolved" {
		t.Errorf("expected status='resolved', got %q", status)
	}
}

func TestResolveBroadcastRule_WithPorts(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()
	database.Exec("PRAGMA foreign_keys=OFF")

	// Insert a peer
	peerID := insertTestPeer(t, database, "dhcp-peer", "10.0.0.1", false)

	// Insert DHCP service with port 67
	dhcpServiceID := insertTestService(t, database, "DHCP", "67", "udp")

	// Also insert broadcast system services (should NOT be used when port is specified)
	_ = insertSystemService(t, database, "Limited Broadcast", "", "udp", "Limited broadcast", true)

	// Create an import session for the peer
	result, err := database.Exec("INSERT INTO import_sessions (peer_id, status, raw_backup) VALUES (?, 'parsed', 'test')", peerID)
	if err != nil {
		t.Fatalf("insert session: %v", err)
	}
	sessionID, _ := result.LastInsertId()

	// Insert an import_rule with broadcast destination and specific port
	result, err = database.Exec(
		`INSERT INTO import_rules (session_id, chain, rule_order, raw_rule, status, action, priority, direction, target_scope, policy_name)
		 VALUES (?, 'INPUT', 1, '-d 255.255.255.255/32 -p udp --dport 67 -j ACCEPT', 'pending', 'ACCEPT', 100, 'both', 'both', 'dhcp-policy')`,
		sessionID)
	if err != nil {
		t.Fatalf("insert rule: %v", err)
	}
	ruleID, _ := result.LastInsertId()

	// Create a ParsedRule with a specific DestPort
	rule := iptparse.ParsedRule{
		DestIP:   "255.255.255.255/32",
		Protocol: "udp",
		DestPort: "67",
		Target:   "ACCEPT",
	}

	ctx := context.Background()
	err = resolveBroadcastRule(ctx, database, sessionID, ruleID, peerID, specialTargetLimitedBroadcast, &rule)
	if err != nil {
		t.Fatalf("resolveBroadcastRule returned error: %v", err)
	}

	// Query the import_rule to verify the service resolved to DHCP, not broadcast system service
	var serviceID int64
	err = database.QueryRow(
		"SELECT service_id FROM import_rules WHERE id = ?",
		ruleID,
	).Scan(&serviceID)
	if err != nil {
		t.Fatalf("query rule service_id: %v", err)
	}

	if serviceID != dhcpServiceID {
		t.Errorf("expected service_id=%d (DHCP), got %d — broadcast rules with specific ports should resolve to port-specific services", dhcpServiceID, serviceID)
	}

	// Also verify source/target mappings (Bug #1 fix)
	var sourceType, targetType string
	var sourceID, targetID int64
	err = database.QueryRow(
		"SELECT source_type, source_id, target_type, target_id FROM import_rules WHERE id = ?",
		ruleID,
	).Scan(&sourceType, &sourceID, &targetType, &targetID)
	if err != nil {
		t.Fatalf("query rule source/target: %v", err)
	}
	if sourceType != "special" {
		t.Errorf("expected source_type='special', got %q", sourceType)
	}
	if sourceID != specialTargetLimitedBroadcast {
		t.Errorf("expected source_id=%d (limited_broadcast), got %d", specialTargetLimitedBroadcast, sourceID)
	}
	if targetType != "peer" {
		t.Errorf("expected target_type='peer', got %q", targetType)
	}
	if targetID != peerID {
		t.Errorf("expected target_id=%d (peer), got %d", peerID, targetID)
	}
}

func TestResolveBroadcastRule_SubnetBroadcast(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()
	database.Exec("PRAGMA foreign_keys=OFF")

	// Insert a peer with IP on the 10.100.5.x subnet
	peerID := insertTestPeer(t, database, "subnet-peer", "10.100.5.36", false)

	// Insert Subnet Broadcast system service
	subnetBroadcastServiceID := insertSystemService(t, database, "Subnet Broadcast", "", "udp", "Subnet broadcast", true)

	// Create an import session for the peer
	result, err := database.Exec("INSERT INTO import_sessions (peer_id, status, raw_backup) VALUES (?, 'parsed', 'test')", peerID)
	if err != nil {
		t.Fatalf("insert session: %v", err)
	}
	sessionID, _ := result.LastInsertId()

	// Insert an import_rule with subnet broadcast destination
	result, err = database.Exec(
		`INSERT INTO import_rules (session_id, chain, rule_order, raw_rule, status, action, priority, direction, target_scope, policy_name)
		VALUES (?, 'INPUT', 1, '-d 10.100.5.255/32 -p udp -j ACCEPT', 'pending', 'ACCEPT', 100, 'both', 'both', 'test-policy')`,
		sessionID)
	if err != nil {
		t.Fatalf("insert rule: %v", err)
	}
	ruleID, _ := result.LastInsertId()

	// Create a ParsedRule representing the subnet broadcast rule
	rule := iptparse.ParsedRule{
		DestIP:   "10.100.5.255/32",
		Protocol: "udp",
		Target:   "ACCEPT",
	}

	ctx := context.Background()
	err = resolveBroadcastRule(ctx, database, sessionID, ruleID, peerID, specialTargetSubnetBroadcast, &rule)
	if err != nil {
		t.Fatalf("resolveBroadcastRule returned error: %v", err)
	}

	// Query the import_rule to verify the resolved mappings
	var sourceType, targetType, direction, status string
	var sourceID, targetID, serviceID int64
	err = database.QueryRow(
		"SELECT source_type, source_id, target_type, target_id, service_id, direction, status FROM import_rules WHERE id = ?",
		ruleID,
	).Scan(&sourceType, &sourceID, &targetType, &targetID, &serviceID, &direction, &status)
	if err != nil {
		t.Fatalf("query rule: %v", err)
	}

	if sourceType != "special" {
		t.Errorf("expected source_type='special', got %q", sourceType)
	}
	if sourceID != specialTargetSubnetBroadcast {
		t.Errorf("expected source_id=%d (subnet_broadcast), got %d", specialTargetSubnetBroadcast, sourceID)
	}
	if targetType != "peer" {
		t.Errorf("expected target_type='peer', got %q", targetType)
	}
	if targetID != peerID {
		t.Errorf("expected target_id=%d (peer), got %d", peerID, targetID)
	}
	if serviceID != subnetBroadcastServiceID {
		t.Errorf("expected service_id=%d (Subnet Broadcast), got %d", subnetBroadcastServiceID, serviceID)
	}
	if direction != "both" {
		t.Errorf("expected direction='both', got %q", direction)
	}
	if status != "resolved" {
		t.Errorf("expected status='resolved', got %q", status)
	}
}

func TestResolveBroadcastRule_SubnetBroadcast_WithPorts(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()
	database.Exec("PRAGMA foreign_keys=OFF")

	// Insert a peer
	peerID := insertTestPeer(t, database, "subnet-dhcp-peer", "10.100.5.36", false)

	// Insert DHCP service with port 67
	dhcpServiceID := insertTestService(t, database, "DHCP", "67", "udp")

	// Also insert broadcast system services (should NOT be used when port is specified)
	_ = insertSystemService(t, database, "Subnet Broadcast", "", "udp", "Subnet broadcast", true)

	// Create an import session for the peer
	result, err := database.Exec("INSERT INTO import_sessions (peer_id, status, raw_backup) VALUES (?, 'parsed', 'test')", peerID)
	if err != nil {
		t.Fatalf("insert session: %v", err)
	}
	sessionID, _ := result.LastInsertId()

	// Insert an import_rule with subnet broadcast destination and specific port
	result, err = database.Exec(
		`INSERT INTO import_rules (session_id, chain, rule_order, raw_rule, status, action, priority, direction, target_scope, policy_name)
		VALUES (?, 'INPUT', 1, '-d 10.100.5.255/32 -p udp --dport 67 -j ACCEPT', 'pending', 'ACCEPT', 100, 'both', 'both', 'dhcp-policy')`,
		sessionID)
	if err != nil {
		t.Fatalf("insert rule: %v", err)
	}
	ruleID, _ := result.LastInsertId()

	// Create a ParsedRule with a specific DestPort
	rule := iptparse.ParsedRule{
		DestIP:   "10.100.5.255/32",
		Protocol: "udp",
		DestPort: "67",
		Target:   "ACCEPT",
	}

	ctx := context.Background()
	err = resolveBroadcastRule(ctx, database, sessionID, ruleID, peerID, specialTargetSubnetBroadcast, &rule)
	if err != nil {
		t.Fatalf("resolveBroadcastRule returned error: %v", err)
	}

	// Query the import_rule to verify the service resolved to DHCP, not broadcast system service
	var serviceID int64
	err = database.QueryRow(
		"SELECT service_id FROM import_rules WHERE id = ?", ruleID,
	).Scan(&serviceID)
	if err != nil {
		t.Fatalf("query rule service_id: %v", err)
	}
	if serviceID != dhcpServiceID {
		t.Errorf("expected service_id=%d (DHCP), got %d — subnet broadcast rules with specific ports should resolve to port-specific services", dhcpServiceID, serviceID)
	}

	// Also verify source/target mappings
	var sourceType, targetType string
	var sourceID, targetID int64
	err = database.QueryRow(
		"SELECT source_type, source_id, target_type, target_id FROM import_rules WHERE id = ?", ruleID,
	).Scan(&sourceType, &sourceID, &targetType, &targetID)
	if err != nil {
		t.Fatalf("query rule source/target: %v", err)
	}
	if sourceType != "special" {
		t.Errorf("expected source_type='special', got %q", sourceType)
	}
	if sourceID != specialTargetSubnetBroadcast {
		t.Errorf("expected source_id=%d (subnet_broadcast), got %d", specialTargetSubnetBroadcast, sourceID)
	}
	if targetType != "peer" {
		t.Errorf("expected target_type='peer', got %q", targetType)
	}
	if targetID != peerID {
		t.Errorf("expected target_id=%d (peer), got %d", peerID, targetID)
	}
}

func TestResolveBroadcastRule_OutputChainNotBroadcast(t *testing.T) {
	// This test verifies that OUTPUT chain rules with broadcast dest IP
	// do NOT trigger broadcast handling. Since isBroadcastDest returns 0
	// for OUTPUT chain, those rules go through normal resolveEndpoint() path.
	rule := iptparse.ParsedRule{DestIP: "255.255.255.255"}

	if isBroadcastDest(&rule, "OUTPUT", nil) != 0 {
		t.Error("isBroadcastDest should return 0 for OUTPUT chain — OUTPUT broadcast rules should go through normal resolution, not broadcast path")
	}

	// Also verify FORWARD chain is not treated as broadcast
	if isBroadcastDest(&rule, "FORWARD", nil) != 0 {
		t.Error("isBroadcastDest should return 0 for FORWARD chain")
	}
}

// --- resolveMulticastRule tests ---

func TestResolveMulticastRule_SourceIsAllHosts_TargetIsPeer(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()
	database.Exec("PRAGMA foreign_keys=OFF")

	// Insert a peer
	peerID := insertTestPeer(t, database, "multicast-peer", "10.0.0.5", false)

	// Insert Multicast system service
	multicastServiceID := insertSystemService(t, database, "Multicast", "", "udp", "Multicast", true)

	// Create an import session for the peer
	result, err := database.Exec("INSERT INTO import_sessions (peer_id, status, raw_backup) VALUES (?, 'parsed', 'test')", peerID)
	if err != nil {
		t.Fatalf("insert session: %v", err)
	}
	sessionID, _ := result.LastInsertId()

	// Insert an import_rule with multicast pkttype
	result, err = database.Exec(
		`INSERT INTO import_rules (session_id, chain, rule_order, raw_rule, status, action, priority, direction, target_scope, policy_name)
		VALUES (?, 'INPUT', 1, '-m pkttype --pkt-type multicast -j ACCEPT', 'pending', 'ACCEPT', 100, 'both', 'both', 'test-multicast')`, sessionID)
	if err != nil {
		t.Fatalf("insert rule: %v", err)
	}
	ruleID, _ := result.LastInsertId()

	ctx := context.Background()
	err = resolveMulticastRule(ctx, database, ruleID, peerID)
	if err != nil {
		t.Fatalf("resolveMulticastRule returned error: %v", err)
	}

	// Query the import_rule to verify the resolved mappings
	var sourceType, targetType, direction, status string
	var sourceID, targetID, serviceID int64
	err = database.QueryRow(
		"SELECT source_type, source_id, target_type, target_id, service_id, direction, status FROM import_rules WHERE id = ?",
		ruleID,
	).Scan(&sourceType, &sourceID, &targetType, &targetID, &serviceID, &direction, &status)
	if err != nil {
		t.Fatalf("query rule: %v", err)
	}

	// Core fix verification: source = All Hosts special, target = peer
	if sourceType != "special" {
		t.Errorf("expected source_type='special', got %q", sourceType)
	}
	if sourceID != specialTargetAllHosts {
		t.Errorf("expected source_id=%d (all_hosts), got %d", specialTargetAllHosts, sourceID)
	}
	if targetType != "peer" {
		t.Errorf("expected target_type='peer', got %q", targetType)
	}
	if targetID != peerID {
		t.Errorf("expected target_id=%d (peer), got %d", peerID, targetID)
	}
	if serviceID != multicastServiceID {
		t.Errorf("expected service_id=%d (Multicast), got %d", multicastServiceID, serviceID)
	}
	if direction != "both" {
		t.Errorf("expected direction='both', got %q", direction)
	}
	if status != "resolved" {
		t.Errorf("expected status='resolved', got %q", status)
	}
}

func TestResolveMulticastRule_NotOrphaned(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()
	database.Exec("PRAGMA foreign_keys=OFF")

	// Insert a peer
	peerID := insertTestPeer(t, database, "orphan-peer", "10.0.0.6", false)

	// Insert Multicast system service
	_ = insertSystemService(t, database, "Multicast", "", "udp", "Multicast", true)

	// Create an import session for the peer
	result, err := database.Exec("INSERT INTO import_sessions (peer_id, status, raw_backup) VALUES (?, 'parsed', 'test')", peerID)
	if err != nil {
		t.Fatalf("insert session: %v", err)
	}
	sessionID, _ := result.LastInsertId()

	// Insert an import_rule with multicast pkttype
	result, err = database.Exec(
		`INSERT INTO import_rules (session_id, chain, rule_order, raw_rule, status, action, priority, direction, target_scope, policy_name)
		VALUES (?, 'INPUT', 1, '-m pkttype --pkt-type multicast -j ACCEPT', 'pending', 'ACCEPT', 100, 'both', 'both', 'orphan-test')`, sessionID)
	if err != nil {
		t.Fatalf("insert rule: %v", err)
	}
	ruleID, _ := result.LastInsertId()

	ctx := context.Background()
	err = resolveMulticastRule(ctx, database, ruleID, peerID)
	if err != nil {
		t.Fatalf("resolveMulticastRule returned error: %v", err)
	}

	// Verify target_type is 'peer' (not 'special') — the old bug set target_type='special'
	var targetType string
	var targetID int64
	err = database.QueryRow(
		"SELECT target_type, target_id FROM import_rules WHERE id = ?",
		ruleID,
	).Scan(&targetType, &targetID)
	if err != nil {
		t.Fatalf("query rule: %v", err)
	}

	if targetType == "special" {
		t.Errorf("target_type should NOT be 'special' — the old code incorrectly set target_type='special' which orphaned the policy from the peer; got target_type='special', target_id=%d", targetID)
	}
	if targetType != "peer" {
		t.Errorf("expected target_type='peer', got %q", targetType)
	}
	if targetID != peerID {
		t.Errorf("expected target_id=%d (peer), got %d", peerID, targetID)
	}
}

func TestResolveMulticastRule_MulticastService(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()
	database.Exec("PRAGMA foreign_keys=OFF")

	// Insert a peer
	peerID := insertTestPeer(t, database, "svc-peer", "10.0.0.7", false)

	// Insert both Multicast and broadcast system services to verify multicast
	// resolves to the correct one (not a broadcast service)
	multicastServiceID := insertSystemService(t, database, "Multicast", "", "udp", "Multicast", true)
	_ = insertSystemService(t, database, "Limited Broadcast", "", "udp", "Limited broadcast", true)
	_ = insertSystemService(t, database, "Subnet Broadcast", "", "udp", "Subnet broadcast", true)

	// Create an import session for the peer
	result, err := database.Exec("INSERT INTO import_sessions (peer_id, status, raw_backup) VALUES (?, 'parsed', 'test')", peerID)
	if err != nil {
		t.Fatalf("insert session: %v", err)
	}
	sessionID, _ := result.LastInsertId()

	// Insert an import_rule with multicast pkttype
	result, err = database.Exec(
		`INSERT INTO import_rules (session_id, chain, rule_order, raw_rule, status, action, priority, direction, target_scope, policy_name)
		VALUES (?, 'INPUT', 1, '-m pkttype --pkt-type multicast -j ACCEPT', 'pending', 'ACCEPT', 100, 'both', 'both', 'svc-test')`, sessionID)
	if err != nil {
		t.Fatalf("insert rule: %v", err)
	}
	ruleID, _ := result.LastInsertId()

	ctx := context.Background()
	err = resolveMulticastRule(ctx, database, ruleID, peerID)
	if err != nil {
		t.Fatalf("resolveMulticastRule returned error: %v", err)
	}

	// Verify the service resolves to "Multicast", not broadcast services
	var serviceID int64
	err = database.QueryRow(
		"SELECT service_id FROM import_rules WHERE id = ?",
		ruleID,
	).Scan(&serviceID)
	if err != nil {
		t.Fatalf("query rule service_id: %v", err)
	}
	if serviceID != multicastServiceID {
		t.Errorf("expected service_id=%d (Multicast), got %d — multicast rules should resolve to the Multicast system service, not broadcast services", multicastServiceID, serviceID)
	}

	// Also verify by name
	var name string
	err = database.QueryRow("SELECT name FROM services WHERE id = ?", serviceID).Scan(&name)
	if err != nil {
		t.Fatalf("failed to query service name: %v", err)
	}
	if name != "Multicast" {
		t.Errorf("expected service name 'Multicast', got %q", name)
	}
}

func TestResolveMulticastRule_WithPort(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()
	database.Exec("PRAGMA foreign_keys=OFF")

	// Insert a peer
	peerID := insertTestPeer(t, database, "mdns-peer", "10.0.0.8", false)

	// Insert an mDNS service with port 5353
	mdnsServiceID := insertTestService(t, database, "mDNS", "5353", "udp")

	// Also insert the generic Multicast system service
	multicastServiceID := insertSystemService(t, database, "Multicast", "", "udp", "Multicast", true)

	// Create an import session for the peer
	result, err := database.Exec("INSERT INTO import_sessions (peer_id, status, raw_backup) VALUES (?, 'parsed', 'test')", peerID)
	if err != nil {
		t.Fatalf("insert session: %v", err)
	}
	sessionID, _ := result.LastInsertId()

	// Insert an import_rule with multicast pkttype and a specific DestPort (5353 for mDNS)
	result, err = database.Exec(
		`INSERT INTO import_rules (session_id, chain, rule_order, raw_rule, status, action, priority, direction, target_scope, policy_name)
		VALUES (?, 'INPUT', 1, '-m pkttype --pkt-type multicast -p udp --dport 5353 -j ACCEPT', 'pending', 'ACCEPT', 100, 'both', 'both', 'mdns-policy')`, sessionID)
	if err != nil {
		t.Fatalf("insert rule: %v", err)
	}
	ruleID, _ := result.LastInsertId()

	ctx := context.Background()
	err = resolveMulticastRule(ctx, database, ruleID, peerID)
	if err != nil {
		t.Fatalf("resolveMulticastRule returned error: %v", err)
	}

	// Currently resolveMulticastRule always resolves to the generic "Multicast"
	// system service regardless of port. This test documents that behavior.
	// If port-specific service resolution is added later, this test should be
	// updated to expect mdnsServiceID instead.
	var serviceID int64
	err = database.QueryRow(
		"SELECT service_id FROM import_rules WHERE id = ?",
		ruleID,
	).Scan(&serviceID)
	if err != nil {
		t.Fatalf("query rule service_id: %v", err)
	}

	if serviceID == mdnsServiceID {
		t.Logf("Multicast rule with port resolved to port-specific service (mDNS, id=%d) — port-specific resolution is now supported", mdnsServiceID)
	} else if serviceID == multicastServiceID {
		t.Logf("Multicast rule with port resolved to generic Multicast system service (id=%d) instead of port-specific mDNS (id=%d) — current behavior: multicast always uses generic service", multicastServiceID, mdnsServiceID)
	} else {
		t.Errorf("expected service_id to be either Multicast (%d) or mDNS (%d), got %d", multicastServiceID, mdnsServiceID, serviceID)
	}

	// Verify source/target mappings are still correct
	var sourceType, targetType string
	var sourceID, targetID int64
	err = database.QueryRow(
		"SELECT source_type, source_id, target_type, target_id FROM import_rules WHERE id = ?",
		ruleID,
	).Scan(&sourceType, &sourceID, &targetType, &targetID)
	if err != nil {
		t.Fatalf("query rule source/target: %v", err)
	}
	if sourceType != "special" {
		t.Errorf("expected source_type='special', got %q", sourceType)
	}
	if sourceID != specialTargetAllHosts {
		t.Errorf("expected source_id=%d (all_hosts), got %d", specialTargetAllHosts, sourceID)
	}
	if targetType != "peer" {
		t.Errorf("expected target_type='peer', got %q", targetType)
	}
	if targetID != peerID {
		t.Errorf("expected target_id=%d (peer), got %d", peerID, targetID)
	}
}

func TestResolveMulticastRule_ServiceNotFound(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()
	database.Exec("PRAGMA foreign_keys=OFF")

	// Insert a peer
	peerID := insertTestPeer(t, database, "no-svc-peer", "10.0.0.9", false)

	// Do NOT insert the Multicast system service — this is the error condition

	// Create an import session for the peer
	result, err := database.Exec("INSERT INTO import_sessions (peer_id, status, raw_backup) VALUES (?, 'parsed', 'test')", peerID)
	if err != nil {
		t.Fatalf("insert session: %v", err)
	}
	sessionID, _ := result.LastInsertId()

	// Insert an import_rule with multicast pkttype
	result, err = database.Exec(
		`INSERT INTO import_rules (session_id, chain, rule_order, raw_rule, status, action, priority, direction, target_scope, policy_name)
		VALUES (?, 'INPUT', 1, '-m pkttype --pkt-type multicast -j ACCEPT', 'pending', 'ACCEPT', 100, 'both', 'both', 'no-svc-test')`, sessionID)
	if err != nil {
		t.Fatalf("insert rule: %v", err)
	}
	ruleID, _ := result.LastInsertId()

	ctx := context.Background()
	err = resolveMulticastRule(ctx, database, ruleID, peerID)
	if err == nil {
		t.Fatal("expected error when Multicast system service is not found, got nil")
	}
	if !strings.Contains(err.Error(), "multicast system service not found") {
		t.Errorf("expected error to contain 'multicast system service not found', got %q", err.Error())
	}
}

// --- isMulticastPktType tests ---

func TestIsMulticastPktType_InputChain(t *testing.T) {
	rule := iptparse.ParsedRule{PktType: "multicast"}
	if !isMulticastPktType(&rule, "INPUT") {
		t.Error("expected isMulticastPktType to return true for multicast on INPUT chain")
	}
}

func TestIsMulticastPktType_DockerUserChain(t *testing.T) {
	rule := iptparse.ParsedRule{PktType: "multicast"}
	if !isMulticastPktType(&rule, "DOCKER-USER") {
		t.Error("expected isMulticastPktType to return true for multicast on DOCKER-USER chain")
	}
}

func TestIsMulticastPktType_OutputChain(t *testing.T) {
	// OUTPUT chain rules with multicast pkttype should NOT trigger multicast handling.
	// On OUTPUT, the peer is sending multicast, not receiving it — analogous to
	// isBroadcastDest returning false for OUTPUT chain.
	rule := iptparse.ParsedRule{PktType: "multicast"}
	if isMulticastPktType(&rule, "OUTPUT") {
		t.Error("isMulticastPktType should return false for OUTPUT chain — OUTPUT multicast rules should go through normal resolution, not multicast path")
	}
}

func TestIsMulticastPktType_ForwardChain(t *testing.T) {
	rule := iptparse.ParsedRule{PktType: "multicast"}
	if isMulticastPktType(&rule, "FORWARD") {
		t.Error("isMulticastPktType should return false for FORWARD chain")
	}
}

func TestIsMulticastPktType_NonMulticastPktType(t *testing.T) {
	rule := iptparse.ParsedRule{PktType: "unicast"}
	if isMulticastPktType(&rule, "INPUT") {
		t.Error("isMulticastPktType should return false for non-multicast pkttype")
	}
}

func TestIsMulticastPktType_EmptyPktType(t *testing.T) {
	rule := iptparse.ParsedRule{PktType: ""}
	if isMulticastPktType(&rule, "INPUT") {
		t.Error("isMulticastPktType should return false for empty pkttype")
	}
}

// --- isIGMPProtocol tests ---

func TestIsIGMPProtocol_InputChain(t *testing.T) {
	rule := iptparse.ParsedRule{Protocol: "igmp"}
	if !isIGMPProtocol(&rule, "INPUT") {
		t.Error("expected isIGMPProtocol to return true for IGMP on INPUT chain")
	}
}

func TestIsIGMPProtocol_DockerUserChain(t *testing.T) {
	rule := iptparse.ParsedRule{Protocol: "igmp"}
	if !isIGMPProtocol(&rule, "DOCKER-USER") {
		t.Error("expected isIGMPProtocol to return true for IGMP on DOCKER-USER chain")
	}
}

func TestIsIGMPProtocol_OutputChain(t *testing.T) {
	// OUTPUT chain rules with IGMP protocol should NOT trigger IGMP handling.
	// On OUTPUT, the peer is sending IGMP, not receiving it — analogous to
	// isBroadcastDest and isMulticastPktType returning false for OUTPUT chain.
	rule := iptparse.ParsedRule{Protocol: "igmp"}
	if isIGMPProtocol(&rule, "OUTPUT") {
		t.Error("isIGMPProtocol should return false for OUTPUT chain — OUTPUT IGMP rules should go through normal resolution, not IGMP path")
	}
}

func TestIsIGMPProtocol_ForwardChain(t *testing.T) {
	rule := iptparse.ParsedRule{Protocol: "igmp"}
	if isIGMPProtocol(&rule, "FORWARD") {
		t.Error("isIGMPProtocol should return false for FORWARD chain")
	}
}

func TestIsIGMPProtocol_NonIGMPProtocol(t *testing.T) {
	rule := iptparse.ParsedRule{Protocol: "tcp"}
	if isIGMPProtocol(&rule, "INPUT") {
		t.Error("isIGMPProtocol should return false for non-IGMP protocol (tcp)")
	}
}

func TestIsIGMPProtocol_EmptyProtocol(t *testing.T) {
	rule := iptparse.ParsedRule{Protocol: ""}
	if isIGMPProtocol(&rule, "INPUT") {
		t.Error("isIGMPProtocol should return false for empty protocol")
	}
}

// --- resolveIGMPRule tests ---

func TestResolveIGMPRule_SourceIsAllHosts_TargetIsPeer(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()
	database.Exec("PRAGMA foreign_keys=OFF")

	// Insert a peer
	peerID := insertTestPeer(t, database, "igmp-peer", "10.0.0.5", false)

	// Insert IGMP system service
	igmpServiceID := insertSystemService(t, database, "IGMP", "", "igmp", "IGMP", true)

	// Create an import session for the peer
	result, err := database.Exec("INSERT INTO import_sessions (peer_id, status, raw_backup) VALUES (?, 'parsed', 'test')", peerID)
	if err != nil {
		t.Fatalf("insert session: %v", err)
	}
	sessionID, _ := result.LastInsertId()

	// Insert an import_rule with IGMP protocol
	result, err = database.Exec(
		`INSERT INTO import_rules (session_id, chain, rule_order, raw_rule, status, action, priority, direction, target_scope, policy_name)
		VALUES (?, 'INPUT', 1, '-p igmp -j ACCEPT', 'pending', 'ACCEPT', 100, 'both', 'both', 'test-igmp')`, sessionID)
	if err != nil {
		t.Fatalf("insert rule: %v", err)
	}
	ruleID, _ := result.LastInsertId()

	ctx := context.Background()
	err = resolveIGMPRule(ctx, database, ruleID, peerID)
	if err != nil {
		t.Fatalf("resolveIGMPRule returned error: %v", err)
	}

	// Query the import_rule to verify the resolved mappings
	var sourceType, targetType, direction, status string
	var sourceID, targetID, serviceID int64
	err = database.QueryRow(
		"SELECT source_type, source_id, target_type, target_id, service_id, direction, status FROM import_rules WHERE id = ?",
		ruleID,
	).Scan(&sourceType, &sourceID, &targetType, &targetID, &serviceID, &direction, &status)
	if err != nil {
		t.Fatalf("query rule: %v", err)
	}

	// Core verification: source = All Hosts special, target = peer
	if sourceType != "special" {
		t.Errorf("expected source_type='special', got %q", sourceType)
	}
	if sourceID != specialTargetAllHosts {
		t.Errorf("expected source_id=%d (all_hosts), got %d", specialTargetAllHosts, sourceID)
	}
	if targetType != "peer" {
		t.Errorf("expected target_type='peer', got %q", targetType)
	}
	if targetID != peerID {
		t.Errorf("expected target_id=%d (peer), got %d", peerID, targetID)
	}
	if serviceID != igmpServiceID {
		t.Errorf("expected service_id=%d (IGMP), got %d", igmpServiceID, serviceID)
	}
	if direction != "both" {
		t.Errorf("expected direction='both', got %q", direction)
	}
	if status != "resolved" {
		t.Errorf("expected status='resolved', got %q", status)
	}
}

func TestResolveIGMPRule_NotOrphaned(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()
	database.Exec("PRAGMA foreign_keys=OFF")

	// Insert a peer
	peerID := insertTestPeer(t, database, "igmp-orphan-peer", "10.0.0.6", false)

	// Insert IGMP system service
	_ = insertSystemService(t, database, "IGMP", "", "igmp", "IGMP", true)

	// Create an import session for the peer
	result, err := database.Exec("INSERT INTO import_sessions (peer_id, status, raw_backup) VALUES (?, 'parsed', 'test')", peerID)
	if err != nil {
		t.Fatalf("insert session: %v", err)
	}
	sessionID, _ := result.LastInsertId()

	// Insert an import_rule with IGMP protocol
	result, err = database.Exec(
		`INSERT INTO import_rules (session_id, chain, rule_order, raw_rule, status, action, priority, direction, target_scope, policy_name)
		VALUES (?, 'INPUT', 1, '-p igmp -j ACCEPT', 'pending', 'ACCEPT', 100, 'both', 'both', 'orphan-igmp-test')`, sessionID)
	if err != nil {
		t.Fatalf("insert rule: %v", err)
	}
	ruleID, _ := result.LastInsertId()

	ctx := context.Background()
	err = resolveIGMPRule(ctx, database, ruleID, peerID)
	if err != nil {
		t.Fatalf("resolveIGMPRule returned error: %v", err)
	}

	// Verify target_type is 'peer' (not 'special') — the old bug set target_type='special'
	// which orphaned the policy from the peer in loadApplicablePolicies
	var targetType string
	var targetID int64
	err = database.QueryRow(
		"SELECT target_type, target_id FROM import_rules WHERE id = ?",
		ruleID,
	).Scan(&targetType, &targetID)
	if err != nil {
		t.Fatalf("query rule: %v", err)
	}

	if targetType == "special" {
		t.Errorf("target_type should NOT be 'special' — the old code incorrectly set target_type='special' which orphaned the policy from the peer; got target_type='special', target_id=%d", targetID)
	}
	if targetType != "peer" {
		t.Errorf("expected target_type='peer', got %q", targetType)
	}
	if targetID != peerID {
		t.Errorf("expected target_id=%d (peer), got %d", peerID, targetID)
	}
}

func TestResolveIGMPRule_IGMPService(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()
	database.Exec("PRAGMA foreign_keys=OFF")

	// Insert a peer
	peerID := insertTestPeer(t, database, "igmp-svc-peer", "10.0.0.7", false)

	// Insert IGMP, Multicast, and broadcast system services to verify IGMP
	// resolves to the correct one (not Multicast or broadcast)
	igmpServiceID := insertSystemService(t, database, "IGMP", "", "igmp", "IGMP", true)
	_ = insertSystemService(t, database, "Multicast", "", "udp", "Multicast", true)
	_ = insertSystemService(t, database, "Limited Broadcast", "", "udp", "Limited broadcast", true)

	// Create an import session for the peer
	result, err := database.Exec("INSERT INTO import_sessions (peer_id, status, raw_backup) VALUES (?, 'parsed', 'test')", peerID)
	if err != nil {
		t.Fatalf("insert session: %v", err)
	}
	sessionID, _ := result.LastInsertId()

	// Insert an import_rule with IGMP protocol
	result, err = database.Exec(
		`INSERT INTO import_rules (session_id, chain, rule_order, raw_rule, status, action, priority, direction, target_scope, policy_name)
		VALUES (?, 'INPUT', 1, '-p igmp -j ACCEPT', 'pending', 'ACCEPT', 100, 'both', 'both', 'igmp-svc-test')`, sessionID)
	if err != nil {
		t.Fatalf("insert rule: %v", err)
	}
	ruleID, _ := result.LastInsertId()

	ctx := context.Background()
	err = resolveIGMPRule(ctx, database, ruleID, peerID)
	if err != nil {
		t.Fatalf("resolveIGMPRule returned error: %v", err)
	}

	// Verify the service resolves to "IGMP", not Multicast or broadcast
	var serviceID int64
	err = database.QueryRow(
		"SELECT service_id FROM import_rules WHERE id = ?", ruleID,
	).Scan(&serviceID)
	if err != nil {
		t.Fatalf("query rule service_id: %v", err)
	}
	if serviceID != igmpServiceID {
		t.Errorf("expected service_id=%d (IGMP), got %d — IGMP rules should resolve to the IGMP system service, not Multicast or broadcast services", igmpServiceID, serviceID)
	}

	// Also verify by name
	var name string
	err = database.QueryRow("SELECT name FROM services WHERE id = ?", serviceID).Scan(&name)
	if err != nil {
		t.Fatalf("failed to query service name: %v", err)
	}
	if name != "IGMP" {
		t.Errorf("expected service name 'IGMP', got %q", name)
	}
}

func TestResolveIGMPRule_ServiceNotFound(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()
	database.Exec("PRAGMA foreign_keys=OFF")

	// Insert a peer
	peerID := insertTestPeer(t, database, "igmp-no-svc-peer", "10.0.0.9", false)

	// Do NOT insert the IGMP system service — this is the error condition

	// Create an import session for the peer
	result, err := database.Exec("INSERT INTO import_sessions (peer_id, status, raw_backup) VALUES (?, 'parsed', 'test')", peerID)
	if err != nil {
		t.Fatalf("insert session: %v", err)
	}
	sessionID, _ := result.LastInsertId()

	// Insert an import_rule with IGMP protocol
	result, err = database.Exec(
		`INSERT INTO import_rules (session_id, chain, rule_order, raw_rule, status, action, priority, direction, target_scope, policy_name)
		VALUES (?, 'INPUT', 1, '-p igmp -j ACCEPT', 'pending', 'ACCEPT', 100, 'both', 'both', 'igmp-no-svc-test')`, sessionID)
	if err != nil {
		t.Fatalf("insert rule: %v", err)
	}
	ruleID, _ := result.LastInsertId()

	ctx := context.Background()
	err = resolveIGMPRule(ctx, database, ruleID, peerID)
	if err == nil {
		t.Fatal("expected error when IGMP system service is not found, got nil")
	}
	if !strings.Contains(err.Error(), "IGMP system service not found") {
		t.Errorf("expected error to contain 'IGMP system service not found', got %q", err.Error())
	}
}

// --- Direction-specific tests for resolveRules ---

func TestInputRuleDirection_BackwardWhenRemoteIsStagingPeer(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()
	database.Exec("PRAGMA foreign_keys=OFF")

	// Insert the importing peer (the one with the INPUT rule)
	peerID := insertTestPeer(t, database, "input-staging-peer", "10.0.0.1", false)

	// Insert a service for TCP port 443
	_ = insertTestService(t, database, "https", "443", "tcp")

	// Create an import session for the importing peer
	result, err := database.Exec("INSERT INTO import_sessions (peer_id, status, raw_backup) VALUES (?, 'parsed', 'test')", peerID)
	if err != nil {
		t.Fatalf("insert session: %v", err)
	}
	sessionID, _ := result.LastInsertId()

	// Insert an INPUT rule with a source IP that has NO existing peer (staging)
	// The remote (source) IP 10.0.0.99 does not match any peer → staging peer created → direction='backward'
	result, err = database.Exec(
		`INSERT INTO import_rules (session_id, chain, rule_order, raw_rule, status, skip_reason, action, priority, direction, target_scope, policy_name)
		VALUES (?, 'INPUT', 1, '-s 10.0.0.99 -p tcp --dport 443 -j ACCEPT', 'pending', '', 'ACCEPT', 100, 'backward', 'both', 'test-input-staging')`, sessionID)
	if err != nil {
		t.Fatalf("insert rule: %v", err)
	}
	ruleID, _ := result.LastInsertId()

	ctx := context.Background()
	err = resolveRules(ctx, database, sessionID, peerID, []string{"10.0.0.1"}, "")
	if err != nil {
		t.Fatalf("resolveRules returned error: %v", err)
	}

	var direction string
	err = database.QueryRow("SELECT direction FROM import_rules WHERE id = ?", ruleID).Scan(&direction)
	if err != nil {
		t.Fatalf("query rule direction: %v", err)
	}
	if direction != "backward" {
		t.Errorf("expected direction='backward', got %q", direction)
	}
}

func TestInputRuleDirection_BothWhenRemoteIsAgentPeer(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()
	database.Exec("PRAGMA foreign_keys=OFF")

	// Insert the importing peer
	peerID := insertTestPeer(t, database, "input-agent-local", "10.0.0.1", false)

	// Insert an existing AGENT peer (is_manual=0) at the remote IP
	_ = insertTestPeer(t, database, "input-agent-remote", "10.0.0.2", false)

	_ = insertTestService(t, database, "https", "443", "tcp")

	result, err := database.Exec("INSERT INTO import_sessions (peer_id, status, raw_backup) VALUES (?, 'parsed', 'test')", peerID)
	if err != nil {
		t.Fatalf("insert session: %v", err)
	}
	sessionID, _ := result.LastInsertId()

	// INPUT rule where source IP matches existing agent peer → direction='both'
	result, err = database.Exec(
		`INSERT INTO import_rules (session_id, chain, rule_order, raw_rule, status, skip_reason, action, priority, direction, target_scope, policy_name)
		VALUES (?, 'INPUT', 1, '-s 10.0.0.2 -p tcp --dport 443 -j ACCEPT', 'pending', '', 'ACCEPT', 100, 'backward', 'both', 'test-input-agent')`, sessionID)
	if err != nil {
		t.Fatalf("insert rule: %v", err)
	}
	ruleID, _ := result.LastInsertId()

	ctx := context.Background()
	err = resolveRules(ctx, database, sessionID, peerID, []string{"10.0.0.1"}, "")
	if err != nil {
		t.Fatalf("resolveRules returned error: %v", err)
	}

	var direction string
	err = database.QueryRow("SELECT direction FROM import_rules WHERE id = ?", ruleID).Scan(&direction)
	if err != nil {
		t.Fatalf("query rule direction: %v", err)
	}
	if direction != "both" {
		t.Errorf("expected direction='both', got %q", direction)
	}
}

func TestInputRuleDirection_BackwardWhenRemoteIsManualPeer(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()
	database.Exec("PRAGMA foreign_keys=OFF")

	// Insert the importing peer
	peerID := insertTestPeer(t, database, "input-manual-local", "10.0.0.1", false)

	// Insert an existing MANUAL peer (is_manual=1) at the remote IP
	_ = insertTestManualPeer(t, database, "input-manual-remote", "10.0.0.3")

	_ = insertTestService(t, database, "https", "443", "tcp")

	result, err := database.Exec("INSERT INTO import_sessions (peer_id, status, raw_backup) VALUES (?, 'parsed', 'test')", peerID)
	if err != nil {
		t.Fatalf("insert session: %v", err)
	}
	sessionID, _ := result.LastInsertId()

	// INPUT rule where source IP matches existing manual peer → direction='backward'
	result, err = database.Exec(
		`INSERT INTO import_rules (session_id, chain, rule_order, raw_rule, status, skip_reason, action, priority, direction, target_scope, policy_name)
		VALUES (?, 'INPUT', 1, '-s 10.0.0.3 -p tcp --dport 443 -j ACCEPT', 'pending', '', 'ACCEPT', 100, 'backward', 'both', 'test-input-manual')`, sessionID)
	if err != nil {
		t.Fatalf("insert rule: %v", err)
	}
	ruleID, _ := result.LastInsertId()

	ctx := context.Background()
	err = resolveRules(ctx, database, sessionID, peerID, []string{"10.0.0.1"}, "")
	if err != nil {
		t.Fatalf("resolveRules returned error: %v", err)
	}

	var direction string
	err = database.QueryRow("SELECT direction FROM import_rules WHERE id = ?", ruleID).Scan(&direction)
	if err != nil {
		t.Fatalf("query rule direction: %v", err)
	}
	if direction != "backward" {
		t.Errorf("expected direction='backward', got %q", direction)
	}
}

func TestOutputRuleDirection_ForwardWhenRemoteIsStagingPeer(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()
	database.Exec("PRAGMA foreign_keys=OFF")

	// Insert the importing peer
	peerID := insertTestPeer(t, database, "output-staging-peer", "10.0.0.1", false)

	_ = insertTestService(t, database, "https", "443", "tcp")

	result, err := database.Exec("INSERT INTO import_sessions (peer_id, status, raw_backup) VALUES (?, 'parsed', 'test')", peerID)
	if err != nil {
		t.Fatalf("insert session: %v", err)
	}
	sessionID, _ := result.LastInsertId()

	// OUTPUT rule where dest IP has NO existing peer (staging) → direction='forward'
	result, err = database.Exec(
		`INSERT INTO import_rules (session_id, chain, rule_order, raw_rule, status, skip_reason, action, priority, direction, target_scope, policy_name)
		VALUES (?, 'OUTPUT', 1, '-d 10.0.0.99 -p tcp --dport 443 -j ACCEPT', 'pending', '', 'ACCEPT', 100, 'forward', 'both', 'test-output-staging')`, sessionID)
	if err != nil {
		t.Fatalf("insert rule: %v", err)
	}
	ruleID, _ := result.LastInsertId()

	ctx := context.Background()
	err = resolveRules(ctx, database, sessionID, peerID, []string{"10.0.0.1"}, "")
	if err != nil {
		t.Fatalf("resolveRules returned error: %v", err)
	}

	var direction string
	err = database.QueryRow("SELECT direction FROM import_rules WHERE id = ?", ruleID).Scan(&direction)
	if err != nil {
		t.Fatalf("query rule direction: %v", err)
	}
	if direction != "forward" {
		t.Errorf("expected direction='forward', got %q", direction)
	}
}

func TestOutputRuleDirection_BothWhenRemoteIsAgentPeer(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()
	database.Exec("PRAGMA foreign_keys=OFF")

	// Insert the importing peer
	peerID := insertTestPeer(t, database, "output-agent-local", "10.0.0.1", false)

	// Insert an existing AGENT peer (is_manual=0) at the destination IP
	_ = insertTestPeer(t, database, "output-agent-remote", "10.0.0.2", false)

	_ = insertTestService(t, database, "https", "443", "tcp")

	result, err := database.Exec("INSERT INTO import_sessions (peer_id, status, raw_backup) VALUES (?, 'parsed', 'test')", peerID)
	if err != nil {
		t.Fatalf("insert session: %v", err)
	}
	sessionID, _ := result.LastInsertId()

	// OUTPUT rule where dest IP matches existing agent peer → direction='both'
	result, err = database.Exec(
		`INSERT INTO import_rules (session_id, chain, rule_order, raw_rule, status, skip_reason, action, priority, direction, target_scope, policy_name)
		VALUES (?, 'OUTPUT', 1, '-d 10.0.0.2 -p tcp --dport 443 -j ACCEPT', 'pending', '', 'ACCEPT', 100, 'forward', 'both', 'test-output-agent')`, sessionID)
	if err != nil {
		t.Fatalf("insert rule: %v", err)
	}
	ruleID, _ := result.LastInsertId()

	ctx := context.Background()
	err = resolveRules(ctx, database, sessionID, peerID, []string{"10.0.0.1"}, "")
	if err != nil {
		t.Fatalf("resolveRules returned error: %v", err)
	}

	var direction string
	err = database.QueryRow("SELECT direction FROM import_rules WHERE id = ?", ruleID).Scan(&direction)
	if err != nil {
		t.Fatalf("query rule direction: %v", err)
	}
	if direction != "both" {
		t.Errorf("expected direction='both', got %q", direction)
	}
}

func TestOutputRuleDirection_ForwardWhenRemoteIsManualPeer(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()
	database.Exec("PRAGMA foreign_keys=OFF")

	// Insert the importing peer
	peerID := insertTestPeer(t, database, "output-manual-local", "10.0.0.1", false)

	// Insert an existing MANUAL peer (is_manual=1) at the destination IP
	_ = insertTestManualPeer(t, database, "output-manual-remote", "10.0.0.3")

	_ = insertTestService(t, database, "https", "443", "tcp")

	result, err := database.Exec("INSERT INTO import_sessions (peer_id, status, raw_backup) VALUES (?, 'parsed', 'test')", peerID)
	if err != nil {
		t.Fatalf("insert session: %v", err)
	}
	sessionID, _ := result.LastInsertId()

	// OUTPUT rule where dest IP matches existing manual peer → direction='forward'
	result, err = database.Exec(
		`INSERT INTO import_rules (session_id, chain, rule_order, raw_rule, status, skip_reason, action, priority, direction, target_scope, policy_name)
		VALUES (?, 'OUTPUT', 1, '-d 10.0.0.3 -p tcp --dport 443 -j ACCEPT', 'pending', '', 'ACCEPT', 100, 'forward', 'both', 'test-output-manual')`, sessionID)
	if err != nil {
		t.Fatalf("insert rule: %v", err)
	}
	ruleID, _ := result.LastInsertId()

	ctx := context.Background()
	err = resolveRules(ctx, database, sessionID, peerID, []string{"10.0.0.1"}, "")
	if err != nil {
		t.Fatalf("resolveRules returned error: %v", err)
	}

	var direction string
	err = database.QueryRow("SELECT direction FROM import_rules WHERE id = ?", ruleID).Scan(&direction)
	if err != nil {
		t.Fatalf("query rule direction: %v", err)
	}
	if direction != "forward" {
		t.Errorf("expected direction='forward', got %q", direction)
	}
}

func TestInputRuleDirection_BothWhenRemoteIsSpecial(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()
	database.Exec("PRAGMA foreign_keys=OFF")

	// Insert the importing peer
	peerID := insertTestPeer(t, database, "input-special-local", "10.0.0.1", false)

	_ = insertTestService(t, database, "https", "443", "tcp")

	result, err := database.Exec("INSERT INTO import_sessions (peer_id, status, raw_backup) VALUES (?, 'parsed', 'test')", peerID)
	if err != nil {
		t.Fatalf("insert session: %v", err)
	}
	sessionID, _ := result.LastInsertId()

	// INPUT rule with no source IP (0.0.0.0/0) → resolves to special __any_ip__ → direction='both'
	result, err = database.Exec(
		`INSERT INTO import_rules (session_id, chain, rule_order, raw_rule, status, skip_reason, action, priority, direction, target_scope, policy_name)
		VALUES (?, 'INPUT', 1, '-p tcp --dport 443 -j ACCEPT', 'pending', '', 'ACCEPT', 100, 'backward', 'both', 'test-input-special')`, sessionID)
	if err != nil {
		t.Fatalf("insert rule: %v", err)
	}
	ruleID, _ := result.LastInsertId()

	ctx := context.Background()
	err = resolveRules(ctx, database, sessionID, peerID, []string{"10.0.0.1"}, "")
	if err != nil {
		t.Fatalf("resolveRules returned error: %v", err)
	}

	var direction string
	err = database.QueryRow("SELECT direction FROM import_rules WHERE id = ?", ruleID).Scan(&direction)
	if err != nil {
		t.Fatalf("query rule direction: %v", err)
	}
	if direction != "both" {
		t.Errorf("expected direction='both' for special endpoint, got %q", direction)
	}
}

func TestInputRuleDirection_BothWhenRemoteIsGroup(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()
	database.Exec("PRAGMA foreign_keys=OFF")

	// Insert the importing peer
	peerID := insertTestPeer(t, database, "input-group-local", "10.0.0.1", false)

	_ = insertTestService(t, database, "https", "443", "tcp")

	result, err := database.Exec("INSERT INTO import_sessions (peer_id, status, raw_backup) VALUES (?, 'parsed', 'test')", peerID)
	if err != nil {
		t.Fatalf("insert session: %v", err)
	}
	sessionID, _ := result.LastInsertId()

	// INPUT rule with ipset source (-m set --match-set runic_group_test src)
	// This resolves to a group endpoint → direction='both'
	result, err = database.Exec(
		`INSERT INTO import_rules (session_id, chain, rule_order, raw_rule, status, skip_reason, action, priority, direction, target_scope, policy_name)
		VALUES (?, 'INPUT', 1, '-m set --match-set runic_group_test src -p tcp --dport 443 -j ACCEPT', 'pending', '', 'ACCEPT', 100, 'backward', 'both', 'test-input-group')`, sessionID)
	if err != nil {
		t.Fatalf("insert rule: %v", err)
	}
	ruleID, _ := result.LastInsertId()

	// The rawIpsets parameter provides ipset member data for group resolution
	rawIpsets := "Name: runic_group_test\nType: hash:ip\nMembers:\n10.0.0.2\n10.0.0.3\n"

	ctx := context.Background()
	err = resolveRules(ctx, database, sessionID, peerID, []string{"10.0.0.1"}, rawIpsets)
	if err != nil {
		t.Fatalf("resolveRules returned error: %v", err)
	}

	var direction string
	err = database.QueryRow("SELECT direction FROM import_rules WHERE id = ?", ruleID).Scan(&direction)
	if err != nil {
		t.Fatalf("query rule direction: %v", err)
	}
	if direction != "both" {
		t.Errorf("expected direction='both' for group endpoint, got %q", direction)
	}
}
