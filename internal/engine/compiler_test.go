package engine

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	_ "github.com/mattn/go-sqlite3"

	"runic/internal/testutil"
)

// insertPeer inserts a test peer and returns its ID.
func insertPeer(t *testing.T, database *sql.DB, hostname, ip string, hasDocker bool) int {
	t.Helper()
	result, err := database.Exec(
		`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, has_docker) VALUES (?, ?, ?, ?, ?)`,
		hostname, ip, "key-"+hostname, "test-hmac-key", hasDocker)
	if err != nil {
		t.Fatalf("insert peer: %v", err)
	}
	id, _ := result.LastInsertId()
	return int(id)
}

// insertGroup inserts a test group and returns its ID.
func insertGroup(t *testing.T, database *sql.DB, name string) int {
	t.Helper()
	result, err := database.Exec("INSERT INTO groups (name) VALUES (?)", name)
	if err != nil {
		t.Fatalf("insert group: %v", err)
	}
	id, _ := result.LastInsertId()
	return int(id)
}

// insertGroupMember inserts a peer into a group.
func insertGroupMember(t *testing.T, database *sql.DB, groupID, peerID int) {
	t.Helper()
	_, err := database.Exec(
		"INSERT INTO group_members (group_id, peer_id) VALUES (?, ?)",
		groupID, peerID)
	if err != nil {
		t.Fatalf("insert group member: %v", err)
	}
}

// insertManualPeer inserts a manual peer with IP/CIDR and returns its ID.
func insertManualPeer(t *testing.T, database *sql.DB, ipOrCIDR string) int {
	t.Helper()
	result, err := database.Exec(
		`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, is_manual) VALUES (?, ?, ?, ?, 1)`,
		ipOrCIDR, ipOrCIDR, "key-"+ipOrCIDR, "hmac-"+ipOrCIDR)
	if err != nil {
		t.Fatalf("insert manual peer: %v", err)
	}
	id, _ := result.LastInsertId()
	return int(id)
}

// insertService inserts a test service and returns its ID.
func insertService(t *testing.T, database *sql.DB, name, ports, protocol string) int {
	t.Helper()
	result, err := database.Exec(
		`INSERT INTO services (name, ports, protocol) VALUES (?, ?, ?)`,
		name, ports, protocol)
	if err != nil {
		t.Fatalf("insert service: %v", err)
	}
	id, _ := result.LastInsertId()
	return int(id)
}

// insertPolicy inserts a test policy and returns its ID.
func insertPolicy(t *testing.T, database *sql.DB, name string, groupID, serviceID, peerID int, action string, priority int, enabled bool) int {
	t.Helper()
	enabledInt := 0
	if enabled {
		enabledInt = 1
	}
	result, err := database.Exec(
		`INSERT INTO policies (name, source_id, source_type, service_id, target_id, target_type, action, priority, enabled)
		VALUES (?, ?, "group", ?, ?, "peer", ?, ?, ?)`,
		name, groupID, serviceID, peerID, action, priority, enabledInt)
	if err != nil {
		t.Fatalf("insert policy: %v", err)
	}
	id, _ := result.LastInsertId()
	return int(id)
}

func TestSingleIPSource(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()
	database.Exec("PRAGMA foreign_keys=OFF")
	peerID := insertPeer(t, database, "web1", "192.168.1.10", false)
	groupID := insertGroup(t, database, "office")
	manualPeerID := insertManualPeer(t, database, "10.0.1.1")
	insertGroupMember(t, database, groupID, manualPeerID)
	serviceID := insertService(t, database, "ssh", "22", "tcp")
	insertPolicy(t, database, "allow-ssh", groupID, serviceID, peerID, "ACCEPT", 100, true)

	c := NewCompiler(database)
	output, err := c.Compile(context.Background(), peerID)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	if !strings.Contains(output, "-s 10.0.1.1/32 -p tcp --dport 22") {
		t.Errorf("expected INPUT rule with -s 10.0.1.1/32 -p tcp --dport 22, got:\n%s", output)
	}
	if !strings.Contains(output, "--sport 22") {
		t.Errorf("expected OUTPUT rule with --sport 22, got:\n%s", output)
	}
}

func TestCIDRSource(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()
	database.Exec("PRAGMA foreign_keys=OFF")
	peerID := insertPeer(t, database, "web2", "192.168.1.11", false)
	groupID := insertGroup(t, database, "subnet")
	manualPeerID := insertManualPeer(t, database, "10.0.1.0/24")
	insertGroupMember(t, database, groupID, manualPeerID)
	serviceID := insertService(t, database, "https", "443", "tcp")
	insertPolicy(t, database, "allow-https", groupID, serviceID, peerID, "ACCEPT", 100, true)

	c := NewCompiler(database)
	output, err := c.Compile(context.Background(), peerID)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	if !strings.Contains(output, "-s 10.0.1.0/24") {
		t.Errorf("expected -s 10.0.1.0/24 in output, got:\n%s", output)
	}
}

func TestMultiport(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()
	database.Exec("PRAGMA foreign_keys=OFF")
	peerID := insertPeer(t, database, "web3", "192.168.1.12", false)
	groupID := insertGroup(t, database, "any")
	manualPeerID := insertManualPeer(t, database, "0.0.0.0/0")
	insertGroupMember(t, database, groupID, manualPeerID)
	serviceID := insertService(t, database, "web", "80,443", "tcp")
	insertPolicy(t, database, "allow-web", groupID, serviceID, peerID, "ACCEPT", 100, true)

	c := NewCompiler(database)
	output, err := c.Compile(context.Background(), peerID)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	if !strings.Contains(output, "-m multiport --dports 80,443") {
		t.Errorf("expected multiport --dports 80,443 in output, got:\n%s", output)
	}
}

func TestPortRange(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()
	database.Exec("PRAGMA foreign_keys=OFF")
	peerID := insertPeer(t, database, "web4", "192.168.1.13", false)
	groupID := insertGroup(t, database, "any2")
	manualPeerID := insertManualPeer(t, database, "0.0.0.0/0")
	insertGroupMember(t, database, groupID, manualPeerID)
	serviceID := insertService(t, database, "highports", "8000:9000", "tcp")
	insertPolicy(t, database, "allow-highports", groupID, serviceID, peerID, "ACCEPT", 100, true)

	c := NewCompiler(database)
	output, err := c.Compile(context.Background(), peerID)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	if !strings.Contains(output, "-m multiport --dports 8000:9000") {
		t.Errorf("expected multiport --dports 8000:9000 in output, got:\n%s", output)
	}
}

func TestProtocolBoth(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()
	database.Exec("PRAGMA foreign_keys=OFF")
	peerID := insertPeer(t, database, "dns1", "192.168.1.14", false)
	groupID := insertGroup(t, database, "clients")
	manualPeerID := insertManualPeer(t, database, "10.0.0.0/8")
	insertGroupMember(t, database, groupID, manualPeerID)
	serviceID := insertService(t, database, "dns", "53", "both")
	insertPolicy(t, database, "allow-dns", groupID, serviceID, peerID, "ACCEPT", 100, true)

	c := NewCompiler(database)
	output, err := c.Compile(context.Background(), peerID)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	if !strings.Contains(output, "-p tcp --dport 53") {
		t.Errorf("expected tcp rule with --dport 53, got:\n%s", output)
	}
	if !strings.Contains(output, "-p udp --dport 53") {
		t.Errorf("expected udp rule with --dport 53, got:\n%s", output)
	}
}

func TestICMPService(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()
	database.Exec("PRAGMA foreign_keys=OFF")
	peerID := insertPeer(t, database, "mon1", "192.168.1.15", false)
	groupID := insertGroup(t, database, "monitors")
	manualPeerID := insertManualPeer(t, database, "10.0.5.0/24")
	insertGroupMember(t, database, groupID, manualPeerID)
	serviceID := insertService(t, database, "ping", "", "icmp")
	insertPolicy(t, database, "allow-ping", groupID, serviceID, peerID, "ACCEPT", 100, true)

	c := NewCompiler(database)
	output, err := c.Compile(context.Background(), peerID)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	// Should have icmp rule for the policy source, without port clause
	if !strings.Contains(output, "-s 10.0.5.0/24 -p icmp") {
		t.Errorf("expected -s 10.0.5.0/24 -p icmp in output, got:\n%s", output)
	}
	// The policy ICMP rule should NOT contain --dport
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, "10.0.5.0/24") && strings.Contains(line, "icmp") && strings.Contains(line, "--dport") {
			t.Errorf("ICMP rule should not contain --dport: %s", line)
		}
	}
}

func TestMulticastService(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()
	database.Exec("PRAGMA foreign_keys=OFF")
	peerID := insertPeer(t, database, "mcast1", "192.168.1.16", false)
	groupID := insertGroup(t, database, "mcast-group")
	manualPeerID := insertManualPeer(t, database, "10.0.6.0/24")
	insertGroupMember(t, database, groupID, manualPeerID)
	// Insert Multicast system service manually
	result, err := database.Exec(
		`INSERT INTO services (name, ports, protocol, description, is_system) VALUES (?, ?, ?, ?, 1)`,
		"Multicast", "", "udp", "Multicast traffic handling (system service)")
	if err != nil {
		t.Fatalf("insert multicast service: %v", err)
	}
	serviceID, _ := result.LastInsertId()
	insertPolicy(t, database, "allow-multicast", groupID, int(serviceID), peerID, "ACCEPT", 100, true)

	c := NewCompiler(database)
	output, err := c.Compile(context.Background(), peerID)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	// Should have pkttype multicast rule, not source-based rule
	if !strings.Contains(output, "-m pkttype --pkt-type multicast") {
		t.Errorf("expected -m pkttype --pkt-type multicast in output, got:\n%s", output)
	}
	// Should NOT have source-based rule for multicast
	if strings.Contains(output, "-s 10.0.6.0/24") && strings.Contains(output, "multicast") {
		t.Errorf("multicast rule should not use source IP, got:\n%s", output)
	}
}

func TestMulticastServiceWithDocker(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()
	database.Exec("PRAGMA foreign_keys=OFF")
	peerID := insertPeer(t, database, "mcast-docker", "192.168.1.17", true)
	groupID := insertGroup(t, database, "mcast-docker-group")
	manualPeerID := insertManualPeer(t, database, "10.0.7.0/24")
	insertGroupMember(t, database, groupID, manualPeerID)
	// Insert Multicast system service manually
	result, err := database.Exec(
		`INSERT INTO services (name, ports, protocol, description, is_system) VALUES (?, ?, ?, ?, 1)`,
		"Multicast", "", "udp", "Multicast traffic handling (system service)")
	if err != nil {
		t.Fatalf("insert multicast service: %v", err)
	}
	serviceID, _ := result.LastInsertId()
	insertPolicy(t, database, "allow-multicast-docker", groupID, int(serviceID), peerID, "ACCEPT", 100, true)

	c := NewCompiler(database)
	output, err := c.Compile(context.Background(), peerID)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	// Should have pkttype multicast rule for both INPUT and DOCKER-USER
	if !strings.Contains(output, "-A INPUT -m pkttype --pkt-type multicast -j ACCEPT") {
		t.Errorf("expected INPUT multicast rule, got:\n%s", output)
	}
	if !strings.Contains(output, "-A DOCKER-USER -m pkttype --pkt-type multicast -j ACCEPT") {
		t.Errorf("expected DOCKER-USER multicast rule, got:\n%s", output)
	}
}

// TestBroadcastService_SubnetBroadcast tests policy with Source=Subnet Broadcast (ID 1)
// BC-007: Verify INPUT rules use -d (destination) for broadcast traffic
func TestBroadcastService_SubnetBroadcast(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()
	database.Exec("PRAGMA foreign_keys=OFF")
	peerID := insertPeer(t, database, "bcast-peer", "10.100.5.10", false)

	// Insert Subnet Broadcast service manually with no_conntrack=true
	result, err := database.Exec(
		`INSERT INTO services (name, ports, protocol, description, is_system, no_conntrack) VALUES (?, ?, ?, ?, 1, 1)`,
		"Subnet Broadcast", "", "udp", "Subnet broadcast traffic handling (system service)", 1)
	if err != nil {
		t.Fatalf("insert broadcast service: %v", err)
	}
	serviceID, _ := result.LastInsertId()

	// Insert policy: Source=Subnet Broadcast (special ID 1), Target=peer
	_, err = database.Exec(
		`INSERT INTO policies (name, source_id, source_type, service_id, target_id, target_type, action, priority, enabled)
		 VALUES (?, 1, 'special', ?, ?, 'peer', 'ACCEPT', 100, 1)`,
		"allow-subnet-broadcast", serviceID, peerID)
	if err != nil {
		t.Fatalf("insert policy: %v", err)
	}

	c := NewCompiler(database)
	output, err := c.Compile(context.Background(), peerID)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	// BC-007: Should have INPUT rule with -d (destination) for broadcast address
	// Subnet broadcast resolves to the peer's subnet broadcast address (e.g., 10.100.5.255)
	if !strings.Contains(output, "-A INPUT -d 10.100.5.255/32 -p udp -j ACCEPT") {
		t.Errorf("expected INPUT rule with -d for broadcast address, got:\n%s", output)
	}

	// Verify the broadcast rule line doesn't have conntrack
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, "10.100.5.255") && strings.Contains(line, "INPUT") {
			if strings.Contains(line, "-m conntrack") {
				t.Errorf("broadcast rule should not have conntrack, got: %s", line)
			}
		}
	}
}

// TestBroadcastService_LimitedBroadcast tests policy with Source=Limited Broadcast (ID 2)
// BC-007: Verify INPUT rules use -d (destination) for 255.255.255.255
func TestBroadcastService_LimitedBroadcast(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()
	database.Exec("PRAGMA foreign_keys=OFF")
	peerID := insertPeer(t, database, "limited-bcast-peer", "10.100.5.10", false)

	// Insert Limited Broadcast service manually with no_conntrack=true
	result, err := database.Exec(
		`INSERT INTO services (name, ports, protocol, description, is_system, no_conntrack) VALUES (?, ?, ?, ?, 1, 1)`,
		"Limited Broadcast", "", "udp", "Limited broadcast traffic handling (system service)", 1)
	if err != nil {
		t.Fatalf("insert broadcast service: %v", err)
	}
	serviceID, _ := result.LastInsertId()

	// Insert policy: Source=Limited Broadcast (special ID 2), Target=peer
	_, err = database.Exec(
		`INSERT INTO policies (name, source_id, source_type, service_id, target_id, target_type, action, priority, enabled)
		 VALUES (?, 2, 'special', ?, ?, 'peer', 'ACCEPT', 100, 1)`,
		"allow-limited-broadcast", serviceID, peerID)
	if err != nil {
		t.Fatalf("insert policy: %v", err)
	}

	c := NewCompiler(database)
	output, err := c.Compile(context.Background(), peerID)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	// BC-007: Should have INPUT rule with -d 255.255.255.255 for limited broadcast
	if !strings.Contains(output, "-A INPUT -d 255.255.255.255/32 -p udp -j ACCEPT") {
		t.Errorf("expected INPUT rule with -d 255.255.255.255, got:\n%s", output)
	}
}

// TestBroadcastService_PeerToBroadcast tests policy with Target=Subnet Broadcast
// BC-007: Verify correct handling when target is broadcast special
func TestBroadcastService_PeerToBroadcast(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()
	database.Exec("PRAGMA foreign_keys=OFF")
	peerID := insertPeer(t, database, "broadcast-sender", "10.100.5.10", false)

	// Insert Subnet Broadcast service
	result, err := database.Exec(
		`INSERT INTO services (name, ports, protocol, description, is_system, no_conntrack) VALUES (?, ?, ?, ?, 1, 1)`,
		"Subnet Broadcast", "", "udp", "Subnet broadcast traffic handling (system service)", 1)
	if err != nil {
		t.Fatalf("insert broadcast service: %v", err)
	}
	serviceID, _ := result.LastInsertId()

	// Insert policy: Source=peer, Target=Subnet Broadcast (special ID 1)
	_, err = database.Exec(
		`INSERT INTO policies (name, source_id, source_type, service_id, target_id, target_type, action, priority, enabled)
		 VALUES (?, ?, 'peer', ?, 1, 'special', 'ACCEPT', 100, 1)`,
		"send-to-broadcast", peerID, serviceID)
	if err != nil {
		t.Fatalf("insert policy: %v", err)
	}

	c := NewCompiler(database)
	output, err := c.Compile(context.Background(), peerID)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	// When sending TO broadcast, we need OUTPUT rules to the broadcast address
	// The peer is the source, so it should generate OUTPUT rules
	if !strings.Contains(output, "-A OUTPUT") {
		t.Errorf("expected OUTPUT rule for sending to broadcast, got:\n%s", output)
	}
}

func TestNoPolicies(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()
	database.Exec("PRAGMA foreign_keys=OFF")
	peerID := insertPeer(t, database, "empty1", "192.168.1.18", false)

	c := NewCompiler(database)
	output, err := c.Compile(context.Background(), peerID)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	// Should have standard rules
	if !strings.Contains(output, ":INPUT DROP [0:0]") {
		t.Error("expected :INPUT DROP chain policy")
	}
	// Check for loopback rule
	if !strings.Contains(output, "-A INPUT -i lo -j ACCEPT") {
		t.Errorf("expected loopback rule, output: %q", output)
	}
	// Check for default deny
	if !strings.Contains(output, "-A INPUT -j DROP") {
		t.Errorf("expected default deny rule, output: %q", output)
	}
	if !strings.Contains(output, "COMMIT") {
		t.Error("expected COMMIT")
	}
	// Should not have any policy-specific comments
	if strings.Contains(output, "# --- Policy:") {
		t.Error("expected no policy rules for peer with no policies")
	}
}

func TestConntrackStandardRules(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()
	database.Exec("PRAGMA foreign_keys=OFF")
	peerID := insertPeer(t, database, "conntrack1", "192.168.1.25", false)

	c := NewCompiler(database)
	output, err := c.Compile(context.Background(), peerID)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	// Should have ICMP RELATED rules for error messages
	if !strings.Contains(output, "-A INPUT -p icmp -m conntrack --ctstate RELATED -j ACCEPT") {
		t.Error("expected ICMP RELATED rule for INPUT")
	}
	if !strings.Contains(output, "-A OUTPUT -p icmp -m conntrack --ctstate RELATED -j ACCEPT") {
		t.Error("expected ICMP RELATED rule for OUTPUT")
	}

	// Should have INVALID packet drop
	if !strings.Contains(output, "-A INPUT -m conntrack --ctstate INVALID -j DROP") {
		t.Error("expected conntrack INVALID drop rule for INPUT")
	}

	// Should NOT use old state module
	if strings.Contains(output, "-m state --state") {
		t.Error("should not use deprecated state module, should use conntrack")
	}
}

func TestConntrackDockerRules(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()
	database.Exec("PRAGMA foreign_keys=OFF")
	peerID := insertPeer(t, database, "conntrack-docker", "192.168.1.26", true)

	c := NewCompiler(database)
	output, err := c.Compile(context.Background(), peerID)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	// Should have ICMP RELATED rule in DOCKER-USER chain
	if !strings.Contains(output, "-A DOCKER-USER -p icmp -m conntrack --ctstate RELATED -j ACCEPT") {
		t.Error("expected ICMP RELATED rule for DOCKER-USER")
	}
	if !strings.Contains(output, "-A DOCKER-USER -m conntrack --ctstate INVALID -j DROP") {
		t.Error("expected conntrack INVALID drop rule for DOCKER-USER")
	}
}

func TestLogDropAction(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()
	database.Exec("PRAGMA foreign_keys=OFF")
	peerID := insertPeer(t, database, "logdrop1", "192.168.1.19", false)
	groupID := insertGroup(t, database, "untrusted")
	manualPeerID := insertManualPeer(t, database, "172.16.0.0/12")
	insertGroupMember(t, database, groupID, manualPeerID)
	serviceID := insertService(t, database, "telnet", "23", "tcp")
	insertPolicy(t, database, "block-telnet", groupID, serviceID, peerID, "LOG_DROP", 100, true)

	c := NewCompiler(database)
	output, err := c.Compile(context.Background(), peerID)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	if !strings.Contains(output, "-s 172.16.0.0/12 -p tcp --dport 23 -j LOG") {
		t.Errorf("expected LOG rule for LOG_DROP, got:\n%s", output)
	}
	if !strings.Contains(output, "-s 172.16.0.0/12 -p tcp --dport 23 -j DROP") {
		t.Errorf("expected DROP rule for LOG_DROP, got:\n%s", output)
	}
}

func TestDisabledPolicy(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()
	database.Exec("PRAGMA foreign_keys=OFF")
	peerID := insertPeer(t, database, "disabled1", "192.168.1.20", false)
	groupID := insertGroup(t, database, "office2")
	manualPeerID := insertManualPeer(t, database, "10.0.1.0/24")
	insertGroupMember(t, database, groupID, manualPeerID)
	serviceID := insertService(t, database, "ftp", "21", "tcp")
	insertPolicy(t, database, "disabled-ftp", groupID, serviceID, peerID, "ACCEPT", 100, false)

	c := NewCompiler(database)
	output, err := c.Compile(context.Background(), peerID)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	if strings.Contains(output, "disabled-ftp") {
		t.Errorf("disabled policy should not appear in output, got:\n%s", output)
	}
	if strings.Contains(output, "--dport 21") {
		t.Errorf("disabled policy's port should not appear in output, got:\n%s", output)
	}
}

func TestPriorityOrdering(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()
	database.Exec("PRAGMA foreign_keys=OFF")
	peerID := insertPeer(t, database, "prio1", "192.168.1.21", false)

	groupID := insertGroup(t, database, "prio-group")
	manualPeerID := insertManualPeer(t, database, "10.0.0.1")
	insertGroupMember(t, database, groupID, manualPeerID)

	serviceHigh := insertService(t, database, "high-prio-svc", "60443", "tcp")
	serviceLow := insertService(t, database, "low-prio-svc", "9090", "tcp")

	// Insert low priority (200) first, high priority (50) second
	insertPolicy(t, database, "low-prio", groupID, serviceLow, peerID, "ACCEPT", 200, true)
	insertPolicy(t, database, "high-prio", groupID, serviceHigh, peerID, "ACCEPT", 50, true)

	c := NewCompiler(database)
	output, err := c.Compile(context.Background(), peerID)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	// high-prio (priority 50) should appear before low-prio (priority 200)
	idxHigh := strings.Index(output, "high-prio")
	idxLow := strings.Index(output, "low-prio")

	if idxHigh == -1 || idxLow == -1 {
		t.Fatalf("expected both policies in output, got:\n%s", output)
	}
	if idxHigh >= idxLow {
		t.Errorf("expected high-prio (priority 50) before low-prio (priority 200), high at %d, low at %d", idxHigh, idxLow)
	}
}

func TestDockerPeer(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()
	database.Exec("PRAGMA foreign_keys=OFF")
	peerID := insertPeer(t, database, "docker1", "192.168.1.22", true)

	c := NewCompiler(database)
	output, err := c.Compile(context.Background(), peerID)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	if !strings.Contains(output, ":DOCKER-USER - [0:0]") {
		t.Error("expected DOCKER-USER chain declaration for docker peer")
	}
	if !strings.Contains(output, "-A DOCKER-USER -j RETURN") {
		t.Error("expected DOCKER-USER RETURN rule for docker peer")
	}
}

func TestVersionStability(t *testing.T) {
	content := "some iptables rules content"
	v1 := Version(content)
	v2 := Version(content)

	if v1 != v2 {
		t.Errorf("expected same version for same content, got %s and %s", v1, v2)
	}
	if len(v1) != 64 {
		t.Errorf("expected 64 char hex SHA256, got length %d: %s", len(v1), v1)
	}
}

func TestHMACVerifySuccess(t *testing.T) {
	content := "some iptables rules content"
	key := "test-hmac-key"

	sig := Sign(content, key)
	if !Verify(content, key, sig) {
		t.Error("expected Verify to return true for valid signature")
	}
}

func TestHMACTamperDetection(t *testing.T) {
	content := "some iptables rules content"
	key := "test-hmac-key"

	sig := Sign(content, key)
	tamperedContent := content + " tampered"
	if Verify(tamperedContent, key, sig) {
		t.Error("expected Verify to return false for tampered content")
	}
}

// Table-driven tests for policy parsing and validation
func TestPolicyParsingAndValidation(t *testing.T) {
	tests := []struct {
		name        string
		setup       func(*testing.T, *sql.DB) (int, error)
		wantErr     bool
		errContains string
	}{
		{
			name: "valid policy with all fields",
			setup: func(t *testing.T, db *sql.DB) (int, error) {
				peerID := insertPeer(t, db, "test1", "10.0.0.1", false)
				groupID := insertGroup(t, db, "test-group")
				manualPeerID := insertManualPeer(t, db, "192.168.1.0/24")
				insertGroupMember(t, db, groupID, manualPeerID)
				serviceID := insertService(t, db, "test-service", "80", "tcp")
				return insertPolicy(t, db, "test-policy", groupID, serviceID, peerID, "ACCEPT", 100, true), nil
			},
			wantErr: false,
		},
		{
			name: "policy with DROP action",
			setup: func(t *testing.T, db *sql.DB) (int, error) {
				peerID := insertPeer(t, db, "test2", "10.0.0.2", false)
				groupID := insertGroup(t, db, "blocked-group")
				manualPeerID := insertManualPeer(t, db, "10.0.2.0/24")
				insertGroupMember(t, db, groupID, manualPeerID)
				serviceID := insertService(t, db, "blocked-service", "22", "tcp")
				return insertPolicy(t, db, "block-policy", groupID, serviceID, peerID, "DROP", 200, true), nil
			},
			wantErr: false,
		},
		{
			name: "policy with invalid peer ID",
			setup: func(t *testing.T, db *sql.DB) (int, error) {
				groupID := insertGroup(t, db, "test-group")
				manualPeerID := insertManualPeer(t, db, "192.168.1.0/24")
				insertGroupMember(t, db, groupID, manualPeerID)
				serviceID := insertService(t, db, "test-service", "80", "tcp")
				insertPolicy(t, db, "invalid-peer-policy", groupID, serviceID, 99999, "ACCEPT", 100, true)
				return 99999, nil
			},
			wantErr:     true,
			errContains: "sql: no rows in result set",
		},
		{
			name: "policy with invalid group ID",
			setup: func(t *testing.T, db *sql.DB) (int, error) {
				peerID := insertPeer(t, db, "test3", "10.0.0.3", false)
				serviceID := insertService(t, db, "test-service", "80", "tcp")
				insertPolicy(t, db, "invalid-group-policy", 99999, serviceID, peerID, "ACCEPT", 100, true)
				return peerID, nil
			},
			wantErr:     false,
			errContains: "",
		},
		{
			name: "policy with invalid service ID",
			setup: func(t *testing.T, db *sql.DB) (int, error) {
				peerID := insertPeer(t, db, "test4", "10.0.0.4", false)
				groupID := insertGroup(t, db, "test-group")
				manualPeerID := insertManualPeer(t, db, "192.168.1.0/24")
				insertGroupMember(t, db, groupID, manualPeerID)
				insertPolicy(t, db, "invalid-service-policy", groupID, 99999, peerID, "ACCEPT", 100, true)
				return peerID, nil
			},
			wantErr:     true,
			errContains: "service 99999 not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			database, cleanup := testutil.SetupTestDB(t)
			defer cleanup()
			database.Exec("PRAGMA foreign_keys=OFF")
			peerID, err := tt.setup(t, database)
			if err != nil && !tt.wantErr {
				t.Fatalf("setup failed: %v", err)
			}

			c := NewCompiler(database)
			_, err = c.Compile(context.Background(), peerID)

			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tt.errContains)
				} else if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("expected error containing %q, got %v", tt.errContains, err)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestIsSourcePortDirection(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()
	database.Exec("PRAGMA foreign_keys=OFF")
	peerID := insertPeer(t, database, "client", "10.0.0.1", false)
	groupID := insertGroup(t, database, "servers")
	manualPeerID := insertManualPeer(t, database, "10.0.1.50")
	insertGroupMember(t, database, groupID, manualPeerID)
	serviceID := insertService(t, database, "dns", "53", "udp")

	enabledInt := 1
	result, err := database.Exec(
		`INSERT INTO policies (name, source_id, source_type, service_id, target_id, target_type, action, priority, enabled)
		VALUES (?, ?, "peer", ?, ?, "group", "ACCEPT", 100, ?)`,
		"client-to-dns", peerID, serviceID, groupID, enabledInt)
	if err != nil {
		t.Fatalf("insert policy: %v", err)
	}
	_ = result

	c := NewCompiler(database)
	output, err := c.Compile(context.Background(), peerID)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	if !strings.Contains(output, "-A OUTPUT -d 10.0.1.50/32 -p udp --dport 53") {
		t.Errorf("expected OUTPUT rule with --dport 53 (sending to DNS server), got:\n%s", output)
	}
	if !strings.Contains(output, "-A INPUT -s 10.0.1.50/32 -p udp --sport 53") {
		t.Errorf("expected INPUT rule with --sport 53 (receiving from DNS server), got:\n%s", output)
	}
}

// Test rule compilation to iptables format
func TestRuleCompilationToIptablesFormat(t *testing.T) {
	tests := []struct {
		name          string
		setup         func(*testing.T, *sql.DB) (int, error)
		expectedRules []string
	}{
		{
			name: "single port TCP rule",
			setup: func(t *testing.T, db *sql.DB) (int, error) {
				peerID := insertPeer(t, db, "web1", "10.0.0.1", false)
				groupID := insertGroup(t, db, "office")
				manualPeerID := insertManualPeer(t, db, "192.168.1.100")
				insertGroupMember(t, db, groupID, manualPeerID)
				serviceID := insertService(t, db, "ssh", "22", "tcp")
				insertPolicy(t, db, "allow-ssh", groupID, serviceID, peerID, "ACCEPT", 100, true)
				return peerID, nil
			},
			expectedRules: []string{
				"-s 192.168.1.100/32 -p tcp --dport 22 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT",
				"-d 192.168.1.100/32 -p tcp --sport 22 -m conntrack --ctstate ESTABLISHED -j ACCEPT",
			},
		},
		{
			name: "multiport rule",
			setup: func(t *testing.T, db *sql.DB) (int, error) {
				peerID := insertPeer(t, db, "web2", "10.0.0.2", false)
				groupID := insertGroup(t, db, "clients")
				manualPeerID := insertManualPeer(t, db, "10.0.1.0/24")
				insertGroupMember(t, db, groupID, manualPeerID)
				serviceID := insertService(t, db, "web", "80,443", "tcp")
				insertPolicy(t, db, "allow-web", groupID, serviceID, peerID, "ACCEPT", 100, true)
				return peerID, nil
			},
			expectedRules: []string{
				"-s 10.0.1.0/24 -p tcp -m multiport --dports 80,443 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT",
			},
		},
		{
			name: "port range rule",
			setup: func(t *testing.T, db *sql.DB) (int, error) {
				peerID := insertPeer(t, db, "web3", "10.0.0.3", false)
				groupID := insertGroup(t, db, "clients2")
				manualPeerID := insertManualPeer(t, db, "10.0.2.0/24")
				insertGroupMember(t, db, groupID, manualPeerID)
				serviceID := insertService(t, db, "highports", "8000:9000", "tcp")
				insertPolicy(t, db, "allow-highports", groupID, serviceID, peerID, "ACCEPT", 100, true)
				return peerID, nil
			},
			expectedRules: []string{
				"-s 10.0.2.0/24 -p tcp -m multiport --dports 8000:9000 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT",
			},
		},
		{
			name: "UDP rule",
			setup: func(t *testing.T, db *sql.DB) (int, error) {
				peerID := insertPeer(t, db, "dns1", "10.0.0.4", false)
				groupID := insertGroup(t, db, "dns-clients")
				manualPeerID := insertManualPeer(t, db, "10.0.3.0/24")
				insertGroupMember(t, db, groupID, manualPeerID)
				serviceID := insertService(t, db, "dns", "53", "udp")
				insertPolicy(t, db, "allow-dns-udp", groupID, serviceID, peerID, "ACCEPT", 100, true)
				return peerID, nil
			},
			expectedRules: []string{
				"-s 10.0.3.0/24 -p udp --dport 53 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT",
			},
		},
		{
			name: "both TCP and UDP protocol",
			setup: func(t *testing.T, db *sql.DB) (int, error) {
				peerID := insertPeer(t, db, "dns2", "10.0.0.5", false)
				groupID := insertGroup(t, db, "dns-clients2")
				manualPeerID := insertManualPeer(t, db, "10.0.4.0/24")
				insertGroupMember(t, db, groupID, manualPeerID)
				serviceID := insertService(t, db, "dns", "53", "both")
				insertPolicy(t, db, "allow-dns-both", groupID, serviceID, peerID, "ACCEPT", 100, true)
				return peerID, nil
			},
			expectedRules: []string{
				"-p tcp --dport 53",
				"-p udp --dport 53",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			database, cleanup := testutil.SetupTestDB(t)
			defer cleanup()
			database.Exec("PRAGMA foreign_keys=OFF")
			peerID, err := tt.setup(t, database)
			if err != nil {
				t.Fatalf("setup failed: %v", err)
			}

			c := NewCompiler(database)
			output, err := c.Compile(context.Background(), peerID)
			if err != nil {
				t.Fatalf("compile failed: %v", err)
			}

			for _, expectedRule := range tt.expectedRules {
				if !strings.Contains(output, expectedRule) {
					t.Errorf("expected rule %q not found in output:\n%s", expectedRule, output)
				}
			}

			// Verify iptables-restore format
			if !strings.Contains(output, "*filter") {
				t.Error("missing *filter table declaration")
			}
			if !strings.Contains(output, "COMMIT") {
				t.Error("missing COMMIT")
			}
			if !strings.Contains(output, ":INPUT DROP [0:0]") {
				t.Error("missing :INPUT DROP chain")
			}
		})
	}
}

// Test invalid policies and malformed rules
func TestInvalidPoliciesAndMalformedRules(t *testing.T) {
	tests := []struct {
		name        string
		setup       func(*testing.T, *sql.DB) (int, error)
		wantErr     bool
		errContains string
	}{
		{
			name: "invalid IP in peer",
			setup: func(t *testing.T, db *sql.DB) (int, error) {
				peerID := insertPeer(t, db, "test1", "10.0.0.1", false)
				groupID := insertGroup(t, db, "bad-ip")
				// Insert a peer with invalid IP directly (bypassing validation)
				_, err := db.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, is_manual) VALUES (?, ?, ?, ?, 1)`,
					"bad-ip-peer", "999.999.999.999", "key", "hmac")
				if err != nil {
					return 0, err
				}
				_, err = db.Exec("INSERT INTO group_members (group_id, peer_id) VALUES (?, ?)", groupID, 2)
				if err != nil {
					return 0, err
				}
				serviceID := insertService(t, db, "test", "80", "tcp")
				insertPolicy(t, db, "bad-ip-policy", groupID, serviceID, peerID, "ACCEPT", 100, true)
				return peerID, nil
			},
			wantErr:     true,
			errContains: "invalid IP",
		},
		{
			name: "invalid CIDR in peer",
			setup: func(t *testing.T, db *sql.DB) (int, error) {
				peerID := insertPeer(t, db, "test2", "10.0.0.2", false)
				groupID := insertGroup(t, db, "bad-cidr")
				// Insert a peer with invalid CIDR directly
				_, err := db.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, is_manual) VALUES (?, ?, ?, ?, 1)`,
					"bad-cidr-peer", "10.0.0.0/33", "key", "hmac")
				if err != nil {
					return 0, err
				}
				_, err = db.Exec("INSERT INTO group_members (group_id, peer_id) VALUES (?, ?)", groupID, 2)
				if err != nil {
					return 0, err
				}
				serviceID := insertService(t, db, "test", "80", "tcp")
				insertPolicy(t, db, "bad-cidr-policy", groupID, serviceID, peerID, "ACCEPT", 100, true)
				return peerID, nil
			},
			wantErr:     true,
			errContains: "invalid CIDR",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			database, cleanup := testutil.SetupTestDB(t)
			defer cleanup()
			database.Exec("PRAGMA foreign_keys=OFF")
			peerID, err := tt.setup(t, database)
			if err != nil && !tt.wantErr {
				t.Fatalf("setup failed: %v", err)
			}

			c := NewCompiler(database)
			_, err = c.Compile(context.Background(), peerID)

			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tt.errContains)
				} else if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("expected error containing %q, got %v", tt.errContains, err)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

// Test Docker integration with DOCKER-USER chain
func TestDockerIntegration(t *testing.T) {
	tests := []struct {
		name         string
		hasDocker    bool
		expectDocker bool
		expectReturn bool
	}{
		{
			name:         "peer with Docker",
			hasDocker:    true,
			expectDocker: true,
			expectReturn: true,
		},
		{
			name:         "peer without Docker",
			hasDocker:    false,
			expectDocker: false,
			expectReturn: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			database, cleanup := testutil.SetupTestDB(t)
			defer cleanup()
			database.Exec("PRAGMA foreign_keys=OFF")
			peerID := insertPeer(t, database, "docker-test", "10.0.0.1", tt.hasDocker)

			c := NewCompiler(database)
			output, err := c.Compile(context.Background(), peerID)
			if err != nil {
				t.Fatalf("compile failed: %v", err)
			}

			hasDockerChain := strings.Contains(output, ":DOCKER-USER - [0:0]")
			hasReturnRule := strings.Contains(output, "-A DOCKER-USER -j RETURN")

			if tt.expectDocker && !hasDockerChain {
				t.Error("expected DOCKER-USER chain declaration")
			}
			if !tt.expectDocker && hasDockerChain {
				t.Error("unexpected DOCKER-USER chain declaration")
			}
			if tt.expectReturn && !hasReturnRule {
				t.Error("expected DOCKER-USER RETURN rule")
			}
		})
	}
}

// Test CompileAndStore functionality
func TestCompileAndStore(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()
	database.Exec("PRAGMA foreign_keys=OFF")
	peerID := insertPeer(t, database, "store-test", "10.0.0.1", false)
	groupID := insertGroup(t, database, "test-group")
	manualPeerID := insertManualPeer(t, database, "192.168.1.0/24")
	insertGroupMember(t, database, groupID, manualPeerID)
	serviceID := insertService(t, database, "test-service", "80", "tcp")
	insertPolicy(t, database, "test-policy", groupID, serviceID, peerID, "ACCEPT", 100, true)

	c := NewCompiler(database)
	bundle, err := c.CompileAndStore(context.Background(), peerID)
	if err != nil {
		t.Fatalf("CompileAndStore failed: %v", err)
	}

	// Verify bundle structure
	if bundle.ID == 0 {
		t.Error("expected non-zero bundle ID")
	}
	if bundle.PeerID != peerID {
		t.Errorf("expected peer_id %d, got %d", peerID, bundle.PeerID)
	}
	if bundle.Version == "" {
		t.Error("expected non-empty version")
	}
	if bundle.VersionNumber <= 0 {
		t.Errorf("expected positive version_number, got %d", bundle.VersionNumber)
	}
	if len(bundle.RulesContent) == 0 {
		t.Error("expected non-empty rules content")
	}
	if bundle.HMAC == "" {
		t.Error("expected non-empty HMAC")
	}

	// Verify bundle is in database
	var count int
	err = database.QueryRow("SELECT COUNT(*) FROM rule_bundles WHERE id = ?", bundle.ID).Scan(&count)
	if err != nil {
		t.Fatalf("query bundle: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 bundle, got %d", count)
	}

	// Verify peer's bundle_version was updated
	var bundleVersion string
	err = database.QueryRow("SELECT bundle_version FROM peers WHERE id = ?", peerID).Scan(&bundleVersion)
	if err != nil {
		t.Fatalf("query peer bundle version: %v", err)
	}
	if bundleVersion != bundle.Version {
		t.Errorf("expected bundle_version %s, got %s", bundle.Version, bundleVersion)
	}

	// Verify HMAC is valid
	if !Verify(bundle.RulesContent, "test-hmac-key", bundle.HMAC) {
		t.Error("HMAC verification failed")
	}
}

// TestCompileAndStore_VersionNumberIncrement verifies that version_number increments correctly.
func TestCompileAndStore_VersionNumberIncrement(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()
	database.Exec("PRAGMA foreign_keys=OFF")
	peerID := insertPeer(t, database, "version-test", "10.0.0.1", false)
	groupID := insertGroup(t, database, "test-group")
	manualPeerID := insertManualPeer(t, database, "192.168.1.0/24")
	insertGroupMember(t, database, groupID, manualPeerID)
	serviceID := insertService(t, database, "test-service", "80", "tcp")
	insertPolicy(t, database, "test-policy", groupID, serviceID, peerID, "ACCEPT", 100, true)

	c := NewCompiler(database)

	// First compile
	bundle1, err := c.CompileAndStore(context.Background(), peerID)
	if err != nil {
		t.Fatalf("first CompileAndStore failed: %v", err)
	}
	if bundle1.VersionNumber != 1 {
		t.Errorf("expected version_number 1, got %d", bundle1.VersionNumber)
	}

	// Add a second policy to change the compiled content (so the hash differs)
	serviceID2 := insertService(t, database, "test-service-2", "443", "tcp")
	insertPolicy(t, database, "test-policy-2", groupID, serviceID2, peerID, "ACCEPT", 200, true)

	// Second compile for same peer (different content → different hash)
	bundle2, err := c.CompileAndStore(context.Background(), peerID)
	if err != nil {
		t.Fatalf("second CompileAndStore failed: %v", err)
	}
	if bundle2.VersionNumber != 2 {
		t.Errorf("expected version_number 2, got %d", bundle2.VersionNumber)
	}

	// Verify both bundles exist in DB
	var count int
	err = database.QueryRow("SELECT COUNT(*) FROM rule_bundles WHERE peer_id = ?", peerID).Scan(&count)
	if err != nil {
		t.Fatalf("query bundles: %v", err)
	}
	if count != 2 {
		t.Errorf("expected 2 bundles, got %d", count)
	}

	// Verify the versions are different
	if bundle1.Version == bundle2.Version {
		t.Error("expected different version hashes for different content")
	}

	// Verify version_numbers are sequential
	var vn1, vn2 int
	err = database.QueryRow("SELECT version_number FROM rule_bundles WHERE peer_id = ? ORDER BY id ASC LIMIT 1", peerID).Scan(&vn1)
	if err != nil {
		t.Fatalf("query first version_number: %v", err)
	}
	err = database.QueryRow("SELECT version_number FROM rule_bundles WHERE peer_id = ? ORDER BY id DESC LIMIT 1", peerID).Scan(&vn2)
	if err != nil {
		t.Fatalf("query second version_number: %v", err)
	}
	if vn1 != 1 || vn2 != 2 {
		t.Errorf("expected sequential version_numbers 1 and 2, got %d and %d", vn1, vn2)
	}
}

// Test RecompileAffectedPeers
func TestRecompileAffectedPeers(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()
	database.Exec("PRAGMA foreign_keys=OFF")

	// Create two peers
	peer1 := insertPeer(t, database, "peer1", "10.0.0.1", false)
	peer2 := insertPeer(t, database, "peer2", "10.0.0.2", false)

	// Create groups and members
	group1 := insertGroup(t, database, "group1")
	manualPeer1 := insertManualPeer(t, database, "192.168.1.0/24")
	insertGroupMember(t, database, group1, manualPeer1)

	group2 := insertGroup(t, database, "group2")
	manualPeer2 := insertManualPeer(t, database, "192.168.2.0/24")
	insertGroupMember(t, database, group2, manualPeer2)

	// Create service and policies affecting both peers
	serviceID := insertService(t, database, "test", "80", "tcp")
	insertPolicy(t, database, "policy1", group1, serviceID, peer1, "ACCEPT", 100, true)
	insertPolicy(t, database, "policy2", group2, serviceID, peer2, "ACCEPT", 100, true)

	// Compile initial bundles
	c := NewCompiler(database)
	_, err := c.CompileAndStore(context.Background(), peer1)
	if err != nil {
		t.Fatalf("compile peer1: %v", err)
	}
	_, err = c.CompileAndStore(context.Background(), peer2)
	if err != nil {
		t.Fatalf("compile peer2: %v", err)
	}

	// Get initial bundle versions
	var v1, v2 string
	database.QueryRow("SELECT bundle_version FROM peers WHERE id = ?", peer1).Scan(&v1)
	database.QueryRow("SELECT bundle_version FROM peers WHERE id = ?", peer2).Scan(&v2)

	// Add a new member to group1 (affects peer1)
	newManualPeer := insertManualPeer(t, database, "10.1.1.1")
	insertGroupMember(t, database, group1, newManualPeer)

	// Recompile affected peers for group1
	err = c.RecompileAffectedPeers(context.Background(), group1)
	if err != nil {
		t.Fatalf("recompile affected: %v", err)
	}

	// Verify peer1 has new bundle version
	var newV1 string
	database.QueryRow("SELECT bundle_version FROM peers WHERE id = ?", peer1).Scan(&newV1)
	if newV1 == v1 {
		t.Error("expected bundle version to change for peer1")
	}

	// Verify peer2 bundle version is unchanged
	var newV2 string
	database.QueryRow("SELECT bundle_version FROM peers WHERE id = ?", peer2).Scan(&newV2)
	if newV2 != v2 {
		t.Error("expected bundle version to stay the same for peer2")
	}
}

// Test edge cases and error scenarios
func TestEdgeCases(t *testing.T) {
	tests := []struct {
		name        string
		setup       func(*testing.T, *sql.DB) (int, error)
		wantErr     bool
		errContains string
		check       func(*testing.T, string)
	}{
		{
			name: "multiple policies with same priority",
			setup: func(t *testing.T, db *sql.DB) (int, error) {
				peerID := insertPeer(t, db, "test1", "10.0.0.1", false)
				group1 := insertGroup(t, db, "group1")
				manualPeer1 := insertManualPeer(t, db, "192.168.1.0/24")
				insertGroupMember(t, db, group1, manualPeer1)
				group2 := insertGroup(t, db, "group2")
				manualPeer2 := insertManualPeer(t, db, "192.168.2.0/24")
				insertGroupMember(t, db, group2, manualPeer2)
				serviceID := insertService(t, db, "test", "80", "tcp")
				insertPolicy(t, db, "policy1", group1, serviceID, peerID, "ACCEPT", 100, true)
				insertPolicy(t, db, "policy2", group2, serviceID, peerID, "ACCEPT", 100, true)
				return peerID, nil
			},
			wantErr: false,
			check: func(t *testing.T, output string) {
				// Both should be present
				if !strings.Contains(output, "policy1") {
					t.Error("expected policy1 in output")
				}
				if !strings.Contains(output, "policy2") {
					t.Error("expected policy2 in output")
				}
			},
		},
		{
			name: "duplicate IP in different groups",
			setup: func(t *testing.T, db *sql.DB) (int, error) {
				peerID := insertPeer(t, db, "test3", "10.0.0.3", false)
				group1 := insertGroup(t, db, "group1")
				group2 := insertGroup(t, db, "group2")
				// Same manual peer added to both groups
				manualPeerID := insertManualPeer(t, db, "192.168.1.100")
				insertGroupMember(t, db, group1, manualPeerID)
				insertGroupMember(t, db, group2, manualPeerID)
				serviceID := insertService(t, db, "test", "80", "tcp")
				insertPolicy(t, db, "policy1", group1, serviceID, peerID, "ACCEPT", 100, true)
				insertPolicy(t, db, "policy2", group2, serviceID, peerID, "ACCEPT", 200, true)
				return peerID, nil
			},
			wantErr: false,
			check: func(t *testing.T, output string) {
				// Count occurrences - should only appear once per policy, not duplicated
				count := strings.Count(output, "192.168.1.100/32")
				if count < 2 {
					t.Errorf("expected at least 2 occurrences of IP, got %d", count)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			database, cleanup := testutil.SetupTestDB(t)
			defer cleanup()
			database.Exec("PRAGMA foreign_keys=OFF")
			peerID, err := tt.setup(t, database)
			if err != nil && !tt.wantErr {
				t.Fatalf("setup failed: %v", err)
			}

			c := NewCompiler(database)
			output, err := c.Compile(context.Background(), peerID)

			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tt.errContains)
				} else if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("expected error containing %q, got %v", tt.errContains, err)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if tt.check != nil {
					tt.check(t, output)
				}
			}
		})
	}
}

// insertPolicyWithDirection inserts a test policy with a direction field and returns its ID.
func insertPolicyWithDirection(t *testing.T, database *sql.DB, name string, groupID, serviceID, peerID int, action string, priority int, enabled bool, direction string) int {
	t.Helper()
	enabledInt := 0
	if enabled {
		enabledInt = 1
	}
	result, err := database.Exec(
		`INSERT INTO policies (name, source_id, source_type, service_id, target_id, target_type, action, priority, enabled, direction)
		VALUES (?, ?, "group", ?, ?, "peer", ?, ?, ?, ?)`,
		name, groupID, serviceID, peerID, action, priority, enabledInt, direction)
	if err != nil {
		t.Fatalf("insert policy with direction: %v", err)
	}
	id, _ := result.LastInsertId()
	return int(id)
}

func TestForwardOnlyPolicy(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()
	database.Exec("PRAGMA foreign_keys=OFF")
	// Setup: jump-server is the SOURCE, target-server is the TARGET
	jumpServer := insertPeer(t, database, "jump-server", "10.0.0.1", false)
	targetServer := insertPeer(t, database, "target-server", "10.0.0.2", false)
	groupID := insertGroup(t, database, "ssh-targets")
	insertGroupMember(t, database, groupID, targetServer)
	serviceID := insertService(t, database, "ssh", "22", "tcp")

	// Insert policy: jump-server -> ssh-targets, forward only
	// Source=jump-server (peer), Target=ssh-targets (group), Direction=forward
	_, err := database.Exec(
		`INSERT INTO policies (name, source_id, source_type, service_id, target_id, target_type, action, priority, enabled, direction)
		VALUES (?, ?, 'peer', ?, ?, 'group', 'ACCEPT', 100, 1, 'forward')`,
		"ssh-forward-only", jumpServer, serviceID, groupID)
	if err != nil {
		t.Fatalf("insert policy: %v", err)
	}

	c := NewCompiler(database)

	// Compile for the jump-server (source): should have OUTPUT rules
	outputJump, err := c.Compile(context.Background(), jumpServer)
	if err != nil {
		t.Fatalf("compile jump-server error: %v", err)
	}

	// Jump server should have OUTPUT rules (it's the source, direction=forward)
	if !strings.Contains(outputJump, "-A OUTPUT -d 10.0.0.2/32 -p tcp --dport 22") {
		t.Errorf("expected OUTPUT rule for jump-server, got:\n%s", outputJump)
	}

	// Jump server should NOT have INPUT rules for this policy (no backward direction)
	lines := strings.Split(outputJump, "\\n")
	for _, line := range lines {
		if strings.Contains(line, "ssh-forward-only") || strings.Contains(line, "As Target") {
			// Check that there are no "As Target" comment blocks for this policy
			if strings.Contains(line, "As Target") {
				t.Errorf("forward-only policy should not generate target/ingress rules on jump-server, found: %s", line)
			}
		}
	}

	// Compile for the target-server: should NOT have ingress rules (direction=forward, so backward is off)
	outputTarget, err := c.Compile(context.Background(), targetServer)
	if err != nil {
		t.Fatalf("compile target-server error: %v", err)
	}

	// Target server should NOT have INPUT rules for this policy (backward is disabled)
	if strings.Contains(outputTarget, "As Target (Ingress from peer") {
		t.Errorf("forward-only policy should not generate ingress rules on target-server, got:\n%s", outputTarget)
	}
}

func TestBackwardOnlyPolicy(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()
	database.Exec("PRAGMA foreign_keys=OFF")
	// Setup: client is the SOURCE, web-server is the TARGET
	webServer := insertPeer(t, database, "web-server", "10.0.0.10", false)
	clientPeer := insertPeer(t, database, "client-peer", "10.0.0.20", false)
	groupID := insertGroup(t, database, "clients")
	insertGroupMember(t, database, groupID, clientPeer)
	serviceID := insertService(t, database, "http", "80", "tcp")

	// Insert policy: clients -> web-server, backward only
	// This means only the target (web-server) gets INPUT rules, source does NOT get OUTPUT rules
	insertPolicyWithDirection(t, database, "http-backward-only", groupID, serviceID, webServer, "ACCEPT", 100, true, "backward")

	c := NewCompiler(database)

	// Compile for web-server (target): should have INPUT rules (backward = ingress allowed)
	outputWeb, err := c.Compile(context.Background(), webServer)
	if err != nil {
		t.Fatalf("compile web-server error: %v", err)
	}

	if !strings.Contains(outputWeb, "-A INPUT -s 10.0.0.20/32 -p tcp --dport 80") {
		t.Errorf("expected INPUT rule on web-server for backward-only policy, got:\n%s", outputWeb)
	}

	// Compile for client (source): should NOT have OUTPUT rules (forward is disabled)
	outputClient, err := c.Compile(context.Background(), clientPeer)
	if err != nil {
		t.Fatalf("compile client error: %v", err)
	}

	if strings.Contains(outputClient, "As Source (Egress to") {
		t.Errorf("backward-only policy should not generate egress rules on client, got:\n%s", outputClient)
	}
}

func TestBidirectionalPolicy(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()
	database.Exec("PRAGMA foreign_keys=OFF")
	peerID := insertPeer(t, database, "bidir-server", "10.0.0.50", false)
	clientPeer := insertPeer(t, database, "bidir-client", "10.0.0.51", false)
	groupID := insertGroup(t, database, "bidir-group")
	insertGroupMember(t, database, groupID, clientPeer)
	serviceID := insertService(t, database, "ssh", "22", "tcp")

	// Insert policy with direction='both' (default behavior)
	insertPolicyWithDirection(t, database, "ssh-bidirectional", groupID, serviceID, peerID, "ACCEPT", 100, true, "both")

	c := NewCompiler(database)

	// Compile for server (target): should have INPUT rules
	outputServer, err := c.Compile(context.Background(), peerID)
	if err != nil {
		t.Fatalf("compile server error: %v", err)
	}

	if !strings.Contains(outputServer, "-A INPUT -s 10.0.0.51/32 -p tcp --dport 22") {
		t.Errorf("expected INPUT rule on server for bidirectional policy, got:\n%s", outputServer)
	}

	// Compile for client (source): should have OUTPUT rules
	outputClient, err := c.Compile(context.Background(), clientPeer)
	if err != nil {
		t.Fatalf("compile client error: %v", err)
	}

	if !strings.Contains(outputClient, "-A OUTPUT -d 10.0.0.50/32 -p tcp --dport 22") {
		t.Errorf("expected OUTPUT rule on client for bidirectional policy, got:\n%s", outputClient)
	}
}

// Test __any_ip__ special target (ID 6)
func TestResolver_AnyIP(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()
	database.Exec("PRAGMA foreign_keys=OFF")
	r := &Resolver{db: database}

	// Test that __any_ip__ returns 0.0.0.0/0
	result, err := r.ResolveSpecialTarget(context.Background(), 6, "10.0.0.1")
	if err != nil {
		t.Fatalf("ResolveSpecialTarget failed: %v", err)
	}

	if len(result) != 1 {
		t.Errorf("expected 1 result, got %d: %v", len(result), result)
	}

	if result[0] != "0.0.0.0/0" {
		t.Errorf("expected 0.0.0.0/0, got %s", result[0])
	}
}

// Test __all_peers__ special target (ID 7) with peers in database
func TestResolver_AllPeers(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()
	database.Exec("PRAGMA foreign_keys=OFF")

	// Insert multiple peers
	insertPeer(t, database, "peer1", "10.0.0.1", false)
	insertPeer(t, database, "peer2", "10.0.0.2", false)
	insertPeer(t, database, "peer3", "192.168.1.100", false)

	r := &Resolver{db: database}

	// Test that __all_peers__ returns all peer IPs
	result, err := r.ResolveSpecialTarget(context.Background(), 7, "10.0.0.50")
	if err != nil {
		t.Fatalf("ResolveSpecialTarget failed: %v", err)
	}

	if len(result) != 3 {
		t.Errorf("expected 3 peers, got %d: %v", len(result), result)
	}

	// Check that all expected IPs are present
	expectedIPs := map[string]bool{
		"10.0.0.1":      false,
		"10.0.0.2":      false,
		"192.168.1.100": false,
	}

	for _, ip := range result {
		if _, ok := expectedIPs[ip]; !ok {
			t.Errorf("unexpected IP in result: %s", ip)
		} else {
			expectedIPs[ip] = true
		}
	}

	for ip, found := range expectedIPs {
		if !found {
			t.Errorf("expected IP not found: %s", ip)
		}
	}
}

// Test __all_peers__ special target (ID 7) with empty peer list
func TestResolver_AllPeers_Empty(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()
	database.Exec("PRAGMA foreign_keys=OFF")
	r := &Resolver{db: database}

	// Test that __all_peers__ returns empty slice when no peers exist
	result, err := r.ResolveSpecialTarget(context.Background(), 7, "10.0.0.50")
	if err != nil {
		t.Fatalf("ResolveSpecialTarget failed: %v", err)
	}

	if len(result) != 0 {
		t.Errorf("expected empty result, got %d items: %v", len(result), result)
	}

	if result == nil {
		t.Error("expected non-nil empty slice, got nil")
	}
}

// Test PreviewCompile with target_scope = "docker"
func TestPreviewCompile_DockerScope(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()
	database.Exec("PRAGMA foreign_keys=OFF")

	// Create source and target peers
	sourcePeer := insertPeer(t, database, "source", "10.0.0.1", false)
	targetPeer := insertPeer(t, database, "target", "10.0.0.2", false)

	// Create service
	serviceID := insertService(t, database, "web", "80", "tcp")

	c := NewCompiler(database)

	// Preview with target_scope = "docker"
	rules, err := c.PreviewCompile(context.Background(), 0, sourcePeer, "peer", targetPeer, "peer", serviceID, "both", "docker")
	if err != nil {
		t.Fatalf("PreviewCompile failed: %v", err)
	}

	// Should generate DOCKER-USER rules (target_scope=docker adds Docker-specific rules)
	hasDockerUserRules := false
	for _, rule := range rules {
		if strings.Contains(rule, "DOCKER-USER") {
			hasDockerUserRules = true
			break
		}
	}

	if !hasDockerUserRules {
		t.Errorf("expected DOCKER-USER rules for target_scope=docker, got: %v", rules)
	}

	// Verify the DOCKER-USER rules have the expected content
	dockerRuleCount := 0
	for _, rule := range rules {
		if strings.Contains(rule, "DOCKER-USER") {
			dockerRuleCount++
		}
	}

	if dockerRuleCount == 0 {
		t.Errorf("expected at least one DOCKER-USER rule, got: %v", rules)
	}
}

// Test PreviewCompile with target_scope = "host"
func TestPreviewCompile_HostScope(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()
	database.Exec("PRAGMA foreign_keys=OFF")

	// Create source and target peers
	sourcePeer := insertPeer(t, database, "source", "10.0.0.1", false)
	targetPeer := insertPeer(t, database, "target", "10.0.0.2", false)

	// Create service
	serviceID := insertService(t, database, "web", "80", "tcp")

	c := NewCompiler(database)

	// Preview with target_scope = "host"
	rules, err := c.PreviewCompile(context.Background(), 0, sourcePeer, "peer", targetPeer, "peer", serviceID, "both", "host")
	if err != nil {
		t.Fatalf("PreviewCompile failed: %v", err)
	}

	// Should generate standard INPUT/OUTPUT rules
	hasInputRule := false
	hasOutputRule := false
	for _, rule := range rules {
		if strings.Contains(rule, "-A INPUT") {
			hasInputRule = true
		}
		if strings.Contains(rule, "-A OUTPUT") {
			hasOutputRule = true
		}
	}

	if !hasInputRule {
		t.Errorf("expected INPUT rule for target_scope=host, got: %v", rules)
	}
	if !hasOutputRule {
		t.Errorf("expected OUTPUT rule for target_scope=host, got: %v", rules)
	}

	// Should NOT generate DOCKER-USER rules (target_scope=host means no Docker rules)
	for _, rule := range rules {
		if strings.Contains(rule, "DOCKER-USER") {
			t.Errorf("unexpected DOCKER-USER rule for target_scope=host: %s", rule)
		}
	}
}

// Test PreviewCompile with target_scope = "both"
func TestPreviewCompile_BothScope(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()
	database.Exec("PRAGMA foreign_keys=OFF")

	// Create source and target peers
	sourcePeer := insertPeer(t, database, "source", "10.0.0.1", false)
	targetPeer := insertPeer(t, database, "target", "10.0.0.2", false)

	// Create service
	serviceID := insertService(t, database, "web", "80", "tcp")

	c := NewCompiler(database)

	// Preview with target_scope = "both"
	rules, err := c.PreviewCompile(context.Background(), 0, sourcePeer, "peer", targetPeer, "peer", serviceID, "both", "both")
	if err != nil {
		t.Fatalf("PreviewCompile failed: %v", err)
	}

	// Should generate both standard INPUT/OUTPUT rules AND DOCKER-USER rules
	hasInputRule := false
	hasOutputRule := false
	hasDockerUserRules := false
	for _, rule := range rules {
		if strings.Contains(rule, "-A INPUT") && !strings.Contains(rule, "DOCKER-USER") {
			hasInputRule = true
		}
		if strings.Contains(rule, "-A OUTPUT") && !strings.Contains(rule, "DOCKER-USER") {
			hasOutputRule = true
		}
		if strings.Contains(rule, "DOCKER-USER") {
			hasDockerUserRules = true
		}
	}

	if !hasInputRule {
		t.Errorf("expected INPUT rule for target_scope=both, got: %v", rules)
	}
	if !hasOutputRule {
		t.Errorf("expected OUTPUT rule for target_scope=both, got: %v", rules)
	}
	if !hasDockerUserRules {
		t.Errorf("expected DOCKER-USER rules for target_scope=both, got: %v", rules)
	}
}

// TestIGMPService verifies that IGMP service generates fixed rules without conntrack
func TestIGMPService(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()
	database.Exec("PRAGMA foreign_keys=OFF")
	peerID := insertPeer(t, database, "igmp1", "192.168.1.50", false)
	groupID := insertGroup(t, database, "igmp-group")
	manualPeerID := insertManualPeer(t, database, "10.0.8.0/24")
	insertGroupMember(t, database, groupID, manualPeerID)
	// Insert IGMP service
	serviceID := insertService(t, database, "IGMP", "", "igmp")
	insertPolicy(t, database, "allow-igmp", groupID, serviceID, peerID, "ACCEPT", 100, true)

	c := NewCompiler(database)
	output, err := c.Compile(context.Background(), peerID)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	// Should have fixed IGMP rules
	if !strings.Contains(output, "-A INPUT -d 224.0.0.1/32 -p igmp -j ACCEPT") {
		t.Errorf("expected INPUT rule for IGMP queries (224.0.0.1), got:\n%s", output)
	}
	if !strings.Contains(output, "-A OUTPUT -d 224.0.0.22/32 -p igmp -j ACCEPT") {
		t.Errorf("expected OUTPUT rule for IGMPv3 reports (224.0.0.22), got:\n%s", output)
	}
}

// TestIGMPService_NoConntrack verifies no conntrack rules are generated for IGMP
func TestIGMPService_NoConntrack(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()
	database.Exec("PRAGMA foreign_keys=OFF")
	peerID := insertPeer(t, database, "igmp-nc", "192.168.1.51", false)
	groupID := insertGroup(t, database, "igmp-nc-group")
	manualPeerID := insertManualPeer(t, database, "10.0.9.0/24")
	insertGroupMember(t, database, groupID, manualPeerID)
	serviceID := insertService(t, database, "IGMP", "", "igmp")
	insertPolicy(t, database, "allow-igmp-nc", groupID, serviceID, peerID, "ACCEPT", 100, true)

	c := NewCompiler(database)
	output, err := c.Compile(context.Background(), peerID)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	// Should NOT have conntrack on any IGMP rule (check per-line)
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, "igmp") && strings.Contains(line, "conntrack") {
			t.Errorf("IGMP rule should not use conntrack: %s", line)
		}
	}
}

// TestIGMPService_NoReturnRules verifies no return rules are generated for IGMP
func TestIGMPService_NoReturnRules(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()
	database.Exec("PRAGMA foreign_keys=OFF")
	peerID := insertPeer(t, database, "igmp-nr", "192.168.1.52", false)
	groupID := insertGroup(t, database, "igmp-nr-group")
	manualPeerID := insertManualPeer(t, database, "10.0.10.0/24")
	insertGroupMember(t, database, groupID, manualPeerID)
	serviceID := insertService(t, database, "IGMP", "", "igmp")
	insertPolicy(t, database, "allow-igmp-nr", groupID, serviceID, peerID, "ACCEPT", 100, true)

	c := NewCompiler(database)
	output, err := c.Compile(context.Background(), peerID)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	// IGMP should only have the two fixed rules, no source-based rules
	// Count IGMP-related rules - should be exactly 2 (INPUT + OUTPUT)
	igmpRuleCount := 0
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, "-p igmp") && strings.Contains(line, "-A") {
			igmpRuleCount++
		}
	}
	if igmpRuleCount != 2 {
		t.Errorf("expected exactly 2 IGMP rules (INPUT + OUTPUT), got %d:\n%s", igmpRuleCount, output)
	}
}

// TestIGMPService_WithDocker verifies IGMP generates DOCKER-USER rules when Docker is enabled
func TestIGMPService_WithDocker(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()
	database.Exec("PRAGMA foreign_keys=OFF")
	peerID := insertPeer(t, database, "igmp-docker", "192.168.1.53", true)
	groupID := insertGroup(t, database, "igmp-docker-group")
	manualPeerID := insertManualPeer(t, database, "10.0.11.0/24")
	insertGroupMember(t, database, groupID, manualPeerID)
	serviceID := insertService(t, database, "IGMP", "", "igmp")
	insertPolicy(t, database, "allow-igmp-docker", groupID, serviceID, peerID, "ACCEPT", 100, true)

	c := NewCompiler(database)
	output, err := c.Compile(context.Background(), peerID)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	// Should have standard IGMP rules
	if !strings.Contains(output, "-A INPUT -d 224.0.0.1/32 -p igmp -j ACCEPT") {
		t.Errorf("expected INPUT rule for IGMP queries, got:\n%s", output)
	}
	if !strings.Contains(output, "-A OUTPUT -d 224.0.0.22/32 -p igmp -j ACCEPT") {
		t.Errorf("expected OUTPUT rule for IGMPv3 reports, got:\n%s", output)
	}

	// Should have DOCKER-USER rules for IGMP
	if !strings.Contains(output, "-A DOCKER-USER -d 224.0.0.1/32 -p igmp -j ACCEPT") {
		t.Errorf("expected DOCKER-USER rule for IGMP queries (224.0.0.1), got:\n%s", output)
	}
	if !strings.Contains(output, "-A DOCKER-USER -d 224.0.0.22/32 -p igmp -j ACCEPT") {
		t.Errorf("expected DOCKER-USER rule for IGMPv3 reports (224.0.0.22), got:\n%s", output)
	}
}

// TestPreviewCompile_IGMP verifies PreviewCompile handles IGMP correctly
func TestPreviewCompile_IGMP(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()
	database.Exec("PRAGMA foreign_keys=OFF")

	// Create source and target peers
	sourcePeer := insertPeer(t, database, "igmp-source", "10.0.0.1", false)
	targetPeer := insertPeer(t, database, "igmp-target", "10.0.0.2", false)

	// Create IGMP service
	serviceID := insertService(t, database, "IGMP", "", "igmp")

	c := NewCompiler(database)

	// Preview with IGMP service
	rules, err := c.PreviewCompile(context.Background(), 0, sourcePeer, "peer", targetPeer, "peer", serviceID, "both", "both")
	if err != nil {
		t.Fatalf("PreviewCompile failed: %v", err)
	}

	// Should generate fixed IGMP rules
	hasInputRule := false
	hasOutputRule := false
	for _, rule := range rules {
		if strings.Contains(rule, "-A INPUT -d 224.0.0.1/32 -p igmp -j ACCEPT") {
			hasInputRule = true
		}
		if strings.Contains(rule, "-A OUTPUT -d 224.0.0.22/32 -p igmp -j ACCEPT") {
			hasOutputRule = true
		}
	}

	if !hasInputRule {
		t.Errorf("expected INPUT rule for IGMP in preview, got: %v", rules)
	}
	if !hasOutputRule {
		t.Errorf("expected OUTPUT rule for IGMP in preview, got: %v", rules)
	}

	// Should NOT have conntrack rules for IGMP
	for _, rule := range rules {
		if strings.Contains(rule, "igmp") && strings.Contains(rule, "conntrack") {
			t.Errorf("IGMP preview rules should not use conntrack: %s", rule)
		}
	}

	// Should have DOCKER-USER rules for IGMP (target_scope=both)
	hasDockerIGMP := false
	for _, rule := range rules {
		if strings.Contains(rule, "DOCKER-USER") && strings.Contains(rule, "igmp") {
			hasDockerIGMP = true
			break
		}
	}
	if !hasDockerIGMP {
		t.Errorf("expected DOCKER-USER rules for IGMP in preview (target_scope=both), got: %v", rules)
	}
}

// TestMulticastPolicy_SourceIsMulticastSpecial verifies that when Source is a multicast special target,
// the compiler generates INPUT rules for receiving multicast traffic
func TestMulticastPolicy_SourceIsMulticastSpecial(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()
	database.Exec("PRAGMA foreign_keys=OFF")

	peerID := insertPeer(t, database, "mcast-receiver", "192.168.1.100", false)

	// Insert Multicast service
	result, _ := database.Exec(
		`INSERT INTO services (name, ports, protocol, description, is_system) VALUES (?, ?, ?, ?, 1)`,
		"Multicast", "", "udp", "Multicast traffic handling")
	serviceID, _ := result.LastInsertId()

	// Policy with Source = special 3 (All Hosts IGMP), Target = peer
	// This means the peer receives multicast traffic from the All Hosts multicast group
	_, err := database.Exec(
		`INSERT INTO policies (name, source_id, source_type, service_id, target_id, target_type, action, priority, enabled, target_scope)
		VALUES (?, 3, 'special', ?, ?, 'peer', 'ACCEPT', 100, 1, 'host')`,
		"multicast-receive", serviceID, peerID)
	if err != nil {
		t.Fatalf("insert policy: %v", err)
	}

	c := NewCompiler(database)
	output, err := c.Compile(context.Background(), peerID)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	// Should have INPUT rule for receiving multicast from the special source
	if !strings.Contains(output, "-A INPUT -m pkttype --pkt-type multicast -j ACCEPT") {
		t.Errorf("expected INPUT multicast rule for receiving multicast from special source, got:\n%s", output)
	}
}

// TestMulticastPolicy_SourceIsMulticastSpecial_WithService verifies multicast special source with non-Multicast service
func TestMulticastPolicy_SourceIsMulticastSpecial_WithService(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()
	database.Exec("PRAGMA foreign_keys=OFF")

	peerID := insertPeer(t, database, "mcast-service-receiver", "192.168.1.101", false)

	// Create a service (e.g., mDNS on port 5353 UDP)
	serviceID := insertService(t, database, "mdns", "5353", "udp")

	// Policy with Source = special 4 (mDNS multicast address), Target = peer
	// This means the peer receives mDNS multicast traffic
	_, err := database.Exec(
		`INSERT INTO policies (name, source_id, source_type, service_id, target_id, target_type, action, priority, enabled, target_scope)
		VALUES (?, 4, 'special', ?, ?, 'peer', 'ACCEPT', 100, 1, 'host')`,
		"mdns-receive", serviceID, peerID)
	if err != nil {
		t.Fatalf("insert policy: %v", err)
	}

	c := NewCompiler(database)
	output, err := c.Compile(context.Background(), peerID)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	// Should have INPUT rule for receiving multicast traffic (packet type matching)
	// The multicast special source generates packet type matching, not source IP matching
	if !strings.Contains(output, "-A INPUT -m pkttype --pkt-type multicast -j ACCEPT") {
		t.Errorf("expected INPUT multicast rule for mDNS service, got:\n%s", output)
	}

	// Verify that As Target section is present with multicast special source
	if !strings.Contains(output, "# As Target (Ingress from mDNS)") {
		t.Errorf("expected 'As Target (Ingress from mDNS)' comment, got:\n%s", output)
	}
}
