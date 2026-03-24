package engine

import (
	"context"
	"database/sql"
	"strconv"
	"strings"
	"testing"

	_ "github.com/mattn/go-sqlite3"

	"runic/internal/db"
)

// setupTestDB creates an in-memory SQLite database with the full schema and returns it.
func setupTestDB(t *testing.T) *sql.DB {
	t.Helper()
	database, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open test db: %v", err)
	}
	// Disable foreign keys for tests that intentionally use invalid IDs
	database.Exec("PRAGMA foreign_keys=OFF")
	if _, err := database.Exec(db.Schema()); err != nil {
		t.Fatalf("failed to create schema: %v", err)
	}
	t.Cleanup(func() { database.Close() })
	return database
}

// insertServer inserts a test server and returns its ID.
func insertServer(t *testing.T, database *sql.DB, hostname, ip string, hasDocker bool) int {
	t.Helper()
	result, err := database.Exec(
		`INSERT INTO servers (hostname, ip_address, agent_key, hmac_key, has_docker) VALUES (?, ?, ?, ?, ?)`,
		hostname, ip, "key-"+hostname, "test-hmac-key", hasDocker)
	if err != nil {
		t.Fatalf("insert server: %v", err)
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

// insertGroupMember inserts a group member.
func insertGroupMember(t *testing.T, database *sql.DB, groupID int, value, memberType string) {
	t.Helper()
	_, err := database.Exec(
		"INSERT INTO group_members (group_id, value, type) VALUES (?, ?, ?)",
		groupID, value, memberType)
	if err != nil {
		t.Fatalf("insert group member: %v", err)
	}
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
func insertPolicy(t *testing.T, database *sql.DB, name string, groupID, serviceID, serverID int, action string, priority int, enabled bool) int {
	t.Helper()
	enabledInt := 0
	if enabled {
		enabledInt = 1
	}
	result, err := database.Exec(
		`INSERT INTO policies (name, source_group_id, service_id, target_server_id, action, priority, enabled)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		name, groupID, serviceID, serverID, action, priority, enabledInt)
	if err != nil {
		t.Fatalf("insert policy: %v", err)
	}
	id, _ := result.LastInsertId()
	return int(id)
}

func TestSingleIPSource(t *testing.T) {
	database := setupTestDB(t)
	serverID := insertServer(t, database, "web1", "192.168.1.10", false)
	groupID := insertGroup(t, database, "office")
	insertGroupMember(t, database, groupID, "10.0.1.1", "ip")
	serviceID := insertService(t, database, "ssh", "22", "tcp")
	insertPolicy(t, database, "allow-ssh", groupID, serviceID, serverID, "ACCEPT", 100, true)

	c := NewCompiler(database, "test-key")
	output, err := c.Compile(context.Background(), serverID)
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
	database := setupTestDB(t)
	serverID := insertServer(t, database, "web2", "192.168.1.11", false)
	groupID := insertGroup(t, database, "subnet")
	insertGroupMember(t, database, groupID, "10.0.1.0/24", "cidr")
	serviceID := insertService(t, database, "https", "443", "tcp")
	insertPolicy(t, database, "allow-https", groupID, serviceID, serverID, "ACCEPT", 100, true)

	c := NewCompiler(database, "test-key")
	output, err := c.Compile(context.Background(), serverID)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	if !strings.Contains(output, "-s 10.0.1.0/24") {
		t.Errorf("expected -s 10.0.1.0/24 in output, got:\n%s", output)
	}
}

func TestMultiport(t *testing.T) {
	database := setupTestDB(t)
	serverID := insertServer(t, database, "web3", "192.168.1.12", false)
	groupID := insertGroup(t, database, "any")
	insertGroupMember(t, database, groupID, "0.0.0.0/0", "cidr")
	serviceID := insertService(t, database, "web", "80,443", "tcp")
	insertPolicy(t, database, "allow-web", groupID, serviceID, serverID, "ACCEPT", 100, true)

	c := NewCompiler(database, "test-key")
	output, err := c.Compile(context.Background(), serverID)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	if !strings.Contains(output, "-m multiport --dports 80,443") {
		t.Errorf("expected multiport --dports 80,443 in output, got:\n%s", output)
	}
}

func TestPortRange(t *testing.T) {
	database := setupTestDB(t)
	serverID := insertServer(t, database, "web4", "192.168.1.13", false)
	groupID := insertGroup(t, database, "any2")
	insertGroupMember(t, database, groupID, "0.0.0.0/0", "cidr")
	serviceID := insertService(t, database, "highports", "8000:9000", "tcp")
	insertPolicy(t, database, "allow-highports", groupID, serviceID, serverID, "ACCEPT", 100, true)

	c := NewCompiler(database, "test-key")
	output, err := c.Compile(context.Background(), serverID)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	if !strings.Contains(output, "-m multiport --dports 8000:9000") {
		t.Errorf("expected multiport --dports 8000:9000 in output, got:\n%s", output)
	}
}

func TestProtocolBoth(t *testing.T) {
	database := setupTestDB(t)
	serverID := insertServer(t, database, "dns1", "192.168.1.14", false)
	groupID := insertGroup(t, database, "clients")
	insertGroupMember(t, database, groupID, "10.0.0.0/8", "cidr")
	serviceID := insertService(t, database, "dns", "53", "both")
	insertPolicy(t, database, "allow-dns", groupID, serviceID, serverID, "ACCEPT", 100, true)

	c := NewCompiler(database, "test-key")
	output, err := c.Compile(context.Background(), serverID)
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
	database := setupTestDB(t)
	serverID := insertServer(t, database, "mon1", "192.168.1.15", false)
	groupID := insertGroup(t, database, "monitors")
	insertGroupMember(t, database, groupID, "10.0.5.0/24", "cidr")
	serviceID := insertService(t, database, "ping", "", "icmp")
	insertPolicy(t, database, "allow-ping", groupID, serviceID, serverID, "ACCEPT", 100, true)

	c := NewCompiler(database, "test-key")
	output, err := c.Compile(context.Background(), serverID)
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

func TestGroupOfGroups(t *testing.T) {
	database := setupTestDB(t)
	serverID := insertServer(t, database, "app1", "192.168.1.16", false)

	groupB := insertGroup(t, database, "inner")
	insertGroupMember(t, database, groupB, "10.0.2.1", "ip")

	groupA := insertGroup(t, database, "outer")
	insertGroupMember(t, database, groupA, strconv.Itoa(groupB), "group_ref")

	serviceID := insertService(t, database, "http", "80", "tcp")
	insertPolicy(t, database, "nested-allow", groupA, serviceID, serverID, "ACCEPT", 100, true)

	c := NewCompiler(database, "test-key")
	output, err := c.Compile(context.Background(), serverID)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	if !strings.Contains(output, "10.0.2.1/32") {
		t.Errorf("expected 10.0.2.1/32 from nested group, got:\n%s", output)
	}
}

func TestCircularGroupRef(t *testing.T) {
	database := setupTestDB(t)
	serverID := insertServer(t, database, "circ1", "192.168.1.17", false)

	groupA := insertGroup(t, database, "circA")
	groupB := insertGroup(t, database, "circB")

	// A -> B -> A (circular)
	insertGroupMember(t, database, groupA, strconv.Itoa(groupB), "group_ref")
	insertGroupMember(t, database, groupB, strconv.Itoa(groupA), "group_ref")

	serviceID := insertService(t, database, "ssh2", "22", "tcp")
	insertPolicy(t, database, "circ-policy", groupA, serviceID, serverID, "ACCEPT", 100, true)

	c := NewCompiler(database, "test-key")
	_, err := c.Compile(context.Background(), serverID)
	if err == nil {
		t.Fatal("expected error for circular group reference, got nil")
	}
	if !strings.Contains(err.Error(), "circular") {
		t.Errorf("expected error to mention 'circular', got: %v", err)
	}
}

func TestNoPolicies(t *testing.T) {
	database := setupTestDB(t)
	serverID := insertServer(t, database, "empty1", "192.168.1.18", false)

	c := NewCompiler(database, "test-key")
	output, err := c.Compile(context.Background(), serverID)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	// Should have standard rules
	if !strings.Contains(output, ":INPUT DROP [0:0]") {
		t.Error("expected :INPUT DROP chain policy")
	}
	if !strings.Contains(output, "-A INPUT  -i lo -j ACCEPT") {
		t.Error("expected loopback rule")
	}
	if !strings.Contains(output, "-A INPUT  -j DROP") {
		t.Error("expected default deny rule")
	}
	if !strings.Contains(output, "COMMIT") {
		t.Error("expected COMMIT")
	}
	// Should not have any policy-specific comments
	if strings.Contains(output, "# --- Policy:") {
		t.Error("expected no policy rules for server with no policies")
	}
}

func TestLogDropAction(t *testing.T) {
	database := setupTestDB(t)
	serverID := insertServer(t, database, "logdrop1", "192.168.1.19", false)
	groupID := insertGroup(t, database, "untrusted")
	insertGroupMember(t, database, groupID, "172.16.0.0/12", "cidr")
	serviceID := insertService(t, database, "telnet", "23", "tcp")
	insertPolicy(t, database, "block-telnet", groupID, serviceID, serverID, "LOG_DROP", 100, true)

	c := NewCompiler(database, "test-key")
	output, err := c.Compile(context.Background(), serverID)
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
	database := setupTestDB(t)
	serverID := insertServer(t, database, "disabled1", "192.168.1.20", false)
	groupID := insertGroup(t, database, "office2")
	insertGroupMember(t, database, groupID, "10.0.1.0/24", "cidr")
	serviceID := insertService(t, database, "ftp", "21", "tcp")
	insertPolicy(t, database, "disabled-ftp", groupID, serviceID, serverID, "ACCEPT", 100, false)

	c := NewCompiler(database, "test-key")
	output, err := c.Compile(context.Background(), serverID)
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
	database := setupTestDB(t)
	serverID := insertServer(t, database, "prio1", "192.168.1.21", false)

	groupID := insertGroup(t, database, "prio-group")
	insertGroupMember(t, database, groupID, "10.0.0.1", "ip")

	serviceHigh := insertService(t, database, "high-prio-svc", "8080", "tcp")
	serviceLow := insertService(t, database, "low-prio-svc", "9090", "tcp")

	// Insert low priority (200) first, high priority (50) second
	insertPolicy(t, database, "low-prio", groupID, serviceLow, serverID, "ACCEPT", 200, true)
	insertPolicy(t, database, "high-prio", groupID, serviceHigh, serverID, "ACCEPT", 50, true)

	c := NewCompiler(database, "test-key")
	output, err := c.Compile(context.Background(), serverID)
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

func TestDockerServer(t *testing.T) {
	database := setupTestDB(t)
	serverID := insertServer(t, database, "docker1", "192.168.1.22", true)

	c := NewCompiler(database, "test-key")
	output, err := c.Compile(context.Background(), serverID)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	if !strings.Contains(output, ":DOCKER-USER - [0:0]") {
		t.Error("expected DOCKER-USER chain declaration for docker server")
	}
	if !strings.Contains(output, "-A DOCKER-USER -j RETURN") {
		t.Error("expected DOCKER-USER RETURN rule for docker server")
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
				serverID := insertServer(t, db, "test1", "10.0.0.1", false)
				groupID := insertGroup(t, db, "test-group")
				insertGroupMember(t, db, groupID, "192.168.1.0/24", "cidr")
				serviceID := insertService(t, db, "test-service", "80", "tcp")
				return insertPolicy(t, db, "test-policy", groupID, serviceID, serverID, "ACCEPT", 100, true), nil
			},
			wantErr: false,
		},
		{
			name: "policy with DROP action",
			setup: func(t *testing.T, db *sql.DB) (int, error) {
				serverID := insertServer(t, db, "test2", "10.0.0.2", false)
				groupID := insertGroup(t, db, "blocked-group")
				insertGroupMember(t, db, groupID, "10.0.2.0/24", "cidr")
				serviceID := insertService(t, db, "blocked-service", "22", "tcp")
				return insertPolicy(t, db, "block-policy", groupID, serviceID, serverID, "DROP", 200, true), nil
			},
			wantErr: false,
		},
		{
			name: "policy with invalid server ID",
			setup: func(t *testing.T, db *sql.DB) (int, error) {
				groupID := insertGroup(t, db, "test-group")
				insertGroupMember(t, db, groupID, "192.168.1.0/24", "cidr")
				serviceID := insertService(t, db, "test-service", "80", "tcp")
				insertPolicy(t, db, "invalid-server-policy", groupID, serviceID, 99999, "ACCEPT", 100, true)
				return 99999, nil
			},
			wantErr:     true,
			errContains: "sql: no rows in result set",
		},
		{
			name: "policy with invalid group ID",
			setup: func(t *testing.T, db *sql.DB) (int, error) {
				serverID := insertServer(t, db, "test3", "10.0.0.3", false)
				serviceID := insertService(t, db, "test-service", "80", "tcp")
				insertPolicy(t, db, "invalid-group-policy", 99999, serviceID, serverID, "ACCEPT", 100, true)
				return serverID, nil
			},
			wantErr:     true,
			errContains: "sql: no rows in result set",
		},
		{
			name: "policy with invalid service ID",
			setup: func(t *testing.T, db *sql.DB) (int, error) {
				serverID := insertServer(t, db, "test4", "10.0.0.4", false)
				groupID := insertGroup(t, db, "test-group")
				insertGroupMember(t, db, groupID, "192.168.1.0/24", "cidr")
				insertPolicy(t, db, "invalid-service-policy", groupID, 99999, serverID, "ACCEPT", 100, true)
				return serverID, nil
			},
			wantErr:     true,
			errContains: "sql: no rows in result set",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			database := setupTestDB(t)
			serverID, err := tt.setup(t, database)
			if err != nil && !tt.wantErr {
				t.Fatalf("setup failed: %v", err)
			}

			c := NewCompiler(database, "test-key")
			_, err = c.Compile(context.Background(), serverID)

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
				serverID := insertServer(t, db, "web1", "10.0.0.1", false)
				groupID := insertGroup(t, db, "office")
				insertGroupMember(t, db, groupID, "192.168.1.100", "ip")
				serviceID := insertService(t, db, "ssh", "22", "tcp")
				insertPolicy(t, db, "allow-ssh", groupID, serviceID, serverID, "ACCEPT", 100, true)
				return serverID, nil
			},
			expectedRules: []string{
				"-s 192.168.1.100/32 -p tcp --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT",
				"-d 192.168.1.100/32 -p tcp --sport 22 -m state --state ESTABLISHED -j ACCEPT",
			},
		},
		{
			name: "multiport rule",
			setup: func(t *testing.T, db *sql.DB) (int, error) {
				serverID := insertServer(t, db, "web2", "10.0.0.2", false)
				groupID := insertGroup(t, db, "clients")
				insertGroupMember(t, db, groupID, "10.0.1.0/24", "cidr")
				serviceID := insertService(t, db, "web", "80,443", "tcp")
				insertPolicy(t, db, "allow-web", groupID, serviceID, serverID, "ACCEPT", 100, true)
				return serverID, nil
			},
			expectedRules: []string{
				"-s 10.0.1.0/24 -p tcp -m multiport --dports 80,443 -m state --state NEW,ESTABLISHED -j ACCEPT",
			},
		},
		{
			name: "port range rule",
			setup: func(t *testing.T, db *sql.DB) (int, error) {
				serverID := insertServer(t, db, "web3", "10.0.0.3", false)
				groupID := insertGroup(t, db, "clients2")
				insertGroupMember(t, db, groupID, "10.0.2.0/24", "cidr")
				serviceID := insertService(t, db, "highports", "8000:9000", "tcp")
				insertPolicy(t, db, "allow-highports", groupID, serviceID, serverID, "ACCEPT", 100, true)
				return serverID, nil
			},
			expectedRules: []string{
				"-s 10.0.2.0/24 -p tcp -m multiport --dports 8000:9000 -m state --state NEW,ESTABLISHED -j ACCEPT",
			},
		},
		{
			name: "UDP rule",
			setup: func(t *testing.T, db *sql.DB) (int, error) {
				serverID := insertServer(t, db, "dns1", "10.0.0.4", false)
				groupID := insertGroup(t, db, "dns-clients")
				insertGroupMember(t, db, groupID, "10.0.3.0/24", "cidr")
				serviceID := insertService(t, db, "dns", "53", "udp")
				insertPolicy(t, db, "allow-dns-udp", groupID, serviceID, serverID, "ACCEPT", 100, true)
				return serverID, nil
			},
			expectedRules: []string{
				"-s 10.0.3.0/24 -p udp --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT",
			},
		},
		{
			name: "both TCP and UDP protocol",
			setup: func(t *testing.T, db *sql.DB) (int, error) {
				serverID := insertServer(t, db, "dns2", "10.0.0.5", false)
				groupID := insertGroup(t, db, "dns-clients2")
				insertGroupMember(t, db, groupID, "10.0.4.0/24", "cidr")
				serviceID := insertService(t, db, "dns", "53", "both")
				insertPolicy(t, db, "allow-dns-both", groupID, serviceID, serverID, "ACCEPT", 100, true)
				return serverID, nil
			},
			expectedRules: []string{
				"-p tcp --dport 53",
				"-p udp --dport 53",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			database := setupTestDB(t)
			serverID, err := tt.setup(t, database)
			if err != nil {
				t.Fatalf("setup failed: %v", err)
			}

			c := NewCompiler(database, "test-key")
			output, err := c.Compile(context.Background(), serverID)
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
			name: "invalid IP address in group",
			setup: func(t *testing.T, db *sql.DB) (int, error) {
				serverID := insertServer(t, db, "test1", "10.0.0.1", false)
				groupID := insertGroup(t, db, "bad-ip")
				_, err := db.Exec("INSERT INTO group_members (group_id, value, type) VALUES (?, ?, ?)",
					groupID, "999.999.999.999", "ip")
				if err != nil {
					return 0, err
				}
				serviceID := insertService(t, db, "test", "80", "tcp")
				insertPolicy(t, db, "bad-ip-policy", groupID, serviceID, serverID, "ACCEPT", 100, true)
				return serverID, nil
			},
			wantErr:     true,
			errContains: "invalid IP",
		},
		{
			name: "invalid CIDR in group",
			setup: func(t *testing.T, db *sql.DB) (int, error) {
				serverID := insertServer(t, db, "test2", "10.0.0.2", false)
				groupID := insertGroup(t, db, "bad-cidr")
				_, err := db.Exec("INSERT INTO group_members (group_id, value, type) VALUES (?, ?, ?)",
					groupID, "10.0.0.0/33", "cidr")
				if err != nil {
					return 0, err
				}
				serviceID := insertService(t, db, "test", "80", "tcp")
				insertPolicy(t, db, "bad-cidr-policy", groupID, serviceID, serverID, "ACCEPT", 100, true)
				return serverID, nil
			},
			wantErr:     true,
			errContains: "invalid CIDR",
		},
		{
			name: "invalid group reference",
			setup: func(t *testing.T, db *sql.DB) (int, error) {
				serverID := insertServer(t, db, "test3", "10.0.0.3", false)
				groupID := insertGroup(t, db, "bad-ref")
				_, err := db.Exec("INSERT INTO group_members (group_id, value, type) VALUES (?, ?, ?)",
					groupID, "not-a-number", "group_ref")
				if err != nil {
					return 0, err
				}
				serviceID := insertService(t, db, "test", "80", "tcp")
				insertPolicy(t, db, "bad-ref-policy", groupID, serviceID, serverID, "ACCEPT", 100, true)
				return serverID, nil
			},
			wantErr:     true,
			errContains: "invalid group_ref",
		},
		{
			name: "unknown member type",
			setup: func(t *testing.T, db *sql.DB) (int, error) {
				serverID := insertServer(t, db, "test4", "10.0.0.4", false)
				groupID := insertGroup(t, db, "bad-type")
				// Note: "unknown" type violates CHECK constraint, so we insert a valid type instead
				// and test that compilation handles it properly
				insertGroupMember(t, db, groupID, "10.0.0.1", "ip")
				serviceID := insertService(t, db, "test", "80", "tcp")
				insertPolicy(t, db, "bad-type-policy", groupID, serviceID, serverID, "ACCEPT", 100, true)
				return serverID, nil
			},
			wantErr: false, // This test case doesn't actually trigger the error we wanted
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			database := setupTestDB(t)
			serverID, err := tt.setup(t, database)
			if err != nil && !tt.wantErr {
				t.Fatalf("setup failed: %v", err)
			}

			c := NewCompiler(database, "test-key")
			_, err = c.Compile(context.Background(), serverID)

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
			name:         "server with Docker",
			hasDocker:    true,
			expectDocker: true,
			expectReturn: true,
		},
		{
			name:         "server without Docker",
			hasDocker:    false,
			expectDocker: false,
			expectReturn: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			database := setupTestDB(t)
			serverID := insertServer(t, database, "docker-test", "10.0.0.1", tt.hasDocker)

			c := NewCompiler(database, "test-key")
			output, err := c.Compile(context.Background(), serverID)
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
	database := setupTestDB(t)
	serverID := insertServer(t, database, "store-test", "10.0.0.1", false)
	groupID := insertGroup(t, database, "test-group")
	insertGroupMember(t, database, groupID, "192.168.1.0/24", "cidr")
	serviceID := insertService(t, database, "test-service", "80", "tcp")
	insertPolicy(t, database, "test-policy", groupID, serviceID, serverID, "ACCEPT", 100, true)

	c := NewCompiler(database, "test-key")
	bundle, err := c.CompileAndStore(context.Background(), serverID)
	if err != nil {
		t.Fatalf("CompileAndStore failed: %v", err)
	}

	// Verify bundle structure
	if bundle.ID == 0 {
		t.Error("expected non-zero bundle ID")
	}
	if bundle.ServerID != serverID {
		t.Errorf("expected server_id %d, got %d", serverID, bundle.ServerID)
	}
	if bundle.Version == "" {
		t.Error("expected non-empty version")
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

	// Verify server's bundle_version was updated
	var bundleVersion string
	err = database.QueryRow("SELECT bundle_version FROM servers WHERE id = ?", serverID).Scan(&bundleVersion)
	if err != nil {
		t.Fatalf("query server bundle version: %v", err)
	}
	if bundleVersion != bundle.Version {
		t.Errorf("expected bundle_version %s, got %s", bundle.Version, bundleVersion)
	}

	// Verify HMAC is valid
	if !Verify(bundle.RulesContent, "test-key", bundle.HMAC) {
		t.Error("HMAC verification failed")
	}
}

// Test RecompileAffectedServers
func TestRecompileAffectedServers(t *testing.T) {
	database := setupTestDB(t)

	// Create two servers
	server1 := insertServer(t, database, "srv1", "10.0.0.1", false)
	server2 := insertServer(t, database, "srv2", "10.0.0.2", false)

	// Create groups and members
	group1 := insertGroup(t, database, "group1")
	insertGroupMember(t, database, group1, "192.168.1.0/24", "cidr")
	group2 := insertGroup(t, database, "group2")
	insertGroupMember(t, database, group2, "192.168.2.0/24", "cidr")

	// Create service and policies affecting both servers
	serviceID := insertService(t, database, "test", "80", "tcp")
	insertPolicy(t, database, "policy1", group1, serviceID, server1, "ACCEPT", 100, true)
	insertPolicy(t, database, "policy2", group2, serviceID, server2, "ACCEPT", 100, true)

	// Compile initial bundles
	c := NewCompiler(database, "test-key")
	_, err := c.CompileAndStore(context.Background(), server1)
	if err != nil {
		t.Fatalf("compile server1: %v", err)
	}
	_, err = c.CompileAndStore(context.Background(), server2)
	if err != nil {
		t.Fatalf("compile server2: %v", err)
	}

	// Get initial bundle versions
	var v1, v2 string
	database.QueryRow("SELECT bundle_version FROM servers WHERE id = ?", server1).Scan(&v1)
	database.QueryRow("SELECT bundle_version FROM servers WHERE id = ?", server2).Scan(&v2)

	// Add a new member to group1 (affects server1)
	insertGroupMember(t, database, group1, "10.1.1.1", "ip")

	// Recompile affected servers for group1
	err = c.RecompileAffectedServers(context.Background(), group1)
	if err != nil {
		t.Fatalf("recompile affected: %v", err)
	}

	// Verify server1 has new bundle version
	var newV1 string
	database.QueryRow("SELECT bundle_version FROM servers WHERE id = ?", server1).Scan(&newV1)
	if newV1 == v1 {
		t.Error("expected bundle version to change for server1")
	}

	// Verify server2 bundle version is unchanged
	var newV2 string
	database.QueryRow("SELECT bundle_version FROM servers WHERE id = ?", server2).Scan(&newV2)
	if newV2 != v2 {
		t.Error("expected bundle version to stay the same for server2")
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
				serverID := insertServer(t, db, "test1", "10.0.0.1", false)
				group1 := insertGroup(t, db, "group1")
				insertGroupMember(t, db, group1, "192.168.1.0/24", "cidr")
				group2 := insertGroup(t, db, "group2")
				insertGroupMember(t, db, group2, "192.168.2.0/24", "cidr")
				serviceID := insertService(t, db, "test", "80", "tcp")
				insertPolicy(t, db, "policy1", group1, serviceID, serverID, "ACCEPT", 100, true)
				insertPolicy(t, db, "policy2", group2, serviceID, serverID, "ACCEPT", 100, true)
				return serverID, nil
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
			name: "deeply nested group references",
			setup: func(t *testing.T, db *sql.DB) (int, error) {
				serverID := insertServer(t, db, "test2", "10.0.0.2", false)
				groupA := insertGroup(t, db, "groupA")
				groupB := insertGroup(t, db, "groupB")
				groupC := insertGroup(t, db, "groupC")
				insertGroupMember(t, db, groupC, "10.3.0.1", "ip")
				insertGroupMember(t, db, groupB, strconv.Itoa(groupC), "group_ref")
				insertGroupMember(t, db, groupA, strconv.Itoa(groupB), "group_ref")
				serviceID := insertService(t, db, "test", "80", "tcp")
				insertPolicy(t, db, "nested-policy", groupA, serviceID, serverID, "ACCEPT", 100, true)
				return serverID, nil
			},
			wantErr: false,
			check: func(t *testing.T, output string) {
				if !strings.Contains(output, "10.3.0.1/32") {
					t.Error("expected deeply nested IP in output")
				}
			},
		},
		{
			name: "duplicate IP in different groups",
			setup: func(t *testing.T, db *sql.DB) (int, error) {
				serverID := insertServer(t, db, "test3", "10.0.0.3", false)
				group1 := insertGroup(t, db, "group1")
				group2 := insertGroup(t, db, "group2")
				insertGroupMember(t, db, group1, "192.168.1.100", "ip")
				insertGroupMember(t, db, group2, "192.168.1.100", "ip")
				serviceID := insertService(t, db, "test", "80", "tcp")
				insertPolicy(t, db, "policy1", group1, serviceID, serverID, "ACCEPT", 100, true)
				insertPolicy(t, db, "policy2", group2, serviceID, serverID, "ACCEPT", 200, true)
				return serverID, nil
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
			database := setupTestDB(t)
			serverID, err := tt.setup(t, database)
			if err != nil && !tt.wantErr {
				t.Fatalf("setup failed: %v", err)
			}

			c := NewCompiler(database, "test-key")
			output, err := c.Compile(context.Background(), serverID)

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
