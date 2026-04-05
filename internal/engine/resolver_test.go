package engine

import (
	"context"
	"database/sql"
	"fmt"
	"testing"

	_ "github.com/mattn/go-sqlite3"

	"runic/internal/testutil"
)

func TestResolveEntityPeer(t *testing.T) {
	tests := []struct {
		name        string
		setupDB     func(*sql.DB) error
		entityType  string
		entityID    int
		expectCIDRs []string
		expectError bool
	}{
		{
			name: "peer with single IP",
			setupDB: func(db *sql.DB) error {
				_, err := db.Exec(`INSERT INTO peers (id, hostname, ip_address, agent_key, hmac_key) VALUES (1, 'peer1', '192.168.1.10', 'test-agent-key-1', 'test-hmac-key-1')`)
				return err
			},
			entityType:  "peer",
			entityID:    1,
			expectCIDRs: []string{"192.168.1.10/32"},
			expectError: false,
		},
		{
			name: "peer with CIDR notation",
			setupDB: func(db *sql.DB) error {
				_, err := db.Exec(`INSERT INTO peers (id, hostname, ip_address, agent_key, hmac_key) VALUES (2, 'peer2', '10.0.0.0/24', 'test-agent-key-2', 'test-hmac-key-2')`)
				return err
			},
			entityType:  "peer",
			entityID:    2,
			expectCIDRs: []string{"10.0.0.0/24"},
			expectError: false,
		},
		{
			name: "peer with IPv6",
			setupDB: func(db *sql.DB) error {
				_, err := db.Exec(`INSERT INTO peers (id, hostname, ip_address, agent_key, hmac_key) VALUES (3, 'peer6', '::1', 'test-agent-key-3', 'test-hmac-key-3')`)
				return err
			},
			entityType:  "peer",
			entityID:    3,
			expectCIDRs: []string{"::1/32"}, // Note: code adds /32 for all IPs, even IPv6
			expectError: false,
		},
		{
			name: "peer not found",
			setupDB: func(db *sql.DB) error {
				return nil
			},
			entityType:  "peer",
			entityID:    999,
			expectCIDRs: nil,
			expectError: true,
		},
		{
			name: "invalid IP address",
			setupDB: func(db *sql.DB) error {
				_, err := db.Exec(`INSERT INTO peers (id, hostname, ip_address, agent_key, hmac_key) VALUES (4, 'badpeer', 'not-an-ip', 'test-agent-key-4', 'test-hmac-key-4')`)
				return err
			},
			entityType:  "peer",
			entityID:    4,
			expectCIDRs: nil,
			expectError: true,
		},
		{
			name: "invalid CIDR notation",
			setupDB: func(db *sql.DB) error {
				_, err := db.Exec(`INSERT INTO peers (id, hostname, ip_address, agent_key, hmac_key) VALUES (5, 'badcidr', '192.168.1.0/99', 'test-agent-key-5', 'test-hmac-key-5')`)
				return err
			},
			entityType:  "peer",
			entityID:    5,
			expectCIDRs: nil,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, cleanup := testutil.SetupTestDB(t)
			defer cleanup()
			defer cleanup()

			if err := tt.setupDB(db); err != nil {
				t.Fatalf("setupDB failed: %v", err)
			}

			resolver := &Resolver{db: db}
			cidrs, err := resolver.ResolveEntity(context.Background(), tt.entityType, tt.entityID)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if len(cidrs) != len(tt.expectCIDRs) {
				t.Errorf("expected %d CIDRs, got %d", len(tt.expectCIDRs), len(cidrs))
				return
			}

			for i, cidr := range cidrs {
				if cidr != tt.expectCIDRs[i] {
					t.Errorf("CIDR[%d] = %q, want %q", i, cidr, tt.expectCIDRs[i])
				}
			}
		})
	}
}

func TestResolveEntityGroup(t *testing.T) {
	tests := []struct {
		name        string
		setupDB     func(*sql.DB) error
		entityType  string
		entityID    int
		expectCIDRs []string
		expectError bool
	}{
		{
			name: "group with multiple peers",
			setupDB: func(db *sql.DB) error {
				if err := insertPeerForTest(db, 1, "peer1", "192.168.1.10"); err != nil {
					return err
				}
				if err := insertPeerForTest(db, 2, "peer2", "192.168.1.11"); err != nil {
					return err
				}
				if err := insertPeerForTest(db, 3, "peer3", "192.168.1.12"); err != nil {
					return err
				}
				if err := insertGroupForTest(db, 1, "testgroup"); err != nil {
					return err
				}
				if err := insertGroupMemberForTest(db, 1, 1, 1); err != nil {
					return err
				}
				if err := insertGroupMemberForTest(db, 2, 1, 2); err != nil {
					return err
				}
				if err := insertGroupMemberForTest(db, 3, 1, 3); err != nil {
					return err
				}
				return nil
			},
			entityType:  "group",
			entityID:    1,
			expectCIDRs: []string{"192.168.1.10/32", "192.168.1.11/32", "192.168.1.12/32"},
			expectError: false,
		},
		{
			name: "group with CIDR peers",
			setupDB: func(db *sql.DB) error {
				if err := insertPeerForTest(db, 1, "peer1", "10.0.0.0/24"); err != nil {
					return err
				}
				if err := insertPeerForTest(db, 2, "peer2", "172.16.0.0/16"); err != nil {
					return err
				}
				if err := insertGroupForTest(db, 1, "cidrgroup"); err != nil {
					return err
				}
				if err := insertGroupMemberForTest(db, 1, 1, 1); err != nil {
					return err
				}
				if err := insertGroupMemberForTest(db, 2, 1, 2); err != nil {
					return err
				}
				return nil
			},
			entityType:  "group",
			entityID:    1,
			expectCIDRs: []string{"10.0.0.0/24", "172.16.0.0/16"},
			expectError: false,
		},
		{
			name: "empty group",
			setupDB: func(db *sql.DB) error {
				if err := insertGroupForTest(db, 1, "emptygroup"); err != nil {
					return err
				}
				return nil
			},
			entityType:  "group",
			entityID:    1,
			expectCIDRs: nil,
			expectError: false,
		},
		{
			name: "group with duplicate IP peers",
			setupDB: func(db *sql.DB) error {
				if err := insertPeerForTest(db, 1, "peer1", "192.168.1.10"); err != nil {
					return err
				}
				if err := insertPeerForTest(db, 2, "peer2", "192.168.1.10"); err != nil {
					return err
				}
				if err := insertPeerForTest(db, 3, "peer3", "192.168.1.11"); err != nil {
					return err
				}
				if err := insertGroupForTest(db, 1, "dupgroup"); err != nil {
					return err
				}
				if err := insertGroupMemberForTest(db, 1, 1, 1); err != nil {
					return err
				}
				if err := insertGroupMemberForTest(db, 2, 1, 2); err != nil {
					return err
				}
				if err := insertGroupMemberForTest(db, 3, 1, 3); err != nil {
					return err
				}
				return nil
			},
			entityType:  "group",
			entityID:    1,
			expectCIDRs: []string{"192.168.1.10/32", "192.168.1.11/32"}, // deduplicated
			expectError: false,
		},
		{
			name: "group not found",
			setupDB: func(db *sql.DB) error {
				return nil
			},
			entityType:  "group",
			entityID:    999,
			expectCIDRs: nil,
			expectError: false, // empty result, not an error
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, cleanup := testutil.SetupTestDB(t)
			defer cleanup()
			defer cleanup()

			if err := tt.setupDB(db); err != nil {
				t.Fatalf("setupDB failed: %v", err)
			}

			resolver := &Resolver{db: db}
			cidrs, err := resolver.ResolveEntity(context.Background(), tt.entityType, tt.entityID)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if len(cidrs) != len(tt.expectCIDRs) {
				t.Errorf("expected %d CIDRs, got %d", len(tt.expectCIDRs), len(cidrs))
				return
			}

			for i, cidr := range cidrs {
				if cidr != tt.expectCIDRs[i] {
					t.Errorf("CIDR[%d] = %q, want %q", i, cidr, tt.expectCIDRs[i])
				}
			}
		})
	}
}

func TestResolveSpecialTarget(t *testing.T) {
	tests := []struct {
		name          string
		specialID     int
		peerIP        string
		setupDB       func(*sql.DB) error
		expectCIDRs   []string
		expectError   bool
		errorContains string
	}{
		{
			name:        "subnet_broadcast (ID 1)",
			specialID:   1,
			peerIP:      "10.100.5.36",
			setupDB:     noOpSetup,
			expectCIDRs: []string{"10.100.5.255/32"},
			expectError: false,
		},
		{
			name:        "subnet_broadcast with /24",
			specialID:   1,
			peerIP:      "192.168.0.1",
			setupDB:     noOpSetup,
			expectCIDRs: []string{"192.168.0.255/32"},
			expectError: false,
		},
		{
			name:          "subnet_broadcast invalid IP",
			specialID:     1,
			peerIP:        "not-an-ip",
			setupDB:       noOpSetup,
			expectCIDRs:   nil,
			expectError:   true,
			errorContains: "invalid IPv4",
		},
		{
			name:        "limited_broadcast (ID 2)",
			specialID:   2,
			peerIP:      "10.0.0.1",
			setupDB:     noOpSetup,
			expectCIDRs: []string{"255.255.255.255/32"},
			expectError: false,
		},
		{
			name:        "all_hosts IGMP (ID 3)",
			specialID:   3,
			peerIP:      "10.0.0.1",
			setupDB:     noOpSetup,
			expectCIDRs: []string{"224.0.0.1/32"},
			expectError: false,
		},
		{
			name:        "mdns (ID 4)",
			specialID:   4,
			peerIP:      "10.0.0.1",
			setupDB:     noOpSetup,
			expectCIDRs: []string{"224.0.0.251/32"},
			expectError: false,
		},
		{
			name:        "loopback (ID 5)",
			specialID:   5,
			peerIP:      "10.0.0.1",
			setupDB:     noOpSetup,
			expectCIDRs: []string{"127.0.0.1/32"},
			expectError: false,
		},
		{
			name:        "any_ip (ID 6)",
			specialID:   6,
			peerIP:      "10.0.0.1",
			setupDB:     noOpSetup,
			expectCIDRs: []string{"0.0.0.0/0"},
			expectError: false,
		},
		{
			name:      "all_peers (ID 7) with peers",
			specialID: 7,
			peerIP:    "10.0.0.1",
			setupDB: func(db *sql.DB) error {
				if err := insertPeerForTest(db, 1, "peer1", "192.168.1.10"); err != nil {
					return err
				}
				if err := insertPeerForTest(db, 2, "peer2", "192.168.1.11"); err != nil {
					return err
				}
				return nil
			},
			expectCIDRs: []string{"192.168.1.10", "192.168.1.11"},
			expectError: false,
		},
		{
			name:        "all_peers (ID 7) empty",
			specialID:   7,
			peerIP:      "10.0.0.1",
			setupDB:     noOpSetup,
			expectCIDRs: nil,
			expectError: false,
		},
		{
			name:          "unknown special ID",
			specialID:     99,
			peerIP:        "10.0.0.1",
			setupDB:       noOpSetup,
			expectCIDRs:   nil,
			expectError:   true,
			errorContains: "unknown special target",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, cleanup := testutil.SetupTestDB(t)
			defer cleanup()
			defer cleanup()

			if err := tt.setupDB(db); err != nil {
				t.Fatalf("setupDB failed: %v", err)
			}

			resolver := &Resolver{db: db}
			cidrs, err := resolver.ResolveSpecialTarget(context.Background(), tt.specialID, tt.peerIP)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				} else if tt.errorContains != "" {
					if !containsString(err.Error(), tt.errorContains) {
						t.Errorf("error %q does not contain %q", err.Error(), tt.errorContains)
					}
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if len(cidrs) != len(tt.expectCIDRs) {
				t.Errorf("expected %d CIDRs, got %d", len(tt.expectCIDRs), len(cidrs))
				return
			}

			for i, cidr := range cidrs {
				if cidr != tt.expectCIDRs[i] {
					t.Errorf("CIDR[%d] = %q, want %q", i, cidr, tt.expectCIDRs[i])
				}
			}
		})
	}
}

func TestExpandPorts(t *testing.T) {
	tests := []struct {
		name      string
		dstPorts  string
		srcPorts  string
		protocol  string
		expectErr bool
		checkFunc func([]PortClause) bool
	}{
		{
			name:     "tcp single port",
			dstPorts: "80",
			srcPorts: "",
			protocol: "tcp",
			checkFunc: func(clauses []PortClause) bool {
				return len(clauses) == 1 &&
					clauses[0].Protocol == "tcp" &&
					clauses[0].PortMatch == "--dport 80" &&
					clauses[0].SrcPortMatch == ""
			},
		},
		{
			name:     "udp single port",
			dstPorts: "53",
			srcPorts: "",
			protocol: "udp",
			checkFunc: func(clauses []PortClause) bool {
				return len(clauses) == 1 &&
					clauses[0].Protocol == "udp" &&
					clauses[0].PortMatch == "--dport 53"
			},
		},
		{
			name:     "tcp multiple ports (multiport)",
			dstPorts: "80,443",
			srcPorts: "",
			protocol: "tcp",
			checkFunc: func(clauses []PortClause) bool {
				return len(clauses) == 1 &&
					clauses[0].Protocol == "tcp" &&
					clauses[0].PortMatch == "-m multiport --dports 80,443"
			},
		},
		{
			name:     "tcp port range",
			dstPorts: "8000:9000",
			srcPorts: "",
			protocol: "tcp",
			checkFunc: func(clauses []PortClause) bool {
				return len(clauses) == 1 &&
					clauses[0].Protocol == "tcp" &&
					clauses[0].PortMatch == "-m multiport --dports 8000:9000"
			},
		},
		{
			name:     "tcp with source port",
			dstPorts: "80",
			srcPorts: "12345",
			protocol: "tcp",
			checkFunc: func(clauses []PortClause) bool {
				return len(clauses) == 1 &&
					clauses[0].Protocol == "tcp" &&
					clauses[0].PortMatch == "--dport 80" &&
					clauses[0].SrcPortMatch == "--sport 12345"
			},
		},
		{
			name:     "icmp no ports",
			dstPorts: "",
			srcPorts: "",
			protocol: "icmp",
			checkFunc: func(clauses []PortClause) bool {
				return len(clauses) == 1 &&
					clauses[0].Protocol == "icmp" &&
					clauses[0].PortMatch == "" &&
					clauses[0].SrcPortMatch == ""
			},
		},
		{
			name:     "igmp no ports",
			dstPorts: "",
			srcPorts: "",
			protocol: "igmp",
			checkFunc: func(clauses []PortClause) bool {
				return len(clauses) == 1 &&
					clauses[0].Protocol == "igmp" &&
					clauses[0].PortMatch == "" &&
					clauses[0].SrcPortMatch == ""
			},
		},
		{
			name:     "protocol both tcp and udp",
			dstPorts: "80",
			srcPorts: "",
			protocol: "both",
			checkFunc: func(clauses []PortClause) bool {
				return len(clauses) == 2 &&
					clauses[0].Protocol == "tcp" &&
					clauses[1].Protocol == "udp"
			},
		},
		{
			name:      "empty dst and src requires error for tcp",
			dstPorts:  "",
			srcPorts:  "",
			protocol:  "tcp",
			expectErr: true,
			checkFunc: nil,
		},
		{
			name:      "invalid dst port chars",
			dstPorts:  "abc",
			srcPorts:  "",
			protocol:  "tcp",
			expectErr: true,
			checkFunc: nil,
		},
		{
			name:      "invalid src port chars",
			dstPorts:  "80",
			srcPorts:  "xyz",
			protocol:  "tcp",
			expectErr: true,
			checkFunc: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clauses, err := ExpandPorts(tt.dstPorts, tt.srcPorts, tt.protocol)

			if tt.expectErr {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if tt.checkFunc != nil && !tt.checkFunc(clauses) {
				t.Errorf("ExpandPorts(%q, %q, %q) returned unexpected clauses: %+v",
					tt.dstPorts, tt.srcPorts, tt.protocol, clauses)
			}
		})
	}
}

func TestValidatePorts(t *testing.T) {
	tests := []struct {
		name      string
		ports     string
		expectErr bool
	}{
		{
			name:      "empty string is valid",
			ports:     "",
			expectErr: false,
		},
		{
			name:      "single port",
			ports:     "80",
			expectErr: false,
		},
		{
			name:      "multiple ports comma separated",
			ports:     "80,443",
			expectErr: false,
		},
		{
			name:      "port range colon separated",
			ports:     "8000:9000",
			expectErr: false,
		},
		{
			name:      "complex port spec",
			ports:     "22,80,443,8000:9000",
			expectErr: false,
		},
		{
			name:      "invalid characters",
			ports:     "80abc",
			expectErr: true,
		},
		{
			name:      "letters in port",
			ports:     "http",
			expectErr: true,
		},
		{
			name:      "spaces in port",
			ports:     "80 443",
			expectErr: true,
		},
		{
			name:      "special characters",
			ports:     "80-443",
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePorts(tt.ports)

			if tt.expectErr {
				if err == nil {
					t.Errorf("expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestSanitizeForIpset(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "lowercase letters only",
			input:    "webserver",
			expected: "webserver",
		},
		{
			name:     "mixed case converted to lowercase",
			input:    "WebServer",
			expected: "webserver",
		},
		{
			name:     "spaces become underscores",
			input:    "my group",
			expected: "my_group",
		},
		{
			name:     "special characters become underscores",
			input:    "group@#$%",
			expected: "group", // special chars collapse to single underscore, then trimmed
		},
		{
			name:     "multiple spaces collapsed",
			input:    "group   name",
			expected: "group_name", // multiple spaces collapse to one underscore
		},
		{
			name:     "leading underscore trimmed",
			input:    "_group_",
			expected: "group",
		},
		{
			name:     "trailing underscore trimmed",
			input:    "group_",
			expected: "group",
		},
		{
			name:     "numbers preserved",
			input:    "group123",
			expected: "group123",
		},
		{
			name:     "underscores preserved",
			input:    "group_name",
			expected: "group_name",
		},
		{
			name:     "complex input",
			input:    "My Group @2024!",
			expected: "my_group_2024", // special chars collapse to underscore, trailing trimmed
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizeForIpset(tt.input)
			if result != tt.expected {
				t.Errorf("sanitizeForIpset(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

// Helper functions for resolver tests

func noOpSetup(db *sql.DB) error {
	return nil
}

func insertPeerForTest(db *sql.DB, id int, hostname, ipAddress string) error {
	_, err := db.Exec(
		`INSERT INTO peers (id, hostname, ip_address, has_docker, has_ipset, is_manual, agent_key, hmac_key) VALUES (?, ?, ?, 0, 0, 0, ?, ?)`,
		id, hostname, ipAddress, fmt.Sprintf("test-agent-key-%d", id), fmt.Sprintf("test-hmac-key-%d", id),
	)
	return err
}

func insertGroupForTest(db *sql.DB, id int, name string) error {
	_, err := db.Exec(
		`INSERT INTO groups (id, name, is_system) VALUES (?, ?, 0)`,
		id, name,
	)
	return err
}

func insertGroupMemberForTest(db *sql.DB, id, groupID, peerID int) error {
	_, err := db.Exec(
		`INSERT INTO group_members (id, group_id, peer_id) VALUES (?, ?, ?)`,
		id, groupID, peerID,
	)
	return err
}

func containsString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
