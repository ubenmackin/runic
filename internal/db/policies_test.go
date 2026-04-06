package db

import (
	"context"
	"database/sql"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

// TestListEnabledPolicies tests the ListEnabledPolicies function.
func TestListEnabledPolicies(t *testing.T) {
	tests := []struct {
		name           string
		setupDB        func(t *testing.T, db *sql.DB) (peerID int)
		expectedCount  int
		expectPolicies []string // expected policy names in order
	}{
		{
			name: "return policies where target is directly the peer",
			setupDB: func(t *testing.T, db *sql.DB) int {
				// Insert service (required for foreign key)
				_, err := db.Exec(`INSERT INTO services (id, name, ports, protocol) VALUES (1, 'http', '80', 'tcp')`)
				if err != nil {
					t.Fatal(err)
				}
				// Insert peer
				_, err = db.Exec(`INSERT INTO peers (id, hostname, ip_address, agent_key, hmac_key) VALUES (1, 'testpeer', '10.0.0.1', 'testkey', 'hmackey')`)
				if err != nil {
					t.Fatal(err)
				}
				// Insert policy targeting the peer directly
				_, err = db.Exec(`INSERT INTO policies (id, name, source_id, source_type, service_id, target_id, target_type, action, priority, enabled) VALUES (1, 'peer-policy', 1, 'peer', 1, 1, 'peer', 'ACCEPT', 100, 1)`)
				if err != nil {
					t.Fatal(err)
				}
				return 1 // peerID
			},
			expectedCount:  1,
			expectPolicies: []string{"peer-policy"},
		},
		{
			name: "return policies where target is a group containing the peer",
			setupDB: func(t *testing.T, db *sql.DB) int {
				// Insert service
				_, err := db.Exec(`INSERT INTO services (id, name, ports, protocol) VALUES (1, 'http', '80', 'tcp')`)
				if err != nil {
					t.Fatal(err)
				}
				// Insert peer
				_, err = db.Exec(`INSERT INTO peers (id, hostname, ip_address, agent_key, hmac_key) VALUES (1, 'testpeer', '10.0.0.1', 'testkey', 'hmackey')`)
				if err != nil {
					t.Fatal(err)
				}
				// Insert group
				_, err = db.Exec(`INSERT INTO groups (id, name) VALUES (1, 'test-group')`)
				if err != nil {
					t.Fatal(err)
				}
				// Insert group member (peer in group)
				_, err = db.Exec(`INSERT INTO group_members (group_id, peer_id) VALUES (1, 1)`)
				if err != nil {
					t.Fatal(err)
				}
				// Insert policy targeting the group
				_, err = db.Exec(`INSERT INTO policies (id, name, source_id, source_type, service_id, target_id, target_type, action, priority, enabled) VALUES (1, 'group-policy', 1, 'peer', 1, 1, 'group', 'ACCEPT', 100, 1)`)
				if err != nil {
					t.Fatal(err)
				}
				return 1 // peerID
			},
			expectedCount:  1,
			expectPolicies: []string{"group-policy"},
		},
		{
			name: "return only enabled policies",
			setupDB: func(t *testing.T, db *sql.DB) int {
				// Insert service
				_, err := db.Exec(`INSERT INTO services (id, name, ports, protocol) VALUES (1, 'http', '80', 'tcp')`)
				if err != nil {
					t.Fatal(err)
				}
				// Insert peer
				_, err = db.Exec(`INSERT INTO peers (id, hostname, ip_address, agent_key, hmac_key) VALUES (1, 'testpeer', '10.0.0.1', 'testkey', 'hmackey')`)
				if err != nil {
					t.Fatal(err)
				}
				// Insert enabled policy
				_, err = db.Exec(`INSERT INTO policies (id, name, source_id, source_type, service_id, target_id, target_type, action, priority, enabled) VALUES (1, 'enabled-policy', 1, 'peer', 1, 1, 'peer', 'ACCEPT', 100, 1)`)
				if err != nil {
					t.Fatal(err)
				}
				// Insert disabled policy
				_, err = db.Exec(`INSERT INTO policies (id, name, source_id, source_type, service_id, target_id, target_type, action, priority, enabled) VALUES (2, 'disabled-policy', 1, 'peer', 1, 1, 'peer', 'ACCEPT', 200, 0)`)
				if err != nil {
					t.Fatal(err)
				}
				return 1 // peerID
			},
			expectedCount:  1,
			expectPolicies: []string{"enabled-policy"},
		},
		{
			name: "return policies ordered by priority ASC",
			setupDB: func(t *testing.T, db *sql.DB) int {
				// Insert service
				_, err := db.Exec(`INSERT INTO services (id, name, ports, protocol) VALUES (1, 'http', '80', 'tcp')`)
				if err != nil {
					t.Fatal(err)
				}
				// Insert peer
				_, err = db.Exec(`INSERT INTO peers (id, hostname, ip_address, agent_key, hmac_key) VALUES (1, 'testpeer', '10.0.0.1', 'testkey', 'hmackey')`)
				if err != nil {
					t.Fatal(err)
				}
				// Insert policies with different priorities (out of order)
				_, err = db.Exec(`INSERT INTO policies (id, name, source_id, source_type, service_id, target_id, target_type, action, priority, enabled) VALUES (1, 'low-priority', 1, 'peer', 1, 1, 'peer', 'ACCEPT', 300, 1)`)
				if err != nil {
					t.Fatal(err)
				}
				_, err = db.Exec(`INSERT INTO policies (id, name, source_id, source_type, service_id, target_id, target_type, action, priority, enabled) VALUES (2, 'high-priority', 1, 'peer', 1, 1, 'peer', 'ACCEPT', 100, 1)`)
				if err != nil {
					t.Fatal(err)
				}
				_, err = db.Exec(`INSERT INTO policies (id, name, source_id, source_type, service_id, target_id, target_type, action, priority, enabled) VALUES (3, 'medium-priority', 1, 'peer', 1, 1, 'peer', 'ACCEPT', 200, 1)`)
				if err != nil {
					t.Fatal(err)
				}
				return 1 // peerID
			},
			expectedCount:  3,
			expectPolicies: []string{"high-priority", "medium-priority", "low-priority"},
		},
		{
			name: "return empty slice when no policies match",
			setupDB: func(t *testing.T, db *sql.DB) int {
				// Insert service
				_, err := db.Exec(`INSERT INTO services (id, name, ports, protocol) VALUES (1, 'http', '80', 'tcp')`)
				if err != nil {
					t.Fatal(err)
				}
				// Insert peer
				_, err = db.Exec(`INSERT INTO peers (id, hostname, ip_address, agent_key, hmac_key) VALUES (1, 'testpeer', '10.0.0.1', 'testkey', 'hmackey')`)
				if err != nil {
					t.Fatal(err)
				}
				// Insert policy targeting a different peer
				_, err = db.Exec(`INSERT INTO policies (id, name, source_id, source_type, service_id, target_id, target_type, action, priority, enabled) VALUES (1, 'other-peer-policy', 1, 'peer', 1, 2, 'peer', 'ACCEPT', 100, 1)`)
				if err != nil {
					t.Fatal(err)
				}
				return 1 // peerID
			},
			expectedCount:  0,
			expectPolicies: nil,
		},
		{
			name: "test with multiple groups and policies",
			setupDB: func(t *testing.T, db *sql.DB) int {
				// Insert service
				_, err := db.Exec(`INSERT INTO services (id, name, ports, protocol) VALUES (1, 'http', '80', 'tcp')`)
				if err != nil {
					t.Fatal(err)
				}
				// Insert peers
				_, err = db.Exec(`INSERT INTO peers (id, hostname, ip_address, agent_key, hmac_key) VALUES (1, 'testpeer1', '10.0.0.1', 'testkey1', 'hmackey1')`)
				if err != nil {
					t.Fatal(err)
				}
				_, err = db.Exec(`INSERT INTO peers (id, hostname, ip_address, agent_key, hmac_key) VALUES (2, 'testpeer2', '10.0.0.2', 'testkey2', 'hmackey2')`)
				if err != nil {
					t.Fatal(err)
				}
				// Insert groups
				_, err = db.Exec(`INSERT INTO groups (id, name) VALUES (1, 'group1')`)
				if err != nil {
					t.Fatal(err)
				}
				_, err = db.Exec(`INSERT INTO groups (id, name) VALUES (2, 'group2')`)
				if err != nil {
					t.Fatal(err)
				}
				// Insert group members (peer 1 in group 1, peer 2 in group 2)
				_, err = db.Exec(`INSERT INTO group_members (group_id, peer_id) VALUES (1, 1)`)
				if err != nil {
					t.Fatal(err)
				}
				_, err = db.Exec(`INSERT INTO group_members (group_id, peer_id) VALUES (2, 2)`)
				if err != nil {
					t.Fatal(err)
				}
				// Insert policy targeting group1
				_, err = db.Exec(`INSERT INTO policies (id, name, source_id, source_type, service_id, target_id, target_type, action, priority, enabled) VALUES (1, 'group1-policy', 1, 'peer', 1, 1, 'group', 'ACCEPT', 100, 1)`)
				if err != nil {
					t.Fatal(err)
				}
				// Insert policy directly targeting peer 1
				_, err = db.Exec(`INSERT INTO policies (id, name, source_id, source_type, service_id, target_id, target_type, action, priority, enabled) VALUES (2, 'peer1-direct', 1, 'peer', 1, 1, 'peer', 'ACCEPT', 50, 1)`)
				if err != nil {
					t.Fatal(err)
				}
				// Insert policy targeting group2 (should NOT be returned for peer 1)
				_, err = db.Exec(`INSERT INTO policies (id, name, source_id, source_type, service_id, target_id, target_type, action, priority, enabled) VALUES (3, 'group2-policy', 1, 'peer', 1, 2, 'group', 'ACCEPT', 100, 1)`)
				if err != nil {
					t.Fatal(err)
				}
				return 1 // peerID
			},
			expectedCount:  2,
			expectPolicies: []string{"peer1-direct", "group1-policy"}, // ordered by priority
		},
		{
			name: "returns both peer-direct and group policies for same peer",
			setupDB: func(t *testing.T, db *sql.DB) int {
				// Insert service
				_, err := db.Exec(`INSERT INTO services (id, name, ports, protocol) VALUES (1, 'http', '80', 'tcp')`)
				if err != nil {
					t.Fatal(err)
				}
				// Insert peer
				_, err = db.Exec(`INSERT INTO peers (id, hostname, ip_address, agent_key, hmac_key) VALUES (1, 'testpeer', '10.0.0.1', 'testkey', 'hmackey')`)
				if err != nil {
					t.Fatal(err)
				}
				// Insert group
				_, err = db.Exec(`INSERT INTO groups (id, name) VALUES (1, 'test-group')`)
				if err != nil {
					t.Fatal(err)
				}
				// Insert group member
				_, err = db.Exec(`INSERT INTO group_members (group_id, peer_id) VALUES (1, 1)`)
				if err != nil {
					t.Fatal(err)
				}
				// Insert policy targeting peer directly
				_, err = db.Exec(`INSERT INTO policies (id, name, source_id, source_type, service_id, target_id, target_type, action, priority, enabled) VALUES (1, 'direct-policy', 1, 'peer', 1, 1, 'peer', 'ACCEPT', 200, 1)`)
				if err != nil {
					t.Fatal(err)
				}
				// Insert policy targeting group
				_, err = db.Exec(`INSERT INTO policies (id, name, source_id, source_type, service_id, target_id, target_type, action, priority, enabled) VALUES (2, 'group-policy', 1, 'peer', 1, 1, 'group', 'ACCEPT', 100, 1)`)
				if err != nil {
					t.Fatal(err)
				}
				return 1 // peerID
			},
			expectedCount:  2,
			expectPolicies: []string{"group-policy", "direct-policy"}, // ordered by priority
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			database, cleanup := SetupTestDB(t)
			defer cleanup()

			peerID := tt.setupDB(t, database)

			ctx := context.Background()
			policies, err := ListEnabledPolicies(ctx, database, peerID)
			if err != nil {
				t.Fatalf("ListEnabledPolicies() error = %v", err)
			}

			if len(policies) != tt.expectedCount {
				t.Errorf("expected %d policies, got %d", tt.expectedCount, len(policies))
			}

			if tt.expectPolicies != nil {
				for i, p := range policies {
					if i >= len(tt.expectPolicies) {
						break
					}
					if p.Name != tt.expectPolicies[i] {
						t.Errorf("policy[%d] expected name %q, got %q", i, tt.expectPolicies[i], p.Name)
					}
				}
			}
		})
	}
}
