package common

import (
	"context"
	"database/sql"
	"testing"

	_ "github.com/mattn/go-sqlite3"

	"runic/internal/testutil"
)

// TestCheckPeerDeleteConstraints tests the peer delete constraint checker
func TestCheckPeerDeleteConstraints(t *testing.T) {
	tests := []struct {
		name        string
		setup       func(*testing.T, *sql.DB)
		peerID      int
		wantErr     bool
		wantErrPart string
	}{
		{
			name: "peer is target_peer_id in a policy",
			setup: func(t *testing.T, db *sql.DB) {
				// Insert peer
				db.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)`,
					"test-peer", "10.0.0.1", "agent-key-1", "hmac-key-1")
				// Insert group
				db.Exec(`INSERT INTO groups (name) VALUES (?)`, "test-group")
				// Insert service
				db.Exec(`INSERT INTO services (name, ports, protocol) VALUES (?, ?, ?)`, "ssh", "22", "tcp")
				// Insert policy using peer as target_peer_id
				db.Exec(`INSERT INTO policies (name, source_id, source_type, service_id, target_id, target_type, action, priority, enabled) VALUES (?, ?, 'group', ?, ?, 'peer', ?, ?, ?)`,
					"test-policy", 1, 1, 1, "ACCEPT", 100, 1)
			},
			peerID:      1,
			wantErr:     true,
			wantErrPart: "cannot delete peer — it is explicitly targeted in policy 'test-policy'",
		},
		{
			name: "peer is in a group used as source_group_id",
			setup: func(t *testing.T, db *sql.DB) {
				// Insert peer
				db.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)`,
					"test-peer", "10.0.0.1", "agent-key-1", "hmac-key-1")
				// Insert another peer to be target
				db.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)`,
					"target-peer", "10.0.0.2", "agent-key-2", "hmac-key-2")
				// Insert group
				db.Exec(`INSERT INTO groups (name) VALUES (?)`, "test-group")
				// Insert peer into group
				db.Exec(`INSERT INTO group_members (group_id, peer_id) VALUES (?, ?)`, 1, 1)
				// Insert service
				db.Exec(`INSERT INTO services (name, ports, protocol) VALUES (?, ?, ?)`, "ssh", "22", "tcp")
				// Insert policy using group as source
				db.Exec(`INSERT INTO policies (name, source_id, source_type, service_id, target_id, target_type, action, priority, enabled) VALUES (?, ?, 'group', ?, ?, 'peer', ?, ?, ?)`,
					"group-policy", 1, 1, 2, "ACCEPT", 100, 1)
			},
			peerID:      1,
			wantErr:     true,
			wantErrPart: "cannot delete peer — it is in group used by policy 'group-policy'",
		},
		{
			name: "peer is not used anywhere",
			setup: func(t *testing.T, db *sql.DB) {
				// Insert peer
				db.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)`,
					"unused-peer", "10.0.0.1", "agent-key-1", "hmac-key-1")
			},
			peerID:  1,
			wantErr: false,
		},
		{
			name: "peer is in a group but group is not used by any policy",
			setup: func(t *testing.T, db *sql.DB) {
				// Insert peer
				db.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)`,
					"test-peer", "10.0.0.1", "agent-key-1", "hmac-key-1")
				// Insert group
				db.Exec(`INSERT INTO groups (name) VALUES (?)`, "unused-group")
				// Insert peer into group
				db.Exec(`INSERT INTO group_members (group_id, peer_id) VALUES (?, ?)`, 1, 1)
			},
			peerID:  1,
			wantErr: false,
		},
		{
			name: "peer is target_peer_id takes precedence over group membership",
			setup: func(t *testing.T, db *sql.DB) {
				// Insert peer
				db.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)`,
					"test-peer", "10.0.0.1", "agent-key-1", "hmac-key-1")
				// Insert group
				db.Exec(`INSERT INTO groups (name) VALUES (?)`, "test-group")
				// Insert peer into group
				db.Exec(`INSERT INTO group_members (group_id, peer_id) VALUES (?, ?)`, 1, 1)
				// Insert service
				db.Exec(`INSERT INTO services (name, ports, protocol) VALUES (?, ?, ?)`, "ssh", "22", "tcp")
				// Insert policy using peer as target_peer_id (should be checked first)
				db.Exec(`INSERT INTO policies (name, source_id, source_type, service_id, target_id, target_type, action, priority, enabled) VALUES (?, ?, 'group', ?, ?, 'peer', ?, ?, ?)`,
					"target-policy", 1, 1, 1, "ACCEPT", 100, 1)
			},
			peerID:      1,
			wantErr:     true,
			wantErrPart: "cannot delete peer — it is explicitly targeted in policy 'target-policy'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, cleanup := testutil.SetupTestDB(t)
			defer cleanup()

			if tt.setup != nil {
				tt.setup(t, db)
			}

			ctx := context.Background()
			err := CheckPeerDeleteConstraints(ctx, db, tt.peerID)

			if tt.wantErr {
				if err == nil {
					t.Errorf("CheckPeerDeleteConstraints() expected error, got nil")
				} else if err.Error() != tt.wantErrPart {
					t.Errorf("CheckPeerDeleteConstraints() error = %q, want %q", err.Error(), tt.wantErrPart)
				}
			} else {
				if err != nil {
					t.Errorf("CheckPeerDeleteConstraints() unexpected error: %v", err)
				}
			}
		})
	}
}

// TestCheckGroupDeleteConstraints tests the group delete constraint checker
func TestCheckGroupDeleteConstraints(t *testing.T) {
	tests := []struct {
		name        string
		setup       func(*testing.T, *sql.DB)
		groupID     int
		wantErr     bool
		wantErrPart string
	}{
		{
			name: "group is used as source_group_id in a policy",
			setup: func(t *testing.T, db *sql.DB) {
				// Insert peer
				db.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)`,
					"test-peer", "10.0.0.1", "agent-key-1", "hmac-key-1")
				// Insert group
				db.Exec(`INSERT INTO groups (name) VALUES (?)`, "test-group")
				// Insert service
				db.Exec(`INSERT INTO services (name, ports, protocol) VALUES (?, ?, ?)`, "ssh", "22", "tcp")
				// Insert policy using group as source
				db.Exec(`INSERT INTO policies (name, source_id, source_type, service_id, target_id, target_type, action, priority, enabled) VALUES (?, ?, 'group', ?, ?, 'peer', ?, ?, ?)`,
					"test-policy", 1, 1, 1, "ACCEPT", 100, 1)
			},
			groupID:     1,
			wantErr:     true,
			wantErrPart: "cannot delete group — it is used by policy 'test-policy'",
		},
		{
			name: "group is not used anywhere",
			setup: func(t *testing.T, db *sql.DB) {
				// Insert group
				db.Exec(`INSERT INTO groups (name) VALUES (?)`, "unused-group")
			},
			groupID: 1,
			wantErr: false,
		},
		{
			name: "group with members but not used in policy",
			setup: func(t *testing.T, db *sql.DB) {
				// Insert peer
				db.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)`,
					"test-peer", "10.0.0.1", "agent-key-1", "hmac-key-1")
				// Insert group
				db.Exec(`INSERT INTO groups (name) VALUES (?)`, "group-with-members")
				// Insert peer into group
				db.Exec(`INSERT INTO group_members (group_id, peer_id) VALUES (?, ?)`, 1, 1)
			},
			groupID: 1,
			wantErr: false,
		},
		{
			name: "group used by multiple policies returns first policy name",
			setup: func(t *testing.T, db *sql.DB) {
				// Insert peer
				db.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)`,
					"test-peer", "10.0.0.1", "agent-key-1", "hmac-key-1")
				// Insert group
				db.Exec(`INSERT INTO groups (name) VALUES (?)`, "test-group")
				// Insert service
				db.Exec(`INSERT INTO services (name, ports, protocol) VALUES (?, ?, ?)`, "ssh", "22", "tcp")
				// Insert multiple policies using the same group
				db.Exec(`INSERT INTO policies (name, source_id, source_type, service_id, target_id, target_type, action, priority, enabled) VALUES (?, ?, 'group', ?, ?, 'peer', ?, ?, ?)`,
					"first-policy", 1, 1, 1, "ACCEPT", 100, 1)
				db.Exec(`INSERT INTO policies (name, source_id, source_type, service_id, target_id, target_type, action, priority, enabled) VALUES (?, ?, 'group', ?, ?, 'peer', ?, ?, ?)`,
					"second-policy", 1, 1, 1, "DROP", 200, 1)
			},
			groupID: 1,
			wantErr: true,
			// The query uses LIMIT 1, so it returns the first found policy
			// SQLite doesn't guarantee order without ORDER BY, so we just check it's an error
			wantErrPart: "cannot delete group — it is used by policy",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, cleanup := testutil.SetupTestDB(t)
			defer cleanup()

			if tt.setup != nil {
				tt.setup(t, db)
			}

			ctx := context.Background()
			err := CheckGroupDeleteConstraints(ctx, db, tt.groupID)

			if tt.wantErr {
				if err == nil {
					t.Errorf("CheckGroupDeleteConstraints() expected error, got nil")
				} else if tt.wantErrPart != "" && err.Error() != tt.wantErrPart {
					// For cases where exact match isn't required, check prefix
					if tt.name == "group used by multiple policies returns first policy name" {
						if err.Error() != "cannot delete group — it is used by policy 'first-policy'" &&
							err.Error() != "cannot delete group — it is used by policy 'second-policy'" {
							t.Errorf("CheckGroupDeleteConstraints() error = %q, want containing policy name", err.Error())
						}
					} else {
						t.Errorf("CheckGroupDeleteConstraints() error = %q, want %q", err.Error(), tt.wantErrPart)
					}
				}
			} else {
				if err != nil {
					t.Errorf("CheckGroupDeleteConstraints() unexpected error: %v", err)
				}
			}
		})
	}
}

// TestCheckPeerDeleteConstraintsNonExistentPeer tests behavior with non-existent peer
func TestCheckPeerDeleteConstraintsNonExistentPeer(t *testing.T) {
	db, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	// Test with non-existent peer ID - should return nil (no constraints found)
	err := CheckPeerDeleteConstraints(ctx, db, 999)
	if err != nil {
		t.Errorf("CheckPeerDeleteConstraints() with non-existent peer should return nil, got: %v", err)
	}
}

// TestCheckGroupDeleteConstraintsNonExistentGroup tests behavior with non-existent group
func TestCheckGroupDeleteConstraintsNonExistentGroup(t *testing.T) {
	db, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	// Test with non-existent group ID - should return nil (no constraints found)
	err := CheckGroupDeleteConstraints(ctx, db, 999)
	if err != nil {
		t.Errorf("CheckGroupDeleteConstraints() with non-existent group should return nil, got: %v", err)
	}
}
