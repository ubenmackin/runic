package common

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// setupTestDB creates an in-memory SQLite database for testing
func setupTestDB(t *testing.T) (*sql.DB, func()) {
	t.Helper()
	dsn := fmt.Sprintf("file:testdb%d?mode=memory&cache=shared", time.Now().UnixNano())
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		t.Fatalf("failed to open test db: %v", err)
	}

	// Create schema
	schema := `
	CREATE TABLE IF NOT EXISTS peers (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		hostname TEXT UNIQUE NOT NULL,
		ip_address TEXT NOT NULL,
		os_type TEXT NOT NULL DEFAULT 'linux',
		arch TEXT NOT NULL DEFAULT 'amd64',
		has_docker BOOLEAN NOT NULL DEFAULT 0,
		agent_key TEXT UNIQUE NOT NULL,
		agent_token TEXT,
		agent_version TEXT,
		is_manual BOOLEAN NOT NULL DEFAULT 0,
		bundle_version TEXT,
		hmac_key TEXT NOT NULL,
		last_heartbeat DATETIME,
		status TEXT NOT NULL DEFAULT 'pending',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS groups (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT UNIQUE NOT NULL,
		description TEXT
	);

	CREATE TABLE IF NOT EXISTS group_members (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		group_id INTEGER NOT NULL,
		peer_id INTEGER NOT NULL,
		added_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY(group_id) REFERENCES groups(id) ON DELETE CASCADE,
		FOREIGN KEY(peer_id) REFERENCES peers(id) ON DELETE CASCADE,
		UNIQUE(group_id, peer_id)
	);
	CREATE INDEX IF NOT EXISTS idx_group_members_peer_id ON group_members(peer_id);

	CREATE TABLE IF NOT EXISTS services (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT UNIQUE NOT NULL,
		ports TEXT NOT NULL DEFAULT '',
		protocol TEXT NOT NULL DEFAULT 'tcp',
		description TEXT,
		direction_hint TEXT NOT NULL DEFAULT 'inbound'
	);

	CREATE TABLE IF NOT EXISTS policies (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		description TEXT,
		source_group_id INTEGER NOT NULL,
		service_id INTEGER NOT NULL,
		target_peer_id INTEGER NOT NULL,
		action TEXT NOT NULL DEFAULT 'ACCEPT' CHECK(action IN ('ACCEPT', 'DROP', 'LOG_DROP')),
		priority INTEGER NOT NULL DEFAULT 100,
		enabled BOOLEAN NOT NULL DEFAULT 1,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY(source_group_id) REFERENCES groups(id),
		FOREIGN KEY(service_id) REFERENCES services(id),
		FOREIGN KEY(target_peer_id) REFERENCES peers(id)
	);
	`

	if _, err := db.Exec(schema); err != nil {
		t.Fatalf("failed to create schema: %v", err)
	}

	cleanup := func() {
		db.Close()
	}
	return db, cleanup
}

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
				db.Exec(`INSERT INTO policies (name, source_group_id, service_id, target_peer_id, action, priority, enabled) VALUES (?, ?, ?, ?, ?, ?, ?)`,
					"test-policy", 1, 1, 1, "ACCEPT", 100, 1)
			},
			peerID:      1,
			wantErr:     true,
			wantErrPart: "Cannot delete peer — it is the target of policy 'test-policy'",
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
				db.Exec(`INSERT INTO policies (name, source_group_id, service_id, target_peer_id, action, priority, enabled) VALUES (?, ?, ?, ?, ?, ?, ?)`,
					"group-policy", 1, 1, 2, "ACCEPT", 100, 1)
			},
			peerID:      1,
			wantErr:     true,
			wantErrPart: "Cannot delete peer — it is in group used by policy 'group-policy'",
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
				db.Exec(`INSERT INTO policies (name, source_group_id, service_id, target_peer_id, action, priority, enabled) VALUES (?, ?, ?, ?, ?, ?, ?)`,
					"target-policy", 1, 1, 1, "ACCEPT", 100, 1)
			},
			peerID:      1,
			wantErr:     true,
			wantErrPart: "Cannot delete peer — it is the target of policy 'target-policy'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, cleanup := setupTestDB(t)
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
				db.Exec(`INSERT INTO policies (name, source_group_id, service_id, target_peer_id, action, priority, enabled) VALUES (?, ?, ?, ?, ?, ?, ?)`,
					"test-policy", 1, 1, 1, "ACCEPT", 100, 1)
			},
			groupID:     1,
			wantErr:     true,
			wantErrPart: "Cannot delete group — it is used by policy 'test-policy'",
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
				db.Exec(`INSERT INTO policies (name, source_group_id, service_id, target_peer_id, action, priority, enabled) VALUES (?, ?, ?, ?, ?, ?, ?)`,
					"first-policy", 1, 1, 1, "ACCEPT", 100, 1)
				db.Exec(`INSERT INTO policies (name, source_group_id, service_id, target_peer_id, action, priority, enabled) VALUES (?, ?, ?, ?, ?, ?, ?)`,
					"second-policy", 1, 1, 1, "DROP", 200, 1)
			},
			groupID: 1,
			wantErr: true,
			// The query uses LIMIT 1, so it returns the first found policy
			// SQLite doesn't guarantee order without ORDER BY, so we just check it's an error
			wantErrPart: "Cannot delete group — it is used by policy",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, cleanup := setupTestDB(t)
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
						if err.Error() != "Cannot delete group — it is used by policy 'first-policy'" &&
							err.Error() != "Cannot delete group — it is used by policy 'second-policy'" {
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
	db, cleanup := setupTestDB(t)
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
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	// Test with non-existent group ID - should return nil (no constraints found)
	err := CheckGroupDeleteConstraints(ctx, db, 999)
	if err != nil {
		t.Errorf("CheckGroupDeleteConstraints() with non-existent group should return nil, got: %v", err)
	}
}
