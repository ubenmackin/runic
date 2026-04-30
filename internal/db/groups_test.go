package db

import (
	"context"
	"database/sql"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func TestListGroupMembers(t *testing.T) {
	tests := []struct {
		name      string
		groupID   int
		setupDB   func(*sql.DB) error
		wantCount int
		wantErr   bool
	}{
		{
			name:      "return empty slice when no members",
			groupID:   1,
			setupDB:   func(db *sql.DB) error { return nil },
			wantCount: 0,
			wantErr:   false,
		},
		{
			name:    "return all members when group has peers",
			groupID: 1,
			setupDB: func(db *sql.DB) error {
				// Insert group
				if _, err := db.Exec(`INSERT INTO groups (id, name) VALUES (1, 'test-group')`); err != nil {
					return err
				}
				// Insert peers (with all NOT NULL fields)
				if _, err := db.Exec(`INSERT INTO peers (hostname, ip_address, os_type, arch, has_docker, agent_key, hmac_key, status) VALUES ('peer1', '10.0.0.1', 'linux', 'amd64', 1, 'key1', 'hmac1', 'online'), ('peer2', '10.0.0.2', 'linux', 'amd64', 1, 'key2', 'hmac2', 'online')`); err != nil {
					return err
				}
				// Insert group members
				if _, err := db.Exec(`INSERT INTO group_members (group_id, peer_id) VALUES (1, 1), (1, 2)`); err != nil {
					return err
				}
				return nil
			},
			wantCount: 2,
			wantErr:   false,
		},
		{
			name:      "return empty for non-existent group",
			groupID:   999,
			setupDB:   func(db *sql.DB) error { return nil },
			wantCount: 0,
			wantErr:   false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			db, cleanup := SetupTestDB(t)
			defer cleanup()

			if tc.setupDB != nil {
				if err := tc.setupDB(db); err != nil {
					t.Fatalf("setupDB failed: %v", err)
				}
			}

			ctx := context.Background()
			members, err := ListGroupMembers(ctx, db, tc.groupID)

			if tc.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
					return
				}
				if len(members) != tc.wantCount {
					t.Errorf("got %d members; want %d", len(members), tc.wantCount)
				}
			}
		})
	}
}
