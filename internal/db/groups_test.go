package db

import (
	"context"
	"database/sql"
	"testing"

	"runic/internal/models"

	_ "github.com/mattn/go-sqlite3"
)

func TestGetGroup(t *testing.T) {
	tests := []struct {
		name      string
		groupID   int
		setupDB   func(*sql.DB) error
		want      bool // true = expect group, false = expect error
		checkFunc func(*testing.T, models.GroupRow, error)
	}{
		{
			name:    "successfully fetch existing group",
			groupID: 1,
			setupDB: func(db *sql.DB) error {
				_, err := db.Exec(`INSERT INTO groups (id, name, description, is_system) VALUES (1, 'test-group', 'Test group description', 0)`)
				return err
			},
			want: true,
			checkFunc: func(t *testing.T, g models.GroupRow, err error) {
				if g.ID != 1 || g.Name != "test-group" {
					t.Errorf("got group ID=%d, name=%s; want 1, test-group", g.ID, g.Name)
				}
			},
		},
		{
			name:    "return error for non-existent group",
			groupID: 999,
			setupDB: func(db *sql.DB) error {
				return nil
			},
			want: false,
			checkFunc: func(t *testing.T, g models.GroupRow, err error) {
				if err == nil {
					t.Error("expected sql.ErrNoRows, got nil")
				}
			},
		},
		{
			name:    "fetch group with description and is_system fields",
			groupID: 2,
			setupDB: func(db *sql.DB) error {
				_, err := db.Exec(`INSERT INTO groups (id, name, description, is_system) VALUES (2, 'system-group', 'System group', 1)`)
				return err
			},
			want: true,
			checkFunc: func(t *testing.T, g models.GroupRow, err error) {
				if g.Description != "System group" {
					t.Errorf("description = %q; want 'System group'", g.Description)
				}
				if !g.IsSystem {
					t.Error("IsSystem = false; want true")
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			db, cleanup := SetupTestDB(t)
			defer cleanup()

			if err := tc.setupDB(db); err != nil {
				t.Fatalf("setupDB failed: %v", err)
			}

			ctx := context.Background()
			result, err := GetGroup(ctx, db, tc.groupID)

			if tc.want {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
					return
				}
				tc.checkFunc(t, result, err)
			} else {
				if err == nil {
					t.Error("expected error, got nil")
					return
				}
				tc.checkFunc(t, result, err)
			}
		})
	}
}

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
