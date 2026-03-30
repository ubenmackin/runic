package db

import (
	"context"
	"database/sql"
	_ "embed"
	"fmt"
	"log"
	"os"

	_ "github.com/mattn/go-sqlite3"

	"runic/internal/models"
)

//go:embed schema.sql
var schemaSQL string

// Schema returns the database schema SQL.
func Schema() string {
	return schemaSQL
}

// Database wraps *sql.DB to allow dependency injection.
// The global DB variable is kept for backward compatibility,
// but new code should prefer passing *Database explicitly.
type Database struct {
	*sql.DB
}

// New creates a new Database wrapper around an existing *sql.DB.
func New(database *sql.DB) *Database {
	return &Database{DB: database}
}

// UnderlyingDB returns the raw *sql.DB for cases where the database driver is needed.
func (d *Database) UnderlyingDB() *sql.DB {
	return d.DB
}

// DB is the global database connection.
// For backward compatibility, code can use this directly.
// New code should prefer dependency injection.
var DB *Database

func InitDB(dataSourceName string) {
	// Check for environment variable override
	if dbPath := os.Getenv("RUNIC_DB_PATH"); dbPath != "" {
		dataSourceName = dbPath
		log.Printf("Using database path from RUNIC_DB_PATH: %s", dataSourceName)
	}

	var err error
	sqlDB, err := sql.Open("sqlite3", dataSourceName)
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}

	if err = sqlDB.Ping(); err != nil {
		log.Fatalf("Failed to ping database: %v", err)
	}

	// Enable WAL mode and foreign keys
	sqlDB.Exec("PRAGMA journal_mode=WAL")
	sqlDB.Exec("PRAGMA foreign_keys=ON")

	DB = New(sqlDB)

	// Run migrations BEFORE schema creation to handle existing databases.
	// For example, the servers → peers table rename must complete before
	// schema.sql tries to create indexes on peer_id columns, which would
	// fail on older databases that still have the "servers" table.
	if err := migrateSchema(DB.DB); err != nil {
		log.Fatalf("Failed to migrate schema: %v", err)
	}

	if err := createSchema(DB.DB); err != nil {
		log.Fatalf("Failed to create schema: %v", err)
	}

	// Seed default system services
	if err := seedSystemServices(DB.DB); err != nil {
		log.Fatalf("Failed to seed system services: %v", err)
	}

	// Seed system groups
	if err := seedSystemGroups(DB.DB); err != nil {
		log.Fatalf("Failed to seed system groups: %v", err)
	}

	log.Println("Database connection established")
}

func createSchema(database *sql.DB) error {
	_, err := database.Exec(schemaSQL)
	return err
}

// migrateSchema adds missing columns for schema upgrades on existing databases.
func migrateSchema(database *sql.DB) error {
	// Fresh database check: if no tables exist, skip all migrations
	var tableCount int
	err := database.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").Scan(&tableCount)
	if err != nil {
		return fmt.Errorf("failed to count tables: %w", err)
	}
	if tableCount == 0 {
		log.Println("Migration: fresh database detected, skipping migrations")
		return nil
	}

	// Check if users table exists (fresh install check)
	var usersTableExists bool
	err = database.QueryRow("SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='table' AND name='users'").Scan(&usersTableExists)
	if err != nil {
		return fmt.Errorf("failed to check for users table: %w", err)
	}

	if usersTableExists {
		existingColumns := make(map[string]bool)
		rows, err := database.Query("PRAGMA table_info(users)")
		if err != nil {
			return fmt.Errorf("failed to get table info: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var cid int
			var name string
			var typ string
			var notnull int
			var dflt sql.NullString
			var pk int
			if err := rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk); err != nil {
				return fmt.Errorf("failed to scan column info: %w", err)
			}
			existingColumns[name] = true
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("error iterating column info: %w", err)
		}

		if !existingColumns["email"] {
			if _, err := database.Exec("ALTER TABLE users ADD COLUMN email TEXT DEFAULT ''"); err != nil {
				return fmt.Errorf("failed to add email column: %w", err)
			}
			log.Println("Migration: added email column to users table")
		}

		if !existingColumns["role"] {
			if _, err := database.Exec("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'"); err != nil {
				return fmt.Errorf("failed to add role column: %w", err)
			}
			log.Println("Migration: added role column to users table")
		}
	}

	// Migration: Rename servers → peers (for existing databases)
	var hasServersTable bool
	err = database.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='servers'").Scan(&hasServersTable)
	if err != nil {
		return fmt.Errorf("failed to check for servers table: %w", err)
	}

	if hasServersTable {
		log.Println("Migration: renaming servers → peers")

		tx, err := database.Begin()
		if err != nil {
			return fmt.Errorf("failed to begin migration transaction: %w", err)
		}
		defer tx.Rollback()

		// 1. Rename servers table to peers
		if _, err := tx.Exec("ALTER TABLE servers RENAME TO peers"); err != nil {
			return fmt.Errorf("failed to rename servers to peers: %w", err)
		}

		// 2. Add is_manual column
		if _, err := tx.Exec("ALTER TABLE peers ADD COLUMN is_manual BOOLEAN NOT NULL DEFAULT 0"); err != nil {
			return fmt.Errorf("failed to add is_manual column: %w", err)
		}

		// 3. Recreate policies table with target_peer_id
		if _, err := tx.Exec(`CREATE TABLE policies_new (
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
        )`); err != nil {
			return fmt.Errorf("failed to create policies_new: %w", err)
		}
		if _, err := tx.Exec(`INSERT INTO policies_new SELECT id, name, description, source_group_id, service_id, target_server_id, action, priority, enabled, created_at, updated_at FROM policies`); err != nil {
			return fmt.Errorf("failed to copy policies: %w", err)
		}
		if _, err := tx.Exec("DROP TABLE policies"); err != nil {
			return fmt.Errorf("failed to drop policies: %w", err)
		}
		if _, err := tx.Exec("ALTER TABLE policies_new RENAME TO policies"); err != nil {
			return fmt.Errorf("failed to rename policies_new: %w", err)
		}

		// 4. Recreate rule_bundles table with peer_id
		if _, err := tx.Exec(`CREATE TABLE rule_bundles_new (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            peer_id INTEGER NOT NULL,
            version TEXT NOT NULL,
            rules_content TEXT NOT NULL,
            hmac TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            applied_at DATETIME,
            FOREIGN KEY(peer_id) REFERENCES peers(id) ON DELETE CASCADE
        )`); err != nil {
			return fmt.Errorf("failed to create rule_bundles_new: %w", err)
		}
		if _, err := tx.Exec(`INSERT INTO rule_bundles_new SELECT id, server_id, version, rules_content, hmac, created_at, applied_at FROM rule_bundles`); err != nil {
			return fmt.Errorf("failed to copy rule_bundles: %w", err)
		}
		if _, err := tx.Exec("DROP TABLE rule_bundles"); err != nil {
			return fmt.Errorf("failed to drop rule_bundles: %w", err)
		}
		if _, err := tx.Exec("ALTER TABLE rule_bundles_new RENAME TO rule_bundles"); err != nil {
			return fmt.Errorf("failed to rename rule_bundles_new: %w", err)
		}

		// 5. Recreate firewall_logs table with peer_id
		if _, err := tx.Exec(`CREATE TABLE firewall_logs_new (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            peer_id INTEGER NOT NULL,
            timestamp DATETIME NOT NULL,
            direction TEXT,
            src_ip TEXT NOT NULL,
            dst_ip TEXT NOT NULL,
            protocol TEXT NOT NULL,
            src_port INTEGER,
            dst_port INTEGER,
            action TEXT NOT NULL,
            raw_line TEXT,
            FOREIGN KEY(peer_id) REFERENCES peers(id) ON DELETE CASCADE
        )`); err != nil {
			return fmt.Errorf("failed to create firewall_logs_new: %w", err)
		}
		if _, err := tx.Exec(`INSERT INTO firewall_logs_new SELECT id, server_id, timestamp, direction, src_ip, dst_ip, protocol, src_port, dst_port, action, raw_line FROM firewall_logs`); err != nil {
			return fmt.Errorf("failed to copy firewall_logs: %w", err)
		}
		if _, err := tx.Exec("DROP TABLE firewall_logs"); err != nil {
			return fmt.Errorf("failed to drop firewall_logs: %w", err)
		}
		if _, err := tx.Exec("ALTER TABLE firewall_logs_new RENAME TO firewall_logs"); err != nil {
			return fmt.Errorf("failed to rename firewall_logs_new: %w", err)
		}

		// 6. Drop old indexes and create new ones
		tx.Exec("DROP INDEX IF EXISTS idx_servers_last_heartbeat")
		tx.Exec("DROP INDEX IF EXISTS idx_firewall_logs_server_id")
		tx.Exec("DROP INDEX IF EXISTS idx_firewall_logs_server_timestamp")
		tx.Exec("DROP INDEX IF EXISTS idx_servers_status_heartbeat")

		if _, err := tx.Exec("CREATE INDEX idx_peers_last_heartbeat ON peers(last_heartbeat)"); err != nil {
			return fmt.Errorf("failed to create idx_peers_last_heartbeat: %w", err)
		}
		if _, err := tx.Exec("CREATE INDEX idx_firewall_logs_peer_id ON firewall_logs(peer_id)"); err != nil {
			return fmt.Errorf("failed to create idx_firewall_logs_peer_id: %w", err)
		}
		if _, err := tx.Exec("CREATE INDEX idx_firewall_logs_peer_timestamp ON firewall_logs(peer_id, timestamp DESC)"); err != nil {
			return fmt.Errorf("failed to create idx_firewall_logs_peer_timestamp: %w", err)
		}
		if _, err := tx.Exec("CREATE INDEX idx_peers_status_heartbeat ON peers(status, last_heartbeat)"); err != nil {
			return fmt.Errorf("failed to create idx_peers_status_heartbeat: %w", err)
		}

		if err := tx.Commit(); err != nil {
			return fmt.Errorf("failed to commit migration: %w", err)
		}
		log.Println("Migration: successfully renamed servers → peers")
	}

	// Check peers table columns for is_manual (handles both fresh installs and migrated DBs)
	existingPeerColumns := make(map[string]bool)
	peerRows, err := database.Query("PRAGMA table_info(peers)")
	if err == nil {
		defer peerRows.Close()
		for peerRows.Next() {
			var cid int
			var name string
			var typ string
			var notnull int
			var dflt sql.NullString
			var pk int
			if err := peerRows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk); err != nil {
				return fmt.Errorf("failed to scan peer column info: %w", err)
			}
			existingPeerColumns[name] = true
		}
	}

	if !existingPeerColumns["is_manual"] {
		if _, err := database.Exec("ALTER TABLE peers ADD COLUMN is_manual BOOLEAN NOT NULL DEFAULT 0"); err != nil {
			return fmt.Errorf("failed to add is_manual column: %w", err)
		}
		log.Println("Migration: added is_manual column to peers table")
	}

	if !existingPeerColumns["description"] {
		if _, err := database.Exec("ALTER TABLE peers ADD COLUMN description TEXT DEFAULT ''"); err != nil {
			return fmt.Errorf("failed to add description column: %w", err)
		}
		log.Println("Migration: added description column to peers table")
	}

	// Migration: Add is_system column to services table
	existingServiceColumns := make(map[string]bool)
	serviceRows, err := database.Query("PRAGMA table_info(services)")
	if err == nil {
		defer serviceRows.Close()
		for serviceRows.Next() {
			var cid int
			var name string
			var typ string
			var notnull int
			var dflt sql.NullString
			var pk int
			if err := serviceRows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk); err != nil {
				return fmt.Errorf("failed to scan service column info: %w", err)
			}
			existingServiceColumns[name] = true
		}
	}

	if !existingServiceColumns["is_system"] {
		if _, err := database.Exec("ALTER TABLE services ADD COLUMN is_system BOOLEAN NOT NULL DEFAULT 0"); err != nil {
			return fmt.Errorf("failed to add is_system column: %w", err)
		}
		log.Println("Migration: added is_system column to services table")
	}

	if !existingServiceColumns["source_ports"] {
		if _, err := database.Exec("ALTER TABLE services ADD COLUMN source_ports TEXT DEFAULT ''"); err != nil {
			return fmt.Errorf("failed to add source_ports column: %w", err)
		}
		log.Println("Migration: added source_ports column to services table")
	}

	// Migration: Add is_system column to groups table
	existingGroupColumns := make(map[string]bool)
	groupRows, err := database.Query("PRAGMA table_info(groups)")
	if err == nil {
		defer groupRows.Close()
		for groupRows.Next() {
			var cid int
			var name string
			var typ string
			var notnull int
			var dflt sql.NullString
			var pk int
			if err := groupRows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk); err != nil {
				return fmt.Errorf("failed to scan group column info: %w", err)
			}
			existingGroupColumns[name] = true
		}
	}

	if !existingGroupColumns["is_system"] {
		if _, err := database.Exec("ALTER TABLE groups ADD COLUMN is_system BOOLEAN NOT NULL DEFAULT 0"); err != nil {
			return fmt.Errorf("failed to add is_system column to groups: %w", err)
		}
		log.Println("Migration: added is_system column to groups table")
	}

	// Migration: Add docker_only column to policies table
	existingPolicyColumns := make(map[string]bool)
	policyRows, err := database.Query("PRAGMA table_info(policies)")
	if err == nil {
		defer policyRows.Close()
		for policyRows.Next() {
			var cid int
			var name string
			var typ string
			var notnull int
			var dflt sql.NullString
			var pk int
			if err := policyRows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk); err != nil {
				return fmt.Errorf("failed to scan policy column info: %w", err)
			}
			existingPolicyColumns[name] = true
		}
	}

	if !existingPolicyColumns["docker_only"] {
		if _, err := database.Exec("ALTER TABLE policies ADD COLUMN docker_only BOOLEAN NOT NULL DEFAULT 0"); err != nil {
			return fmt.Errorf("failed to add docker_only column: %w", err)
		}
		log.Println("Migration: added docker_only column to policies table")
	}

	// Migration: group_members table restructure (peer-based)
	// Check if group_members has the old schema (value/type columns instead of peer_id)
	var hasOldGroupMembersSchema bool
	groupMembersRows, err := database.Query("PRAGMA table_info(group_members)")
	if err == nil {
		defer groupMembersRows.Close()
		for groupMembersRows.Next() {
			var cid int
			var name string
			var typ string
			var notnull int
			var dflt sql.NullString
			var pk int
			if err := groupMembersRows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk); err != nil {
				return fmt.Errorf("failed to scan group_members column info: %w", err)
			}
			// Old schema has 'value' column, new schema has 'peer_id'
			if name == "value" {
				hasOldGroupMembersSchema = true
				break
			}
		}
	}

	if hasOldGroupMembersSchema {
		log.Println("Migration: restructuring group_members table to peer-based schema")

		tx, err := database.Begin()
		if err != nil {
			return fmt.Errorf("failed to begin group_members migration transaction: %w", err)
		}
		defer tx.Rollback()

		// 1. Drop existing group_members table
		if _, err := tx.Exec("DROP TABLE group_members"); err != nil {
			return fmt.Errorf("failed to drop group_members table: %w", err)
		}

		// 2. Create new group_members table with peer_id
		if _, err := tx.Exec(`
			CREATE TABLE group_members (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				group_id INTEGER NOT NULL,
				peer_id INTEGER NOT NULL,
				added_at DATETIME DEFAULT CURRENT_TIMESTAMP,
				FOREIGN KEY(group_id) REFERENCES groups(id) ON DELETE CASCADE,
				FOREIGN KEY(peer_id) REFERENCES peers(id) ON DELETE CASCADE,
				UNIQUE(group_id, peer_id)
			)
		`); err != nil {
			return fmt.Errorf("failed to create group_members table: %w", err)
		}

		// 3. Create index
		if _, err := tx.Exec("CREATE INDEX idx_group_members_peer_id ON group_members(peer_id)"); err != nil {
			return fmt.Errorf("failed to create group_members index: %w", err)
		}

		// 4. Delete existing "any" group and recreate fresh
		if _, err := tx.Exec("DELETE FROM groups WHERE name = 'any'"); err != nil {
			return fmt.Errorf("failed to delete existing any group: %w", err)
		}
		if _, err := tx.Exec("INSERT INTO groups (name, description) VALUES ('any', 'System group representing all peers')"); err != nil {
			return fmt.Errorf("failed to create any group: %w", err)
		}

		if err := tx.Commit(); err != nil {
			return fmt.Errorf("failed to commit group_members migration: %w", err)
		}
		log.Println("Migration: successfully restructured group_members table")
	}

	// Migration: Upgrading policies to polymorphic sources and targets
	var hasPolymorphic bool
	err = database.QueryRow("SELECT COUNT(*) > 0 FROM pragma_table_info('policies') WHERE name='source_type'").Scan(&hasPolymorphic)
	if err == nil && !hasPolymorphic {
		log.Println("Migration: upgrading policies to polymorphic sources and targets")
		tx, err := database.Begin()
		if err != nil {
			return fmt.Errorf("begin polymorphic migration: %w", err)
		}
		defer tx.Rollback()

		if _, err := tx.Exec(`CREATE TABLE policies_poly (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			description TEXT,
			source_id INTEGER NOT NULL,
			source_type TEXT NOT NULL,
			service_id INTEGER NOT NULL,
			target_id INTEGER NOT NULL,
			target_type TEXT NOT NULL,
			action TEXT NOT NULL DEFAULT 'ACCEPT' CHECK(action IN ('ACCEPT', 'DROP', 'LOG_DROP')),
			priority INTEGER NOT NULL DEFAULT 100,
			enabled BOOLEAN NOT NULL DEFAULT 1,
			docker_only BOOLEAN NOT NULL DEFAULT 0,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY(service_id) REFERENCES services(id)
		)`); err != nil {
			return fmt.Errorf("create policies_poly: %w", err)
		}

		if _, err := tx.Exec(`INSERT INTO policies_poly 
			SELECT id, name, description, source_group_id, 'group', service_id, target_peer_id, 'peer', 
			action, priority, enabled, docker_only, created_at, updated_at FROM policies`); err != nil {
			return fmt.Errorf("copy policies: %w", err)
		}

		if _, err := tx.Exec("DROP TABLE policies"); err != nil {
			return fmt.Errorf("drop old policies: %w", err)
		}
		if _, err := tx.Exec("ALTER TABLE policies_poly RENAME TO policies"); err != nil {
			return fmt.Errorf("rename policies_poly: %w", err)
		}

		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit polymorphic migration: %w", err)
		}
		log.Println("Migration: successfully upgraded policies to polymorphic")
	}

	// Migration: Create special_targets table for broadcast/multicast addresses
	var hasSpecialTargets bool
	err = database.QueryRow("SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='table' AND name='special_targets'").Scan(&hasSpecialTargets)
	if err != nil {
		return fmt.Errorf("failed to check for special_targets table: %w", err)
	}

	if !hasSpecialTargets {
		log.Println("Migration: creating special_targets table")

		_, err = database.Exec(`
			CREATE TABLE special_targets (
				id INTEGER PRIMARY KEY,
				name TEXT UNIQUE NOT NULL,
				display_name TEXT NOT NULL,
				description TEXT,
				address TEXT NOT NULL
			)
		`)
		if err != nil {
			return fmt.Errorf("failed to create special_targets table: %w", err)
		}

		// Seed the special targets
		specialTargets := []struct {
			Name        string
			DisplayName string
			Description string
			Address     string
		}{
			{"__subnet_broadcast__", "Subnet Broadcast", "The broadcast address for the peer's subnet (e.g., 10.100.5.255)", "computed"},
			{"__limited_broadcast__", "Limited Broadcast", "The limited broadcast address (255.255.255.255)", "255.255.255.255"},
			{"__all_hosts__", "All Hosts (IGMP)", "All hosts multicast address for IGMP (224.0.0.1)", "224.0.0.1"},
			{"__mdns__", "mDNS", "mDNS multicast address (224.0.0.251)", "224.0.0.251"},
		}

		for _, st := range specialTargets {
			_, err = database.Exec(
				"INSERT INTO special_targets (name, display_name, description, address) VALUES (?, ?, ?, ?)",
				st.Name, st.DisplayName, st.Description, st.Address,
			)
			if err != nil {
				return fmt.Errorf("failed to seed special_target %s: %w", st.Name, err)
			}
		}

		log.Println("Migration: created and seeded special_targets table")
	}

	// Migration: Add loopback special target
	var hasLoopbackTarget bool
	err = database.QueryRow("SELECT COUNT(*) > 0 FROM special_targets WHERE name = ?", "loopback").Scan(&hasLoopbackTarget)
	if err != nil {
		return fmt.Errorf("failed to check for loopback special target: %w", err)
	}

	if !hasLoopbackTarget {
		log.Println("Migration: adding loopback special target")
		_, err = database.Exec(
			"INSERT INTO special_targets (name, display_name, description, address) VALUES (?, ?, ?, ?)",
			"loopback", "Loopback", "Local loopback address (127.0.0.1)", "127.0.0.1",
		)
		if err != nil {
			return fmt.Errorf("failed to add loopback special target: %w", err)
		}
		log.Println("Migration: added loopback special target")
	}

	// Migration: Add HMAC key rotation columns to peers table
	if !existingPeerColumns["hmac_key_rotation_token"] {
		if _, err := database.Exec("ALTER TABLE peers ADD COLUMN hmac_key_rotation_token TEXT"); err != nil {
			return fmt.Errorf("failed to add hmac_key_rotation_token column: %w", err)
		}
		log.Println("Migration: added hmac_key_rotation_token column to peers table")
	}

	if !existingPeerColumns["hmac_key_last_rotated_at"] {
		if _, err := database.Exec("ALTER TABLE peers ADD COLUMN hmac_key_last_rotated_at DATETIME"); err != nil {
			return fmt.Errorf("failed to add hmac_key_last_rotated_at column: %w", err)
		}
		log.Println("Migration: added hmac_key_last_rotated_at column to peers table")
	}

	return nil
}

// GetPeer fetches a peer by ID.
func GetPeer(ctx context.Context, database *sql.DB, peerID int) (models.PeerRow, error) {
	var p models.PeerRow
	err := database.QueryRowContext(ctx,
		`SELECT id, hostname, ip_address, os_type, arch, has_docker, agent_key,
		        agent_token, agent_version, is_manual, bundle_version, last_heartbeat, status, created_at
		 FROM peers WHERE id = ?`, peerID,
	).Scan(&p.ID, &p.Hostname, &p.IPAddress, &p.OSType, &p.Arch, &p.HasDocker,
		&p.AgentKey, &p.AgentToken, &p.AgentVersion, &p.IsManual, &p.BundleVersion,
		&p.LastHeartbeat, &p.Status, &p.CreatedAt)
	return p, err
}

// ListGroupMembers fetches all members of a group.
func ListGroupMembers(ctx context.Context, database *sql.DB, groupID int) ([]models.GroupMemberRow, error) {
	rows, err := database.QueryContext(ctx,
		"SELECT id, group_id, peer_id, added_at FROM group_members WHERE group_id = ?", groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var members []models.GroupMemberRow
	for rows.Next() {
		var m models.GroupMemberRow
		if err := rows.Scan(&m.ID, &m.GroupID, &m.PeerID, &m.AddedAt); err != nil {
			return nil, err
		}
		members = append(members, m)
	}
	return members, rows.Err()
}

// ListEnabledPolicies fetches enabled policies for a target peer (direct or group member), ordered by priority ASC.
func ListEnabledPolicies(ctx context.Context, database *sql.DB, peerID int) ([]models.PolicyRow, error) {
	// A policy applies to a peer if the target is exactly the peer (target_type='peer' AND target_id=peerID)
	// OR if the target is a group containing the peer (target_type='group' AND target_id IN group_members where peer_id=peerID).
	rows, err := database.QueryContext(ctx,
		`SELECT DISTINCT p.id, p.name, COALESCE(p.description, ''), p.source_id, p.source_type, p.service_id, p.target_id, p.target_type, 
	p.action, p.priority, p.enabled, p.docker_only, p.created_at, p.updated_at 
	FROM policies p
	LEFT JOIN group_members gm ON p.target_type = 'group' AND p.target_id = gm.group_id
	WHERE p.enabled = 1 AND (
		(p.target_type = 'peer' AND p.target_id = ?) OR
		(p.target_type = 'group' AND gm.peer_id = ?)
	)
	ORDER BY p.priority ASC`, peerID, peerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var policies []models.PolicyRow
	for rows.Next() {
		var p models.PolicyRow
		if err := rows.Scan(&p.ID, &p.Name, &p.Description, &p.SourceID, &p.SourceType, &p.ServiceID,
			&p.TargetID, &p.TargetType, &p.Action, &p.Priority, &p.Enabled, &p.DockerOnly, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, err
		}
		policies = append(policies, p)
	}
	return policies, rows.Err()
}

// GetService fetches a service by ID.
func GetService(ctx context.Context, database *sql.DB, serviceID int) (models.ServiceRow, error) {
	var s models.ServiceRow
	err := database.QueryRowContext(ctx,
		`SELECT id, name, ports, COALESCE(source_ports, ''), protocol, COALESCE(description, ''), direction_hint, COALESCE(is_system, 0)
		FROM services WHERE id = ?`, serviceID,
	).Scan(&s.ID, &s.Name, &s.Ports, &s.SourcePorts, &s.Protocol, &s.Description, &s.DirectionHint, &s.IsSystem)
	return s, err
}

// GetGroup fetches a group by ID.
func GetGroup(ctx context.Context, database *sql.DB, groupID int) (models.GroupRow, error) {
	var g models.GroupRow
	err := database.QueryRowContext(ctx,
		"SELECT id, name, COALESCE(description, ''), COALESCE(is_system, 0) FROM groups WHERE id = ?", groupID,
	).Scan(&g.ID, &g.Name, &g.Description, &g.IsSystem)
	return g, err
}

// SaveBundle inserts a new rule bundle and updates the peer's bundle_version.
func SaveBundle(ctx context.Context, database *sql.DB, params models.CreateBundleParams) (models.RuleBundleRow, error) {
	tx, err := database.BeginTx(ctx, nil)
	if err != nil {
		return models.RuleBundleRow{}, err
	}
	defer tx.Rollback()

	result, err := tx.ExecContext(ctx,
		`INSERT INTO rule_bundles (peer_id, version, rules_content, hmac) VALUES (?, ?, ?, ?)`,
		params.PeerID, params.Version, params.RulesContent, params.HMAC)
	if err != nil {
		return models.RuleBundleRow{}, err
	}

	bundleID, _ := result.LastInsertId()

	_, err = tx.ExecContext(ctx,
		`UPDATE peers SET bundle_version = ? WHERE id = ?`, params.Version, params.PeerID)
	if err != nil {
		return models.RuleBundleRow{}, err
	}

	if err := tx.Commit(); err != nil {
		return models.RuleBundleRow{}, err
	}

	return models.RuleBundleRow{
		ID:           int(bundleID),
		PeerID:       params.PeerID,
		Version:      params.Version,
		RulesContent: params.RulesContent,
		HMAC:         params.HMAC,
	}, nil
}

// FindPoliciesByGroupID finds policies by source target group id.
func FindPoliciesByGroupID(ctx context.Context, database *sql.DB, groupID int) ([]models.PolicyRow, error) {
	rows, err := database.QueryContext(ctx,
		`SELECT id, name, COALESCE(description, ''), source_id, source_type, service_id, target_id, target_type,
		action, priority, enabled, docker_only, created_at, updated_at
		FROM policies
		WHERE (source_type = 'group' AND source_id = ?) OR (target_type = 'group' AND target_id = ?)`, groupID, groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var policies []models.PolicyRow
	for rows.Next() {
		var p models.PolicyRow
		if err := rows.Scan(&p.ID, &p.Name, &p.Description, &p.SourceID, &p.SourceType, &p.ServiceID,
			&p.TargetID, &p.TargetType, &p.Action, &p.Priority, &p.Enabled, &p.DockerOnly, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, err
		}
		policies = append(policies, p)
	}
	return policies, rows.Err()
}

// seedSystemServices creates default system services if they don't exist.
// System services are non-deletable and provide essential firewall functionality.
func seedSystemServices(database *sql.DB) error {
	// Define system services to seed
	systemServices := []struct {
		Name        string
		Ports       string
		SourcePorts string
		Protocol    string
		Description string
	}{
		{
			Name:        "ICMP",
			Ports:       "",
			SourcePorts: "",
			Protocol:    "icmp",
			Description: "ICMP protocol for ping and network diagnostics (system service)",
		},
		{
			Name:        "IGMP",
			Ports:       "",
			SourcePorts: "",
			Protocol:    "igmp",
			Description: "IGMP protocol for multicast group management (system service)",
		},
		{
			Name:        "Multicast",
			Ports:       "",
			SourcePorts: "",
			Protocol:    "udp",
			Description: "Multicast traffic handling (system service)",
		},
		{
			Name:        "mDNS",
			Ports:       "5353",
			SourcePorts: "5353",
			Protocol:    "udp",
			Description: "Multicast DNS for local network service discovery (system service)",
		},
	}

	for _, svc := range systemServices {
		// Check if service already exists
		var count int
		err := database.QueryRow("SELECT COUNT(*) FROM services WHERE name = ?", svc.Name).Scan(&count)
		if err != nil {
			return fmt.Errorf("failed to check for existing service %s: %w", svc.Name, err)
		}

		if count > 0 {
			// Service exists, ensure it's marked as system service
			_, err := database.Exec("UPDATE services SET is_system = 1 WHERE name = ?", svc.Name)
			if err != nil {
				return fmt.Errorf("failed to update system flag for service %s: %w", svc.Name, err)
			}
			log.Printf("Seeding: ensured %s service is marked as system service", svc.Name)
			continue
		}

		// Insert new system service
		_, err = database.Exec(
			"INSERT INTO services (name, ports, source_ports, protocol, description, is_system) VALUES (?, ?, ?, ?, ?, 1)",
			svc.Name, svc.Ports, svc.SourcePorts, svc.Protocol, svc.Description,
		)
		if err != nil {
			return fmt.Errorf("failed to create system service %s: %w", svc.Name, err)
		}
		log.Printf("Seeding: created %s system service", svc.Name)
	}

	return nil
}

// seedSystemGroups creates default system groups if they don't exist.
// System groups are non-deletable and provide essential group functionality.
func seedSystemGroups(database *sql.DB) error {
	// Define system groups to seed
	systemGroups := []struct {
		Name        string
		Description string
	}{
		{
			Name:        "any",
			Description: "System group representing all peers",
		},
		{
			Name:        "localhost",
			Description: "Virtual group for local traffic (127.0.0.1/8)",
		},
	}

	for _, grp := range systemGroups {
		// Check if group already exists
		var count int
		err := database.QueryRow("SELECT COUNT(*) FROM groups WHERE name = ?", grp.Name).Scan(&count)
		if err != nil {
			return fmt.Errorf("failed to check for existing group %s: %w", grp.Name, err)
		}

		if count > 0 {
			// Group exists, ensure it's marked as system group
			_, err := database.Exec("UPDATE groups SET is_system = 1 WHERE name = ?", grp.Name)
			if err != nil {
				return fmt.Errorf("failed to update system flag for group %s: %w", grp.Name, err)
			}
			log.Printf("Seeding: ensured %s group is marked as system group", grp.Name)
			continue
		}

		// Insert new system group
		_, err = database.Exec(
			"INSERT INTO groups (name, description, is_system) VALUES (?, ?, 1)",
			grp.Name, grp.Description,
		)
		if err != nil {
			return fmt.Errorf("failed to create system group %s: %w", grp.Name, err)
		}
		log.Printf("Seeding: created %s system group", grp.Name)
	}

	return nil
}
