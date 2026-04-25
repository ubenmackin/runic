package db

import (
	"context"
	"database/sql"
	"fmt"

	"runic/internal/common"
	"runic/internal/common/log"
	"runic/internal/crypto"
)

// columnExists checks if a column exists in a table using pragma_table_info.
// Note: table name is validated by allowedTables safelist in the caller (addColumnIfMissing).
// We use fmt.Sprintf here because SQLite doesn't support parameterized identifiers.
func columnExists(ctx context.Context, database *sql.DB, table, column string) (bool, error) {
	// Validate table name against safelist to prevent SQL injection
	if !allowedTables[table] {
		return false, fmt.Errorf("table %q not in migration safelist", table)
	}

	var exists bool
	err := database.QueryRowContext(ctx,
		fmt.Sprintf("SELECT COUNT(*) > 0 FROM pragma_table_info('%s') WHERE name='%s'", table, column),
	).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check column %s.%s: %w", table, column, err)
	}
	return exists, nil
}

// addColumnIfMissing adds a column to a table if it doesn't already exist.
func addColumnIfMissing(ctx context.Context, database *sql.DB, table, column, definition string) error {
	// Validate table name against safelist to prevent SQL injection
	if !allowedTables[table] {
		return fmt.Errorf("table %q not in migration safelist", table)
	}

	exists, err := columnExists(ctx, database, table, column)
	if err != nil {
		return err
	}
	if !exists {
		if _, err := database.ExecContext(ctx, fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", table, column, definition)); err != nil {
			return fmt.Errorf("add column %s.%s: %w", table, column, err)
		}
		log.Info("Migration: added column", "column", column, "table", table)
	}
	return nil
}

func createSchema(ctx context.Context, database *sql.DB) error {
	_, err := database.ExecContext(ctx, schemaSQL)
	return err
}

// migrateSchema adds missing columns for schema upgrades on existing databases.
func migrateSchema(ctx context.Context, database *sql.DB) error {
	// Fresh database check: if no tables exist, skip all migrations
	var tableCount int
	err := database.QueryRowContext(ctx, "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").Scan(&tableCount)
	if err != nil {
		return fmt.Errorf("failed to count tables: %w", err)
	}
	if tableCount == 0 {
		log.Info("Migration: fresh database detected, skipping migrations")
		return nil
	}

	// Check if users table exists (fresh install check)
	var usersTableExists bool
	err = database.QueryRowContext(ctx, "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='table' AND name='users'").Scan(&usersTableExists)
	if err != nil {
		return fmt.Errorf("failed to check for users table: %w", err)
	}

	if err := addColumnIfMissing(ctx, database, "users", "email", "TEXT DEFAULT ''"); err != nil {
		return err
	}
	if err := addColumnIfMissing(ctx, database, "users", "role", "TEXT NOT NULL DEFAULT 'viewer'"); err != nil {
		return err
	}

	// Migration: Add token_type column to revoked_tokens
	var hasRevokedTokensTable bool
	err = database.QueryRowContext(ctx, "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='revoked_tokens'").Scan(&hasRevokedTokensTable)
	if err != nil {
		return fmt.Errorf("failed to check for revoked_tokens table: %w", err)
	}
	if hasRevokedTokensTable {
		if err := addColumnIfMissing(ctx, database, "revoked_tokens", "token_type", "TEXT NOT NULL DEFAULT 'unknown'"); err != nil {
			return err
		}
	}

	// Migration: Rename servers → peers (for existing databases)
	var hasServersTable bool
	err = database.QueryRowContext(ctx, "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='servers'").Scan(&hasServersTable)
	if err != nil {
		return fmt.Errorf("failed to check for servers table: %w", err)
	}

	if hasServersTable {
		log.Info("Migration: renaming servers to peers")

		tx, err := database.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("failed to begin migration transaction: %w", err)
		}
		committed := false
		defer func() {
			if !committed {
				if rErr := tx.Rollback(); rErr != nil {
					fmt.Printf("rollback failed: %v", rErr)
				}
			}
		}()

		// 1. Rename servers table to peers
		if _, err := tx.ExecContext(ctx, "ALTER TABLE servers RENAME TO peers"); err != nil {
			return fmt.Errorf("failed to rename servers to peers: %w", err)
		}

		// 2. Add is_manual column
		if _, err := tx.ExecContext(ctx, "ALTER TABLE peers ADD COLUMN is_manual BOOLEAN NOT NULL DEFAULT 0"); err != nil {
			return fmt.Errorf("failed to add is_manual column: %w", err)
		}

		// 3. Recreate policies table with target_peer_id
		if _, err := tx.ExecContext(ctx, `CREATE TABLE policies_new (
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
		if _, err := tx.ExecContext(ctx, `INSERT INTO policies_new SELECT id, name, description, source_group_id, service_id, target_server_id, action, priority, enabled, created_at, updated_at FROM policies`); err != nil {
			return fmt.Errorf("failed to copy policies: %w", err)
		}
		if _, err := tx.ExecContext(ctx, "DROP TABLE policies"); err != nil {
			return fmt.Errorf("failed to drop policies: %w", err)
		}
		if _, err := tx.ExecContext(ctx, "ALTER TABLE policies_new RENAME TO policies"); err != nil {
			return fmt.Errorf("failed to rename policies_new: %w", err)
		}

		// 4. Recreate rule_bundles table with peer_id
		if _, err := tx.ExecContext(ctx, `CREATE TABLE rule_bundles_new (
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
		if _, err := tx.ExecContext(ctx, `INSERT INTO rule_bundles_new SELECT id, server_id, version, rules_content, hmac, created_at, applied_at FROM rule_bundles`); err != nil {
			return fmt.Errorf("failed to copy rule_bundles: %w", err)
		}
		if _, err := tx.ExecContext(ctx, "DROP TABLE rule_bundles"); err != nil {
			return fmt.Errorf("failed to drop rule_bundles: %w", err)
		}
		if _, err := tx.ExecContext(ctx, "ALTER TABLE rule_bundles_new RENAME TO rule_bundles"); err != nil {
			return fmt.Errorf("failed to rename rule_bundles_new: %w", err)
		}

		// 5. Recreate firewall_logs table with peer_id
		if _, err := tx.ExecContext(ctx, `CREATE TABLE firewall_logs_new (
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
		if _, err := tx.ExecContext(ctx, `INSERT INTO firewall_logs_new SELECT id, server_id, timestamp, direction, src_ip, dst_ip, protocol, src_port, dst_port, action, raw_line FROM firewall_logs`); err != nil {
			return fmt.Errorf("failed to copy firewall_logs: %w", err)
		}
		if _, err := tx.ExecContext(ctx, "DROP TABLE firewall_logs"); err != nil {
			return fmt.Errorf("failed to drop firewall_logs: %w", err)
		}
		if _, err := tx.ExecContext(ctx, "ALTER TABLE firewall_logs_new RENAME TO firewall_logs"); err != nil {
			return fmt.Errorf("failed to rename firewall_logs_new: %w", err)
		}

		// 6. Drop old indexes and create new ones
		if _, err := tx.ExecContext(ctx, "DROP INDEX IF EXISTS idx_servers_last_heartbeat"); err != nil {
			log.Warn("Failed to drop old index idx_servers_last_heartbeat", "error", err)
		}
		if _, err := tx.ExecContext(ctx, "DROP INDEX IF EXISTS idx_firewall_logs_server_id"); err != nil {
			log.Warn("Failed to drop old index idx_firewall_logs_server_id", "error", err)
		}
		if _, err := tx.ExecContext(ctx, "DROP INDEX IF EXISTS idx_firewall_logs_server_timestamp"); err != nil {
			log.Warn("Failed to drop old index idx_firewall_logs_server_timestamp", "error", err)
		}
		if _, err := tx.ExecContext(ctx, "DROP INDEX IF EXISTS idx_servers_status_heartbeat"); err != nil {
			log.Warn("Failed to drop old index idx_servers_status_heartbeat", "error", err)
		}

		if _, err := tx.ExecContext(ctx, "CREATE INDEX idx_peers_last_heartbeat ON peers(last_heartbeat)"); err != nil {
			return fmt.Errorf("failed to create idx_peers_last_heartbeat: %w", err)
		}
		if _, err := tx.ExecContext(ctx, "CREATE INDEX idx_firewall_logs_peer_id ON firewall_logs(peer_id)"); err != nil {
			return fmt.Errorf("failed to create idx_firewall_logs_peer_id: %w", err)
		}
		if _, err := tx.ExecContext(ctx, "CREATE INDEX idx_firewall_logs_peer_timestamp ON firewall_logs(peer_id, timestamp DESC)"); err != nil {
			return fmt.Errorf("failed to create idx_firewall_logs_peer_timestamp: %w", err)
		}
		if _, err := tx.ExecContext(ctx, "CREATE INDEX idx_peers_status_heartbeat ON peers(status, last_heartbeat)"); err != nil {
			return fmt.Errorf("failed to create idx_peers_status_heartbeat: %w", err)
		}

		if err := tx.Commit(); err != nil {
			return fmt.Errorf("failed to commit migration: %w", err)
		}
		committed = true
		log.Info("Migration: successfully renamed servers to peers")
	}

	// Check peers table columns for missing columns (handles both fresh installs and migrated DBs)
	if err := addColumnIfMissing(ctx, database, "peers", "is_manual", "BOOLEAN NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	if err := addColumnIfMissing(ctx, database, "peers", "description", "TEXT DEFAULT ''"); err != nil {
		return err
	}
	if err := addColumnIfMissing(ctx, database, "peers", "has_ipset", "BOOLEAN DEFAULT NULL"); err != nil {
		return err
	}

	// Migration: Add is_system and source_ports columns to services table
	if err := addColumnIfMissing(ctx, database, "services", "is_system", "BOOLEAN NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	if err := addColumnIfMissing(ctx, database, "services", "source_ports", "TEXT DEFAULT ''"); err != nil {
		return err
	}
	// MC-001: Add no_conntrack column to services table
	if err := addColumnIfMissing(ctx, database, "services", "no_conntrack", "BOOLEAN NOT NULL DEFAULT 0"); err != nil {
		return err
	}

	// Migration: Add is_system column to groups table
	if err := addColumnIfMissing(ctx, database, "groups", "is_system", "BOOLEAN NOT NULL DEFAULT 0"); err != nil {
		return err
	}

	// Migration: Add docker_only and direction columns to policies table
	if err := addColumnIfMissing(ctx, database, "policies", "docker_only", "BOOLEAN NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	if err := addColumnIfMissing(ctx, database, "policies", "direction", "TEXT NOT NULL DEFAULT 'both'"); err != nil {
		return err
	}

	// Migration: group_members table restructure (peer-based)
	// Check if group_members has the old schema (value/type columns instead of peer_id)
	var hasOldGroupMembersSchema bool
	groupMembersRows, err := database.QueryContext(ctx, "PRAGMA table_info(group_members)")
	if err == nil {
		defer func() {
			if cerr := groupMembersRows.Close(); cerr != nil {
				log.Error("failed to close PRAGMA group_members rows", "error", cerr)
			}
		}()
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
		log.Info("Migration: restructuring group_members table to peer-based schema")

		tx, err := database.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("failed to begin group_members migration transaction: %w", err)
		}
		committed := false
		defer func() {
			if !committed {
				if rErr := tx.Rollback(); rErr != nil {
					log.Warn("Failed to rollback transaction", "error", rErr)
				}
			}
		}()

		// 1. Drop existing group_members table
		if _, err := tx.ExecContext(ctx, "DROP TABLE group_members"); err != nil {
			return fmt.Errorf("failed to drop group_members table: %w", err)
		}

		// 2. Create new group_members table with peer_id
		if _, err := tx.ExecContext(ctx, `
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
		if _, err := tx.ExecContext(ctx, "CREATE INDEX idx_group_members_peer_id ON group_members(peer_id)"); err != nil {
			return fmt.Errorf("failed to create group_members index: %w", err)
		}

		// 4. Delete existing "any" group (moved to separate migration with special targets)
		if _, err := tx.ExecContext(ctx, "DELETE FROM groups WHERE name = 'any'"); err != nil {
			return fmt.Errorf("failed to delete existing any group: %w", err)
		}

		if err := tx.Commit(); err != nil {
			return fmt.Errorf("failed to commit group_members migration: %w", err)
		}
		committed = true
		log.Info("Migration: successfully restructured group_members table")
	}

	// Migration: Upgrading policies to polymorphic sources and targets
	var hasPolymorphic bool
	err = database.QueryRowContext(ctx, "SELECT COUNT(*) > 0 FROM pragma_table_info('policies') WHERE name='source_type'").Scan(&hasPolymorphic)
	if err == nil && !hasPolymorphic {
		log.Info("Migration: upgrading policies to polymorphic sources and targets")
		tx, err := database.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("begin polymorphic migration: %w", err)
		}
		committed := false
		defer func() {
			if !committed {
				if rErr := tx.Rollback(); rErr != nil {
					log.Warn("Failed to rollback transaction", "error", rErr)
				}
			}
		}()

		if _, err := tx.ExecContext(ctx, `CREATE TABLE policies_poly (
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

		if _, err := tx.ExecContext(ctx, `INSERT INTO policies_poly
			SELECT id, name, description, source_group_id, 'group', service_id, target_peer_id, 'peer',
			action, priority, enabled, docker_only, created_at, updated_at FROM policies`); err != nil {
			return fmt.Errorf("copy policies: %w", err)
		}

		if _, err := tx.ExecContext(ctx, "DROP TABLE policies"); err != nil {
			return fmt.Errorf("drop old policies: %w", err)
		}
		if _, err := tx.ExecContext(ctx, "ALTER TABLE policies_poly RENAME TO policies"); err != nil {
			return fmt.Errorf("rename policies_poly: %w", err)
		}

		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit polymorphic migration: %w", err)
		}
		committed = true
		log.Info("Migration: successfully upgraded policies to polymorphic")
	}

	// Migration: Create special_targets table for broadcast/multicast addresses
	var hasSpecialTargets bool
	err = database.QueryRowContext(ctx, "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='table' AND name='special_targets'").Scan(&hasSpecialTargets)
	if err != nil {
		return fmt.Errorf("failed to check for special_targets table: %w", err)
	}

	if !hasSpecialTargets {
		log.Info("Migration: creating special_targets table")

		_, err = database.ExecContext(ctx, `
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
			{"__subnet_broadcast__", "Subnet Broadcast", "The broadcast address for the peer's local subnet (e.g., 10.100.5.255 for 10.100.5.0/24). Computed dynamically from each peer's IP and CIDR. Used as a policy Source to accept incoming broadcast traffic, or as a Target to send broadcasts.", "computed"},
			{"__limited_broadcast__", "Limited Broadcast", "The limited broadcast address 255.255.255.255. Reaches all hosts on the local network segment regardless of subnet configuration. Used as a Source to accept broadcast traffic.", "255.255.255.255"},
			{"__all_hosts__", "All Hosts (IGMP)", "The all-hosts multicast address 224.0.0.1. Used by IGMP to reach every host on the local subnet. When used as a Source, accepts multicast traffic destined for all hosts.", "224.0.0.1"},
			{"__mdns__", "mDNS", "The mDNS multicast address 224.0.0.251. Used for local network service discovery (.local hostnames). When used as a Target with the mDNS service, enables multicast DNS resolution.", "224.0.0.251"},
			{"__igmpv3__", "IGMPv3", "The IGMPv3 routers multicast address 224.0.0.22. Used by hosts to report multicast group membership to routers. When used as a Target, enables IGMPv3 membership reporting.", "224.0.0.22"},
		}

		for _, st := range specialTargets {
			_, err = database.ExecContext(ctx,
				"INSERT INTO special_targets (name, display_name, description, address) VALUES (?, ?, ?, ?)",
				st.Name, st.DisplayName, st.Description, st.Address,
			)
			if err != nil {
				return fmt.Errorf("failed to seed special_target %s: %w", st.Name, err)
			}
		}

		log.Info("Migration: created and seeded special_targets table")
	}

	// Migration: Add loopback special target
	var hasLoopbackTarget bool
	err = database.QueryRowContext(ctx, "SELECT COUNT(*) > 0 FROM special_targets WHERE name = ?", "loopback").Scan(&hasLoopbackTarget)
	if err != nil {
		return fmt.Errorf("failed to check for loopback special target: %w", err)
	}

	if !hasLoopbackTarget {
		log.Info("Migration: adding loopback special target")
		_, err = database.ExecContext(ctx,
			"INSERT INTO special_targets (name, display_name, description, address) VALUES (?, ?, ?, ?)",
			"loopback", "Loopback", "The local loopback address 127.0.0.1. Traffic sent to this address never leaves the host—it is routed back internally. Used as a Source or Target to allow or restrict local inter-process communication on the same machine.", "127.0.0.1",
		)
		if err != nil {
			return fmt.Errorf("failed to add loopback special target: %w", err)
		}
		log.Info("Migration: added loopback special target")
	}

	// Migration: Add __any_ip__ special target
	var hasAnyIPTarget bool
	err = database.QueryRowContext(ctx, "SELECT COUNT(*) > 0 FROM special_targets WHERE name = ?", "__any_ip__").Scan(&hasAnyIPTarget)
	if err != nil {
		return fmt.Errorf("failed to check for __any_ip__ special target: %w", err)
	}

	if !hasAnyIPTarget {
		log.Info("Migration: adding __any_ip__ special target")
		_, err = database.ExecContext(ctx,
			"INSERT INTO special_targets (id, name, display_name, description, address) VALUES (?, ?, ?, ?, ?)",
			6, "__any_ip__", "Any IP (0.0.0.0/0)", "Matches any IPv4 address (0.0.0.0/0). Used as a Source to accept traffic from anywhere on the network, or as a Target to allow outbound connections to any destination. This is the broadest possible address scope.", "0.0.0.0/0",
		)
		if err != nil {
			return fmt.Errorf("failed to add __any_ip__ special target: %w", err)
		}
		log.Info("Migration: added __any_ip__ special target")
	}

	// Migration: Add __all_peers__ special target
	var hasAllPeersTarget bool
	err = database.QueryRowContext(ctx, "SELECT COUNT(*) > 0 FROM special_targets WHERE name = ?", "__all_peers__").Scan(&hasAllPeersTarget)
	if err != nil {
		return fmt.Errorf("failed to check for __all_peers__ special target: %w", err)
	}

	if !hasAllPeersTarget {
		log.Info("Migration: adding __all_peers__ special target")
		_, err = database.ExecContext(ctx,
			"INSERT INTO special_targets (id, name, display_name, description, address) VALUES (?, ?, ?, ?, ?)",
			7, "__all_peers__", "All Peers", "Resolves to the IP addresses of all registered Runic peers in the mesh. When used as a Target, allows traffic to reach every peer in the network. When used as a Source, accepts traffic originating from any peer.", "dynamic",
		)
		if err != nil {
			return fmt.Errorf("failed to add __all_peers__ special target: %w", err)
		}
		log.Info("Migration: added __all_peers__ special target")
	}

	// MC-002: Migration: Add __igmpv3__ special target for existing databases
	var hasIGMPv3Target bool
	err = database.QueryRowContext(ctx, "SELECT COUNT(*) > 0 FROM special_targets WHERE name = ?", "__igmpv3__").Scan(&hasIGMPv3Target)
	if err != nil {
		return fmt.Errorf("failed to check for __igmpv3__ special target: %w", err)
	}

	if !hasIGMPv3Target {
		log.Info("Migration: adding __igmpv3__ special target")
		_, err = database.ExecContext(ctx,
			"INSERT INTO special_targets (id, name, display_name, description, address) VALUES (?, ?, ?, ?, ?)",
			8, "__igmpv3__", "IGMPv3", "The IGMPv3 routers multicast address 224.0.0.22. Used by hosts to report multicast group membership to routers on the local subnet. When used as a Target with a matching service, enables IGMPv3 membership reporting for multicast routing.", "224.0.0.22",
		)
		if err != nil {
			return fmt.Errorf("failed to add __igmpv3__ special target: %w", err)
		}
		log.Info("Migration: added __igmpv3__ special target")
	}

	// Migration: Add __internet__ special target
	var hasInternetTarget bool
	err = database.QueryRowContext(ctx, "SELECT COUNT(*) > 0 FROM special_targets WHERE name = ?", "__internet__").Scan(&hasInternetTarget)
	if err != nil {
		return fmt.Errorf("failed to check for __internet__ special target: %w", err)
	}

	if !hasInternetTarget {
		log.Info("Migration: adding __internet__ special target")
		_, err = database.ExecContext(ctx,
			"INSERT INTO special_targets (id, name, display_name, description, address) VALUES (?, ?, ?, ?, ?)",
			9, "__internet__", "Internet", "All public IPs (excludes private ranges 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8)", "computed",
		)
		if err != nil {
			return fmt.Errorf("failed to add __internet__ special target: %w", err)
		}
		log.Info("Migration: added __internet__ special target")
	}

	// Migration: Delete the broken "any" system group
	log.Info("Migration: deleting broken any system group")
	_, err = database.ExecContext(ctx, "DELETE FROM group_members WHERE group_id IN (SELECT id FROM groups WHERE name = 'any')")
	if err != nil {
		return fmt.Errorf("failed to delete group_members for 'any' group: %w", err)
	}
	_, err = database.ExecContext(ctx, "DELETE FROM groups WHERE name = 'any'")
	if err != nil {
		return fmt.Errorf("failed to delete 'any' group: %w", err)
	}
	log.Info("Migration: deleted broken any system group")

	// Migration: Create system_config table
	var hasSystemConfig bool
	err = database.QueryRowContext(ctx, "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='table' AND name='system_config'").Scan(&hasSystemConfig)
	if err != nil {
		return fmt.Errorf("failed to check for system_config table: %w", err)
	}
	if !hasSystemConfig {
		log.Info("Migration: creating system_config table")
		_, err = database.ExecContext(ctx, `
			CREATE TABLE system_config (
				key TEXT PRIMARY KEY,
				value TEXT NOT NULL,
				created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
				updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
			)
		`)
		if err != nil {
			return fmt.Errorf("failed to create system_config table: %w", err)
		}
		log.Info("Migration: created system_config table")
	}

	// Migration: Add HMAC key rotation columns to peers table
	if err := addColumnIfMissing(ctx, database, "peers", "hmac_key_rotation_token", "TEXT"); err != nil {
		return err
	}
	if err := addColumnIfMissing(ctx, database, "peers", "hmac_key_last_rotated_at", "DATETIME"); err != nil {
		return err
	}

	// Migration: Add target_scope column to policies table
	targetScopeExists, err := columnExists(ctx, database, "policies", "target_scope")
	if err != nil {
		return err
	}
	if !targetScopeExists {
		if err := addColumnIfMissing(ctx, database, "policies", "target_scope", "TEXT NOT NULL DEFAULT 'both' CHECK(target_scope IN ('both', 'host', 'docker'))"); err != nil {
			return err
		}

		// Migrate docker_only values to target_scope if docker_only column exists
		dockerOnlyExists, err := columnExists(ctx, database, "policies", "docker_only")
		if err != nil {
			return err
		}
		if dockerOnlyExists {
			if _, err := database.ExecContext(ctx, "UPDATE policies SET target_scope = 'docker' WHERE docker_only = 1"); err != nil {
				log.Warn("Failed to map docker_only to target_scope", "error", err)
			}
		}
	}

	// Try to drop docker_only column (requires SQLite 3.35.0+)
	dockerOnlyExists, err := columnExists(ctx, database, "policies", "docker_only")
	if err != nil {
		return err
	}
	if dockerOnlyExists {
		if _, err := database.ExecContext(ctx, "ALTER TABLE policies DROP COLUMN docker_only"); err != nil {
			log.Warn("Skipped dropping docker_only column (SQLite 3.35.0+ required)", "error", err)
		} else {
			log.Info("Migration: successfully dropped docker_only column from policies table")
		}
	}

	// Migration: Create registration_tokens table
	var hasRegistrationTokens bool
	err = database.QueryRowContext(ctx, "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='table' AND name='registration_tokens'").Scan(&hasRegistrationTokens)
	if err != nil {
		return fmt.Errorf("failed to check for registration_tokens table: %w", err)
	}
	if !hasRegistrationTokens {
		log.Info("Migration: creating registration_tokens table")
		_, err = database.ExecContext(ctx, `
			CREATE TABLE registration_tokens (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				token TEXT NOT NULL UNIQUE,
				description TEXT,
				created_by INTEGER REFERENCES users(id),
				created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
				used_at DATETIME,
				used_by_hostname TEXT,
				is_revoked INTEGER DEFAULT 0
			)
		`)
		if err != nil {
			return fmt.Errorf("failed to create registration_tokens table: %w", err)
		}
		_, err = database.ExecContext(ctx, "CREATE INDEX IF NOT EXISTS idx_reg_tokens_active ON registration_tokens(used_at, is_revoked)")
		if err != nil {
			return fmt.Errorf("failed to create idx_reg_tokens_active index: %w", err)
		}
		log.Info("Migration: created registration_tokens table")
	}

	// Migration: Create composite index on firewall_logs(action, timestamp DESC) for dashboard performance
	// This index optimizes queries that filter by action and order by timestamp (e.g., blocked events)
	// First check if firewall_logs table exists (may not exist on fresh install before migration)
	var hasFirewallLogsTable bool
	err = database.QueryRowContext(ctx, "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='table' AND name='firewall_logs'").Scan(&hasFirewallLogsTable)
	if err != nil {
		return fmt.Errorf("failed to check for firewall_logs table: %w", err)
	}
	if hasFirewallLogsTable {
		var hasActionTimestampIdx bool
		err = database.QueryRowContext(ctx, "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='index' AND name='idx_firewall_logs_action_timestamp'").Scan(&hasActionTimestampIdx)
		if err != nil {
			return fmt.Errorf("failed to check for idx_firewall_logs_action_timestamp: %w", err)
		}
		if !hasActionTimestampIdx {
			log.Info("Migration: creating idx-firewall-logs-action-timestamp index")
			if _, err := database.ExecContext(ctx, "CREATE INDEX IF NOT EXISTS idx_firewall_logs_action_timestamp ON firewall_logs(action, timestamp DESC)"); err != nil {
				return fmt.Errorf("failed to create idx_firewall_logs_action_timestamp: %w", err)
			}
			log.Info("Migration: created idx-firewall-logs-action-timestamp index")
		}
	}

	// Migration: Create pending_changes table for tracking queued changes per peer
	var hasPendingChanges bool
	err = database.QueryRowContext(ctx, "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='table' AND name='pending_changes'").Scan(&hasPendingChanges)
	if err != nil {
		return fmt.Errorf("failed to check for pending_changes table: %w", err)
	}
	if !hasPendingChanges {
		log.Info("Migration: creating pending_changes table")
		_, err = database.ExecContext(ctx, `
			CREATE TABLE pending_changes (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				peer_id INTEGER NOT NULL REFERENCES peers(id),
				change_type TEXT NOT NULL CHECK (change_type IN ('policy', 'group', 'service')),
				change_id INTEGER NOT NULL,
				change_action TEXT NOT NULL CHECK (change_action IN ('create', 'update', 'delete')),
				change_summary TEXT NOT NULL,
				created_at DATETIME DEFAULT CURRENT_TIMESTAMP
			)
		`)
		if err != nil {
			return fmt.Errorf("failed to create pending_changes table: %w", err)
		}
		_, err = database.ExecContext(ctx, "CREATE INDEX IF NOT EXISTS idx_pending_changes_peer ON pending_changes(peer_id)")
		if err != nil {
			return fmt.Errorf("failed to create idx_pending_changes_peer index: %w", err)
		}
		log.Info("Migration: created pending_changes table")
	}

	// Migration: Create pending_bundle_previews table for storing bundle previews
	var hasPendingBundlePreviews bool
	err = database.QueryRowContext(ctx, "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='table' AND name='pending_bundle_previews'").Scan(&hasPendingBundlePreviews)
	if err != nil {
		return fmt.Errorf("failed to check for pending_bundle_previews table: %w", err)
	}
	if !hasPendingBundlePreviews {
		log.Info("Migration: creating pending_bundle_previews table")
		_, err = database.ExecContext(ctx, `
			CREATE TABLE pending_bundle_previews (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				peer_id INTEGER NOT NULL UNIQUE REFERENCES peers(id),
				rules_content TEXT NOT NULL,
				diff_content TEXT,
				version_hash TEXT NOT NULL,
				created_at DATETIME DEFAULT CURRENT_TIMESTAMP
			)
		`)
		if err != nil {
			return fmt.Errorf("failed to create pending_bundle_previews table: %w", err)
		}
		log.Info("Migration: created pending_bundle_previews table")
	}

	// Migration: Add version_number column to rule_bundles
	var hasVersionNumberColumn bool
	err = database.QueryRowContext(ctx, "SELECT COUNT(*) > 0 FROM pragma_table_info('rule_bundles') WHERE name='version_number'").Scan(&hasVersionNumberColumn)
	if err != nil {
		return fmt.Errorf("failed to check for version_number column: %w", err)
	}
	if !hasVersionNumberColumn {
		log.Info("Migration: adding version_number column to rule_bundles")
		tx, err := database.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("failed to begin version_number migration: %w", err)
		}
		committed := false
		defer func() {
			if !committed {
				if rErr := tx.Rollback(); rErr != nil {
					log.Warn("Failed to rollback transaction", "error", rErr)
				}
			}
		}()

		// Create new table with version_number
		if _, err := tx.ExecContext(ctx, `CREATE TABLE rule_bundles_v2 (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			peer_id INTEGER NOT NULL,
			version TEXT NOT NULL,
			version_number INTEGER NOT NULL DEFAULT 0,
			rules_content TEXT NOT NULL,
			hmac TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			applied_at DATETIME,
			FOREIGN KEY(peer_id) REFERENCES peers(id) ON DELETE CASCADE,
			UNIQUE(peer_id, version)
		)`); err != nil {
			return fmt.Errorf("failed to create rule_bundles_v2: %w", err)
		}

		// Copy data and backfill version_number using ROW_NUMBER()
		if _, err := tx.ExecContext(ctx, `INSERT INTO rule_bundles_v2 (id, peer_id, version, version_number, rules_content, hmac, created_at, applied_at)
			SELECT id, peer_id, version,
			ROW_NUMBER() OVER (PARTITION BY peer_id ORDER BY created_at),
			rules_content, hmac, created_at, applied_at
			FROM rule_bundles`); err != nil {
			return fmt.Errorf("failed to copy rule_bundles: %w", err)
		}

		if _, err := tx.ExecContext(ctx, "DROP TABLE rule_bundles"); err != nil {
			return fmt.Errorf("failed to drop rule_bundles: %w", err)
		}
		if _, err := tx.ExecContext(ctx, "ALTER TABLE rule_bundles_v2 RENAME TO rule_bundles"); err != nil {
			return fmt.Errorf("failed to rename rule_bundles_v2: %w", err)
		}

		if err := tx.Commit(); err != nil {
			return fmt.Errorf("failed to commit version_number migration: %w", err)
		}
		committed = true
		log.Info("Migration: added version_number column to rule_bundles")
	}

	// Migration: Add push_jobs and push_job_peers tables for async push-all-rules
	var hasPushJobsTable bool
	err = database.QueryRowContext(ctx, "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='push_jobs'").Scan(&hasPushJobsTable)
	if err != nil {
		return fmt.Errorf("failed to check for push_jobs table: %w", err)
	}
	if !hasPushJobsTable {
		if _, err := database.ExecContext(ctx, `CREATE TABLE push_jobs (
			id TEXT PRIMARY KEY,
			initiated_by TEXT,
			total_peers INTEGER NOT NULL,
			succeeded_count INTEGER DEFAULT 0,
			failed_count INTEGER DEFAULT 0,
			status TEXT NOT NULL DEFAULT 'running' CHECK(status IN ('pending', 'running', 'completed', 'completed_with_errors', 'failed', 'cancelled')),
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			completed_at DATETIME
		)`); err != nil {
			return fmt.Errorf("failed to create push_jobs table: %w", err)
		}
		if _, err := database.ExecContext(ctx, `CREATE TABLE push_job_peers (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			job_id TEXT NOT NULL REFERENCES push_jobs(id) ON DELETE CASCADE,
			peer_id INTEGER NOT NULL REFERENCES peers(id),
			peer_hostname TEXT NOT NULL,
			status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending', 'notified', 'applied', 'failed')),
			error_message TEXT,
			notified_at DATETIME,
			applied_at DATETIME,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(job_id, peer_id)
		)`); err != nil {
			return fmt.Errorf("failed to create push_job_peers table: %w", err)
		}
		if _, err := database.ExecContext(ctx, "CREATE INDEX idx_push_job_peers_job_id ON push_job_peers(job_id)"); err != nil {
			return fmt.Errorf("failed to create idx_push_job_peers_job_id index: %w", err)
		}
		if _, err := database.ExecContext(ctx, "CREATE INDEX idx_push_jobs_status ON push_jobs(status)"); err != nil {
			return fmt.Errorf("failed to create idx_push_jobs_status index: %w", err)
		}
		log.Info("Migration: added push_jobs and push_job_peers tables")
	}

	// Migration: Set default log retention days
	var hasLogRetention int
	err = database.QueryRowContext(ctx, "SELECT COUNT(*) > 0 FROM system_config WHERE key = 'log_retention_days'").Scan(&hasLogRetention)
	if err != nil {
		return fmt.Errorf("failed to check for log_retention_days: %w", err)
	}
	if hasLogRetention == 0 {
		log.Info("Migration: setting default log_retention_days")
		_, err = database.ExecContext(ctx, "INSERT INTO system_config (key, value) VALUES ('log_retention_days', '30')")
		if err != nil {
			return fmt.Errorf("failed to set default log_retention_days: %w", err)
		}
		log.Info("Migration: set default log_retention_days to 30")
	}

	// Migration: Add is_pending_delete columns
	if err := addColumnIfMissing(ctx, database, "groups", "is_pending_delete", "BOOLEAN NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	if err := addColumnIfMissing(ctx, database, "services", "is_pending_delete", "BOOLEAN NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	if err := addColumnIfMissing(ctx, database, "policies", "is_pending_delete", "BOOLEAN NOT NULL DEFAULT 0"); err != nil {
		return err
	}

	// Migration: Create change_snapshots table
	var hasChangeSnapshots bool
	err = database.QueryRowContext(ctx, "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='table' AND name='change_snapshots'").Scan(&hasChangeSnapshots)
	if err != nil {
		return fmt.Errorf("failed to check for change_snapshots table: %w", err)
	}
	if !hasChangeSnapshots {
		log.Info("Migration: creating change_snapshots table")
		_, err = database.ExecContext(ctx, `
			CREATE TABLE change_snapshots (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				entity_type TEXT NOT NULL CHECK (entity_type IN ('group', 'service', 'policy')),
				entity_id INTEGER NOT NULL,
				action TEXT NOT NULL CHECK (action IN ('create', 'update', 'delete')),
				snapshot_data TEXT,
				created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
				UNIQUE(entity_type, entity_id)
			)
		`)
		if err != nil {
			return fmt.Errorf("failed to create change_snapshots table: %w", err)
		}
		log.Info("Migration: created change_snapshots table")
	}

	// Migration: Add encryption_key to system_config for AES-256-GCM encryption
	var hasEncryptionKey int
	err = database.QueryRowContext(ctx, "SELECT COUNT(*) > 0 FROM system_config WHERE key = 'encryption_key'").Scan(&hasEncryptionKey)
	if err != nil {
		return fmt.Errorf("failed to check for encryption_key: %w", err)
	}
	if hasEncryptionKey == 0 {
		log.Info("Migration: generating and storing encryption_key")
		// Generate a secure random 32-byte key (hex-encoded for storage)
		encryptionKey, err := common.GenerateHMACKey()
		if err != nil {
			return fmt.Errorf("failed to generate encryption_key: %w", err)
		}
		_, err = database.ExecContext(ctx, "INSERT INTO system_config (key, value) VALUES ('encryption_key', ?)", encryptionKey)
		if err != nil {
			return fmt.Errorf("failed to store encryption_key: %w", err)
		}
		log.Info("Migration: stored encryption_key in system_config")
	}

	// Migration: Encrypt existing jwt_secret and agent_jwt_secret
	// This migration encrypts any plaintext secrets that were stored before encryption was implemented
	var secretsEncrypted int
	err = database.QueryRowContext(ctx, "SELECT COUNT(*) > 0 FROM system_config WHERE key = 'secrets_encrypted'").Scan(&secretsEncrypted)
	if err != nil {
		return fmt.Errorf("failed to check for secrets_encrypted marker: %w", err)
	}
	if secretsEncrypted == 0 {
		log.Info("Migration: encrypting existing secrets (jwt_secret, agent_jwt_secret)")

		// Get the encryption key
		var encryptionKey string
		err = database.QueryRowContext(ctx, "SELECT value FROM system_config WHERE key = 'encryption_key'").Scan(&encryptionKey)
		if err != nil {
			return fmt.Errorf("failed to get encryption_key: %w", err)
		}

		// List of secrets to encrypt
		secretsToEncrypt := []string{"jwt_secret", "agent_jwt_secret"}

		for _, secretKey := range secretsToEncrypt {
			// Check if the secret exists
			var secretValue string
			err = database.QueryRowContext(ctx, "SELECT value FROM system_config WHERE key = ?", secretKey).Scan(&secretValue)
			if err == sql.ErrNoRows {
				// Secret doesn't exist, skip
				continue
			}
			if err != nil {
				return fmt.Errorf("failed to get sensitive configuration: %w", err)
			}

			// Check if already encrypted by trying to decrypt
			// Encrypted values are base64-encoded and have a specific format (salt || nonce || ciphertext)
			// We attempt to decrypt to verify. If it succeeds, it's already encrypted.
			_, decryptErr := crypto.Decrypt(secretValue, encryptionKey)
			if decryptErr == nil {
				// Already encrypted, skip
				log.Info("Migration: secret already encrypted")
				continue
			}

			// Encrypt the plaintext value
			encryptedValue, err := crypto.Encrypt(secretValue, encryptionKey)
			if err != nil {
				return fmt.Errorf("failed to encrypt sensitive configuration: %w", err)
			}

			// Update the secret with encrypted value
			_, err = database.ExecContext(ctx, "UPDATE system_config SET value = ?, updated_at = CURRENT_TIMESTAMP WHERE key = ?", encryptedValue, secretKey)
			if err != nil {
				return fmt.Errorf("failed to update sensitive configuration: %w", err)
			}
			log.Info("Migration: encrypted secret")
		}

		// Mark that secrets have been encrypted
		_, err = database.ExecContext(ctx, "INSERT INTO system_config (key, value) VALUES ('secrets_encrypted', '1')")
		if err != nil {
			return fmt.Errorf("failed to mark secrets as encrypted: %w", err)
		}
		log.Info("Migration: completed encrypting existing secrets")
	}

	// Migration: Create alert system tables
	// Table 1: alert_rules - stores alert rule definitions
	var hasAlertRules bool
	err = database.QueryRowContext(ctx, "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='table' AND name='alert_rules'").Scan(&hasAlertRules)
	if err != nil {
		return fmt.Errorf("failed to check for alert_rules table: %w", err)
	}
	if !hasAlertRules {
		log.Info("Migration: creating alert_rules table")
		_, err = database.ExecContext(ctx, `
CREATE TABLE alert_rules (
id INTEGER PRIMARY KEY AUTOINCREMENT,
name TEXT NOT NULL,
alert_type TEXT NOT NULL CHECK(alert_type IN ('peer_offline', 'bundle_failed', 'blocked_spike', 'peer_online', 'new_peer', 'bundle_deployed')),
enabled BOOLEAN NOT NULL DEFAULT 1,
threshold_value INTEGER,
threshold_window_minutes INTEGER,
peer_id TEXT,
throttle_minutes INTEGER NOT NULL DEFAULT 5,
created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
)
`)
		if err != nil {
			return fmt.Errorf("failed to create alert_rules table: %w", err)
		}
		_, err = database.ExecContext(ctx, "CREATE INDEX IF NOT EXISTS idx_alert_rules_type_enabled ON alert_rules(alert_type, enabled)")
		if err != nil {
			return fmt.Errorf("failed to create idx_alert_rules_type_enabled index: %w", err)
		}
		_, err = database.ExecContext(ctx, "CREATE INDEX IF NOT EXISTS idx_alert_rules_peer_id ON alert_rules(peer_id)")
		if err != nil {
			return fmt.Errorf("failed to create idx_alert_rules_peer_id index: %w", err)
		}
		log.Info("Migration: created alert_rules table")

		// Seed default alert rules
		log.Info("Migration: seeding default alert rules")
		_, err = database.ExecContext(ctx, `
INSERT INTO alert_rules (name, alert_type, enabled, threshold_value, threshold_window_minutes, throttle_minutes) VALUES
('Peer Offline', 'peer_offline', 1, 0, 5, 15),
('Peer Online', 'peer_online', 1, 0, 5, 15),
('Bundle Deployed', 'bundle_deployed', 1, 0, 5, 5),
('Bundle Failed', 'bundle_failed', 1, 0, 5, 5),
('Blocked Traffic Spike', 'blocked_spike', 1, 100, 5, 15),
('New Peer', 'new_peer', 1, 0, 5, 30)
`)
		if err != nil {
			return fmt.Errorf("failed to seed default alert rules: %w", err)
		}
		log.Info("Migration: seeded default alert rules")
	}

	// Table 2: alert_history - stores alert event history
	var hasAlertHistory bool
	err = database.QueryRowContext(ctx, "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='table' AND name='alert_history'").Scan(&hasAlertHistory)
	if err != nil {
		return fmt.Errorf("failed to check for alert_history table: %w", err)
	}
	if !hasAlertHistory {
		log.Info("Migration: creating alert_history table")
		_, err = database.ExecContext(ctx, `
			CREATE TABLE alert_history (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				rule_id INTEGER REFERENCES alert_rules(id),
				alert_type TEXT NOT NULL,
				peer_id TEXT,
				severity TEXT NOT NULL CHECK(severity IN ('info', 'warning', 'critical')),
				subject TEXT NOT NULL,
				message TEXT NOT NULL,
				metadata TEXT,
				status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending', 'sent', 'failed')),
				sent_at DATETIME,
				error_message TEXT,
				created_at DATETIME DEFAULT CURRENT_TIMESTAMP
			)
		`)
		if err != nil {
			return fmt.Errorf("failed to create alert_history table: %w", err)
		}
		_, err = database.ExecContext(ctx, "CREATE INDEX IF NOT EXISTS idx_alert_history_rule_id ON alert_history(rule_id)")
		if err != nil {
			return fmt.Errorf("failed to create idx_alert_history_rule_id index: %w", err)
		}
		_, err = database.ExecContext(ctx, "CREATE INDEX IF NOT EXISTS idx_alert_history_status ON alert_history(status)")
		if err != nil {
			return fmt.Errorf("failed to create idx_alert_history_status index: %w", err)
		}
		_, err = database.ExecContext(ctx, "CREATE INDEX IF NOT EXISTS idx_alert_history_created_at ON alert_history(created_at DESC)")
		if err != nil {
			return fmt.Errorf("failed to create idx_alert_history_created_at index: %w", err)
		}
		log.Info("Migration: created alert_history table")
	}

	// Table 3: user_notification_preferences - stores per-user notification settings
	var hasUserNotificationPrefs bool
	err = database.QueryRowContext(ctx, "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='table' AND name='user_notification_preferences'").Scan(&hasUserNotificationPrefs)
	if err != nil {
		return fmt.Errorf("failed to check for user_notification_preferences table: %w", err)
	}
	if !hasUserNotificationPrefs {
		log.Info("Migration: creating user_notification_preferences table")
		_, err = database.ExecContext(ctx, `
			CREATE TABLE user_notification_preferences (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
				enabled_alerts TEXT DEFAULT '[]',
				quiet_hours_start TEXT DEFAULT '22:00',
				quiet_hours_end TEXT DEFAULT '07:00',
				quiet_hours_timezone TEXT DEFAULT 'UTC',
				digest_enabled BOOLEAN NOT NULL DEFAULT 0,
				digest_time TEXT DEFAULT '08:00',
				created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
				updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
				UNIQUE(user_id)
			)
		`)
		if err != nil {
			return fmt.Errorf("failed to create user_notification_preferences table: %w", err)
		}
		_, err = database.ExecContext(ctx, "CREATE INDEX IF NOT EXISTS idx_user_notification_prefs_user_id ON user_notification_preferences(user_id)")
		if err != nil {
			return fmt.Errorf("failed to create idx_user_notification_prefs_user_id index: %w", err)
		}
		log.Info("Migration: created user_notification_preferences table")
	}

	// Add missing columns to user_notification_preferences if they don't exist
	if hasUserNotificationPrefs {
		if err := addColumnIfMissing(ctx, database, "user_notification_preferences", "quiet_hours_enabled", "BOOLEAN NOT NULL DEFAULT 0"); err != nil {
			return err
		}
		if err := addColumnIfMissing(ctx, database, "user_notification_preferences", "digest_frequency", "TEXT DEFAULT 'daily'"); err != nil {
			return err
		}
		if err := addColumnIfMissing(ctx, database, "user_notification_preferences", "digest_timezone", "TEXT DEFAULT 'UTC'"); err != nil {
			return err
		}
	}

	// Table 4: alert_digests - stores daily digest history
	var hasAlertDigests bool
	err = database.QueryRowContext(ctx, "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='table' AND name='alert_digests'").Scan(&hasAlertDigests)
	if err != nil {
		return fmt.Errorf("failed to check for alert_digests table: %w", err)
	}
	if !hasAlertDigests {
		log.Info("Migration: creating alert_digests table")
		_, err = database.ExecContext(ctx, `
			CREATE TABLE alert_digests (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
				digest_date DATE NOT NULL,
				alert_count INTEGER NOT NULL DEFAULT 0,
				summary TEXT,
				sent_at DATETIME,
				created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
				UNIQUE(user_id, digest_date)
			)
		`)
		if err != nil {
			return fmt.Errorf("failed to create alert_digests table: %w", err)
		}
		_, err = database.ExecContext(ctx, "CREATE INDEX IF NOT EXISTS idx_alert_digests_user_date ON alert_digests(user_id, digest_date DESC)")
		if err != nil {
			return fmt.Errorf("failed to create idx_alert_digests_user_date index: %w", err)
		}
		log.Info("Migration: created alert_digests table")
	}

	// Migration: Add description column to import_rules table
	var hasImportRulesTable bool
	err = database.QueryRowContext(ctx, "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='table' AND name='import_rules'").Scan(&hasImportRulesTable)
	if err != nil {
		return fmt.Errorf("failed to check for import_rules table: %w", err)
	}
	if hasImportRulesTable {
		if err := addColumnIfMissing(ctx, database, "import_rules", "description", "TEXT DEFAULT ''"); err != nil {
			return err
		}
	}

	return nil
}
