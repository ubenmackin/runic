// Package db provides database interactions.
package db

import (
	"database/sql"
	"fmt"

	"runic/internal/common/log"

	_ "github.com/mattn/go-sqlite3"
)

// logsDBSchema contains the schema for the separate logs database.
const logsDBSchema = `
CREATE TABLE IF NOT EXISTS firewall_logs (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	timestamp DATETIME NOT NULL,
	peer_id TEXT NOT NULL,
	peer_hostname TEXT,
	event_type TEXT,
	source_ip TEXT,
	dest_ip TEXT,
	source_port INTEGER,
	dest_port INTEGER,
	protocol TEXT,
	action TEXT,
	details TEXT
);

-- Index for timestamp-based queries (most common filter)
CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON firewall_logs(timestamp DESC);

-- Index for peer-based queries
CREATE INDEX IF NOT EXISTS idx_logs_peer_id ON firewall_logs(peer_id);

-- Composite index for peer + timestamp queries
CREATE INDEX IF NOT EXISTS idx_logs_peer_timestamp ON firewall_logs(peer_id, timestamp DESC);
`

// LogsDBSchema returns the database schema for the logs database.
func LogsDBSchema() string {
	return logsDBSchema
}

// InitLogsDB initializes a separate SQLite database for storing firewall logs.
// This separation provides improved performance, storage isolation, and operational flexibility.
//
// The database is configured with:
//   - WAL mode for better concurrent read/write performance
//   - Foreign keys enabled for data integrity
//   - Busy timeout of 5000ms to handle concurrent access
//
// Parameters:
//   - path: The file path for the logs database (e.g., "/var/lib/runic/logs.db")
//
// Returns:
//   - *sql.DB: The initialized database connection
//   - error: Any error that occurred during initialization
func InitLogsDB(path string) (*sql.DB, error) {
	// Build connection string with WAL mode and busy timeout
	dataSourceName := fmt.Sprintf("%s?_journal_mode=WAL&_busy_timeout=5000", path)

	sqlDB, err := sql.Open("sqlite3", dataSourceName)
	if err != nil {
		return nil, fmt.Errorf("failed to open logs database: %w", err)
	}

	if err = sqlDB.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping logs database: %w", err)
	}

	// Enable WAL mode for better concurrent performance
	if _, err := sqlDB.Exec("PRAGMA journal_mode=WAL"); err != nil {
		log.Warn("Failed to set WAL mode for logs database", "error", err)
	}

	// Enable foreign keys for data integrity
	if _, err := sqlDB.Exec("PRAGMA foreign_keys=ON"); err != nil {
		log.Warn("Failed to enable foreign keys for logs database", "error", err)
	}

	// Create the schema
	if _, err := sqlDB.Exec(logsDBSchema); err != nil {
		return nil, fmt.Errorf("failed to create logs database schema: %w", err)
	}

	log.Info("Logs database connection established", "path", path)
	return sqlDB, nil
}

// MigrateLogsFromMainDB migrates firewall_logs data from the main database to the logs database.
// This function should be called after both databases are initialized.
//
// Migration strategy:
//  1. Check if firewall_logs table exists in main DB (legacy databases)
//  2. If exists, copy all data to logs DB using straight INSERT...SELECT with JOIN
//  3. On failure, leave old table intact (rollback)
//  4. On success, DROP the old table from main DB
//
// Parameters:
//   - mainDB: The main database connection (source of logs data)
//   - logsDB: The logs database connection (destination for logs data)
//
// Returns:
//   - int64: Number of rows migrated
//   - error: Any error that occurred during migration
func MigrateLogsFromMainDB(mainDB, logsDB *sql.DB) (int64, error) {
	// Check if firewall_logs table exists in main DB
	var tableExists bool
	err := mainDB.QueryRow(
		"SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='table' AND name='firewall_logs'",
	).Scan(&tableExists)
	if err != nil {
		return 0, fmt.Errorf("failed to check for firewall_logs table: %w", err)
	}

	if !tableExists {
		log.Info("Migration: firewall_logs table not found in main DB, skipping migration")
		return 0, nil
	}

	// Check if there's any data to migrate
	var rowCount int
	err = mainDB.QueryRow("SELECT COUNT(*) FROM firewall_logs").Scan(&rowCount)
	if err != nil {
		return 0, fmt.Errorf("failed to count firewall_logs rows: %w", err)
	}

	if rowCount == 0 {
		log.Info("Migration: firewall_logs table is empty, dropping table from main DB")
		if _, err := mainDB.Exec("DROP TABLE firewall_logs"); err != nil {
			log.Warn("Failed to drop empty firewall_logs table", "error", err)
		}
		return 0, nil
	}

	log.Info("Migration: starting firewall_logs migration to separate database", "rows", rowCount)

	// Attach the logs database to the main database connection for cross-database queries
	// We need to get the path from the logsDB connection - we'll use a temporary attach
	// First, get the logs DB path by querying from logsDB
	var logsDBPath string
	err = logsDB.QueryRow("PRAGMA database_list").Scan(nil, nil, &logsDBPath)
	if err != nil {
		// If we can't get the path, we'll need to use the attach approach differently
		log.Warn("Could not determine logs DB path, using alternative migration approach", "error", err)
		return migrateLogsWithoutAttach(mainDB, logsDB)
	}

	// Use ATTACH DATABASE to enable cross-database queries
	// Begin transaction on main DB to ensure atomicity
	tx, err := mainDB.Begin()
	if err != nil {
		return 0, fmt.Errorf("failed to begin migration transaction: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			if rErr := tx.Rollback(); rErr != nil {
				log.Warn("Failed to rollback migration transaction", "error", rErr)
			}
		}
	}()

	// Attach logs database
	if _, err := tx.Exec(fmt.Sprintf("ATTACH DATABASE '%s' AS logs_db", logsDBPath)); err != nil {
		return 0, fmt.Errorf("failed to attach logs database: %w", err)
	}
	defer func() {
		if _, err := mainDB.Exec("DETACH DATABASE logs_db"); err != nil {
			log.Warn("Failed to detach logs database", "error", err)
		}
	}()

	// Check the schema of the old firewall_logs table to determine column structure
	var hasPeerHostname bool
	err = tx.QueryRow(
		"SELECT COUNT(*) > 0 FROM pragma_table_info('firewall_logs') WHERE name='peer_hostname'",
	).Scan(&hasPeerHostname)
	if err != nil {
		return 0, fmt.Errorf("failed to check firewall_logs schema: %w", err)
	}

	// Copy data using INSERT INTO ... SELECT with JOIN to get hostname
	// The logs DB schema has: id, timestamp, peer_id, peer_hostname, event_type, source_ip, dest_ip, source_port, dest_port, protocol, action, details
	// The main DB schema (current) has: id, peer_id, peer_hostname, timestamp, direction, src_ip, dst_ip, protocol, src_port, dst_port, action, raw_line
	//
	// We need to map old columns to new schema:
	// - timestamp: timestamp (same)
	// - peer_id: peer_id (same)
	// - peer_hostname: peer_hostname (same, or from peers table if missing)
	// - event_type: direction (rename)
	// - source_ip: src_ip (rename)
	// - dest_ip: dst_ip (rename)
	// - source_port: src_port (rename)
	// - dest_port: dst_port (rename)
	// - protocol: protocol (same)
	// - action: action (same)
	// - details: raw_line (rename)

	var result sql.Result
	if hasPeerHostname {
		// New schema - columns already have peer_hostname
		result, err = tx.Exec(`
			INSERT INTO logs_db.firewall_logs (timestamp, peer_id, peer_hostname, event_type, source_ip, dest_ip, source_port, dest_port, protocol, action, details)
			SELECT timestamp, peer_id, peer_hostname, direction, src_ip, dst_ip, src_port, dst_port, protocol, action, raw_line
			FROM main.firewall_logs
		`)
	} else {
		// Old schema - need to join with peers table to get hostname
		result, err = tx.Exec(`
			INSERT INTO logs_db.firewall_logs (timestamp, peer_id, peer_hostname, event_type, source_ip, dest_ip, source_port, dest_port, protocol, action, details)
			SELECT fl.timestamp, fl.peer_id, p.hostname, fl.direction, fl.src_ip, fl.dst_ip, fl.src_port, fl.dst_port, fl.protocol, fl.action, fl.raw_line
			FROM main.firewall_logs fl
			LEFT JOIN main.peers p ON fl.peer_id = p.id
		`)
	}

	if err != nil {
		return 0, fmt.Errorf("failed to copy firewall_logs data: %w", err)
	}

	rowsMigrated, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to get rows affected: %w", err)
	}

	// Drop the old table from main DB
	if _, err := tx.Exec("DROP TABLE main.firewall_logs"); err != nil {
		return 0, fmt.Errorf("failed to drop old firewall_logs table: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("failed to commit migration: %w", err)
	}
	committed = true

	log.Info("Migration: successfully migrated firewall_logs to separate database", "rows_migrated", rowsMigrated)
	return rowsMigrated, nil
}

// migrateLogsWithoutAttach performs migration by reading data and inserting row by row.
// This is a fallback when ATTACH DATABASE cannot be used (e.g., path unavailable).
func migrateLogsWithoutAttach(mainDB, logsDB *sql.DB) (int64, error) {
	log.Info("Migration: using row-by-row migration approach")

	// Begin transactions on both databases
	mainTx, err := mainDB.Begin()
	if err != nil {
		return 0, fmt.Errorf("failed to begin main DB transaction: %w", err)
	}
	mainCommitted := false
	defer func() {
		if !mainCommitted {
			if rErr := mainTx.Rollback(); rErr != nil {
				log.Warn("Failed to rollback main DB transaction", "error", rErr)
			}
		}
	}()

	logsTx, err := logsDB.Begin()
	if err != nil {
		return 0, fmt.Errorf("failed to begin logs DB transaction: %w", err)
	}
	logsCommitted := false
	defer func() {
		if !logsCommitted {
			if rErr := logsTx.Rollback(); rErr != nil {
				log.Warn("Failed to rollback logs DB transaction", "error", rErr)
			}
		}
	}()

	// Check schema for peer_hostname column
	var hasPeerHostname bool
	err = mainTx.QueryRow(
		"SELECT COUNT(*) > 0 FROM pragma_table_info('firewall_logs') WHERE name='peer_hostname'",
	).Scan(&hasPeerHostname)
	if err != nil {
		return 0, fmt.Errorf("failed to check firewall_logs schema: %w", err)
	}

	// Read all rows from main DB
	var rows *sql.Rows
	if hasPeerHostname {
		rows, err = mainTx.Query(`
			SELECT timestamp, peer_id, peer_hostname, direction, src_ip, dst_ip, src_port, dst_port, protocol, action, raw_line
			FROM firewall_logs
		`)
	} else {
		rows, err = mainTx.Query(`
			SELECT fl.timestamp, fl.peer_id, p.hostname, fl.direction, fl.src_ip, fl.dst_ip, fl.src_port, fl.dst_port, fl.protocol, fl.action, fl.raw_line
			FROM firewall_logs fl
			LEFT JOIN peers p ON fl.peer_id = p.id
		`)
	}
	if err != nil {
		return 0, fmt.Errorf("failed to query firewall_logs: %w", err)
	}
	defer func() { _ = rows.Close() }()

	// Prepare insert statement
	stmt, err := logsTx.Prepare(`
		INSERT INTO firewall_logs (timestamp, peer_id, peer_hostname, event_type, source_ip, dest_ip, source_port, dest_port, protocol, action, details)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return 0, fmt.Errorf("failed to prepare insert statement: %w", err)
	}
	defer func() { _ = stmt.Close() }()

	var count int64
	for rows.Next() {
		var timestamp, peerID, peerHostname, direction, srcIP, dstIP, protocol, action, rawLine sql.NullString
		var srcPort, dstPort sql.NullInt64

		if err := rows.Scan(&timestamp, &peerID, &peerHostname, &direction, &srcIP, &dstIP, &srcPort, &dstPort, &protocol, &action, &rawLine); err != nil {
			return 0, fmt.Errorf("failed to scan row: %w", err)
		}

		if _, err := stmt.Exec(
			timestamp, peerID, peerHostname, direction, srcIP, dstIP, srcPort, dstPort, protocol, action, rawLine,
		); err != nil {
			return 0, fmt.Errorf("failed to insert row: %w", err)
		}
		count++
	}

	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("error iterating rows: %w", err)
	}

	// Drop the old table from main DB
	if _, err := mainTx.Exec("DROP TABLE firewall_logs"); err != nil {
		return 0, fmt.Errorf("failed to drop old firewall_logs table: %w", err)
	}

	// Commit logs transaction first
	if err := logsTx.Commit(); err != nil {
		return 0, fmt.Errorf("failed to commit logs DB transaction: %w", err)
	}
	logsCommitted = true

	// Then commit main transaction
	if err := mainTx.Commit(); err != nil {
		return 0, fmt.Errorf("failed to commit main DB transaction: %w", err)
	}
	mainCommitted = true

	log.Info("Migration: successfully migrated firewall_logs using row-by-row approach", "rows_migrated", count)
	return count, nil
}
