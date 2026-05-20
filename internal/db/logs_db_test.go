package db

import (
	"context"
	"os"
	"testing"

	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInitLogsDB(t *testing.T) {
	f, err := os.CreateTemp("", "runic-logs-test-*.db")
	require.NoError(t, err)
	dbPath := f.Name()
	require.NoError(t, f.Close())
	defer os.Remove(dbPath)

	logsDB, err := InitLogsDB(dbPath)
	require.NoError(t, err, "InitLogsDB should succeed")
	defer logsDB.Close()

	// Verify schema was applied
	var tableName string
	err = logsDB.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name='firewall_logs'").Scan(&tableName)
	require.NoError(t, err, "firewall_logs table should exist")
	assert.Equal(t, "firewall_logs", tableName)

	// Verify indexes exist
	indexes := []string{"idx_logs_timestamp", "idx_logs_peer_id", "idx_logs_peer_timestamp"}
	for _, idx := range indexes {
		var indexName string
		err = logsDB.QueryRow("SELECT name FROM sqlite_master WHERE type='index' AND name=?", idx).Scan(&indexName)
		if err != nil {
			t.Errorf("expected index %q to exist, got error: %v", idx, err)
		}
	}
}

func TestInitLogsDB_InvalidPath(t *testing.T) {
	// Path to a non-existent directory
	_, err := InitLogsDB("/nonexistent/dir/logs.db")
	assert.Error(t, err, "InitLogsDB should fail with invalid path")
}

func TestMigrateLogsFromMainDB_NoFirewallLogsTable(t *testing.T) {
	mainDB, cleanup := SetupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	// Create a separate logs DB
	f, err := os.CreateTemp("", "runic-logs-migrate-test-*.db")
	require.NoError(t, err)
	logsDBPath := f.Name()
	require.NoError(t, f.Close())
	defer os.Remove(logsDBPath)

	logsDB, err := InitLogsDB(logsDBPath)
	require.NoError(t, err)
	defer logsDB.Close()

	// Fresh main DB has no firewall_logs table
	rowsMigrated, err := MigrateLogsFromMainDB(ctx, mainDB, logsDB)
	require.NoError(t, err, "MigrateLogsFromMainDB should succeed with no firewall_logs table")
	assert.Equal(t, int64(0), rowsMigrated, "Expected 0 rows migrated when no firewall_logs table")
}

func TestMigrateLogsFromMainDB_EmptyTable(t *testing.T) {
	mainDB, cleanup := SetupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	// Create a firewall_logs table in main DB (old schema)
	_, err := mainDB.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS firewall_logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			timestamp DATETIME NOT NULL,
			peer_id INTEGER NOT NULL,
			direction TEXT,
			src_ip TEXT,
			dst_ip TEXT,
			src_port INTEGER,
			dst_port INTEGER,
			protocol TEXT,
			action TEXT,
			raw_line TEXT
		)
	`)
	require.NoError(t, err, "Creating old-style firewall_logs table should succeed")

	// Create logs DB
	f, err := os.CreateTemp("", "runic-logs-migrate-empty-*.db")
	require.NoError(t, err)
	logsDBPath := f.Name()
	require.NoError(t, f.Close())
	defer os.Remove(logsDBPath)

	logsDB, err := InitLogsDB(logsDBPath)
	require.NoError(t, err)
	defer logsDB.Close()

	// Migrate empty table
	rowsMigrated, err := MigrateLogsFromMainDB(ctx, mainDB, logsDB)
	require.NoError(t, err, "MigrateLogsFromMainDB should succeed with empty firewall_logs")
	assert.Equal(t, int64(0), rowsMigrated, "Expected 0 rows migrated for empty table")

	// Verify the table was dropped from main DB
	var tableExists bool
	err = mainDB.QueryRowContext(ctx,
		"SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='table' AND name='firewall_logs'",
	).Scan(&tableExists)
	require.NoError(t, err)
	assert.False(t, tableExists, "firewall_logs table should be dropped from main DB after migration of empty table")
}

func TestMigrateLogsFromMainDB_WithData(t *testing.T) {
	mainDB, cleanup := SetupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	// Create old-style firewall_logs table in main DB
	_, err := mainDB.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS firewall_logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			timestamp DATETIME NOT NULL,
			peer_id INTEGER NOT NULL,
			peer_hostname TEXT,
			direction TEXT,
			src_ip TEXT,
			dst_ip TEXT,
			src_port INTEGER,
			dst_port INTEGER,
			protocol TEXT,
			action TEXT,
			raw_line TEXT
		)
	`)
	require.NoError(t, err)

	// Insert peers that firewall_logs.peer_id references (FOREIGN KEY constraint)
	_, err = mainDB.ExecContext(ctx,
		"INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, is_manual) VALUES (?, ?, ?, ?, 0)",
		"test-peer", "10.0.0.1", "agent-key-1", "hmac-key-1")
	require.NoError(t, err)

	_, err = mainDB.ExecContext(ctx,
		"INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, is_manual) VALUES (?, ?, ?, ?, 0)",
		"test-peer-2", "10.0.0.3", "agent-key-2", "hmac-key-2")
	require.NoError(t, err)

	// Insert test data (peer_id 1 and 2 reference the peers above)
	_, err = mainDB.ExecContext(ctx, `
	INSERT INTO firewall_logs (timestamp, peer_id, peer_hostname, direction, src_ip, dst_ip, src_port, dst_port, protocol, action, raw_line)
	VALUES ('2026-01-01 00:00:00', 1, 'test-peer', 'ingress', '10.0.0.1', '10.0.0.2', 12345, 80, 'tcp', 'ACCEPT', 'raw line 1')
	`)
	require.NoError(t, err)

	_, err = mainDB.ExecContext(ctx, `
	INSERT INTO firewall_logs (timestamp, peer_id, peer_hostname, direction, src_ip, dst_ip, src_port, dst_port, protocol, action, raw_line)
	VALUES ('2026-01-01 00:01:00', 2, 'test-peer-2', 'egress', '10.0.0.3', '10.0.0.4', 54321, 443, 'tcp', 'DROP', 'raw line 2')
	`)
	require.NoError(t, err)

	// Create logs DB
	f, err := os.CreateTemp("", "runic-logs-migrate-data-*.db")
	require.NoError(t, err)
	logsDBPath := f.Name()
	require.NoError(t, f.Close())
	defer os.Remove(logsDBPath)

	logsDB, err := InitLogsDB(logsDBPath)
	require.NoError(t, err)
	defer logsDB.Close()

	// Migrate
	rowsMigrated, err := MigrateLogsFromMainDB(ctx, mainDB, logsDB)
	require.NoError(t, err, "MigrateLogsFromMainDB should succeed")
	assert.Equal(t, int64(2), rowsMigrated, "Expected 2 rows migrated")

	// Verify data in logs DB
	var count int
	err = logsDB.QueryRowContext(ctx, "SELECT COUNT(*) FROM firewall_logs").Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 2, count, "Expected 2 rows in logs DB")

	// Verify specific data
	var peerHostname string
	err = logsDB.QueryRowContext(ctx,
		"SELECT peer_hostname FROM firewall_logs WHERE peer_id = 1").Scan(&peerHostname)
	require.NoError(t, err)
	assert.Equal(t, "test-peer", peerHostname)

	// Verify firewall_logs table is dropped from main DB
	var tableExists bool
	err = mainDB.QueryRowContext(ctx,
		"SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='table' AND name='firewall_logs'",
	).Scan(&tableExists)
	require.NoError(t, err)
	assert.False(t, tableExists, "firewall_logs table should be dropped from main DB after migration")
}

func TestLogsDBSchema(t *testing.T) {
	schema := LogsDBSchema()
	if schema == "" {
		t.Error("LogsDBSchema() returned empty string")
	}
	if len(schema) < 100 {
		t.Errorf("LogsDBSchema() seems too short (%d bytes)", len(schema))
	}
}
