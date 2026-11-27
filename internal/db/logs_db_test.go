package db

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
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

func TestInitLogsDB_Permissions(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "logs.db")
	logsDB, err := InitLogsDB(dbPath)
	require.NoError(t, err)
	defer logsDB.Close()

	// Force a write so WAL/SHM sidecars exist while the connection is open.
	_, err = logsDB.ExecContext(context.Background(),
		"INSERT INTO firewall_logs (timestamp, peer_id, action) VALUES ('2026-01-01 00:00:00', 1, 'DROP')")
	require.NoError(t, err)

	info, err := os.Stat(dbPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())

	for _, candidate := range []string{dbPath + "-wal", dbPath + "-shm"} {
		info, err := os.Stat(candidate)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
	}
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

func TestMigrateFirewallLogTimestamps(t *testing.T) {
	ctx := context.Background()

	f, err := os.CreateTemp("", "runic-logs-timestamps-*.db")
	require.NoError(t, err)
	logsDBPath := f.Name()
	require.NoError(t, f.Close())
	defer os.Remove(logsDBPath)

	logsDB, err := InitLogsDB(logsDBPath)
	require.NoError(t, err)
	defer logsDB.Close()

	seed := []string{
		"2026-11-25 19:40:00",
		"2026-11-25T19:40:01.123-07:00",
		"2026-11-24",
		"Nov 25 19:40:00",
		"not-a-time",
		"",
	}
	for _, timestamp := range seed {
		_, err := logsDB.ExecContext(ctx,
			"INSERT INTO firewall_logs (timestamp, peer_id, action) VALUES (?, 1, 'DROP')", timestamp)
		require.NoError(t, err)
	}

	normalized, deleted, err := MigrateFirewallLogTimestamps(ctx, logsDB)
	require.NoError(t, err, "MigrateFirewallLogTimestamps should succeed")
	assert.Equal(t, int64(2), normalized, "expected two rows rewritten to canonical UTC")
	assert.Equal(t, int64(3), deleted, "expected three unparseable rows deleted")

	// The sqlite3 driver parses DATETIME-declared columns into time.Time, which
	// database/sql renders as RFC3339 when scanned into a string. CAST forces
	// the stored TEXT representation the canonical layout contract defines.
	var canonical string
	err = logsDB.QueryRowContext(ctx,
		"SELECT CAST(timestamp AS TEXT) FROM firewall_logs WHERE timestamp = '2026-11-25 19:40:00'").Scan(&canonical)
	require.NoError(t, err)
	assert.Equal(t, "2026-11-25 19:40:00", canonical, "canonical row must remain unchanged")

	var offset string
	err = logsDB.QueryRowContext(ctx,
		"SELECT CAST(timestamp AS TEXT) FROM firewall_logs WHERE timestamp = '2026-11-26 02:40:01'").Scan(&offset)
	require.NoError(t, err)
	assert.Equal(t, "2026-11-26 02:40:01", offset, "RFC3339 offset row must be rewritten to UTC")

	var dateOnly string
	err = logsDB.QueryRowContext(ctx,
		"SELECT CAST(timestamp AS TEXT) FROM firewall_logs WHERE timestamp = '2026-11-24 00:00:00'").Scan(&dateOnly)
	require.NoError(t, err)
	assert.Equal(t, "2026-11-24 00:00:00", dateOnly, "date-only row must be rewritten to midnight UTC")

	var remaining int
	err = logsDB.QueryRowContext(ctx, "SELECT COUNT(*) FROM firewall_logs").Scan(&remaining)
	require.NoError(t, err)
	assert.Equal(t, 3, remaining, "expected three surviving rows")

	normalized, deleted, err = MigrateFirewallLogTimestamps(ctx, logsDB)
	require.NoError(t, err, "second run should skip the completed migration")
	assert.Zero(t, normalized, "second run must not rewrite rows")
	assert.Zero(t, deleted, "second run must not delete rows")

	var userVersion int
	err = logsDB.QueryRowContext(ctx, "PRAGMA user_version").Scan(&userVersion)
	require.NoError(t, err)
	assert.Equal(t, 1, userVersion, "migration must record PRAGMA user_version = 1")

	_, _, err = MigrateFirewallLogTimestamps(ctx, nil)
	assert.Error(t, err, "nil logs DB must return an error")
}

func TestMigrateLogsDB_NormalizesRowsCopiedAfterGateSet(t *testing.T) {
	ctx := context.Background()

	mainDB, cleanup := SetupTestDB(t)
	defer cleanup()

	// A legacy main-DB table still holds rows while the gate was already set by
	// an earlier partial run (relocation failed, timestamp pass succeeded).
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
	_, err = mainDB.ExecContext(ctx,
		"INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, is_manual) VALUES (?, ?, ?, ?, 0)",
		"legacy-peer", "10.0.0.1", "agent-key", "hmac-key")
	require.NoError(t, err)
	_, err = mainDB.ExecContext(ctx, `
		INSERT INTO firewall_logs (timestamp, peer_id, direction, src_ip, dst_ip, src_port, dst_port, protocol, action, raw_line)
		VALUES ('2026-11-25T19:40:01Z', 1, 'ingress', '10.0.0.1', '10.0.0.2', 12345, 80, 'tcp', 'DROP', 'legacy row')
	`)
	require.NoError(t, err)

	f, err := os.CreateTemp("", "runic-logs-sequence-*.db")
	require.NoError(t, err)
	logsDBPath := f.Name()
	require.NoError(t, f.Close())
	defer os.Remove(logsDBPath)

	logsDB, err := InitLogsDB(logsDBPath)
	require.NoError(t, err)
	defer logsDB.Close()

	_, err = logsDB.ExecContext(ctx, "PRAGMA user_version = 1")
	require.NoError(t, err)

	migrated, normalized, deleted, err := MigrateLogsDB(ctx, mainDB, logsDB)
	require.NoError(t, err, "MigrateLogsDB should succeed")
	assert.Equal(t, int64(1), migrated, "expected one legacy row relocated")
	assert.Equal(t, int64(1), normalized, "expected the relocated row to be normalized")
	assert.Zero(t, deleted, "expected no rows deleted")

	var stored string
	err = logsDB.QueryRowContext(ctx, "SELECT CAST(timestamp AS TEXT) FROM firewall_logs").Scan(&stored)
	require.NoError(t, err)
	assert.Equal(t, "2026-11-25 19:40:01", stored, "relocated rows must be rewritten to canonical UTC")

	var userVersion int
	err = logsDB.QueryRowContext(ctx, "PRAGMA user_version").Scan(&userVersion)
	require.NoError(t, err)
	assert.Equal(t, 1, userVersion, "the sequence must record completion after both stages")
}

func TestMigrateLogsDB_MainMigrationFailureClearsGate(t *testing.T) {
	ctx := context.Background()

	mainDB, cleanup := SetupTestDB(t)
	defer cleanup()

	f, err := os.CreateTemp("", "runic-logs-sequence-fail-*.db")
	require.NoError(t, err)
	logsDBPath := f.Name()
	require.NoError(t, f.Close())
	defer os.Remove(logsDBPath)

	logsDB, err := InitLogsDB(logsDBPath)
	require.NoError(t, err)
	defer logsDB.Close()

	_, err = logsDB.ExecContext(ctx, "PRAGMA user_version = 1")
	require.NoError(t, err)

	require.NoError(t, mainDB.Close(), "closing the main DB forces the relocation to fail")

	_, _, _, err = MigrateLogsDB(ctx, mainDB, logsDB)
	require.Error(t, err, "a failed relocation must abort the sequence")

	var userVersion int
	err = logsDB.QueryRowContext(ctx, "PRAGMA user_version").Scan(&userVersion)
	require.NoError(t, err)
	assert.Zero(t, userVersion, "a failed relocation must clear the timestamp completion gate")
}

func TestMigrateLogsDB_RestartKeepsGateWithoutLegacyRows(t *testing.T) {
	ctx := context.Background()

	mainDB, cleanup := SetupTestDB(t)
	defer cleanup()

	f, err := os.CreateTemp("", "runic-logs-restart-*.db")
	require.NoError(t, err)
	logsDBPath := f.Name()
	require.NoError(t, f.Close())
	defer os.Remove(logsDBPath)

	logsDB, err := InitLogsDB(logsDBPath)
	require.NoError(t, err)
	defer logsDB.Close()

	// First boot: the schema-created main-DB table is empty, so the sequence
	// records completion after the (empty) timestamp pass.
	migrated, normalized, deleted, err := MigrateLogsDB(ctx, mainDB, logsDB)
	require.NoError(t, err)
	assert.Zero(t, migrated, "expected no legacy rows on a fresh main DB")
	assert.Zero(t, normalized, "expected no timestamps to normalize on a fresh logs DB")
	assert.Zero(t, deleted, "expected no rows to delete on a fresh logs DB")

	var userVersion int
	require.NoError(t, logsDB.QueryRowContext(ctx, "PRAGMA user_version").Scan(&userVersion))
	assert.Equal(t, 1, userVersion, "first boot must record the timestamp completion gate")

	// Post-migration row with a legacy layout. A restart that re-ran the
	// full-table scan would rewrite this value; the completion gate must
	// prevent that.
	_, err = logsDB.ExecContext(ctx,
		"INSERT INTO firewall_logs (timestamp, peer_id, action) VALUES (?, 1, 'DROP')",
		"2026-11-26T01:02:03Z")
	require.NoError(t, err)

	// Restart: reopen the logs DB so the durable completion gate is re-read,
	// then re-run schema.sql the way InitDB does, which recreates the empty
	// legacy firewall_logs table.
	require.NoError(t, logsDB.Close())
	logsDB, err = InitLogsDB(logsDBPath)
	require.NoError(t, err, "restart must reopen the logs DB")
	defer logsDB.Close()

	_, err = mainDB.ExecContext(ctx, Schema())
	require.NoError(t, err, "restart must recreate the empty firewall_logs table")

	migrated, normalized, deleted, err = MigrateLogsDB(ctx, mainDB, logsDB)
	require.NoError(t, err, "restart must succeed without legacy rows")
	assert.Zero(t, migrated, "restart must not relocate rows")
	assert.Zero(t, normalized, "restart must not re-run the full-table timestamp scan")
	assert.Zero(t, deleted, "restart must not delete rows")

	require.NoError(t, logsDB.QueryRowContext(ctx, "PRAGMA user_version").Scan(&userVersion))
	assert.Equal(t, 1, userVersion, "restart must keep the timestamp completion gate")

	var stored string
	require.NoError(t, logsDB.QueryRowContext(ctx,
		"SELECT CAST(timestamp AS TEXT) FROM firewall_logs").Scan(&stored))
	assert.Equal(t, "2026-11-26T01:02:03Z", stored,
		"the completion gate must suppress the full-table scan on restart")
}

func TestMigrateLogsDB_PreCheckFailureStillNormalizesAfterEmptyRelocation(t *testing.T) {
	ctx := context.Background()

	// A fresh main DB carries the empty schema-created firewall_logs table, so
	// the relocation stage succeeds without copying any rows.
	mainDB, cleanup := SetupTestDB(t)
	defer cleanup()

	f, err := os.CreateTemp("", "runic-logs-precheck-*.db")
	require.NoError(t, err)
	logsDBPath := f.Name()
	require.NoError(t, f.Close())
	defer os.Remove(logsDBPath)

	logsDB, err := InitLogsDB(logsDBPath)
	require.NoError(t, err)
	defer logsDB.Close()

	// An earlier partial run already recorded the completion gate, and the
	// logs DB holds a row with a non-canonical timestamp.
	_, err = logsDB.ExecContext(ctx, "PRAGMA user_version = 1")
	require.NoError(t, err)
	_, err = logsDB.ExecContext(ctx,
		"INSERT INTO firewall_logs (timestamp, peer_id, action) VALUES (?, 1, 'DROP')",
		"2026-11-25T19:40:01Z")
	require.NoError(t, err)

	originalCheck := legacyFirewallLogsRowsCheck
	legacyFirewallLogsRowsCheck = func(context.Context, *sql.DB) (bool, error) {
		return false, errors.New("injected pre-check failure")
	}
	t.Cleanup(func() { legacyFirewallLogsRowsCheck = originalCheck })

	migrated, normalized, deleted, err := MigrateLogsDB(ctx, mainDB, logsDB)
	require.NoError(t, err, "an empty successful relocation must not suppress the timestamp pass")
	assert.Zero(t, migrated, "expected no rows relocated")
	assert.Equal(t, int64(1), normalized, "an inconclusive pre-check must invalidate the gate so normalization runs")
	assert.Zero(t, deleted, "expected no rows deleted")

	var stored string
	require.NoError(t, logsDB.QueryRowContext(ctx,
		"SELECT CAST(timestamp AS TEXT) FROM firewall_logs").Scan(&stored))
	assert.Equal(t, "2026-11-25 19:40:01", stored, "the legacy timestamp must be rewritten to canonical UTC")

	var userVersion int
	require.NoError(t, logsDB.QueryRowContext(ctx, "PRAGMA user_version").Scan(&userVersion))
	assert.Equal(t, 1, userVersion, "the sequence must record completion after the timestamp pass")
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
