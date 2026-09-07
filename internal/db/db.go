// Package db provides database interactions.
package db

import (
	"context"
	"database/sql"
	_ "embed"
	"errors"
	"fmt"
	"os"
	"strings"

	"runic/internal/common/log"

	_ "github.com/mattn/go-sqlite3"
)

//go:embed schema.sql
var schemaSQL string

func Schema() string {
	return schemaSQL
}

// Safelist of allowed tables for migrations.
// This prevents SQL injection through malicious table/column names
// in migration helper functions. Only hardcoded table names are permitted.
var allowedTables = map[string]bool{
	"users":                         true,
	"peers":                         true,
	"services":                      true,
	"groups":                        true,
	"policies":                      true,
	"revoked_tokens":                true,
	"rule_bundles":                  true,
	"firewall_logs":                 true,
	"group_members":                 true,
	"special_targets":               true,
	"system_config":                 true,
	"registration_tokens":           true,
	"user_api_tokens":               true,
	"pending_changes":               true,
	"pending_bundle_previews":       true,
	"change_snapshots":              true,
	"alert_rules":                   true,
	"alert_history":                 true,
	"user_notification_preferences": true,
	"alert_digests":                 true,
	"import_sessions":               true,
	"import_rules":                  true,
	"import_group_mappings":         true,
	"import_peer_mappings":          true,
	"import_service_mappings":       true,
	"peer_ips":                      true,
	"push_jobs":                     true,
	"push_job_peers":                true,
}

// IsAllowedTable reports whether the given table name is in the migration
// safelist. This is the exported version of the safelist, used by callers
// that need to validate table names before composing dynamic SQL.
func IsAllowedTable(table string) bool {
	return allowedTables[table]
}

// Database wraps *sql.DB via embedding so the full *sql.DB surface
// (Query/Exec/BeginTx/Ping/Close/Stats/Prepare/PrepareContext/Begin/Conn/Driver
// and connection-pool tuning) is promoted automatically. The global DB variable
// is kept for backward compatibility, but new code should prefer passing
// *Database explicitly.
type Database struct {
	*sql.DB
}

func New(database *sql.DB) *Database {
	return &Database{DB: database}
}

func (d *Database) UnderlyingDB() *sql.DB {
	return d.DB
}

// isMemoryDSN reports whether the DSN refers to an in-memory SQLite database.
func isMemoryDSN(dataSourceName string) bool {
	return dataSourceName == ":memory:" || strings.HasPrefix(dataSourceName, "file::memory:")
}

// sqliteDSNWithPragmas appends journal mode, busy timeout, synchronous mode,
// and foreign key enforcement to the SQLite DSN so pooled connections inherit
// them before any PRAGMA runs. This avoids SQLITE_BUSY errors under burst
// concurrency when several writers race before the first Exec.
// Existing query keys are preserved and never duplicated; go-sqlite3 expects
// _foreign_keys as 0/1. Bare ":memory:" is rewritten to a shared-cache URI so
// pooled connections share a single database.
func sqliteDSNWithPragmas(dataSourceName string) string {
	base := dataSourceName
	rawQuery := ""
	if dataSourceName == ":memory:" {
		base = "file::memory:"
	} else if cutBase, cutQuery, ok := strings.Cut(dataSourceName, "?"); ok {
		base = cutBase
		rawQuery = cutQuery
	}

	isMem := isMemoryDSN(dataSourceName)

	var pairs []string
	seen := make(map[string]bool)
	if rawQuery != "" {
		for _, part := range strings.Split(rawQuery, "&") {
			if part == "" {
				continue
			}
			key := part
			if eq := strings.Index(part, "="); eq != -1 {
				key = part[:eq]
			}
			if seen[key] {
				continue
			}
			seen[key] = true
			pairs = append(pairs, part)
		}
	}

	if isMem && !seen["cache"] {
		pairs = append(pairs, "cache=shared")
		seen["cache"] = true
	}

	defaults := []string{
		"_journal_mode=WAL",
		"_busy_timeout=5000",
		"_synchronous=NORMAL",
		"_foreign_keys=1",
	}
	for _, d := range defaults {
		key := d
		if eq := strings.Index(d, "="); eq != -1 {
			key = d[:eq]
		}
		if !seen[key] {
			pairs = append(pairs, d)
			seen[key] = true
		}
	}

	if len(pairs) == 0 {
		return base
	}
	return base + "?" + strings.Join(pairs, "&")
}

func InitDB(dataSourceName string) (*sql.DB, error) {
	if dbPath := os.Getenv("RUNIC_DB_PATH"); dbPath != "" {
		dataSourceName = dbPath
		log.Info("Using database path from RUNIC_DB_PATH", "path", dataSourceName)
	}

	dataSourceName = sqliteDSNWithPragmas(dataSourceName)

	sqlDB, err := sql.Open("sqlite3", dataSourceName)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	if isMemoryDSN(dataSourceName) {
		sqlDB.SetMaxOpenConns(1)
		sqlDB.SetMaxIdleConns(1)
	} else {
		sqlDB.SetMaxOpenConns(10)
		sqlDB.SetMaxIdleConns(5)
	}

	if err = sqlDB.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	// Enable WAL mode, foreign keys, busy timeout, and synchronous mode.
	// WAL is kept for concurrent read/write performance.
	if _, err := sqlDB.Exec("PRAGMA journal_mode=WAL"); err != nil {
		log.Warn("Failed to set WAL mode", "error", err)
	}
	if _, err := sqlDB.Exec("PRAGMA foreign_keys=ON"); err != nil {
		log.Warn("Failed to enable foreign keys", "error", err)
	}
	if _, err := sqlDB.Exec("PRAGMA busy_timeout=5000"); err != nil {
		log.Warn("Failed to set busy timeout", "error", err)
	}
	if _, err := sqlDB.Exec("PRAGMA synchronous=NORMAL"); err != nil {
		log.Warn("Failed to set synchronous mode", "error", err)
	}

	database := New(sqlDB)

	// Run migrations BEFORE schema creation to handle existing databases.
	// schema.sql tries to create indexes on peer_id columns, which would
	// fail on older databases that still have the "servers" table.
	if err := migrateSchema(context.Background(), database.DB); err != nil {
		return nil, fmt.Errorf("failed to migrate schema: %w", err)
	}

	if err := createSchema(context.Background(), database.DB); err != nil {
		return nil, fmt.Errorf("failed to create schema: %w", err)
	}

	// Seed default system services
	if err := seedSystemServices(context.Background(), database.DB); err != nil {
		return nil, fmt.Errorf("failed to seed system services: %w", err)
	}

	// Seed system groups
	if err := seedSystemGroups(context.Background(), database.DB); err != nil {
		return nil, fmt.Errorf("failed to seed system groups: %w", err)
	}

	// Migrate secrets from .env to database
	if err := migrateEnvToDB(context.Background(), database.DB); err != nil {
		log.Warn("Failed to migrate secrets from .env", "error", err)
	}

	if err := addDBConstraints(context.Background(), database.DB); err != nil {
		log.Warn("Failed to add DB constraints", "error", err)
	}

	log.Info("Database connection established")
	return database.DB, nil
}

// RunInTx is the canonical transaction helper. It begins a transaction,
// runs fn, and commits on success or rolls back on error/failure. Rollback
// errors that are not sql.ErrTxDone are logged at warn level.
func RunInTx(ctx context.Context, db Beginner, fn func(ctx context.Context, tx *sql.Tx) error) (err error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}

	committed := false
	defer func() {
		if !committed {
			if rErr := tx.Rollback(); rErr != nil && !errors.Is(rErr, sql.ErrTxDone) {
				log.WarnContext(ctx, "transaction rollback failed", "error", rErr)
			}
		}
	}()

	if err := fn(ctx, tx); err != nil {
		return err // deferred rollback handles cleanup
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	committed = true
	return nil
}
