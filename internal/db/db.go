// Package db provides database interactions.
package db

import (
	"context"
	"database/sql"
	_ "embed"
	"fmt"
	"os"

	"runic/internal/common/log"

	_ "github.com/mattn/go-sqlite3"
)

//go:embed schema.sql
var schemaSQL string

// Schema returns the database schema SQL.
func Schema() string {
	return schemaSQL
}

// Safelist of allowed tables for migrations.
// This prevents SQL injection through malicious table/column names
// in migration helper functions. Only hardcoded table names are permitted.
var allowedTables = map[string]bool{
	"users":                   true,
	"peers":                   true,
	"services":                true,
	"groups":                  true,
	"policies":                true,
	"revoked_tokens":          true,
	"rule_bundles":            true,
	"firewall_logs":           true,
	"group_members":           true,
	"special_targets":         true,
	"system_config":           true,
	"registration_tokens":     true,
	"pending_changes":         true,
	"pending_bundle_previews": true,
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

func InitDB(dataSourceName string) (*sql.DB, error) {
	// Check for environment variable override
	if dbPath := os.Getenv("RUNIC_DB_PATH"); dbPath != "" {
		dataSourceName = dbPath
		log.Info("Using database path from RUNIC_DB_PATH", "path", dataSourceName)
	}

	sqlDB, err := sql.Open("sqlite3", dataSourceName)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	if err = sqlDB.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	// Enable WAL mode and foreign keys
	if _, err := sqlDB.Exec("PRAGMA journal_mode=WAL"); err != nil {
		log.Warn("Failed to set WAL mode", "error", err)
	}
	if _, err := sqlDB.Exec("PRAGMA foreign_keys=ON"); err != nil {
		log.Warn("Failed to enable foreign keys", "error", err)
	}

	database := New(sqlDB)

	// Run migrations BEFORE schema creation to handle existing databases.
	// For example, the servers → peers table rename must complete before
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
	if err := migrateEnvToDB(database.DB); err != nil {
		log.Warn("Failed to migrate secrets from .env", "error", err)
	}

	// Add DB constraints (CHECK, UNIQUE) via table recreation
	if err := addDBConstraints(database.DB); err != nil {
		log.Warn("Failed to add DB constraints", "error", err)
	}

	log.Info("Database connection established")
	return database.DB, nil
}
