package db

import (
	"context"
	"database/sql"
	_ "embed"
	"log"

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

	if err := createSchema(DB.DB); err != nil {
		log.Fatalf("Failed to create schema: %v", err)
	}

	log.Println("Database connection established")
}

func createSchema(database *sql.DB) error {
	_, err := database.Exec(schemaSQL)
	return err
}

// GetServer fetches a server by ID.
func GetServer(ctx context.Context, database *sql.DB, serverID int) (models.ServerRow, error) {
	var s models.ServerRow
	err := database.QueryRowContext(ctx,
		`SELECT id, hostname, ip_address, os_type, arch, has_docker, agent_key,
		        agent_token, agent_version, bundle_version, last_heartbeat, status, created_at
		 FROM servers WHERE id = ?`, serverID,
	).Scan(&s.ID, &s.Hostname, &s.IPAddress, &s.OSType, &s.Arch, &s.HasDocker,
		&s.AgentKey, &s.AgentToken, &s.AgentVersion, &s.BundleVersion,
		&s.LastHeartbeat, &s.Status, &s.CreatedAt)
	return s, err
}

// ListGroupMembers fetches all members of a group.
func ListGroupMembers(ctx context.Context, database *sql.DB, groupID int) ([]models.GroupMemberRow, error) {
	rows, err := database.QueryContext(ctx,
		"SELECT id, group_id, value, type FROM group_members WHERE group_id = ?", groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var members []models.GroupMemberRow
	for rows.Next() {
		var m models.GroupMemberRow
		if err := rows.Scan(&m.ID, &m.GroupID, &m.Value, &m.Type); err != nil {
			return nil, err
		}
		members = append(members, m)
	}
	return members, rows.Err()
}

// ListEnabledPolicies fetches enabled policies for a server, ordered by priority ASC.
func ListEnabledPolicies(ctx context.Context, database *sql.DB, serverID int) ([]models.PolicyRow, error) {
	rows, err := database.QueryContext(ctx,
		`SELECT id, name, COALESCE(description, ''), source_group_id, service_id, target_server_id,
		        action, priority, enabled, created_at, updated_at
		 FROM policies
		 WHERE target_server_id = ? AND enabled = 1
		 ORDER BY priority ASC`, serverID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var policies []models.PolicyRow
	for rows.Next() {
		var p models.PolicyRow
		if err := rows.Scan(&p.ID, &p.Name, &p.Description, &p.SourceGroupID, &p.ServiceID,
			&p.TargetServerID, &p.Action, &p.Priority, &p.Enabled, &p.CreatedAt, &p.UpdatedAt); err != nil {
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
		`SELECT id, name, ports, protocol, COALESCE(description, ''), direction_hint
		 FROM services WHERE id = ?`, serviceID,
	).Scan(&s.ID, &s.Name, &s.Ports, &s.Protocol, &s.Description, &s.DirectionHint)
	return s, err
}

// GetGroup fetches a group by ID.
func GetGroup(ctx context.Context, database *sql.DB, groupID int) (models.GroupRow, error) {
	var g models.GroupRow
	err := database.QueryRowContext(ctx,
		"SELECT id, name, COALESCE(description, '') FROM groups WHERE id = ?", groupID,
	).Scan(&g.ID, &g.Name, &g.Description)
	return g, err
}

// SaveBundle inserts a new rule bundle and updates the server's bundle_version.
func SaveBundle(ctx context.Context, database *sql.DB, params models.CreateBundleParams) (models.RuleBundleRow, error) {
	tx, err := database.BeginTx(ctx, nil)
	if err != nil {
		return models.RuleBundleRow{}, err
	}
	defer tx.Rollback()

	result, err := tx.ExecContext(ctx,
		`INSERT INTO rule_bundles (server_id, version, rules_content, hmac) VALUES (?, ?, ?, ?)`,
		params.ServerID, params.Version, params.RulesContent, params.HMAC)
	if err != nil {
		return models.RuleBundleRow{}, err
	}

	bundleID, _ := result.LastInsertId()

	_, err = tx.ExecContext(ctx,
		`UPDATE servers SET bundle_version = ? WHERE id = ?`, params.Version, params.ServerID)
	if err != nil {
		return models.RuleBundleRow{}, err
	}

	if err := tx.Commit(); err != nil {
		return models.RuleBundleRow{}, err
	}

	return models.RuleBundleRow{
		ID:           int(bundleID),
		ServerID:     params.ServerID,
		Version:      params.Version,
		RulesContent: params.RulesContent,
		HMAC:         params.HMAC,
	}, nil
}

// FindPoliciesByGroupID finds policies by source_group_id.
func FindPoliciesByGroupID(ctx context.Context, database *sql.DB, groupID int) ([]models.PolicyRow, error) {
	rows, err := database.QueryContext(ctx,
		`SELECT id, name, COALESCE(description, ''), source_group_id, service_id, target_server_id,
		        action, priority, enabled, created_at, updated_at
		 FROM policies
		 WHERE source_group_id = ?`, groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var policies []models.PolicyRow
	for rows.Next() {
		var p models.PolicyRow
		if err := rows.Scan(&p.ID, &p.Name, &p.Description, &p.SourceGroupID, &p.ServiceID,
			&p.TargetServerID, &p.Action, &p.Priority, &p.Enabled, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, err
		}
		policies = append(policies, p)
	}
	return policies, rows.Err()
}
