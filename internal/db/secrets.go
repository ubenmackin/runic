package db

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
)

// JWTSecretsSeedMarker is the system_config key recording that JWT signing-key
// seeding already happened once. It must never be deleted: without it, a
// deleted signing key would be re-seeded from the environment on the next boot
// and every token signed with the revoked key would validate again.
const JWTSecretsSeedMarker = "jwt_secrets_seeded"

// JWTSecretsSeeded reports whether the one-time JWT signing-key seeding marker
// exists.
func JWTSecretsSeeded(ctx context.Context, database Querier) (bool, error) {
	var seeded bool
	err := database.QueryRowContext(ctx,
		"SELECT COUNT(*) > 0 FROM system_config WHERE key = ?", JWTSecretsSeedMarker).Scan(&seeded)
	if err != nil {
		return false, fmt.Errorf("check %s marker: %w", JWTSecretsSeedMarker, err)
	}
	return seeded, nil
}

// MarkJWTSecretsSeeded records the one-time JWT signing-key seeding marker.
// The insert is idempotent and preserves an existing marker.
func MarkJWTSecretsSeeded(ctx context.Context, database Querier) error {
	_, err := database.ExecContext(ctx,
		"INSERT INTO system_config (key, value, updated_at) VALUES (?, '1', CURRENT_TIMESTAMP) ON CONFLICT(key) DO NOTHING",
		JWTSecretsSeedMarker)
	if err != nil {
		return fmt.Errorf("mark %s: %w", JWTSecretsSeedMarker, err)
	}
	return nil
}

// seedJWTSecrets seeds JWT signing keys from the RUNIC_ENV_PATH file exactly
// once per database. It only fills keys that are absent and never runs after
// the one-time marker exists, so a stale .env file can neither replace a
// rotated key nor resurrect a deleted one. Persisted keys or a provisioned
// database mean bootstrap already happened (for example installer-seeded
// keys), so those record the marker instead of seeding.
// It accepts a Querier (which *sql.DB satisfies) and is invoked during initialization
// with the underlying *sql.DB handle.
func seedJWTSecrets(ctx context.Context, database Querier) error {
	markerPresent, err := JWTSecretsSeeded(ctx, database)
	if err != nil {
		return err
	}
	if markerPresent {
		return nil
	}

	persisted, err := jwtSecretsPersisted(ctx, database)
	if err != nil {
		return err
	}
	provisioned, err := databaseProvisioned(ctx, database)
	if err != nil {
		return err
	}
	if persisted || provisioned {
		return MarkJWTSecretsSeeded(ctx, database)
	}

	envPath := os.Getenv("RUNIC_ENV_PATH")
	if envPath == "" {
		envPath = "/opt/runic/.env"
	}

	data, err := os.ReadFile(envPath)
	if err != nil {
		if os.IsNotExist(err) {
			// No .env file, nothing to seed
			return nil
		}
		return fmt.Errorf("failed to read env file: %w", err)
	}

	lines := strings.Split(string(data), "\n")
	migrations := map[string]string{
		"RUNIC_JWT_SECRET":       "jwt_secret",
		"RUNIC_AGENT_JWT_SECRET": "agent_jwt_secret",
	}

	seeded := false
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		for envKey, dbKey := range migrations {
			prefix := envKey + "="
			if strings.HasPrefix(line, prefix) {
				value := strings.TrimPrefix(line, prefix)
				if value != "" {
					_, err := database.ExecContext(ctx,
						"INSERT INTO system_config (key, value, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP) ON CONFLICT(key) DO NOTHING",
						dbKey, value,
					)
					if err != nil {
						return fmt.Errorf("failed to migrate %s: %w", envKey, err)
					}
					seeded = true
				}
			}
		}
	}

	if !seeded {
		return nil
	}
	return MarkJWTSecretsSeeded(ctx, database)
}

// jwtSecretsPersisted reports whether either JWT signing key already exists.
func jwtSecretsPersisted(ctx context.Context, database Querier) (bool, error) {
	var persisted bool
	err := database.QueryRowContext(ctx,
		"SELECT COUNT(*) > 0 FROM system_config WHERE key IN ('jwt_secret', 'agent_jwt_secret')").Scan(&persisted)
	if err != nil {
		return false, fmt.Errorf("check persisted JWT secrets: %w", err)
	}
	return persisted, nil
}

// databaseProvisioned reports whether the database already holds a user. A
// provisioned database has completed setup, so environment seeding must not
// run for it even when its signing keys were deleted.
func databaseProvisioned(ctx context.Context, database Querier) (bool, error) {
	var provisioned bool
	err := database.QueryRowContext(ctx, "SELECT COUNT(*) > 0 FROM users").Scan(&provisioned)
	if err != nil {
		return false, fmt.Errorf("check provisioned database: %w", err)
	}
	return provisioned, nil
}

// SQLite doesn't support ALTER TABLE ADD CONSTRAINT, so we recreate tables.
// TODO: Replace with a proper migration framework (e.g., golang-migrate) that handles DDL.
// This function requires *sql.DB for DDL operations (CREATE TABLE, DROP TABLE, ALTER TABLE).
func addDBConstraints(ctx context.Context, database *sql.DB) error {
	var constraintApplied bool
	err := database.QueryRowContext(ctx, "SELECT COUNT(*) > 0 FROM system_config WHERE key = 'constraints_applied'").Scan(&constraintApplied)
	if err != nil {
		constraintApplied = false
	}
	if constraintApplied {
		return nil
	}

	// peers: CHECK (hostname != '')
	if _, err := database.ExecContext(ctx, `
		CREATE TABLE peers_new (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			hostname TEXT UNIQUE NOT NULL CHECK(hostname != ''),
			ip_address TEXT NOT NULL,
			os_type TEXT NOT NULL DEFAULT 'linux',
			arch TEXT NOT NULL DEFAULT 'amd64',
			has_docker BOOLEAN NOT NULL DEFAULT 0,
			has_ipset BOOLEAN DEFAULT NULL,
			agent_key TEXT UNIQUE NOT NULL,
			agent_token TEXT,
			agent_version TEXT,
			is_manual BOOLEAN NOT NULL DEFAULT 0,
			bundle_version TEXT,
			hmac_key TEXT NOT NULL,
			hmac_key_rotation_token TEXT,
			hmac_key_last_rotated_at DATETIME,
			last_heartbeat DATETIME,
			status TEXT NOT NULL DEFAULT 'pending',
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			description TEXT DEFAULT ''
		)
	`); err != nil {
		return fmt.Errorf("create peers_new: %w", err)
	}
	if _, err := database.ExecContext(ctx, "INSERT INTO peers_new SELECT * FROM peers"); err != nil {
		return fmt.Errorf("copy peers: %w", err)
	}
	if _, err := database.ExecContext(ctx, "DROP TABLE peers"); err != nil {
		return fmt.Errorf("drop peers: %w", err)
	}
	if _, err := database.ExecContext(ctx, "ALTER TABLE peers_new RENAME TO peers"); err != nil {
		return fmt.Errorf("rename peers_new: %w", err)
	}

	// users: CHECK (role IN ('admin', 'editor', 'viewer'))
	if _, err := database.ExecContext(ctx, `
		CREATE TABLE users_new (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			email TEXT DEFAULT '',
			role TEXT NOT NULL DEFAULT 'viewer' CHECK(role IN ('admin', 'editor', 'viewer')),
			token_version INTEGER NOT NULL DEFAULT 1,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	`); err != nil {
		return fmt.Errorf("create users_new: %w", err)
	}
	// Migrate existing roles: first user -> admin, rest -> viewer
	// Also map old 'user' role to 'viewer'. token_version is preserved from
	// the pre-recreation table (migrateSchema runs before this function and
	// has already added the column when the table predates it).
	if _, err := database.ExecContext(ctx, `
		INSERT INTO users_new 
		SELECT id, username, password_hash, email, 
			   CASE 
				   WHEN id = (SELECT MIN(id) FROM users) THEN 'admin'
				   WHEN role = 'admin' THEN 'admin'
				   ELSE 'viewer'
			   END,
			   token_version,
			   created_at 
		FROM users
	`); err != nil {
		return fmt.Errorf("copy users: %w", err)
	}
	if _, err := database.ExecContext(ctx, "DROP TABLE users"); err != nil {
		return fmt.Errorf("drop users: %w", err)
	}
	if _, err := database.ExecContext(ctx, "ALTER TABLE users_new RENAME TO users"); err != nil {
		return fmt.Errorf("rename users_new: %w", err)
	}

	if _, err := database.ExecContext(ctx, `
		CREATE TABLE rule_bundles_new (
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
		)
	`); err != nil {
		return fmt.Errorf("create rule_bundles_new: %w", err)
	}
	if _, err := database.ExecContext(ctx, `INSERT INTO rule_bundles_new (id, peer_id, version, version_number, rules_content, hmac, created_at, applied_at)
		SELECT id, peer_id, version, COALESCE(version_number, 0), rules_content, hmac, created_at, applied_at FROM rule_bundles`); err != nil {
		return fmt.Errorf("copy rule_bundles: %w", err)
	}
	if _, err := database.ExecContext(ctx, "DROP TABLE rule_bundles"); err != nil {
		return fmt.Errorf("drop rule_bundles: %w", err)
	}
	if _, err := database.ExecContext(ctx, "ALTER TABLE rule_bundles_new RENAME TO rule_bundles"); err != nil {
		return fmt.Errorf("rename rule_bundles_new: %w", err)
	}

	// Mark constraints as applied
	_, err = database.ExecContext(ctx, "INSERT INTO system_config (key, value) VALUES ('constraints_applied', '1')")
	if err != nil {
		return fmt.Errorf("mark constraints applied: %w", err)
	}

	return nil
}
