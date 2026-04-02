package db

import (
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"crypto/rand"
)

// GetSecret retrieves a secret from the system_config table.
func GetSecret(key string) (string, error) {
	if DB == nil {
		return "", fmt.Errorf("database not initialized")
	}
	var value string
	err := DB.QueryRow("SELECT value FROM system_config WHERE key = ?", key).Scan(&value)
	if err != nil {
		return "", err
	}
	return value, nil
}

// SetSecret stores or updates a secret in the system_config table.
func SetSecret(key, value string) error {
	if DB == nil {
		return fmt.Errorf("database not initialized")
	}
	_, err := DB.Exec(
		`INSERT INTO system_config (key, value, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP) 
		 ON CONFLICT(key) DO UPDATE SET value = ?, updated_at = CURRENT_TIMESTAMP`,
		key, value, value,
	)
	return err
}

// EnsureSecretExists reads a secret or generates one using the generator and stores it.
func EnsureSecretExists(key string, generator func() (string, error)) (string, error) {
	value, err := GetSecret(key)
	if err == nil {
		return value, nil
	}
	if err != sql.ErrNoRows {
		return "", err
	}
	value, err = generator()
	if err != nil {
		return "", err
	}
	if err := SetSecret(key, value); err != nil {
		return "", err
	}
	return value, nil
}

// GenerateSecureKey generates a 32-byte random hex key.
func GenerateSecureKey() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// migrateEnvToDB reads /opt/runic/.env and migrates secrets to system_config.
func migrateEnvToDB(database *sql.DB) error {
	envPath := os.Getenv("RUNIC_ENV_PATH")
	if envPath == "" {
		envPath = "/opt/runic/.env"
	}

	data, err := os.ReadFile(envPath)
	if err != nil {
		if os.IsNotExist(err) {
			// No .env file, nothing to migrate
			return nil
		}
		return fmt.Errorf("failed to read env file: %w", err)
	}

	lines := strings.Split(string(data), "\n")
	migrations := map[string]string{
		"RUNIC_JWT_SECRET":       "jwt_secret",
		"RUNIC_AGENT_JWT_SECRET": "agent_jwt_secret",
	}

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
					_, err := database.Exec(
						"INSERT INTO system_config (key, value, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP) ON CONFLICT(key) DO UPDATE SET value = ?, updated_at = CURRENT_TIMESTAMP",
						dbKey, value, value,
					)
					if err != nil {
						return fmt.Errorf("failed to migrate %s: %w", envKey, err)
					}
				}
			}
		}
	}

	return nil
}

// addDBConstraints adds CHECK constraints and UNIQUE constraints via table recreation.
// SQLite doesn't support ALTER TABLE ADD CONSTRAINT, so we recreate tables.
func addDBConstraints(database *sql.DB) error {
	// Check if constraints already applied by checking for a marker
	var constraintApplied bool
	err := database.QueryRow("SELECT COUNT(*) > 0 FROM system_config WHERE key = 'constraints_applied'").Scan(&constraintApplied)
	if err != nil {
		constraintApplied = false
	}
	if constraintApplied {
		return nil
	}

	// peers: CHECK (hostname != '')
	if _, err := database.Exec(`
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
	if _, err := database.Exec("INSERT INTO peers_new SELECT * FROM peers"); err != nil {
		return fmt.Errorf("copy peers: %w", err)
	}
	if _, err := database.Exec("DROP TABLE peers"); err != nil {
		return fmt.Errorf("drop peers: %w", err)
	}
	if _, err := database.Exec("ALTER TABLE peers_new RENAME TO peers"); err != nil {
		return fmt.Errorf("rename peers_new: %w", err)
	}

	// users: CHECK (role IN ('admin', 'editor', 'viewer'))
	if _, err := database.Exec(`
		CREATE TABLE users_new (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			email TEXT DEFAULT '',
			role TEXT NOT NULL DEFAULT 'viewer' CHECK(role IN ('admin', 'editor', 'viewer')),
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	`); err != nil {
		return fmt.Errorf("create users_new: %w", err)
	}
	// Migrate existing roles: first user -> admin, rest -> viewer
	// Also map old 'user' role to 'viewer'
	if _, err := database.Exec(`
		INSERT INTO users_new 
		SELECT id, username, password_hash, email, 
			   CASE 
				   WHEN id = (SELECT MIN(id) FROM users) THEN 'admin'
				   WHEN role = 'admin' THEN 'admin'
				   ELSE 'viewer'
			   END,
			   created_at 
		FROM users
	`); err != nil {
		return fmt.Errorf("copy users: %w", err)
	}
	if _, err := database.Exec("DROP TABLE users"); err != nil {
		return fmt.Errorf("drop users: %w", err)
	}
	if _, err := database.Exec("ALTER TABLE users_new RENAME TO users"); err != nil {
		return fmt.Errorf("rename users_new: %w", err)
	}

	// rule_bundles: UNIQUE(peer_id, version)
	if _, err := database.Exec(`
		CREATE TABLE rule_bundles_new (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			peer_id INTEGER NOT NULL,
			version TEXT NOT NULL,
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
	if _, err := database.Exec("INSERT INTO rule_bundles_new SELECT * FROM rule_bundles"); err != nil {
		return fmt.Errorf("copy rule_bundles: %w", err)
	}
	if _, err := database.Exec("DROP TABLE rule_bundles"); err != nil {
		return fmt.Errorf("drop rule_bundles: %w", err)
	}
	if _, err := database.Exec("ALTER TABLE rule_bundles_new RENAME TO rule_bundles"); err != nil {
		return fmt.Errorf("rename rule_bundles_new: %w", err)
	}

	// Mark constraints as applied
	_, err = database.Exec("INSERT INTO system_config (key, value) VALUES ('constraints_applied', '1')")
	if err != nil {
		return fmt.Errorf("mark constraints applied: %w", err)
	}

	return nil
}
