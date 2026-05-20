package db

import (
	"context"
	"os"
	"testing"

	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAddDBConstraints_Idempotent(t *testing.T) {
	database, cleanup := SetupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	// First call should apply constraints
	err := addDBConstraints(ctx, database)
	require.NoError(t, err, "First addDBConstraints should succeed")

	// Check that the marker was set
	var applied bool
	err = database.QueryRowContext(ctx, "SELECT COUNT(*) > 0 FROM system_config WHERE key = 'constraints_applied'").Scan(&applied)
	require.NoError(t, err)
	assert.True(t, applied, "constraints_applied should be set")

	// Second call should be a no-op (idempotent)
	err = addDBConstraints(ctx, database)
	require.NoError(t, err, "Second addDBConstraints should succeed (idempotent)")
}

func TestAddDBConstraints_EnforcesHostnameCheck(t *testing.T) {
	database, cleanup := SetupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	err := addDBConstraints(ctx, database)
	require.NoError(t, err, "addDBConstraints should succeed")

	// After constraints, inserting an empty hostname should fail
	_, err = database.ExecContext(ctx,
		"INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, is_manual) VALUES (?, ?, ?, ?, 0)",
		"", "10.0.0.1", "agent-key", "hmac-key")
	assert.Error(t, err, "Expected error for empty hostname after constraints applied")
}

func TestAddDBConstraints_EnforcesRoleCheck(t *testing.T) {
	database, cleanup := SetupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	err := addDBConstraints(ctx, database)
	require.NoError(t, err, "addDBConstraints should succeed")

	// After constraints, inserting a user with invalid role should fail
	_, err = database.ExecContext(ctx,
		"INSERT INTO users (username, password_hash, email, role) VALUES (?, ?, ?, ?)",
		"baduser", "hash", "bad@example.com", "superadmin")
	assert.Error(t, err, "Expected error for invalid role after constraints applied")

	// Valid roles should still work
	for _, role := range []string{"admin", "editor", "viewer"} {
		_, err = database.ExecContext(ctx,
			"INSERT INTO users (username, password_hash, email, role) VALUES (?, ?, ?, ?)",
			"user_"+role, "hash", role+"@example.com", role)
		if err != nil {
			t.Errorf("expected valid role %q to be accepted, got error: %v", role, err)
		}
	}
}

func TestAddDBConstraints_PreservesExistingData(t *testing.T) {
	database, cleanup := SetupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	// Insert data before constraints
	_, err := database.ExecContext(ctx,
		"INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, is_manual) VALUES (?, ?, ?, ?, 0)",
		"existing-peer", "10.0.0.1", "key1", "hmac1")
	require.NoError(t, err, "Insert peer before constraints should succeed")

	_, err = database.ExecContext(ctx,
		"INSERT INTO users (username, password_hash, email, role) VALUES (?, ?, ?, ?)",
		"existing-user", "hash", "user@example.com", "admin")
	require.NoError(t, err, "Insert user before constraints should succeed")

	// Apply constraints
	err = addDBConstraints(ctx, database)
	require.NoError(t, err, "addDBConstraints should succeed")

	// Verify data still exists
	var peerCount, userCount int
	err = database.QueryRowContext(ctx, "SELECT COUNT(*) FROM peers WHERE hostname = ?", "existing-peer").Scan(&peerCount)
	require.NoError(t, err)
	assert.Equal(t, 1, peerCount, "Existing peer should be preserved")

	err = database.QueryRowContext(ctx, "SELECT COUNT(*) FROM users WHERE username = ?", "existing-user").Scan(&userCount)
	require.NoError(t, err)
	assert.Equal(t, 1, userCount, "Existing user should be preserved")
}

func TestMigrateEnvToDB_NoEnvFile(t *testing.T) {
	database, cleanup := SetupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	// Ensure RUNIC_ENV_PATH points to a non-existent file
	os.Setenv("RUNIC_ENV_PATH", "/tmp/runic-nonexistent-env-file-.env")
	defer os.Unsetenv("RUNIC_ENV_PATH")

	err := migrateEnvToDB(ctx, database)
	assert.NoError(t, err, "migrateEnvToDB should succeed with no .env file")
}

func TestMigrateEnvToDB_WithEnvFile(t *testing.T) {
	database, cleanup := SetupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	// Create a temp .env file
	envContent := "RUNIC_JWT_SECRET=my-jwt-secret\nRUNIC_AGENT_JWT_SECRET=my-agent-secret\n# comment line\n\nRUNIC_OTHER_KEY=ignored\n"
	f, err := os.CreateTemp("", "runic-test-env-*.env")
	require.NoError(t, err)
	defer os.Remove(f.Name())

	_, err = f.WriteString(envContent)
	require.NoError(t, err)
	require.NoError(t, f.Close())

	os.Setenv("RUNIC_ENV_PATH", f.Name())
	defer os.Unsetenv("RUNIC_ENV_PATH")

	err = migrateEnvToDB(ctx, database)
	require.NoError(t, err, "migrateEnvToDB should succeed")

	// Verify secrets were stored
	var jwtSecret string
	err = database.QueryRowContext(ctx, "SELECT value FROM system_config WHERE key = ?", "jwt_secret").Scan(&jwtSecret)
	require.NoError(t, err)
	assert.Equal(t, "my-jwt-secret", jwtSecret, "JWT secret should be migrated")

	var agentSecret string
	err = database.QueryRowContext(ctx, "SELECT value FROM system_config WHERE key = ?", "agent_jwt_secret").Scan(&agentSecret)
	require.NoError(t, err)
	assert.Equal(t, "my-agent-secret", agentSecret, "Agent JWT secret should be migrated")
}

func TestMigrateEnvToDB_EmptyValuesSkipped(t *testing.T) {
	database, cleanup := SetupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	// Create a temp .env file with empty value
	envContent := "RUNIC_JWT_SECRET=\n"
	f, err := os.CreateTemp("", "runic-test-env-empty-*.env")
	require.NoError(t, err)
	defer os.Remove(f.Name())

	_, err = f.WriteString(envContent)
	require.NoError(t, err)
	require.NoError(t, f.Close())

	os.Setenv("RUNIC_ENV_PATH", f.Name())
	defer os.Unsetenv("RUNIC_ENV_PATH")

	err = migrateEnvToDB(ctx, database)
	require.NoError(t, err, "migrateEnvToDB should succeed")

	// Empty values should NOT be inserted
	var count int
	err = database.QueryRowContext(ctx, "SELECT COUNT(*) FROM system_config WHERE key = ?", "jwt_secret").Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 0, count, "Empty values should not be migrated")
}
