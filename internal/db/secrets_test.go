package db

import (
	"context"
	"database/sql"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func TestGetSecret(t *testing.T) {
	db, cleanup := SetupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	t.Run("successfully retrieve existing secret", func(t *testing.T) {
		// Arrange: Insert a secret first
		key := "test_key"
		expectedValue := "test_value"
		_, err := db.ExecContext(ctx,
			"INSERT INTO system_config (key, value) VALUES (?, ?)",
			key, expectedValue,
		)
		if err != nil {
			t.Fatalf("failed to insert test secret: %v", err)
		}

		// Act
		value, err := GetSecret(ctx, db, key)

		// Assert
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if value != expectedValue {
			t.Errorf("expected %q, got %q", expectedValue, value)
		}
	})

	t.Run("return error for non-existent key", func(t *testing.T) {
		// Act
		_, err := GetSecret(ctx, db, "non_existent_key")

		// Assert
		if err != sql.ErrNoRows {
			t.Errorf("expected sql.ErrNoRows, got %v", err)
		}
	})

	t.Run("return error when database is nil", func(t *testing.T) {
		// Act
		_, err := GetSecret(ctx, nil, "any_key")

		// Assert
		if err == nil {
			t.Error("expected error for nil database")
		}
		if err != nil && err.Error() != "database not initialized" {
			t.Errorf("expected 'database not initialized' error, got %v", err)
		}
	})

	t.Run("retrieve multiple different secrets", func(t *testing.T) {
		// Arrange: Insert multiple secrets
		secrets := map[string]string{
			"key1": "value1",
			"key2": "value2",
			"key3": "value3",
		}
		for k, v := range secrets {
			_, err := db.ExecContext(ctx,
				"INSERT INTO system_config (key, value) VALUES (?, ?)",
				k, v,
			)
			if err != nil {
				t.Fatalf("failed to insert secret %s: %v", k, err)
			}
		}

		// Act & Assert
		for key, expectedValue := range secrets {
			value, err := GetSecret(ctx, db, key)
			if err != nil {
				t.Errorf("failed to get secret %s: %v", key, err)
				continue
			}
			if value != expectedValue {
				t.Errorf("for key %s: expected %q, got %q", key, expectedValue, value)
			}
		}
	})
}

func TestSetSecret(t *testing.T) {
	db, cleanup := SetupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	t.Run("successfully insert new secret", func(t *testing.T) {
		// Arrange
		key := "new_secret_key"
		value := "new_secret_value"

		// Act
		err := SetSecret(ctx, db, key, value)

		// Assert
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		// Verify it was inserted
		var retrievedValue string
		err = db.QueryRowContext(ctx, "SELECT value FROM system_config WHERE key = ?", key).Scan(&retrievedValue)
		if err != nil {
			t.Fatalf("failed to retrieve secret: %v", err)
		}
		if retrievedValue != value {
			t.Errorf("expected %q, got %q", value, retrievedValue)
		}
	})

	t.Run("successfully update existing secret", func(t *testing.T) {
		// Arrange: Insert initial secret
		key := "updateable_key"
		initialValue := "initial_value"
		_, err := db.ExecContext(ctx,
			"INSERT INTO system_config (key, value) VALUES (?, ?)",
			key, initialValue,
		)
		if err != nil {
			t.Fatalf("failed to insert initial secret: %v", err)
		}

		// Act: Update the secret
		updatedValue := "updated_value"
		err = SetSecret(ctx, db, key, updatedValue)

		// Assert
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		// Verify it was updated
		var retrievedValue string
		err = db.QueryRowContext(ctx, "SELECT value FROM system_config WHERE key = ?", key).Scan(&retrievedValue)
		if err != nil {
			t.Fatalf("failed to retrieve secret: %v", err)
		}
		if retrievedValue != updatedValue {
			t.Errorf("expected %q, got %q", updatedValue, retrievedValue)
		}
	})

	t.Run("return error when database is nil", func(t *testing.T) {
		// Act
		err := SetSecret(ctx, nil, "any_key", "any_value")

		// Assert
		if err == nil {
			t.Error("expected error for nil database")
		}
		if err != nil && err.Error() != "database not initialized" {
			t.Errorf("expected 'database not initialized' error, got %v", err)
		}
	})

	t.Run("insert multiple secrets", func(t *testing.T) {
		// Act: Insert multiple secrets
		secrets := map[string]string{
			"multi_key1": "multi_value1",
			"multi_key2": "multi_value2",
			"multi_key3": "multi_value3",
		}
		for k, v := range secrets {
			if err := SetSecret(ctx, db, k, v); err != nil {
				t.Fatalf("failed to set secret %s: %v", k, err)
			}
		}

		// Assert: Verify all were inserted
		for k, expectedValue := range secrets {
			var retrievedValue string
			err := db.QueryRowContext(ctx, "SELECT value FROM system_config WHERE key = ?", k).Scan(&retrievedValue)
			if err != nil {
				t.Errorf("failed to retrieve secret %s: %v", k, err)
				continue
			}
			if retrievedValue != expectedValue {
				t.Errorf("for key %s: expected %q, got %q", k, expectedValue, retrievedValue)
			}
		}
	})
}

func TestGenerateSecureKey(t *testing.T) {
	t.Run("generate key with correct length", func(t *testing.T) {
		// Act
		key, err := GenerateSecureKey()

		// Assert
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		// 32 bytes = 64 hex characters
		if len(key) != 64 {
			t.Errorf("expected key length 64, got %d", len(key))
		}
		// Verify it's valid hex
		for _, c := range key {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				t.Errorf("key contains non-hex character: %c", c)
				break
			}
		}
	})

	t.Run("generate unique keys on successive calls", func(t *testing.T) {
		// Act: Generate multiple keys
		keys := make(map[string]bool)
		for i := 0; i < 100; i++ {
			key, err := GenerateSecureKey()
			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
			if keys[key] {
				t.Errorf("generated duplicate key at iteration %d: %s", i, key)
			}
			keys[key] = true
		}

		// Assert: Should have 100 unique keys
		if len(keys) != 100 {
			t.Errorf("expected 100 unique keys, got %d", len(keys))
		}
	})

	t.Run("return non-empty key", func(t *testing.T) {
		// Act
		key, err := GenerateSecureKey()

		// Assert
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if key == "" {
			t.Error("expected non-empty key")
		}
	})

	t.Run("generated keys have sufficient entropy", func(t *testing.T) {
		// This test verifies that generated keys are sufficiently different
		// by checking that at least some bits differ across keys

		// Generate a few keys
		keys, err := generateKeys(10)
		if err != nil {
			t.Fatalf("failed to generate keys: %v", err)
		}

		// Check that keys are different (simple check)
		uniqueCount := 0
		for i := 0; i < len(keys); i++ {
			isUnique := true
			for j := 0; j < i; j++ {
				if keys[i] == keys[j] {
					isUnique = false
					break
				}
			}
			if isUnique {
				uniqueCount++
			}
		}

		// At least 9 out of 10 should be unique (allowing for statistical edge case)
		if uniqueCount < 9 {
			t.Errorf("expected at least 9 unique keys out of 10, got %d", uniqueCount)
		}
	})
}

// Helper function to generate multiple keys
func generateKeys(n int) ([]string, error) {
	keys := make([]string, n)
	for i := 0; i < n; i++ {
		key, err := GenerateSecureKey()
		if err != nil {
			return nil, err
		}
		keys[i] = key
	}
	return keys, nil
}
