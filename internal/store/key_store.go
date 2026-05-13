package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"

	"runic/internal/db"
)

// KeyStore manages API keys stored in the system_config table.
// Get/Set/Delete operations delegate to SettingsStore to avoid
// duplicating system_config SQL queries (DRY).
type KeyStore struct {
	settings *SettingsStore
}

// NewKeyStore creates a new KeyStore.
// The logsDB parameter of SettingsStore is intentionally nil because KeyStore
// only needs access to the main database (system_config table) for secret storage.
func NewKeyStore(database db.Querier) (*KeyStore, error) {
	if database == nil {
		return nil, fmt.Errorf("database is required")
	}
	settings := NewSettingsStore(database, nil)
	return &KeyStore{settings: settings}, nil
}

// ListKeyStatuses returns the existence status of all specified keys in a single query.
// Returns a map of dbKey → exists. This replaces the per-type N+1 query pattern (T007-#5).
func (s *KeyStore) ListKeyStatuses(ctx context.Context, dbKeys []string) (map[string]bool, error) {
	configs, err := s.settings.GetSystemConfigs(ctx, dbKeys)
	if err != nil {
		return nil, fmt.Errorf("list key statuses: %w", err)
	}
	result := make(map[string]bool, len(dbKeys))
	for _, k := range dbKeys {
		_, exists := configs[k]
		result[k] = exists
	}
	return result, nil
}

// KeyExists returns true if a secret with the given key exists in the database.
// It delegates to GetSecret and checks for sql.ErrNoRows instead of
// duplicating the SELECT query.
func (s *KeyStore) KeyExists(ctx context.Context, key string) (bool, error) {
	_, err := s.GetSecret(ctx, key)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("check key exists %q: %w", key, err)
	}
	return true, nil
}

// GetSecret returns the value of a secret by key.
// Returns ("", sql.ErrNoRows) if the key does not exist.
// Delegates to SettingsStore.GetSystemConfig to avoid duplicating the SELECT query.
//
// NOTE: The error wrapping below uses %w (not %v) to preserve sql.ErrNoRows
// so that callers like KeyExists can use errors.Is(err, sql.ErrNoRows).
// Do not change %w to %v without updating all callers that rely on errors.Is.
func (s *KeyStore) GetSecret(ctx context.Context, key string) (string, error) {
	value, err := s.settings.GetSystemConfig(ctx, key)
	if err != nil {
		return "", fmt.Errorf("get secret %q: %w", key, err)
	}
	return value, nil
}

// SetSecret stores a secret value by key, creating or updating as needed.
// Delegates to SettingsStore.SetSystemConfig to avoid duplicating the UPSERT query.
func (s *KeyStore) SetSecret(ctx context.Context, key, value string) error {
	if err := s.settings.SetSystemConfig(ctx, key, value); err != nil {
		return fmt.Errorf("set secret %q: %w", key, err)
	}
	return nil
}

// DeleteSecret removes a secret by key.
// Delegates to SettingsStore.DeleteSystemConfig to avoid duplicating the DELETE query.
func (s *KeyStore) DeleteSecret(ctx context.Context, key string) error {
	if err := s.settings.DeleteSystemConfig(ctx, key); err != nil {
		return fmt.Errorf("delete secret %q: %w", key, err)
	}
	return nil
}

// GenerateSecureKey generates a cryptographically secure random hex-encoded key.
// The implementation is inlined here to avoid depending on the db package-level function.
func (s *KeyStore) GenerateSecureKey() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("generate secure key: %w", err)
	}
	return hex.EncodeToString(bytes), nil
}
