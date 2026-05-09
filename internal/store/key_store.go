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
func NewKeyStore(database db.Querier) *KeyStore {
	settings := NewSettingsStore(database, nil)
	return &KeyStore{settings: settings}
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
