package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"runic/internal/db"
)

// SettingsStore accepts two db.Querier values: one for the main database and one for the
// separate logs database (which may be nil if logs are stored in the main DB).
type SettingsStore struct {
	db     db.Querier
	logsDB db.Querier // may be nil
}

// NewSettingsStore creates a new SettingsStore. logsDB may be nil if the logs database is not configured.
func NewSettingsStore(database db.Querier, logsDB db.Querier) *SettingsStore {
	return &SettingsStore{db: database, logsDB: logsDB}
}

// GetSystemConfig returns ("", sql.ErrNoRows) if the key does not exist.
func (s *SettingsStore) GetSystemConfig(ctx context.Context, key string) (string, error) {
	var value string
	err := s.db.QueryRowContext(ctx,
		"SELECT value FROM system_config WHERE key = ?", key,
	).Scan(&value)
	if err != nil {
		return "", fmt.Errorf("get system config %q: %w", key, err)
	}
	return value, nil
}

// GetSystemConfigInt returns defaultVal if the key does not exist.
func (s *SettingsStore) GetSystemConfigInt(ctx context.Context, key string, defaultVal int) (int, error) {
	var value int
	err := s.db.QueryRowContext(ctx,
		"SELECT CAST(value AS INTEGER) FROM system_config WHERE key = ?", key,
	).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return defaultVal, nil
	}
	if err != nil {
		return defaultVal, fmt.Errorf("get system config int %q: %w", key, err)
	}
	return value, nil
}

// GetSystemConfigs returns values for multiple keys in a single query.
// Returns a map of key → value for existing keys; missing keys are omitted from the map.
func (s *SettingsStore) GetSystemConfigs(ctx context.Context, keys []string) (map[string]string, error) {
	if len(keys) == 0 {
		return map[string]string{}, nil
	}
	placeholders := make([]string, len(keys))
	args := make([]interface{}, len(keys))
	for i, k := range keys {
		placeholders[i] = "?"
		args[i] = k
	}
	query := "SELECT key, value FROM system_config WHERE key IN (" + strings.Join(placeholders, ",") + ")"
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("get system configs: %w", err)
	}
	defer func() { _ = rows.Close() }()

	result := make(map[string]string, len(keys))
	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil {
			return nil, fmt.Errorf("scan system config: %w", err)
		}
		result[key] = value
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows error: %w", err)
	}
	return result, nil
}

func (s *SettingsStore) SetSystemConfig(ctx context.Context, key, value string) error {
	_, err := s.db.ExecContext(ctx,
		"INSERT OR REPLACE INTO system_config (key, value, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)",
		key, value)
	if err != nil {
		return fmt.Errorf("set system config %q: %w", key, err)
	}
	return nil
}

// DeleteSystemConfig removes a system config entry by key.
func (s *SettingsStore) DeleteSystemConfig(ctx context.Context, key string) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM system_config WHERE key = ?", key)
	if err != nil {
		return fmt.Errorf("delete system config %q: %w", key, err)
	}
	return nil
}

func (s *SettingsStore) GetNullableSystemConfig(ctx context.Context, key string) (string, error) {
	var value sql.NullString
	err := s.db.QueryRowContext(ctx,
		"SELECT value FROM system_config WHERE key = ?", key,
	).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("get nullable system config %q: %w", key, err)
	}
	if value.Valid {
		return value.String, nil
	}
	return "", nil
}

// GetLogCount returns 0 if the logs database is not configured.
func (s *SettingsStore) GetLogCount(ctx context.Context) (int, error) {
	if s.logsDB == nil {
		return 0, nil
	}
	var count int
	err := s.logsDB.QueryRowContext(ctx, "SELECT COUNT(*) FROM firewall_logs").Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count logs: %w", err)
	}
	return count, nil
}

// ClearAllLogs returns the number of deleted rows.
func (s *SettingsStore) ClearAllLogs(ctx context.Context) (int64, error) {
	if s.logsDB == nil {
		return 0, fmt.Errorf("logs database not configured")
	}
	result, err := s.logsDB.ExecContext(ctx, "DELETE FROM firewall_logs")
	if err != nil {
		return 0, fmt.Errorf("clear logs: %w", err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("rows affected: %w", err)
	}
	return rowsAffected, nil
}
