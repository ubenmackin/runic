package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"runic/internal/common"
	"runic/internal/db"
	"runic/internal/models"
)

// AlertStore provides data access for alert rules, alert history, SMTP config,
// and user notification preferences.
type AlertStore struct {
	db db.Querier
}

// NewAlertStore creates a new AlertStore.
func NewAlertStore(database db.Querier) *AlertStore {
	return &AlertStore{db: database}
}

// ListAlertHistory returns a paginated list of alert history entries matching the filter.
func (s *AlertStore) ListAlertHistory(ctx context.Context, filter *models.AlertHistoryFilter) (*models.AlertHistoryListResult, error) {
	limit := filter.Limit
	if limit <= 0 {
		limit = 50
	}
	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}

	// Build sort clause
	allowedSortKeys := map[string]string{
		"created_at":    "h.created_at",
		"alert_type":    "h.alert_type",
		"peer_hostname": "p.hostname",
		"status":        "h.status",
		"severity":      "h.severity",
	}
	allowedSortDirections := map[string]string{
		"asc":  "ASC",
		"desc": "DESC",
	}

	orderByColumn := "h.created_at"
	orderByDirection := "DESC"

	if filter.SortBy != "" {
		if col, ok := allowedSortKeys[filter.SortBy]; ok {
			orderByColumn = col
		}
	}
	if filter.SortDir != "" {
		if dir, ok := allowedSortDirections[strings.ToLower(filter.SortDir)]; ok {
			orderByDirection = dir
		}
	}

	// Build WHERE conditions
	var conditions []string
	var args []interface{}

	if filter.AlertType != "" {
		clause, clauseArgs := buildInClause("h.alert_type", filter.AlertType)
		if clause != "" {
			conditions = append(conditions, clause)
			args = append(args, clauseArgs...)
		}
	}
	if filter.Severity != "" {
		clause, clauseArgs := buildInClause("h.severity", filter.Severity)
		if clause != "" {
			conditions = append(conditions, clause)
			args = append(args, clauseArgs...)
		}
	}
	if filter.Status != "" {
		clause, clauseArgs := buildInClause("h.status", filter.Status)
		if clause != "" {
			conditions = append(conditions, clause)
			args = append(args, clauseArgs...)
		}
	}
	if filter.StartDate != "" {
		var t time.Time
		var err error
		t, err = time.Parse(time.RFC3339, filter.StartDate)
		if err != nil {
			t, err = time.Parse("2006-01-02", filter.StartDate)
			if err == nil {
				t = time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
			}
		}
		if err == nil {
			conditions = append(conditions, "h.created_at >= ?")
			args = append(args, t.Format(time.RFC3339))
		}
	}
	if filter.EndDate != "" {
		var t time.Time
		var err error
		t, err = time.Parse(time.RFC3339, filter.EndDate)
		if err != nil {
			t, err = time.Parse("2006-01-02", filter.EndDate)
			if err == nil {
				t = time.Date(t.Year(), t.Month(), t.Day(), 23, 59, 59, 0, time.UTC)
			}
		}
		if err == nil {
			conditions = append(conditions, "h.created_at <= ?")
			args = append(args, t.Format(time.RFC3339))
		}
	}
	if filter.Search != "" {
		conditions = append(conditions, "(h.subject LIKE ? OR h.message LIKE ?)")
		searchPattern := "%" + filter.Search + "%"
		args = append(args, searchPattern, searchPattern)
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	// Count query
	countQuery := `SELECT COUNT(*) FROM alert_history h ` + whereClause
	var total int
	countArgs := make([]interface{}, len(args))
	copy(countArgs, args)
	if err := s.db.QueryRowContext(ctx, countQuery, countArgs...).Scan(&total); err != nil {
		return nil, fmt.Errorf("count alert history: %w", err)
	}

	// Data query
	args = append(args, limit, offset)
	query := `SELECT h.id, h.rule_id, h.alert_type, h.peer_id, p.hostname as peer_hostname, h.severity, h.subject, h.message, h.metadata, h.status, h.sent_at, h.error_message, h.created_at
	FROM alert_history h
	LEFT JOIN peers p ON h.peer_id = p.id
	` + whereClause + `
	ORDER BY ` + orderByColumn + ` ` + orderByDirection + `
	LIMIT ? OFFSET ?`

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list alert history: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var history []models.AlertHistory
	for rows.Next() {
		var h models.AlertHistory
		var peerHostname sql.NullString
		if err := rows.Scan(&h.ID, &h.RuleID, &h.AlertType, &h.PeerID, &peerHostname, &h.Severity, &h.Subject,
			&h.Message, &h.Metadata, &h.Status, &h.SentAt, &h.ErrorMessage, &h.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan alert history row: %w", err)
		}
		if peerHostname.Valid {
			h.PeerHostname = peerHostname.String
		}
		history = append(history, h)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate alert history rows: %w", err)
	}

	return &models.AlertHistoryListResult{
		Alerts: common.EnsureSlice(history),
		Total:  total,
		Limit:  limit,
		Offset: offset,
	}, nil
}

// GetAlertHistory returns a single alert history entry by ID.
// Returns models.ErrAlertHistoryNotFound if the alert does not exist.
func (s *AlertStore) GetAlertHistory(ctx context.Context, id int) (*models.AlertHistory, error) {
	var alert models.AlertHistory

	err := s.db.QueryRowContext(ctx, `
	SELECT id, rule_id, alert_type, peer_id, severity, subject, message, metadata, status, sent_at, error_message, created_at
	FROM alert_history WHERE id = ?`, id,
	).Scan(&alert.ID, &alert.RuleID, &alert.AlertType, &alert.PeerID, &alert.Severity,
		&alert.Subject, &alert.Message, &alert.Metadata, &alert.Status, &alert.SentAt, &alert.ErrorMessage, &alert.CreatedAt)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, models.ErrAlertHistoryNotFound
		}
		return nil, fmt.Errorf("get alert history: %w", err)
	}

	return &alert, nil
}

// ListAlertRules returns all alert rules ordered by creation date.
func (s *AlertStore) ListAlertRules(ctx context.Context) ([]models.AlertRule, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, name, alert_type, enabled, threshold_value, threshold_window_minutes, peer_id, throttle_minutes, created_at, updated_at
		FROM alert_rules ORDER BY created_at DESC`,
	)
	if err != nil {
		return nil, fmt.Errorf("list alert rules: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var rules []models.AlertRule
	for rows.Next() {
		var rule models.AlertRule
		var peerID sql.NullString
		if err := rows.Scan(&rule.ID, &rule.Name, &rule.AlertType, &rule.Enabled, &rule.ThresholdValue,
			&rule.ThresholdWindowMinutes, &peerID, &rule.ThrottleMinutes, &rule.CreatedAt, &rule.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan alert rule: %w", err)
		}
		if peerID.Valid && peerID.String != "" {
			rule.PeerID = &peerID.String
		}
		rules = append(rules, rule)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate alert rules: %w", err)
	}

	return common.EnsureSlice(rules), nil
}

// GetAlertRule returns a single alert rule by ID.
// Returns models.ErrAlertRuleNotFound if the rule does not exist.
func (s *AlertStore) GetAlertRule(ctx context.Context, id uint64) (*models.AlertRule, error) {
	var rule models.AlertRule
	var peerID sql.NullString

	err := s.db.QueryRowContext(ctx,
		`SELECT id, name, alert_type, enabled, threshold_value, threshold_window_minutes, peer_id, throttle_minutes, created_at, updated_at
		FROM alert_rules WHERE id = ?`, id,
	).Scan(&rule.ID, &rule.Name, &rule.AlertType, &rule.Enabled, &rule.ThresholdValue,
		&rule.ThresholdWindowMinutes, &peerID, &rule.ThrottleMinutes, &rule.CreatedAt, &rule.UpdatedAt)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, models.ErrAlertRuleNotFound
		}
		return nil, fmt.Errorf("get alert rule: %w", err)
	}

	if peerID.Valid && peerID.String != "" {
		rule.PeerID = &peerID.String
	}
	return &rule, nil
}

// UpdateAlertRule updates an existing alert rule.
// Returns models.ErrAlertRuleNotFound if no row was affected.
func (s *AlertStore) UpdateAlertRule(ctx context.Context, rule *models.AlertRule) error {
	// Normalize PeerID: treat pointer-to-empty-string as nil so NULL is stored
	// in the database rather than an empty string. This ensures consistency
	// with ListAlertRules/GetAlertRule which treat both NULL and "" as "no peer",
	// and prevents future WHERE peer_id IS NULL queries from missing empty-string rows.
	if rule.PeerID != nil && *rule.PeerID == "" {
		rule.PeerID = nil
	}

	now := time.Now()
	result, err := s.db.ExecContext(ctx,
		`UPDATE alert_rules SET name = ?, alert_type = ?, enabled = ?, threshold_value = ?,
		threshold_window_minutes = ?, peer_id = ?, throttle_minutes = ?, updated_at = ?
		WHERE id = ?`,
		rule.Name, rule.AlertType, rule.Enabled, rule.ThresholdValue, rule.ThresholdWindowMinutes,
		rule.PeerID, rule.ThrottleMinutes, now, rule.ID,
	)
	if err != nil {
		return fmt.Errorf("update alert rule: %w", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("get rows affected: %w", err)
	}

	if affected == 0 {
		return models.ErrAlertRuleNotFound
	}

	rule.UpdatedAt = now
	return nil
}

// GetSMTPConfig returns the current SMTP configuration.
// Missing keys are returned as zero values rather than errors.
func (s *AlertStore) GetSMTPConfig(ctx context.Context) (*models.SMTPConfigView, error) {
	config := &models.SMTPConfigView{}

	err := s.db.QueryRowContext(ctx, "SELECT value FROM system_config WHERE key = 'smtp_host'").Scan(&config.Host)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("get smtp_host: %w", err)
	}

	var portStr string
	err = s.db.QueryRowContext(ctx, "SELECT value FROM system_config WHERE key = 'smtp_port'").Scan(&portStr)
	if err == nil {
		config.Port, _ = strconv.Atoi(portStr)
	}

	err = s.db.QueryRowContext(ctx, "SELECT value FROM system_config WHERE key = 'smtp_username'").Scan(&config.Username)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("get smtp_username: %w", err)
	}

	err = s.db.QueryRowContext(ctx, "SELECT value FROM system_config WHERE key = 'smtp_password'").Scan(&config.Password)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("get smtp_password: %w", err)
	}
	config.PasswordSet = config.Password != ""

	config.UseTLS, _ = getBoolConfig(ctx, s.db, "smtp_use_tls")

	err = s.db.QueryRowContext(ctx, "SELECT value FROM system_config WHERE key = 'smtp_from_address'").Scan(&config.FromAddress)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("get smtp_from_address: %w", err)
	}

	config.Enabled, _ = getBoolConfig(ctx, s.db, "smtp_enabled")

	return config, nil
}

// UpsertSMTPSettings inserts or updates SMTP configuration key-value pairs.
func (s *AlertStore) UpsertSMTPSettings(ctx context.Context, settings map[string]string) error {
	for key, value := range settings {
		_, err := s.db.ExecContext(ctx,
			"INSERT OR REPLACE INTO system_config (key, value, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)",
			key, value,
		)
		if err != nil {
			return fmt.Errorf("upsert SMTP setting %q: %w", key, err)
		}
	}
	return nil
}

// GetUserNotificationPreferences returns notification preferences for a user.
// Returns sql.ErrNoRows if no preferences exist for the user.
func (s *AlertStore) GetUserNotificationPreferences(ctx context.Context, userID uint) (*models.UserNotificationPreferences, error) {
	var prefs models.UserNotificationPreferences

	err := s.db.QueryRowContext(ctx,
		`SELECT id, user_id, quiet_hours_enabled, quiet_hours_start, quiet_hours_end,
		quiet_hours_timezone, digest_enabled, digest_frequency, digest_time, digest_timezone, created_at, updated_at
		FROM user_notification_preferences WHERE user_id = ?`, userID,
	).Scan(&prefs.ID, &prefs.UserID, &prefs.QuietHoursEnabled, &prefs.QuietHoursStart,
		&prefs.QuietHoursEnd, &prefs.QuietHoursTimezone, &prefs.DigestEnabled, &prefs.DigestFrequency,
		&prefs.DigestTime, &prefs.DigestTimezone, &prefs.CreatedAt, &prefs.UpdatedAt)

	if err != nil {
		return nil, fmt.Errorf("get notification preferences for user %d: %w", userID, err)
	}

	return &prefs, nil
}

// UpsertUserNotificationPreferences inserts or updates user notification preferences.
func (s *AlertStore) UpsertUserNotificationPreferences(ctx context.Context, prefs *models.UserNotificationPreferences) error {
	now := time.Now()

	result, err := s.db.ExecContext(ctx,
		`INSERT INTO user_notification_preferences (user_id, quiet_hours_enabled, quiet_hours_start,
		quiet_hours_end, quiet_hours_timezone, digest_enabled, digest_frequency, digest_time, digest_timezone, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(user_id) DO UPDATE SET
		quiet_hours_enabled = excluded.quiet_hours_enabled,
		quiet_hours_start = excluded.quiet_hours_start,
		quiet_hours_end = excluded.quiet_hours_end,
		quiet_hours_timezone = excluded.quiet_hours_timezone,
		digest_enabled = excluded.digest_enabled,
		digest_frequency = excluded.digest_frequency,
		digest_time = excluded.digest_time,
		digest_timezone = excluded.digest_timezone,
		updated_at = excluded.updated_at`,
		prefs.UserID, prefs.QuietHoursEnabled, prefs.QuietHoursStart, prefs.QuietHoursEnd,
		prefs.QuietHoursTimezone, prefs.DigestEnabled, prefs.DigestFrequency, prefs.DigestTime, prefs.DigestTimezone, now, now,
	)
	if err != nil {
		return fmt.Errorf("upsert notification preferences: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		// Try to get the existing ID
		var existingID uint
		err2 := s.db.QueryRowContext(ctx,
			`SELECT id FROM user_notification_preferences WHERE user_id = ?`, prefs.UserID,
		).Scan(&existingID)
		if err2 != nil {
			return fmt.Errorf("get existing preferences id: %w", err2)
		}
		prefs.ID = existingID
	} else {
		prefs.ID = uint(id)
	}

	prefs.UpdatedAt = now
	if prefs.CreatedAt.IsZero() {
		prefs.CreatedAt = now
	}

	return nil
}

// DeleteAlertHistory deletes a single alert history entry by ID.
// Returns models.ErrAlertHistoryNotFound if the alert does not exist.
func (s *AlertStore) DeleteAlertHistory(ctx context.Context, id uint64) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM alert_history WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete alert history: %w", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("get rows affected: %w", err)
	}

	if affected == 0 {
		return models.ErrAlertHistoryNotFound
	}

	return nil
}

// ClearAllAlertHistory deletes all alert history entries.
func (s *AlertStore) ClearAllAlertHistory(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM alert_history`)
	if err != nil {
		return fmt.Errorf("clear alert history: %w", err)
	}

	return nil
}

// CreateAlertRule creates a new alert rule and returns with ID set.
func (s *AlertStore) CreateAlertRule(ctx context.Context, rule *models.AlertRule) error {
	// Normalize PeerID: treat pointer-to-empty-string as nil so NULL is stored
	// in the database rather than an empty string. This ensures consistency
	// with ListAlertRules/GetAlertRule which treat both NULL and "" as "no peer",
	// and prevents future WHERE peer_id IS NULL queries from missing empty-string rows.
	if rule.PeerID != nil && *rule.PeerID == "" {
		rule.PeerID = nil
	}

	now := time.Now()
	result, err := s.db.ExecContext(ctx,
		`INSERT INTO alert_rules (name, alert_type, enabled, threshold_value, threshold_window_minutes, peer_id, throttle_minutes, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		rule.Name, rule.AlertType, rule.Enabled, rule.ThresholdValue, rule.ThresholdWindowMinutes,
		rule.PeerID, rule.ThrottleMinutes, now, now,
	)
	if err != nil {
		return fmt.Errorf("create alert rule: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("get last insert id: %w", err)
	}

	rule.ID = uint(id)
	rule.CreatedAt = now
	rule.UpdatedAt = now
	return nil
}

// CreateAlertHistory creates a new alert history entry.
func (s *AlertStore) CreateAlertHistory(ctx context.Context, history *models.AlertHistory) error {
	now := time.Now()
	result, err := s.db.ExecContext(ctx,
		`INSERT INTO alert_history (rule_id, alert_type, peer_id, severity, subject, message, metadata, status, sent_at, error_message, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		history.RuleID, history.AlertType, history.PeerID, history.Severity, history.Subject,
		history.Message, history.Metadata, history.Status, history.SentAt, history.ErrorMessage, now,
	)
	if err != nil {
		return fmt.Errorf("create alert history: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("get last insert id: %w", err)
	}

	history.ID = uint(id)
	history.CreatedAt = now
	return nil
}

// GetEnabledAlertRulesByType returns all enabled alert rules of a specific type.
func (s *AlertStore) GetEnabledAlertRulesByType(ctx context.Context, alertType models.AlertType) ([]models.AlertRule, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, name, alert_type, enabled, threshold_value, threshold_window_minutes, peer_id, throttle_minutes, created_at, updated_at
		 FROM alert_rules WHERE alert_type = ? AND enabled = 1 ORDER BY created_at DESC`,
		alertType,
	)
	if err != nil {
		return nil, fmt.Errorf("get enabled alert rules by type: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var rules []models.AlertRule
	for rows.Next() {
		var rule models.AlertRule
		var peerID sql.NullString
		if err := rows.Scan(&rule.ID, &rule.Name, &rule.AlertType, &rule.Enabled, &rule.ThresholdValue,
			&rule.ThresholdWindowMinutes, &peerID, &rule.ThrottleMinutes, &rule.CreatedAt, &rule.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan alert rule: %w", err)
		}
		if peerID.Valid && peerID.String != "" {
			rule.PeerID = &peerID.String
		}
		rules = append(rules, rule)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate alert rules: %w", err)
	}

	return common.EnsureSlice(rules), nil
}

// CreateAlertDigest creates a new alert digest entry.
func (s *AlertStore) CreateAlertDigest(ctx context.Context, digest *models.AlertDigest) error {
	now := time.Now()
	result, err := s.db.ExecContext(ctx,
		`INSERT INTO alert_digests (user_id, digest_date, alert_count, summary, sent_at, created_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		digest.UserID, digest.DigestDate, digest.AlertCount, digest.Summary, digest.SentAt, now,
	)
	if err != nil {
		return fmt.Errorf("create alert digest: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("get last insert id: %w", err)
	}

	digest.ID = uint(id)
	digest.CreatedAt = now
	return nil
}

// UpdateAlertHistoryStatus updates the status and error_message for an alert history entry.
func (s *AlertStore) UpdateAlertHistoryStatus(ctx context.Context, id uint64, status models.AlertStatus, errorMessage string) error {
	var errMsg interface{}
	if errorMessage != "" {
		errMsg = errorMessage
	}

	result, err := s.db.ExecContext(ctx,
		`UPDATE alert_history SET status = ?, error_message = ? WHERE id = ?`,
		status, errMsg, id,
	)
	if err != nil {
		return fmt.Errorf("update alert history status: %w", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("get rows affected: %w", err)
	}

	if affected == 0 {
		return models.ErrAlertHistoryNotFound
	}

	return nil
}

// buildInClause returns an SQL clause (e.g., "field IN (?, ?)" or "field = ?)")
// and its corresponding arguments. Returns ("", nil) if no valid values are found.
func buildInClause(fieldName, values string) (string, []interface{}) {
	parts := strings.Split(values, ",")
	// Trim whitespace from each part
	for i, part := range parts {
		parts[i] = strings.TrimSpace(part)
	}
	// Filter empty strings
	validParts := make([]string, 0, len(parts))
	for _, part := range parts {
		if part != "" {
			validParts = append(validParts, part)
		}
	}
	if len(validParts) == 0 {
		return "", nil
	}
	// Single value: use = for backward compatibility
	if len(validParts) == 1 {
		return fieldName + " = ?", []interface{}{validParts[0]}
	}
	// Multiple values: use IN clause
	placeholders := make([]string, len(validParts))
	placeholdersArgs := make([]interface{}, len(validParts))
	for i, part := range validParts {
		placeholders[i] = "?"
		placeholdersArgs[i] = part
	}
	return fieldName + " IN (" + strings.Join(placeholders, ", ") + ")", placeholdersArgs
}

// getBoolConfig returns a boolean config value from system_config.
// Returns false if the key doesn't exist or on any error.
func getBoolConfig(ctx context.Context, db db.Querier, key string) (bool, error) {
	var val int
	err := db.QueryRowContext(ctx,
		`SELECT CAST(value AS INTEGER) FROM system_config WHERE key = ?`,
		key,
	).Scan(&val)
	if err != nil {
		return false, err
	}
	return val == 1, nil
}

// IsAlertThrottled checks if there are recent alerts for the given rule within the throttle duration.
func (s *AlertStore) IsAlertThrottled(ctx context.Context, ruleID uint, cutoff time.Time) (bool, error) {
	var count int
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM alert_history
		WHERE rule_id = ? AND created_at > ? AND status IN (?, ?)`,
		ruleID, cutoff, models.AlertStatusSent, models.AlertStatusPending,
	).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("check throttled: %w", err)
	}

	return count > 0, nil
}

// DB returns the underlying database querier for direct queries when needed.
func (s *AlertStore) DB() db.Querier {
	return s.db
}
