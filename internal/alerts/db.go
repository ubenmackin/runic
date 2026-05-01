// Package alerts provides database operations for the alert system.
package alerts

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"runic/internal/common/log"
	"runic/internal/db"
)

// ErrAlertRuleNotFound is returned when an alert rule is not found.
var ErrAlertRuleNotFound = errors.New("alert rule not found")

// ErrAlertHistoryNotFound is returned when an alert history entry is not found.
var ErrAlertHistoryNotFound = errors.New("alert history not found")

// CreateAlertRule inserts a new alert rule into the database.
func CreateAlertRule(ctx context.Context, database db.Querier, rule *AlertRule) error {
	now := time.Now()
	result, err := database.ExecContext(ctx,
		`INSERT INTO alert_rules (name, alert_type, enabled, threshold_value, threshold_window_minutes, peer_id, throttle_minutes, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		rule.Name, rule.AlertType, rule.Enabled, rule.ThresholdValue, rule.ThresholdWindowMinutes,
		rule.PeerID, rule.ThrottleMinutes, now, now,
	)
	if err != nil {
		return fmt.Errorf("failed to create alert rule: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("failed to get last insert id: %w", err)
	}

	rule.ID = uint(id)
	rule.CreatedAt = now
	rule.UpdatedAt = now
	return nil
}

// GetAlertRule fetches an alert rule by ID.
func GetAlertRule(ctx context.Context, database db.Querier, id uint64) (*AlertRule, error) {
	var rule AlertRule
	var peerID sql.NullInt64

	err := database.QueryRowContext(ctx,
		`SELECT id, name, alert_type, enabled, threshold_value, threshold_window_minutes, peer_id, throttle_minutes, created_at, updated_at
		 FROM alert_rules WHERE id = ?`,
		id,
	).Scan(&rule.ID, &rule.Name, &rule.AlertType, &rule.Enabled, &rule.ThresholdValue,
		&rule.ThresholdWindowMinutes, &peerID, &rule.ThrottleMinutes, &rule.CreatedAt, &rule.UpdatedAt)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrAlertRuleNotFound
		}
		return nil, fmt.Errorf("failed to get alert rule: %w", err)
	}

	if peerID.Valid {
		peerIDInt := int(peerID.Int64)
		rule.PeerID = &peerIDInt
	}
	return &rule, nil
}

// ListAlertRules fetches all alert rules.
func ListAlertRules(ctx context.Context, database db.Querier) ([]AlertRule, error) {
	rows, err := database.QueryContext(ctx,
		`SELECT id, name, alert_type, enabled, threshold_value, threshold_window_minutes, peer_id, throttle_minutes, created_at, updated_at
		 FROM alert_rules ORDER BY created_at DESC`,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to list alert rules: %w", err)
	}
	defer func() {
		if cerr := rows.Close(); cerr != nil {
			log.Error("failed to close rows", "error", cerr)
		}
	}()

	var rules []AlertRule
	for rows.Next() {
		var rule AlertRule
		var peerID sql.NullInt64
		if err := rows.Scan(&rule.ID, &rule.Name, &rule.AlertType, &rule.Enabled, &rule.ThresholdValue,
			&rule.ThresholdWindowMinutes, &peerID, &rule.ThrottleMinutes, &rule.CreatedAt, &rule.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan alert rule: %w", err)
		}
		if peerID.Valid {
			peerIDInt := int(peerID.Int64)
			rule.PeerID = &peerIDInt
		}
		rules = append(rules, rule)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating alert rules: %w", err)
	}

	return rules, nil
}

// UpdateAlertRule updates an existing alert rule.
func UpdateAlertRule(ctx context.Context, database db.Querier, rule *AlertRule) error {
	now := time.Now()
	result, err := database.ExecContext(ctx,
		`UPDATE alert_rules SET name = ?, alert_type = ?, enabled = ?, threshold_value = ?, 
		 threshold_window_minutes = ?, peer_id = ?, throttle_minutes = ?, updated_at = ?
		 WHERE id = ?`,
		rule.Name, rule.AlertType, rule.Enabled, rule.ThresholdValue, rule.ThresholdWindowMinutes,
		rule.PeerID, rule.ThrottleMinutes, now, rule.ID,
	)
	if err != nil {
		return fmt.Errorf("failed to update alert rule: %w", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if affected == 0 {
		return ErrAlertRuleNotFound
	}

	rule.UpdatedAt = now
	return nil
}

// CreateAlertHistory inserts a new alert history entry.
func CreateAlertHistory(ctx context.Context, database db.Querier, history *AlertHistory) error {
	now := time.Now()
	result, err := database.ExecContext(ctx,
		`INSERT INTO alert_history (rule_id, alert_type, peer_id, severity, subject, message, metadata, status, sent_at, error_message, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		history.RuleID, history.AlertType, history.PeerID, history.Severity, history.Subject,
		history.Message, history.Metadata, history.Status, history.SentAt, history.ErrorMessage, now,
	)
	if err != nil {
		return fmt.Errorf("failed to create alert history: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("failed to get last insert id: %w", err)
	}

	history.ID = uint(id)
	history.CreatedAt = now
	return nil
}

// GetUserNotificationPreferences fetches notification preferences for a user.
func GetUserNotificationPreferences(ctx context.Context, database db.Querier, userID uint) (*UserNotificationPreferences, error) {
	var prefs UserNotificationPreferences

	err := database.QueryRowContext(ctx,
		`SELECT id, user_id, enabled_alerts, quiet_hours_enabled, quiet_hours_start, quiet_hours_end,
		quiet_hours_timezone, digest_enabled, digest_frequency, digest_time, digest_timezone, created_at, updated_at
		FROM user_notification_preferences WHERE user_id = ?`,
		userID,
	).Scan(&prefs.ID, &prefs.UserID, &prefs.EnabledAlerts, &prefs.QuietHoursEnabled, &prefs.QuietHoursStart,
		&prefs.QuietHoursEnd, &prefs.QuietHoursTimezone, &prefs.DigestEnabled, &prefs.DigestFrequency,
		&prefs.DigestTime, &prefs.DigestTimezone, &prefs.CreatedAt, &prefs.UpdatedAt)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("notification preferences not found for user: %w", err)
		}
		return nil, fmt.Errorf("failed to get notification preferences: %w", err)
	}

	return &prefs, nil
}

// UpsertUserNotificationPreferences inserts or updates notification preferences for a user.
func UpsertUserNotificationPreferences(ctx context.Context, database db.Querier, prefs *UserNotificationPreferences) error {
	now := time.Now()

	result, err := database.ExecContext(ctx,
		`INSERT INTO user_notification_preferences (user_id, enabled_alerts, quiet_hours_enabled, quiet_hours_start,
		quiet_hours_end, quiet_hours_timezone, digest_enabled, digest_frequency, digest_time, digest_timezone, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(user_id) DO UPDATE SET
		enabled_alerts = excluded.enabled_alerts,
		quiet_hours_enabled = excluded.quiet_hours_enabled,
		quiet_hours_start = excluded.quiet_hours_start,
		quiet_hours_end = excluded.quiet_hours_end,
		quiet_hours_timezone = excluded.quiet_hours_timezone,
		digest_enabled = excluded.digest_enabled,
		digest_frequency = excluded.digest_frequency,
		digest_time = excluded.digest_time,
		digest_timezone = excluded.digest_timezone,
		updated_at = excluded.updated_at`,
		prefs.UserID, prefs.EnabledAlerts, prefs.QuietHoursEnabled, prefs.QuietHoursStart, prefs.QuietHoursEnd,
		prefs.QuietHoursTimezone, prefs.DigestEnabled, prefs.DigestFrequency, prefs.DigestTime, prefs.DigestTimezone, now, now,
	)
	if err != nil {
		return fmt.Errorf("failed to upsert notification preferences: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		// For SQLite with ON CONFLICT, LastInsertId may not work as expected on updates
		// Try to get the existing ID
		var existingID uint
		err2 := database.QueryRowContext(ctx,
			`SELECT id FROM user_notification_preferences WHERE user_id = ?`,
			prefs.UserID,
		).Scan(&existingID)
		if err2 != nil {
			return fmt.Errorf("failed to get existing preferences id: %w", err2)
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

// CreateAlertDigest inserts a new alert digest record.
func CreateAlertDigest(ctx context.Context, database db.Querier, digest *AlertDigest) error {
	now := time.Now()
	result, err := database.ExecContext(ctx,
		`INSERT INTO alert_digests (user_id, digest_date, alert_count, summary, sent_at, created_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		digest.UserID, digest.DigestDate, digest.AlertCount, digest.Summary, digest.SentAt, now,
	)
	if err != nil {
		return fmt.Errorf("failed to create alert digest: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("failed to get last insert id: %w", err)
	}

	digest.ID = uint(id)
	digest.CreatedAt = now
	return nil
}

// GetEnabledAlertRulesByType fetches all enabled rules for a specific alert type.
func GetEnabledAlertRulesByType(ctx context.Context, database db.Querier, alertType AlertType) ([]AlertRule, error) {
	rows, err := database.QueryContext(ctx,
		`SELECT id, name, alert_type, enabled, threshold_value, threshold_window_minutes, peer_id, throttle_minutes, created_at, updated_at
		 FROM alert_rules WHERE alert_type = ? AND enabled = 1 ORDER BY created_at DESC`,
		alertType,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get enabled alert rules by type: %w", err)
	}
	defer func() {
		if cerr := rows.Close(); cerr != nil {
			log.Error("failed to close rows", "error", cerr)
		}
	}()

	var rules []AlertRule
	for rows.Next() {
		var rule AlertRule
		var peerID sql.NullInt64
		if err := rows.Scan(&rule.ID, &rule.Name, &rule.AlertType, &rule.Enabled, &rule.ThresholdValue,
			&rule.ThresholdWindowMinutes, &peerID, &rule.ThrottleMinutes, &rule.CreatedAt, &rule.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan alert rule: %w", err)
		}
		if peerID.Valid {
			peerIDInt := int(peerID.Int64)
			rule.PeerID = &peerIDInt
		}
		rules = append(rules, rule)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating alert rules: %w", err)
	}

	return rules, nil
}

// DeleteAlertHistory deletes an alert history entry by ID.
func DeleteAlertHistory(ctx context.Context, database db.Querier, id uint64) error {
	result, err := database.ExecContext(ctx, `DELETE FROM alert_history WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("failed to delete alert history: %w", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if affected == 0 {
		return ErrAlertHistoryNotFound
	}

	return nil
}

// ClearAllAlertHistory deletes all alert history entries.
func ClearAllAlertHistory(ctx context.Context, database db.Querier) error {
	_, err := database.ExecContext(ctx, `DELETE FROM alert_history`)
	if err != nil {
		return fmt.Errorf("failed to clear alert history: %w", err)
	}

	return nil
}

// buildInClause builds a SQL IN clause (or equality check) for comma-separated values.
// For a single value it returns "field = ?", for multiple values "field IN (?, ?, ?)".
// Returns empty string if no valid values are found.
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

// ListAlertHistory returns paginated alert history with filtering and sorting.
func ListAlertHistory(ctx context.Context, database db.Querier, filter *AlertHistoryFilter) (*AlertHistoryListResult, error) {
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
				// For end date, use end of day (23:59:59)
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
	if err := database.QueryRowContext(ctx, countQuery, countArgs...).Scan(&total); err != nil {
		return nil, fmt.Errorf("failed to count alert history: %w", err)
	}

	// Data query
	args = append(args, limit, offset)
	query := `SELECT h.id, h.rule_id, h.alert_type, h.peer_id, p.hostname as peer_hostname, h.severity, h.subject, h.message, h.metadata, h.status, h.sent_at, h.error_message, h.created_at
	FROM alert_history h
	LEFT JOIN peers p ON h.peer_id = p.id
	` + whereClause + `
	ORDER BY ` + orderByColumn + ` ` + orderByDirection + `
	LIMIT ? OFFSET ?`

	rows, err := database.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list alert history: %w", err)
	}
	defer func() {
		if cerr := rows.Close(); cerr != nil {
			log.Error("failed to close rows", "error", cerr)
		}
	}()

	var history []AlertHistory
	for rows.Next() {
		var h AlertHistory
		var peerHostname sql.NullString
		if err := rows.Scan(&h.ID, &h.RuleID, &h.AlertType, &h.PeerID, &peerHostname, &h.Severity, &h.Subject,
			&h.Message, &h.Metadata, &h.Status, &h.SentAt, &h.ErrorMessage, &h.CreatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan alert history row: %w", err)
		}
		if peerHostname.Valid {
			h.PeerHostname = peerHostname.String
		}
		history = append(history, h)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating alert history rows: %w", err)
	}

	if history == nil {
		history = []AlertHistory{}
	}

	return &AlertHistoryListResult{
		Alerts: history,
		Total:  total,
		Limit:  limit,
		Offset: offset,
	}, nil
}

// GetAlertHistory fetches a single alert history entry by ID.
func GetAlertHistory(ctx context.Context, database db.Querier, id int) (*AlertHistory, error) {
	var alert AlertHistory

	err := database.QueryRowContext(ctx, `
		SELECT id, rule_id, alert_type, peer_id, severity, subject, message, metadata, status, sent_at, error_message, created_at
		FROM alert_history WHERE id = ?`, id,
	).Scan(&alert.ID, &alert.RuleID, &alert.AlertType, &alert.PeerID, &alert.Severity,
		&alert.Subject, &alert.Message, &alert.Metadata, &alert.Status, &alert.SentAt, &alert.ErrorMessage, &alert.CreatedAt)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrAlertHistoryNotFound
		}
		return nil, fmt.Errorf("failed to get alert history: %w", err)
	}

	return &alert, nil
}

// GetSMTPConfig reads SMTP configuration from system_config and returns a view with the password masked.
func GetSMTPConfig(ctx context.Context, database db.Querier) (*SMTPConfigView, error) {
	config := &SMTPConfigView{}

	err := database.QueryRowContext(ctx, "SELECT value FROM system_config WHERE key = 'smtp_host'").Scan(&config.Host)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("failed to get smtp_host: %w", err)
	}

	var portStr string
	err = database.QueryRowContext(ctx, "SELECT value FROM system_config WHERE key = 'smtp_port'").Scan(&portStr)
	if err == nil {
		config.Port, _ = strconv.Atoi(portStr)
	}

	err = database.QueryRowContext(ctx, "SELECT value FROM system_config WHERE key = 'smtp_username'").Scan(&config.Username)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("failed to get smtp_username: %w", err)
	}

	var hasPassword bool
	err = database.QueryRowContext(ctx, "SELECT COUNT(*) > 0 FROM system_config WHERE key = 'smtp_password' AND value IS NOT NULL AND value != ''").Scan(&hasPassword)
	config.PasswordSet = err == nil && hasPassword

	config.UseTLS, _ = GetBoolConfig(ctx, database, "smtp_use_tls")

	err = database.QueryRowContext(ctx, "SELECT value FROM system_config WHERE key = 'smtp_from_address'").Scan(&config.FromAddress)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("failed to get smtp_from_address: %w", err)
	}

	config.Enabled, _ = GetBoolConfig(ctx, database, "smtp_enabled")

	return config, nil
}

// UpsertSMTPSettings inserts or replaces SMTP settings into system_config.
func UpsertSMTPSettings(ctx context.Context, database db.Querier, settings map[string]string) error {
	for key, value := range settings {
		_, err := database.ExecContext(ctx,
			"INSERT OR REPLACE INTO system_config (key, value, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)",
			key, value,
		)
		if err != nil {
			return fmt.Errorf("failed to upsert SMTP setting %q: %w", key, err)
		}
	}
	return nil
}
