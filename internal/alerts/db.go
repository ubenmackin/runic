// Package alerts provides database operations for the alert system.
package alerts

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"runic/internal/common/log"
	"runic/internal/db"
)

// AlertRules CRUD Operations

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
func GetAlertRule(ctx context.Context, database db.Querier, id uint) (*AlertRule, error) {
	var rule AlertRule
	var peerID sql.NullInt64

	err := database.QueryRowContext(ctx,
		`SELECT id, name, alert_type, enabled, threshold_value, threshold_window_minutes, peer_id, throttle_minutes, created_at, updated_at
		 FROM alert_rules WHERE id = ?`,
		id,
	).Scan(&rule.ID, &rule.Name, &rule.AlertType, &rule.Enabled, &rule.ThresholdValue,
		&rule.ThresholdWindowMinutes, &peerID, &rule.ThrottleMinutes, &rule.CreatedAt, &rule.UpdatedAt)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("alert rule not found: %w", err)
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
		return fmt.Errorf("alert rule not found")
	}

	rule.UpdatedAt = now
	return nil
}

// DeleteAlertRule deletes an alert rule by ID.
func DeleteAlertRule(ctx context.Context, database db.Querier, id uint) error {
	result, err := database.ExecContext(ctx, `DELETE FROM alert_rules WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("failed to delete alert rule: %w", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if affected == 0 {
		return fmt.Errorf("alert rule not found")
	}

	return nil
}

// AlertHistory Operations

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

// ListAlertHistory fetches alert history entries with pagination.
func ListAlertHistory(ctx context.Context, database db.Querier, limit, offset int) ([]AlertHistory, error) {
	if limit <= 0 {
		limit = 50
	}

	rows, err := database.QueryContext(ctx,
		`SELECT id, rule_id, alert_type, peer_id, severity, subject, message, metadata, status, sent_at, error_message, created_at
		 FROM alert_history ORDER BY created_at DESC LIMIT ? OFFSET ?`,
		limit, offset,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to list alert history: %w", err)
	}
	defer func() {
		if cerr := rows.Close(); cerr != nil {
			log.Error("failed to close rows", "error", cerr)
		}
	}()

	var historyList []AlertHistory
	for rows.Next() {
		var h AlertHistory
		if err := rows.Scan(&h.ID, &h.RuleID, &h.AlertType, &h.PeerID, &h.Severity, &h.Subject,
			&h.Message, &h.Metadata, &h.Status, &h.SentAt, &h.ErrorMessage, &h.CreatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan alert history: %w", err)
		}
		historyList = append(historyList, h)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating alert history: %w", err)
	}

	return historyList, nil
}

// GetAlertHistoryByRule fetches alert history entries for a specific rule.
func GetAlertHistoryByRule(ctx context.Context, database db.Querier, ruleID uint) ([]AlertHistory, error) {
	rows, err := database.QueryContext(ctx,
		`SELECT id, rule_id, alert_type, peer_id, severity, subject, message, metadata, status, sent_at, error_message, created_at
		 FROM alert_history WHERE rule_id = ? ORDER BY created_at DESC`,
		ruleID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get alert history by rule: %w", err)
	}
	defer func() {
		if cerr := rows.Close(); cerr != nil {
			log.Error("failed to close rows", "error", cerr)
		}
	}()

	var historyList []AlertHistory
	for rows.Next() {
		var h AlertHistory
		if err := rows.Scan(&h.ID, &h.RuleID, &h.AlertType, &h.PeerID, &h.Severity, &h.Subject,
			&h.Message, &h.Metadata, &h.Status, &h.SentAt, &h.ErrorMessage, &h.CreatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan alert history: %w", err)
		}
		historyList = append(historyList, h)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating alert history: %w", err)
	}

	return historyList, nil
}

// UserNotificationPreferences Operations

// GetUserNotificationPreferences fetches notification preferences for a user.
func GetUserNotificationPreferences(ctx context.Context, database db.Querier, userID uint) (*UserNotificationPreferences, error) {
	var prefs UserNotificationPreferences

	err := database.QueryRowContext(ctx,
		`SELECT id, user_id, enabled_alerts, quiet_hours_enabled, quiet_hours_start, quiet_hours_end,
		 quiet_hours_timezone, digest_enabled, digest_frequency, digest_time, created_at, updated_at
		 FROM user_notification_preferences WHERE user_id = ?`,
		userID,
	).Scan(&prefs.ID, &prefs.UserID, &prefs.EnabledAlerts, &prefs.QuietHoursEnabled, &prefs.QuietHoursStart,
		&prefs.QuietHoursEnd, &prefs.QuietHoursTimezone, &prefs.DigestEnabled, &prefs.DigestFrequency,
		&prefs.DigestTime, &prefs.CreatedAt, &prefs.UpdatedAt)

	if err != nil {
		if err == sql.ErrNoRows {
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
		 quiet_hours_end, quiet_hours_timezone, digest_enabled, digest_frequency, digest_time, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(user_id) DO UPDATE SET
		 enabled_alerts = excluded.enabled_alerts,
		 quiet_hours_enabled = excluded.quiet_hours_enabled,
		 quiet_hours_start = excluded.quiet_hours_start,
		 quiet_hours_end = excluded.quiet_hours_end,
		 quiet_hours_timezone = excluded.quiet_hours_timezone,
		 digest_enabled = excluded.digest_enabled,
		 digest_frequency = excluded.digest_frequency,
		 digest_time = excluded.digest_time,
		 updated_at = excluded.updated_at`,
		prefs.UserID, prefs.EnabledAlerts, prefs.QuietHoursEnabled, prefs.QuietHoursStart, prefs.QuietHoursEnd,
		prefs.QuietHoursTimezone, prefs.DigestEnabled, prefs.DigestFrequency, prefs.DigestTime, now, now,
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

// AlertDigest Operations

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

// GetLatestDigest fetches the most recent digest for a user.
func GetLatestDigest(ctx context.Context, database db.Querier, userID uint) (*AlertDigest, error) {
	var digest AlertDigest

	err := database.QueryRowContext(ctx,
		`SELECT id, user_id, digest_date, alert_count, summary, sent_at, created_at
		 FROM alert_digests WHERE user_id = ? ORDER BY digest_date DESC LIMIT 1`,
		userID,
	).Scan(&digest.ID, &digest.UserID, &digest.DigestDate, &digest.AlertCount, &digest.Summary,
		&digest.SentAt, &digest.CreatedAt)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("no digest found for user: %w", err)
		}
		return nil, fmt.Errorf("failed to get latest digest: %w", err)
	}

	return &digest, nil
}

// Transactional helper functions

// CreateAlertRuleTx creates an alert rule within a transaction.
func CreateAlertRuleTx(ctx context.Context, tx *sql.Tx, rule *AlertRule) error {
	return CreateAlertRule(ctx, tx, rule)
}

// UpdateAlertHistoryStatusTx updates the status of an alert history entry within a transaction.
func UpdateAlertHistoryStatusTx(ctx context.Context, tx *sql.Tx, id uint, status AlertStatus, sentAt sql.NullTime, errorMsg sql.NullString) error {
	result, err := tx.ExecContext(ctx,
		`UPDATE alert_history SET status = ?, sent_at = ?, error_message = ? WHERE id = ?`,
		status, sentAt, errorMsg, id,
	)
	if err != nil {
		return fmt.Errorf("failed to update alert history status: %w", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if affected == 0 {
		return fmt.Errorf("alert history not found")
	}

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

// GetLastAlertForRuleAndPeer fetches the most recent alert for a specific rule and peer.
func GetLastAlertForRuleAndPeer(ctx context.Context, database db.Querier, ruleID uint, peerID sql.NullInt64) (*AlertHistory, error) {
	var h AlertHistory

	err := database.QueryRowContext(ctx,
		`SELECT id, rule_id, alert_type, peer_id, severity, subject, message, metadata, status, sent_at, error_message, created_at
		 FROM alert_history WHERE rule_id = ? AND peer_id = ? ORDER BY created_at DESC LIMIT 1`,
		ruleID, peerID,
	).Scan(&h.ID, &h.RuleID, &h.AlertType, &h.PeerID, &h.Severity, &h.Subject, &h.Message,
		&h.Metadata, &h.Status, &h.SentAt, &h.ErrorMessage, &h.CreatedAt)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // No previous alert, return nil without error
		}
		return nil, fmt.Errorf("failed to get last alert for rule and peer: %w", err)
	}

	return &h, nil
}
