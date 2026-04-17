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
		return fmt.Errorf("alert history not found")
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
