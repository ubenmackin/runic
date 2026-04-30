// Package alerts provides alert and notification functionality.
package alerts

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"runic/internal/crypto"
	"runic/internal/db"

	"runic/internal/common/log"
)

// DigestSummary represents a structured summary of alerts for a digest.
type DigestSummary struct {
	TotalAlerts       int                       `json:"total_alerts"`
	CriticalCount     int                       `json:"critical_count"`
	WarningCount      int                       `json:"warning_count"`
	InfoCount         int                       `json:"info_count"`
	ByType            map[AlertType]int         `json:"by_type"`
	ByTypeAndSeverity map[AlertType]TypeSummary `json:"by_type_and_severity"`
	TimeRange         TimeRange                 `json:"time_range"`
}

// TypeSummary represents a summary of alerts for a specific type.
type TypeSummary struct {
	Count    int      `json:"count"`
	Severity Severity `json:"severity"`
	Messages []string `json:"messages,omitempty"`
}

// TimeRange represents a time range for the digest.
type TimeRange struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// DigestGenerator handles the generation and delivery of alert digests.
type DigestGenerator struct {
	database  db.Querier
	smtp      *SMTPSender
	encryptor *crypto.Encryptor
	logger    *slog.Logger
	stopChan  chan struct{}
	wg        sync.WaitGroup
}

// NewDigestGenerator creates a new digest generator.
func NewDigestGenerator(database db.Querier, smtp *SMTPSender, encryptor *crypto.Encryptor) *DigestGenerator {
	return &DigestGenerator{
		database:  database,
		smtp:      smtp,
		encryptor: encryptor,
		logger:    log.L().With("component", "digest_generator"),
		stopChan:  make(chan struct{}),
	}
}

// SetLogger sets a custom logger for the digest generator.
func (g *DigestGenerator) SetLogger(logger *slog.Logger) {
	g.logger = logger.With("component", "digest_generator")
}

// GenerateDigest generates an alert digest for a specific user.
// It aggregates alerts from the past 24 hours and creates a summary.
func (g *DigestGenerator) GenerateDigest(userID uint) (*AlertDigest, error) {
	ctx := context.Background()

	now := time.Now()
	startTime := now.Add(-24 * time.Hour)

	g.logger.Debug("generating digest",
		"user_id", userID,
		"start_time", startTime.Format(time.RFC3339),
		"end_time", now.Format(time.RFC3339),
	)

	alerts, err := g.getAlertsForUser(ctx, userID, startTime, now)
	if err != nil {
		return nil, fmt.Errorf("failed to get alerts for user: %w", err)
	}

	summary := g.buildDigestSummary(alerts, startTime, now)

	summaryJSON, err := json.Marshal(summary)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal digest summary: %w", err)
	}

	digest := &AlertDigest{
		UserID:     userID,
		DigestDate: now.Format("2006-01-02"),
		AlertCount: summary.TotalAlerts,
		Summary:    string(summaryJSON),
		SentAt:     now,
		CreatedAt:  now,
	}

	if err := CreateAlertDigest(ctx, g.database, digest); err != nil {
		return nil, fmt.Errorf("failed to create alert digest: %w", err)
	}

	g.logger.Info("digest generated",
		"user_id", userID,
		"digest_id", digest.ID,
		"alert_count", digest.AlertCount,
	)

	return digest, nil
}

// SendDigest sends a digest email to the specified user.
func (g *DigestGenerator) SendDigest(digest *AlertDigest, userEmail string) error {
	if g.smtp == nil {
		return fmt.Errorf("SMTP sender not configured")
	}

	if userEmail == "" {
		return fmt.Errorf("user email address is required")
	}

	var summary DigestSummary
	if digest.Summary != "" {
		if err := json.Unmarshal([]byte(digest.Summary), &summary); err != nil {
			return fmt.Errorf("failed to parse digest summary: %w", err)
		}
	}

	instanceURL := GetInstanceURL(context.Background(), g.database)

	htmlBody := g.generateDigestHTML(digest, &summary, instanceURL)

	subject := fmt.Sprintf("[Runic] Daily Alert Digest - %s", digest.DigestDate)
	if digest.AlertCount == 0 {
		subject = fmt.Sprintf("[Runic] Daily Digest - %s (No Alerts)", digest.DigestDate)
	}

	if err := g.smtp.SendHTML(userEmail, subject, htmlBody); err != nil {
		return fmt.Errorf("failed to send digest email: %w", err)
	}

	g.logger.Info("digest email sent",
		"user_id", digest.UserID,
		"digest_id", digest.ID,
		"email", userEmail,
	)

	return nil
}

// RunDaily starts a scheduled task that runs at the configured digest time
// for each user with digest_enabled=true.
func (g *DigestGenerator) RunDaily() {
	g.wg.Add(1)
	go func() {
		defer g.wg.Done()

		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()

		g.logger.Info("daily digest scheduler started")

		for {
			select {
			case <-g.stopChan:
				g.logger.Info("daily digest scheduler stopped")
				return
			case <-ticker.C:
				g.checkAndSendDigests()
			}
		}
	}()
}

// Stop stops the daily digest scheduler.
func (g *DigestGenerator) Stop() {
	close(g.stopChan)
	g.wg.Wait()
	g.logger.Info("digest generator stopped")
}

// checkAndSendDigests checks if any users need a digest sent at the current time.
func (g *DigestGenerator) checkAndSendDigests() {
	ctx := context.Background()

	now := time.Now()

	users, err := g.getUsersWithDigestEnabled(ctx)
	if err != nil {
		g.logger.Error("failed to get users with digest enabled", "error", err)
		return
	}

	for _, user := range users {
		tz := LoadTimezoneOrDefaultWithLogger(user.DigestTimezone, g.logger, "user_id", user.UserID)

		userNow := now.In(tz)
		currentTime := userNow.Format("15:04")
		currentDate := userNow.Format("2006-01-02")

		g.logger.Debug("checking for digest sends",
			"user_id", user.UserID,
			"user_timezone", tz.String(),
			"user_current_time", currentTime,
			"user_current_date", currentDate,
			"user_digest_time", user.DigestTime,
		)

		if user.DigestTime != currentTime {
			continue
		}

		sent, err := g.hasDigestBeenSentToday(ctx, user.UserID, currentDate)
		if err != nil {
			g.logger.Error("failed to check if digest already sent",
				"user_id", user.UserID,
				"error", err,
			)
			continue
		}

		if sent {
			g.logger.Debug("digest already sent today",
				"user_id", user.UserID,
				"date", currentDate,
			)
			continue
		}

		g.sendDigestForUser(ctx, user)
	}
}

// sendDigestForUser generates and sends a digest for a specific user.
func (g *DigestGenerator) sendDigestForUser(ctx context.Context, user *UserNotificationPreferences) {
	email, err := g.getUserEmail(ctx, user.UserID)
	if err != nil {
		g.logger.Error("failed to get user email",
			"user_id", user.UserID,
			"error", err,
		)
		return
	}

	if email == "" {
		g.logger.Warn("user has no email address, skipping digest",
			"user_id", user.UserID,
		)
		return
	}

	digest, err := g.GenerateDigest(user.UserID)
	if err != nil {
		g.logger.Error("failed to generate digest",
			"user_id", user.UserID,
			"error", err,
		)
		return
	}

	if err := g.SendDigest(digest, email); err != nil {
		g.logger.Error("failed to send digest",
			"user_id", user.UserID,
			"digest_id", digest.ID,
			"error", err,
		)
		return
	}

	g.logger.Info("digest sent successfully",
		"user_id", user.UserID,
		"digest_id", digest.ID,
	)
}

// getAlertsForUser retrieves alerts for a user within a time range.
// This joins alert_history with alert_rules to get alerts that apply to the user's context.
func (g *DigestGenerator) getAlertsForUser(ctx context.Context, userID uint, startTime, endTime time.Time) ([]AlertHistory, error) {
	// For now, we return all alerts in the time range since alerts are system-wide
	// In the future, this could be filtered by user's peers or other context
	query := `
		SELECT id, rule_id, alert_type, peer_id, severity, subject, message, metadata, status, sent_at, error_message, created_at
		FROM alert_history
		WHERE created_at >= ? AND created_at <= ?
		ORDER BY created_at DESC
	`

	rows, err := g.database.QueryContext(ctx, query, startTime, endTime)
	if err != nil {
		return nil, fmt.Errorf("failed to query alerts: %w", err)
	}
	defer func() {
		if cerr := rows.Close(); cerr != nil {
			g.logger.Error("failed to close rows", "error", cerr)
		}
	}()

	var alerts []AlertHistory
	for rows.Next() {
		var h AlertHistory
		if err := rows.Scan(&h.ID, &h.RuleID, &h.AlertType, &h.PeerID, &h.Severity,
			&h.Subject, &h.Message, &h.Metadata, &h.Status, &h.SentAt, &h.ErrorMessage, &h.CreatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan alert: %w", err)
		}
		alerts = append(alerts, h)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating alerts: %w", err)
	}

	return alerts, nil
}

// buildDigestSummary builds a summary from a list of alerts.
func (g *DigestGenerator) buildDigestSummary(alerts []AlertHistory, startTime, endTime time.Time) DigestSummary {
	summary := DigestSummary{
		TotalAlerts:       len(alerts),
		ByType:            make(map[AlertType]int),
		ByTypeAndSeverity: make(map[AlertType]TypeSummary),
		TimeRange: TimeRange{
			Start: startTime,
			End:   endTime,
		},
	}

	for i := range alerts {
		alert := &alerts[i]
		switch alert.Severity {
		case SeverityCritical:
			summary.CriticalCount++
		case SeverityWarning:
			summary.WarningCount++
		case SeverityInfo:
			summary.InfoCount++
		}

		summary.ByType[alert.AlertType]++

		typeSummary, exists := summary.ByTypeAndSeverity[alert.AlertType]
		if !exists {
			typeSummary = TypeSummary{
				Count:    0,
				Severity: alert.Severity,
				Messages: []string{},
			}
		}
		typeSummary.Count++
		if alert.Message != "" {
			typeSummary.Messages = append(typeSummary.Messages, alert.Message)
		}
		summary.ByTypeAndSeverity[alert.AlertType] = typeSummary
	}

	return summary
}

// generateDigestHTML creates an HTML email body for the digest.
// Uses terminal aesthetic with dark mode colors and monospace font.
func (g *DigestGenerator) generateDigestHTML(digest *AlertDigest, summary *DigestSummary, instanceURL string) string {
	bodyBg := "#0a0a0a"
	containerBg := "#121212"
	borderColor := "#2d2d2d"
	tableBg := "#0d0d0d"
	textPrimary := "#d1d5db"
	textSecondary := "#e5e7eb"
	textMuted := "#6b7280"
	textDim := "#9ca3af"
	purple := "#a855f7"
	amber := "#d97706"

	var content strings.Builder

	if summary.TotalAlerts == 0 {
		content.WriteString(`
		<p style="color: #6b7280; font-size: 14px; text-align: center; padding: 40px 0;">
			No alerts were recorded in the past 24 hours.
		</p>
		`)
	} else {
		fmt.Fprintf(&content, `
		<div style="margin-bottom: 30px;">
			<h3 style="margin: 0 0 15px 0; color: %s; font-size: 14px; font-weight: bold; text-transform: uppercase; letter-spacing: 1px;">Summary by Severity</h3>
			<table style="width: 100%%; border-collapse: collapse;">
				<tr>
					<td style="padding: 15px; background-color: #1a0a0a; border: 1px solid #3d1515; border-radius: 4px; text-align: center; width: 33.33%%;">
						<div style="font-size: 28px; font-weight: 700; color: #ef4444;">%d</div>
						<div style="font-size: 11px; color: #f87171; text-transform: uppercase; letter-spacing: 1px;">Critical</div>
					</td>
					<td style="padding: 15px; background-color: #1a150a; border: 1px solid #3d2d15; border-radius: 4px; text-align: center; width: 33.33%%;">
						<div style="font-size: 28px; font-weight: 700; color: #d97706;">%d</div>
						<div style="font-size: 11px; color: #fbbf24; text-transform: uppercase; letter-spacing: 1px;">Warning</div>
					</td>
					<td style="padding: 15px; background-color: #0d0d15; border: 1px solid #1f1f3d; border-radius: 4px; text-align: center; width: 33.33%%;">
						<div style="font-size: 28px; font-weight: 700; color: #a855f7;">%d</div>
						<div style="font-size: 11px; color: #c084fc; text-transform: uppercase; letter-spacing: 1px;">Info</div>
					</td>
				</tr>
			</table>
		</div>
		`, textMuted, summary.CriticalCount, summary.WarningCount, summary.InfoCount)

		fmt.Fprintf(&content, `
		<div style="margin-bottom: 30px;">
			<h3 style="margin: 0 0 15px 0; color: %s; font-size: 14px; font-weight: bold; text-transform: uppercase; letter-spacing: 1px;">Alerts by Type</h3>
		`, textMuted)

		for alertType, count := range summary.ByType {
			var typeColor string
			var typeIcon string

			switch alertType {
			case AlertTypePeerOffline:
				typeColor = "#ef4444"
				typeIcon = "&#x1F534;"
			case AlertTypePeerOnline:
				typeColor = "#10b981"
				typeIcon = "&#x1F7E2;"
			case AlertTypeNewPeer:
				typeColor = purple
				typeIcon = "&#x2795;"
			case AlertTypeBundleFailed:
				typeColor = "#f87171"
				typeIcon = "&#x26A0;"
			case AlertTypeBlockedSpike:
				typeColor = amber
				typeIcon = "&#x26A1;"
			default:
				typeColor = textMuted
				typeIcon = "&#x1F4CC;"
			}

			fmt.Fprintf(&content, `
			<div style="display: inline-block; margin: 5px; padding: 10px 15px; background-color: #0d0d0d; border: 1px solid #2d2d2d; border-radius: 4px; border-left: 3px solid %s;">
				<span style="font-size: 14px;">%s</span>
				<span style="font-size: 14px; font-weight: 600; color: %s;"> %s</span>
				<span style="font-size: 13px; color: %s;">: %d alert(s)</span>
			</div>
			`, typeColor, typeIcon, typeColor, formatAlertType(alertType), textDim, count)
		}

		content.WriteString(`</div>`)

		// Recent alerts detail (limit to 10 most recent)
		if len(summary.ByTypeAndSeverity) > 0 {
			fmt.Fprintf(&content, `
			<div style="margin-bottom: 20px;">
				<h3 style="margin: 0 0 15px 0; color: %s; font-size: 14px; font-weight: bold; text-transform: uppercase; letter-spacing: 1px;">Alert Types Overview</h3>
				<ul style="margin: 0; padding-left: 20px; color: %s;">
			`, textMuted, textSecondary)

			for alertType, typeSummary := range summary.ByTypeAndSeverity {
				fmt.Fprintf(&content, `
				<li style="margin-bottom: 8px; color: %s;">
					<strong style="color: %s;">%s</strong>: <span style="color: %s;">%d occurrence(s)</span>
				</li>
				`, textSecondary, textSecondary, formatAlertType(alertType), textDim, typeSummary.Count)
			}

			content.WriteString(`
				</ul>
			</div>
			`)
		}
	}

	settingsLink := instanceURL + "/settings"

	html := fmt.Sprintf(`
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="color-scheme" content="dark">
<meta name="supported-color-schemes" content="dark">
<style type="text/css">
/* Force dark mode in email clients */
:root { color-scheme: dark; }
body { background-color: %s !important; }
</style>
</head>
<body style="margin: 0; padding: 40px 20px; background-color: %s; font-family: 'JetBrains Mono', Consolas, 'Courier New', monospace;">
	<table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%%" style="background-color: %s;">
		<tr>
			<td align="center">
				<table role="presentation" cellspacing="0" cellpadding="0" border="0" width="600" style="background-color: %s; border: 1px solid %s; color: %s; line-height: 1.6;">
					<!-- Header -->
					<tr>
						<td style="padding: 20px;">
							<div style="border-bottom: 1px dashed #4b5563; padding-bottom: 15px; color: %s; font-size: 12px; font-weight: bold; letter-spacing: 2px;">
								[ RUNIC // DAILY DIGEST ]
							</div>
						</td>
					</tr>
					<!-- Digest Badge -->
					<tr>
						<td style="padding: 20px 20px 10px 20px; text-align: center;">
							<span style="display: inline-block; background-color: %s; color: #ffffff; padding: 8px 20px; font-size: 11px; font-weight: bold; text-transform: uppercase; letter-spacing: 2px;">
								%s &bull; %d Alert(s)
							</span>
						</td>
					</tr>
					<!-- Content -->
					<tr>
						<td style="padding: 10px 20px 20px 20px;">
							<h2 style="margin: 0 0 10px 0; color: %s; font-size: 16px; font-weight: bold; text-transform: uppercase; letter-spacing: 1px;">Alert Summary</h2>
							<p style="margin: 0 0 20px 0; color: %s; font-size: 12px;">
								Covering the past 24 hours (%s to %s)
							</p>
							<div style="color: %s; font-size: 13px; line-height: 1.6;">
								%s
							</div>
						</td>
					</tr>
					<!-- Footer -->
					<tr>
						<td style="background-color: %s; border-top: 1px solid %s; padding: 20px; text-align: center;">
							<p style="margin: 0; color: %s; font-size: 11px;">
								This is an automated digest from <span style="color: %s; font-weight: bold;">Runic</span>.
								<br><br>
								<a href="%s" style="color: %s; text-decoration: none; border-bottom: 1px dashed %s; padding-bottom: 2px;">Manage notification preferences</a>
							</p>
						</td>
					</tr>
				</table>
			</td>
		</tr>
	</table>
</body>
</html>
`,
		bodyBg,
		bodyBg,
		bodyBg,
		containerBg,
		borderColor,
		textPrimary,
		purple,
		purple, digest.DigestDate, summary.TotalAlerts,
		textSecondary,
		textMuted,
		summary.TimeRange.Start.Format("Jan 2, 3:04 PM"),
		summary.TimeRange.End.Format("Jan 2, 3:04 PM"),
		textSecondary,
		content.String(),
		tableBg,
		borderColor,
		textMuted,
		purple,
		settingsLink, amber, amber,
	)

	return html
}

// getUsersWithDigestEnabled retrieves all users with digest notifications enabled.
func (g *DigestGenerator) getUsersWithDigestEnabled(ctx context.Context) ([]*UserNotificationPreferences, error) {
	query := `
		SELECT id, user_id, enabled_alerts, quiet_hours_enabled, quiet_hours_start, quiet_hours_end,
		       quiet_hours_timezone, digest_enabled, digest_frequency, digest_time, digest_timezone, created_at, updated_at
		FROM user_notification_preferences
		WHERE digest_enabled = 1
	`

	rows, err := g.database.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query users with digest enabled: %w", err)
	}
	defer func() {
		if cerr := rows.Close(); cerr != nil {
			g.logger.Error("failed to close rows", "error", cerr)
		}
	}()

	var users []*UserNotificationPreferences
	for rows.Next() {
		var prefs UserNotificationPreferences
		if err := rows.Scan(&prefs.ID, &prefs.UserID, &prefs.EnabledAlerts, &prefs.QuietHoursEnabled,
			&prefs.QuietHoursStart, &prefs.QuietHoursEnd, &prefs.QuietHoursTimezone,
			&prefs.DigestEnabled, &prefs.DigestFrequency, &prefs.DigestTime,
			&prefs.DigestTimezone, &prefs.CreatedAt, &prefs.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan user preferences: %w", err)
		}
		users = append(users, &prefs)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating user preferences: %w", err)
	}

	return users, nil
}

// hasDigestBeenSentToday checks if a digest has already been sent for a user today.
func (g *DigestGenerator) hasDigestBeenSentToday(ctx context.Context, userID uint, date string) (bool, error) {
	var count int
	err := g.database.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM alert_digests WHERE user_id = ? AND digest_date = ?",
		userID, date,
	).Scan(&count)

	if err != nil {
		return false, fmt.Errorf("failed to check digest sent: %w", err)
	}

	return count > 0, nil
}

// getUserEmail retrieves the email address for a user.
func (g *DigestGenerator) getUserEmail(ctx context.Context, userID uint) (string, error) {
	var email sql.NullString
	err := g.database.QueryRowContext(ctx,
		"SELECT email FROM users WHERE id = ?",
		userID,
	).Scan(&email)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", fmt.Errorf("user not found")
		}
		return "", fmt.Errorf("failed to get user email: %w", err)
	}

	if !email.Valid {
		return "", nil
	}

	return email.String, nil
}

// formatAlertType formats an alert type for display.
func formatAlertType(alertType AlertType) string {
	switch alertType {
	case AlertTypePeerOffline:
		return "Peer Offline"
	case AlertTypePeerOnline:
		return "Peer Online"
	case AlertTypeNewPeer:
		return "New Peer"
	case AlertTypeBundleFailed:
		return "Bundle Failed"
	case AlertTypeBlockedSpike:
		return "Blocked Traffic Spike"
	default:
		return string(alertType)
	}
}
