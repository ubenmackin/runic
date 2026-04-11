// Package alerts provides alert processing functionality.
package alerts

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	runiclog "runic/internal/common/log"
	"runic/internal/db"
)

// EmailSender defines the interface for sending emails.
// This will be implemented by the smtp package.
type EmailSender interface {
	Send(to, subject, body string) error
	IsEnabled() bool
}

// AlertWorker handles asynchronous alert processing with throttling and quiet hours support.
// This is a separate component from AlertProcessor, providing additional features like
// background queue processing, throttling checks, and quiet hours respect.
type AlertWorker struct {
	database    db.Querier
	emailSender EmailSender
	workCh      chan alertWorkItem
	done        chan struct{}
	startOnce   sync.Once
	stopOnce    sync.Once
	started     atomic.Bool
	wg          sync.WaitGroup
}

type alertWorkItem struct {
	ctx   context.Context
	event *AlertEvent
	rule  *AlertRule
}

// NewAlertWorker creates a new alert worker for asynchronous processing.
func NewAlertWorker(database db.Querier, emailSender EmailSender) *AlertWorker {
	return &AlertWorker{
		database:    database,
		emailSender: emailSender,
		workCh:      make(chan alertWorkItem, 100),
		done:        make(chan struct{}),
	}
}

// Start launches the background worker goroutine.
// Call once during application startup.
func (w *AlertWorker) Start(ctx context.Context) {
	w.startOnce.Do(func() {
		w.started.Store(true)
		w.wg.Add(1)
		go func() {
			defer w.wg.Done()
			defer close(w.done)
			for {
				select {
				case <-ctx.Done():
					runiclog.Info("Alert worker shutting down")
					return
				case work, ok := <-w.workCh:
					if !ok {
						return // channel closed, exit cleanly
					}
					if err := w.processAlertInternal(work.ctx, work.event, work.rule); err != nil {
						runiclog.Error("failed to process alert", "error", err, "rule_id", work.rule.ID)
					}
				}
			}
		}()
		runiclog.Info("Alert worker started")
	})
}

// Stop waits for the worker to finish processing.
func (w *AlertWorker) Stop() {
	w.stopOnce.Do(func() {
		if !w.started.Load() {
			return
		}
		close(w.workCh)
		select {
		case <-w.done:
			runiclog.Info("Alert worker stopped cleanly")
		case <-time.After(10 * time.Second):
			runiclog.Warn("Alert worker.Stop() timed out after 10s")
		}
	})
}

// ProcessAlert processes an alert event asynchronously.
// It queues the alert for background processing and returns immediately.
func (w *AlertWorker) ProcessAlert(event *AlertEvent) error {
	if !w.started.Load() {
		return fmt.Errorf("alert worker not started")
	}

	// Get matching rules for this event type
	rules, err := GetEnabledAlertRulesByType(context.Background(), w.database, event.Type)
	if err != nil {
		runiclog.Error("failed to get alert rules", "error", err, "alert_type", event.Type)
		return fmt.Errorf("failed to get alert rules: %w", err)
	}

	if len(rules) == 0 {
		runiclog.Debug("no enabled rules for alert type", "alert_type", event.Type)
		return nil
	}

	// Queue each matching rule for processing
	queued := 0
	for i := range rules {
		rule := &rules[i]
		// Check if rule applies to this peer
		if event.PeerID != 0 && !rule.AppliesToPeer(event.PeerID) {
			continue
		}

		// Check throttling before queuing
		if w.ShouldThrottle(rule) {
			runiclog.Debug("alert throttled", "rule_id", rule.ID, "rule_name", rule.Name)
			continue
		}

		select {
		case w.workCh <- alertWorkItem{
			ctx:   context.Background(),
			event: event,
			rule:  rule,
		}:
			queued++
		default:
			runiclog.Warn("alert worker queue full, dropping alert", "rule_id", rule.ID)
		}
	}

	runiclog.Info("queued alerts for processing", "count", queued, "alert_type", event.Type)
	return nil
}

// ProcessAlertSync processes an alert synchronously (for testing or critical alerts).
func (w *AlertWorker) ProcessAlertSync(ctx context.Context, event *AlertEvent, rule *AlertRule) error {
	return w.processAlertInternal(ctx, event, rule)
}

// processAlertInternal handles the actual alert processing.
func (w *AlertWorker) processAlertInternal(ctx context.Context, event *AlertEvent, rule *AlertRule) error {
	// Create alert history entry
	history := event.CreateAlertHistory(rule.ID)

	// Set subject and message if not provided
	if history.Subject == "" {
		history.Subject = w.generateSubject(event, rule)
	}
	if history.Message == "" {
		history.Message = w.generateMessage(event, rule)
	}

	// Set metadata
	if len(event.Metadata) > 0 {
		metadataBytes, err := json.Marshal(event.Metadata)
		if err != nil {
			runiclog.Warn("failed to marshal alert metadata", "error", err)
		} else {
			history.Metadata = string(metadataBytes)
		}
	}

	// Save to database with pending status
	if err := CreateAlertHistory(ctx, w.database, &history); err != nil {
		runiclog.Error("failed to create alert history", "error", err)
		return fmt.Errorf("failed to create alert history: %w", err)
	}

	runiclog.Info("processing alert",
		"history_id", history.ID,
		"rule_id", rule.ID,
		"alert_type", event.Type,
		"severity", event.GetSeverity(),
	)

	// Check quiet hours for all users
	// For now, we'll use a default user ID of 1 (admin)
	// In a real system, this would check all users who should receive this alert
	if w.CheckQuietHours(1) {
		runiclog.Info("alert skipped due to quiet hours", "history_id", history.ID)
		// Update status to indicate it was queued for later
		if err := w.updateHistoryStatus(ctx, history.ID, AlertStatusThrottled, sql.NullTime{}, sql.NullString{}); err != nil {
			runiclog.Error("failed to update alert status to throttled", "error", err)
		}
		return nil
	}

	// Send the alert
	var sendErr error
	if w.emailSender != nil && w.emailSender.IsEnabled() {
		// Get notification preferences to determine recipient
		// For now, use a default approach - in production, fetch from user preferences
		recipient := w.getDefaultRecipient(ctx)
		if recipient != "" {
			sendErr = w.emailSender.Send(recipient, history.Subject, history.Message)
		} else {
			sendErr = fmt.Errorf("no email recipient configured")
		}
	} else {
		runiclog.Warn("email sender not configured or disabled")
		sendErr = fmt.Errorf("email sender not available")
	}

	// Update history status
	now := time.Now()
	if sendErr != nil {
		runiclog.Error("failed to send alert",
			"history_id", history.ID,
			"error", sendErr,
		)
		if err := w.updateHistoryStatus(ctx, history.ID, AlertStatusFailed, sql.NullTime{}, sql.NullString{String: sendErr.Error(), Valid: true}); err != nil {
			runiclog.Error("failed to update alert status", "error", err)
		}
		return fmt.Errorf("failed to send alert: %w", sendErr)
	}

	// Mark as sent
	if err := w.updateHistoryStatus(ctx, history.ID, AlertStatusSent, sql.NullTime{Time: now, Valid: true}, sql.NullString{}); err != nil {
		runiclog.Error("failed to update alert status to sent", "error", err)
		return err
	}

	runiclog.Info("alert sent successfully",
		"history_id", history.ID,
		"rule_id", rule.ID,
		"alert_type", event.Type,
	)
	return nil
}

// ShouldThrottle checks if an alert for the given rule should be throttled.
// Returns true if the alert should be skipped due to rate limiting.
func (w *AlertWorker) ShouldThrottle(rule *AlertRule) bool {
	if rule.ThrottleMinutes <= 0 {
		return false // No throttling configured
	}

	ctx := context.Background()

	// Get the last alert for this rule
	// We need to consider peer-specific throttling
	var lastAlert *AlertHistory
	var err error

	// For peer-specific alerts, check by peer
	// For global alerts, check by rule only
	lastAlert, err = GetLastAlertByRule(ctx, w.database, rule.ID)
	if err != nil {
		runiclog.Warn("failed to get last alert for throttling check", "error", err)
		return false // If we can't check, don't throttle
	}

	if lastAlert == nil {
		return false // No previous alert, don't throttle
	}

	// Check if enough time has passed since the last alert
	throttleDuration := rule.GetThrottleDuration()
	timeSinceLastAlert := time.Since(lastAlert.CreatedAt)

	if timeSinceLastAlert < throttleDuration {
		runiclog.Debug("alert throttled",
			"rule_id", rule.ID,
			"time_since_last", timeSinceLastAlert,
			"throttle_duration", throttleDuration,
		)
		return true
	}

	return false
}

// CheckQuietHours checks if the current time is within the user's quiet hours.
// Returns true if alerts should be suppressed.
func (w *AlertWorker) CheckQuietHours(userID uint) bool {
	ctx := context.Background()

	prefs, err := GetUserNotificationPreferences(ctx, w.database, userID)
	if err != nil {
		runiclog.Warn("failed to get user notification preferences", "user_id", userID, "error", err)
		return false // If we can't check, don't suppress
	}

	if !prefs.QuietHoursEnabled {
		return false // Quiet hours not enabled
	}

	if prefs.QuietHoursStart == "" || prefs.QuietHoursEnd == "" {
		return false // Not properly configured
	}

	// Parse the quiet hours times (HH:MM format)
	startTime, err := time.Parse("15:04", prefs.QuietHoursStart)
	if err != nil {
		runiclog.Warn("failed to parse quiet hours start", "value", prefs.QuietHoursStart, "error", err)
		return false
	}

	endTime, err := time.Parse("15:04", prefs.QuietHoursEnd)
	if err != nil {
		runiclog.Warn("failed to parse quiet hours end", "value", prefs.QuietHoursEnd, "error", err)
		return false
	}

	// Get current time in the user's timezone
	now := time.Now()
	if prefs.QuietHoursTimezone != "" {
		loc, err := time.LoadLocation(prefs.QuietHoursTimezone)
		if err != nil {
			runiclog.Warn("failed to load timezone", "timezone", prefs.QuietHoursTimezone, "error", err)
			// Fall back to local time
		} else {
			now = now.In(loc)
		}
	}

	// Get current time of day
	currentTime, _ := time.Parse("15:04", now.Format("15:04"))

	// Check if current time is within quiet hours
	// Handle the case where quiet hours span midnight (e.g., 22:00 - 06:00)
	if startTime.Before(endTime) {
		// Quiet hours don't span midnight (e.g., 02:00 - 06:00)
		return (currentTime.After(startTime) || currentTime.Equal(startTime)) &&
			(currentTime.Before(endTime))
	} else {
		// Quiet hours span midnight (e.g., 22:00 - 06:00)
		return currentTime.After(startTime) || currentTime.Equal(startTime) || currentTime.Before(endTime)
	}
}

// generateSubject creates an alert subject line.
func (w *AlertWorker) generateSubject(event *AlertEvent, rule *AlertRule) string {
	peerInfo := ""
	if event.PeerName != "" {
		peerInfo = fmt.Sprintf(" (%s)", event.PeerName)
	} else if event.PeerID != 0 {
		peerInfo = fmt.Sprintf(" (peer %d)", event.PeerID)
	}

	severity := event.GetSeverity()
	return fmt.Sprintf("[%s] %s: %s%s", severity.String(), rule.Name, event.Type.String(), peerInfo)
}

// generateMessage creates the alert message body.
func (w *AlertWorker) generateMessage(event *AlertEvent, rule *AlertRule) string {
	var msg string

	msg = fmt.Sprintf("Alert: %s\n", event.Type.String())
	msg += fmt.Sprintf("Rule: %s\n", rule.Name)
	msg += fmt.Sprintf("Severity: %s\n", event.GetSeverity().String())
	msg += fmt.Sprintf("Timestamp: %s\n", event.Timestamp.Format(time.RFC3339))

	if event.PeerName != "" {
		msg += fmt.Sprintf("Peer: %s (ID: %d)\n", event.PeerName, event.PeerID)
	} else if event.PeerID != 0 {
		msg += fmt.Sprintf("Peer ID: %d\n", event.PeerID)
	}

	if event.Value > 0 {
		msg += fmt.Sprintf("Value: %d\n", event.Value)
	}

	if len(event.Metadata) > 0 {
		msg += "\nAdditional Details:\n"
		for key, value := range event.Metadata {
			msg += fmt.Sprintf("  %s: %v\n", key, value)
		}
	}

	return msg
}

// updateHistoryStatus updates the status of an alert history entry.
func (w *AlertWorker) updateHistoryStatus(ctx context.Context, id uint, status AlertStatus, sentAt sql.NullTime, errorMsg sql.NullString) error {
	result, err := w.database.ExecContext(ctx,
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

// getDefaultRecipient retrieves the default email recipient.
func (w *AlertWorker) getDefaultRecipient(ctx context.Context) string {
	// In production, this would query user preferences or system config
	// For now, check system_config table
	var email string
	err := w.database.QueryRowContext(ctx,
		`SELECT value FROM system_config WHERE key = 'admin_email'`,
	).Scan(&email)
	if err != nil {
		runiclog.Debug("no admin_email configured for alerts")
		return ""
	}
	return email
}

// GetLastAlertByRule retrieves the most recent alert for a specific rule.
func GetLastAlertByRule(ctx context.Context, database db.Querier, ruleID uint) (*AlertHistory, error) {
	var h AlertHistory

	err := database.QueryRowContext(ctx,
		`SELECT id, rule_id, alert_type, peer_id, severity, subject, message, metadata, status, sent_at, error_message, created_at
		 FROM alert_history WHERE rule_id = ? ORDER BY created_at DESC LIMIT 1`,
		ruleID,
	).Scan(&h.ID, &h.RuleID, &h.AlertType, &h.PeerID, &h.Severity, &h.Subject,
		&h.Message, &h.Metadata, &h.Status, &h.SentAt, &h.ErrorMessage, &h.CreatedAt)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // No previous alert
		}
		return nil, fmt.Errorf("failed to get last alert by rule: %w", err)
	}

	return &h, nil
}

// IsStarted returns true if the worker is currently running.
func (w *AlertWorker) IsStarted() bool {
	return w.started.Load()
}
