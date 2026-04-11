// Package alerts provides a scheduler for periodic alert rule checks.
package alerts

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"runic/internal/common/log"

	"runic/internal/db"
)

// DefaultCheckInterval is the default interval for scheduled alert checks.
const DefaultCheckInterval = 1 * time.Minute

// Scheduler handles periodic alert rule checks.
type Scheduler struct {
	database   *db.Database
	evaluator  *ConditionEvaluator
	processor  *AlertProcessor
	interval   time.Duration
	logger     *slog.Logger
	stopOnce   sync.Once
	stopCh     chan struct{}
	running    bool
	runningMux sync.RWMutex
}

// NewScheduler creates a new alert scheduler.
// The scheduler will use the provided evaluator to check rule conditions
// and the processor to handle triggered alerts.
func NewScheduler(database *db.Database, evaluator *ConditionEvaluator, processor *AlertProcessor) *Scheduler {
	return &Scheduler{
		database:  database,
		evaluator: evaluator,
		processor: processor,
		interval:  DefaultCheckInterval,
		logger:    log.L().With("component", "alert_scheduler"),
		stopCh:    make(chan struct{}),
	}
}

// WithInterval sets a custom check interval for the scheduler.
// Returns the scheduler for method chaining.
func (s *Scheduler) WithInterval(interval time.Duration) *Scheduler {
	if interval > 0 {
		s.interval = interval
	}
	return s
}

// Start begins the scheduled alert checks.
// It returns immediately; the scheduler runs in a background goroutine.
// The scheduler runs an immediate check on startup, then continues at the configured interval.
func (s *Scheduler) Start(ctx context.Context) {
	s.runningMux.Lock()
	if s.running {
		s.runningMux.Unlock()
		return
	}
	s.running = true
	s.runningMux.Unlock()

	// Run once immediately on startup
	s.logger.Info("starting alert scheduler, running initial check")
	s.CheckAllRules(ctx)

	// Then run periodically
	go func() {
		ticker := time.NewTicker(s.interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				s.logger.Info("alert scheduler stopped by context")
				s.setRunning(false)
				return
			case <-s.stopCh:
				s.logger.Info("alert scheduler stopped")
				s.setRunning(false)
				return
			case <-ticker.C:
				s.CheckAllRules(ctx)
			}
		}
	}()
}

// setRunning safely sets the running state.
func (s *Scheduler) setRunning(running bool) {
	s.runningMux.Lock()
	defer s.runningMux.Unlock()
	s.running = running
}

// IsRunning returns whether the scheduler is currently running.
func (s *Scheduler) IsRunning() bool {
	s.runningMux.RLock()
	defer s.runningMux.RUnlock()
	return s.running
}

// Stop stops the scheduler.
// It is safe to call Stop multiple times.
func (s *Scheduler) Stop() {
	s.stopOnce.Do(func() {
		close(s.stopCh)
	})
}

// CheckAllRules evaluates all enabled alert rules.
// For each rule, it checks if the condition is met and triggers alerts accordingly.
func (s *Scheduler) CheckAllRules(ctx context.Context) {
	// Load all enabled rules
	rules, err := s.getEnabledRules(ctx)
	if err != nil {
		s.logger.Error("failed to load enabled alert rules", "error", err)
		return
	}

	if len(rules) == 0 {
		s.logger.Debug("no enabled alert rules to check")
		return
	}

	s.logger.Debug("checking alert rules", "count", len(rules))

	// Check each rule
	for i := range rules {
		rule := &rules[i]

		// Skip if stop channel is closed
		select {
		case <-s.stopCh:
			return
		default:
		}

		if err := s.checkRule(ctx, rule); err != nil {
			s.logger.Error("failed to check rule",
				"rule_id", rule.ID,
				"rule_name", rule.Name,
				"error", err)
		}
	}
}

// CheckRule evaluates a specific alert rule by ID.
// Returns an error if the rule is not found or if evaluation fails.
func (s *Scheduler) CheckRule(ctx context.Context, ruleID uint) error {
	rule, err := GetAlertRule(ctx, s.database, ruleID)
	if err != nil {
		return fmt.Errorf("failed to get alert rule %d: %w", ruleID, err)
	}

	if !rule.Enabled {
		s.logger.Debug("rule is disabled, skipping", "rule_id", ruleID)
		return nil
	}

	return s.checkRule(ctx, rule)
}

// checkRule evaluates a single rule and processes alerts if triggered.
func (s *Scheduler) checkRule(ctx context.Context, rule *AlertRule) error {
	s.logger.Debug("evaluating rule",
		"rule_id", rule.ID,
		"rule_name", rule.Name,
		"alert_type", rule.AlertType)

	// Evaluate the rule condition
	triggered, event, err := s.evaluator.EvaluateRule(ctx, rule)
	if err != nil {
		return fmt.Errorf("failed to evaluate rule %d: %w", rule.ID, err)
	}

	if !triggered {
		s.logger.Debug("rule condition not met",
			"rule_id", rule.ID,
			"rule_name", rule.Name)
		return nil
	}

	// Check throttle - don't send alert if we sent one recently
	if s.isThrottled(ctx, rule) {
		s.logger.Debug("alert throttled",
			"rule_id", rule.ID,
			"rule_name", rule.Name,
			"throttle_minutes", rule.ThrottleMinutes)
		return nil
	}

	// Process the triggered alert
	s.logger.Info("alert rule triggered",
		"rule_id", rule.ID,
		"rule_name", rule.Name,
		"alert_type", rule.AlertType)

	if s.processor != nil {
		if err := s.processor.ProcessAlert(ctx, event, rule); err != nil {
			return fmt.Errorf("failed to process alert for rule %d: %w", rule.ID, err)
		}
	}

	return nil
}

// getEnabledRules loads all enabled alert rules from the database.
func (s *Scheduler) getEnabledRules(ctx context.Context) ([]AlertRule, error) {
	rows, err := s.database.QueryContext(ctx,
		`SELECT id, name, alert_type, enabled, threshold_value, threshold_window_minutes, peer_id, throttle_minutes, created_at, updated_at
		FROM alert_rules WHERE enabled = 1 ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("failed to query enabled rules: %w", err)
	}
	defer func() {
		if cerr := rows.Close(); cerr != nil {
			log.ErrorContext(ctx, "Failed to close rows", "error", cerr)
		}
	}()

	var rules []AlertRule
	for rows.Next() {
		var rule AlertRule
		var peerID sql.NullInt64
		if err := rows.Scan(
			&rule.ID, &rule.Name, &rule.AlertType, &rule.Enabled,
			&rule.ThresholdValue, &rule.ThresholdWindowMinutes,
			&peerID, &rule.ThrottleMinutes,
			&rule.CreatedAt, &rule.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan rule: %w", err)
		}
		if peerID.Valid {
			peerIDInt := int(peerID.Int64)
			rule.PeerID = &peerIDInt
		}
		rules = append(rules, rule)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating rules: %w", err)
	}

	return rules, nil
}

// isThrottled checks if an alert for this rule was recently sent.
// Returns true if the alert should be throttled (skipped).
func (s *Scheduler) isThrottled(ctx context.Context, rule *AlertRule) bool {
	// If throttle is disabled (0 minutes), never throttle
	if rule.ThrottleMinutes <= 0 {
		return false
	}

	// Calculate the cutoff time for throttling
	cutoff := time.Now().Add(-rule.GetThrottleDuration())

	// Check for recent alerts for this rule
	var count int
	err := s.database.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM alert_history 
		WHERE rule_id = ? AND created_at > ? AND status IN (?, ?)`,
		rule.ID, cutoff.Format(time.RFC3339), AlertStatusSent, AlertStatusPending).
		Scan(&count)
	if err != nil {
		s.logger.Error("failed to check throttle status",
			"rule_id", rule.ID,
			"error", err)
		return false // On error, don't throttle
	}

	return count > 0
}
