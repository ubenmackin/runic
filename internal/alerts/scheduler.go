// Package alerts provides a scheduler for periodic alert rule checks.
package alerts

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"runic/internal/common/log"
	"runic/internal/models"
	"runic/internal/store"
)

const DefaultCheckInterval = 1 * time.Minute

type Scheduler struct {
	alertStore *store.AlertStore
	evaluator  *ConditionEvaluator
	processor  *AlertProcessor
	interval   time.Duration
	logger     *slog.Logger
	stopOnce   sync.Once
	stopCh     chan struct{}
	running    bool
	runningMux sync.RWMutex
}

// NewScheduler creates a new alert scheduler. The scheduler will use the provided evaluator to check rule conditions
// and the processor to handle triggered alerts.
func NewScheduler(alertStore *store.AlertStore, evaluator *ConditionEvaluator, processor *AlertProcessor) *Scheduler {
	return &Scheduler{
		alertStore: alertStore,
		evaluator:  evaluator,
		processor:  processor,
		interval:   DefaultCheckInterval,
		logger:     log.L().With("component", "alert_scheduler"),
		stopCh:     make(chan struct{}),
	}
}

// WithInterval sets the check interval. Returns the scheduler for method chaining.
func (s *Scheduler) WithInterval(interval time.Duration) *Scheduler {
	if interval > 0 {
		s.interval = interval
	}
	return s
}

// Start starts the alert scheduler. It returns immediately; the scheduler runs in a background goroutine.
// The scheduler runs an immediate check on startup, then continues at the configured interval.
func (s *Scheduler) Start(ctx context.Context) {
	s.runningMux.Lock()
	if s.running {
		s.runningMux.Unlock()
		return
	}
	s.running = true
	s.runningMux.Unlock()

	s.logger.Info("starting alert scheduler, running initial check")
	s.CheckAllRules(ctx)

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

func (s *Scheduler) setRunning(running bool) {
	s.runningMux.Lock()
	defer s.runningMux.Unlock()
	s.running = running
}

func (s *Scheduler) IsRunning() bool {
	s.runningMux.RLock()
	defer s.runningMux.RUnlock()
	return s.running
}

// Stop stops the alert scheduler. It is safe to call Stop multiple times.
func (s *Scheduler) Stop() {
	s.stopOnce.Do(func() {
		close(s.stopCh)
	})
}

func (s *Scheduler) CheckAllRules(ctx context.Context) {
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

	for i := range rules {
		rule := &rules[i]

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

// CheckRule checks a specific alert rule by ID. Returns an error if the rule is not found or if evaluation fails.
func (s *Scheduler) CheckRule(ctx context.Context, ruleID uint64) error {
	rule, err := s.alertStore.GetAlertRule(ctx, ruleID)
	if err != nil {
		return fmt.Errorf("failed to get alert rule %d: %w", ruleID, err)
	}

	if !rule.Enabled {
		s.logger.Debug("rule is disabled, skipping", "rule_id", ruleID)
		return nil
	}

	return s.checkRule(ctx, rule)
}

func (s *Scheduler) checkRule(ctx context.Context, rule *models.AlertRule) error {
	s.logger.Debug("evaluating rule",
		"rule_id", rule.ID,
		"rule_name", rule.Name,
		"alert_type", rule.AlertType)

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

	if s.isThrottled(ctx, rule) {
		s.logger.Debug("alert throttled",
			"rule_id", rule.ID,
			"rule_name", rule.Name,
			"throttle_minutes", rule.ThrottleMinutes)
		return nil
	}

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

func (s *Scheduler) getEnabledRules(ctx context.Context) ([]models.AlertRule, error) {
	// Get all rules and filter by enabled
	allRules, err := s.alertStore.ListAlertRules(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list alert rules: %w", err)
	}

	var enabledRules []models.AlertRule
	for i := range allRules {
		rule := &allRules[i]
		if rule.Enabled {
			enabledRules = append(enabledRules, *rule)
		}
	}

	return enabledRules, nil
}

// Returns true if the alert should be throttled (skipped).
func (s *Scheduler) isThrottled(ctx context.Context, rule *models.AlertRule) bool {
	if rule.ThrottleMinutes <= 0 {
		return false
	}

	cutoff := time.Now().Add(-rule.GetThrottleDuration())

	throttled, err := s.alertStore.IsAlertThrottled(ctx, rule.ID, cutoff)
	if err != nil {
		s.logger.Warn("failed to check throttled status", "error", err)
		return false
	}

	return throttled
}
