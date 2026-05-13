// Package alerts provides alert and notification functionality.
package alerts

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"runic/internal/crypto"
	"runic/internal/db"
	"runic/internal/store"

	"runic/internal/common/log"
)

// AlertProcessor implements the Processor interface defined in scheduler.go.
type AlertProcessor struct {
	alertStore *store.AlertStore
	userStore  *store.UserStore
	smtp       *SMTPSender
	logger     *slog.Logger
	stopChan   chan struct{}
	stopOnce   sync.Once
	wg         sync.WaitGroup
	alertChan  chan alertTask
}

type alertTask struct {
	event *AlertEvent
	rule  *AlertRule
}

func NewAlertProcessor(alertStore *store.AlertStore, userStore *store.UserStore, smtp *SMTPSender) *AlertProcessor {
	return &AlertProcessor{
		alertStore: alertStore,
		userStore:  userStore,
		smtp:       smtp,
		logger:     log.L().With("component", "alert_processor"),
		stopChan:   make(chan struct{}),
		alertChan:  make(chan alertTask, 100),
	}
}

func (p *AlertProcessor) SetLogger(logger *slog.Logger) {
	p.logger = logger.With("component", "alert_processor")
}

// ProcessAlert processes a triggered alert event by creating a history entry and sending notification.
func (p *AlertProcessor) ProcessAlert(ctx context.Context, event *AlertEvent, rule *AlertRule) error {
	history := event.CreateAlertHistory(rule.ID)
	if err := p.alertStore.CreateAlertHistory(ctx, &history); err != nil {
		p.logger.Error("failed to create alert history", "error", err)
		return fmt.Errorf("failed to create alert history: %w", err)
	}

	email, err := p.getAdminEmail(ctx)
	if err != nil {
		p.logger.Warn("failed to get admin email", "error", err)
		// Don't return error - we still want to track the alert
	} else if email != "" {
		if p.smtp != nil && p.smtp.config.IsEnabled() {
			if err := p.smtp.SendAlertEmail(email, event); err != nil {
				p.logger.Error("failed to send alert email", "error", err)
				p.updateHistoryStatus(ctx, history.ID, AlertStatusFailed, err.Error())
				return fmt.Errorf("failed to send alert email: %w", err)
			}
			p.logger.Info("alert email sent", "email", email, "alert_type", event.Type)
		}
	}

	p.updateHistoryStatus(ctx, history.ID, AlertStatusSent, "")
	p.logger.Info("alert processed successfully", "alert_id", history.ID, "rule_id", rule.ID)

	return nil
}

func (p *AlertProcessor) Start(ctx context.Context) error {
	p.logger.Info("alert processor started")
	return nil
}

func (p *AlertProcessor) Run() {
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		p.logger.Info("processor run loop started")

		for {
			select {
			case <-p.stopChan:
				p.logger.Info("processor stopping")
				return
			case task := <-p.alertChan:
				if err := p.ProcessAlert(context.Background(), task.event, task.rule); err != nil {
					p.logger.Error("failed to process alert", "error", err, "rule_id", task.rule.ID)
				}
			}
		}
	}()
}

func (p *AlertProcessor) Stop() {
	p.stopOnce.Do(func() {
		close(p.stopChan)
	})
	p.wg.Wait()
	p.logger.Info("processor stopped")
}

func (p *AlertProcessor) QueueAlert(ctx context.Context, event *AlertEvent, rule *AlertRule) error {
	select {
	case p.alertChan <- alertTask{event: event, rule: rule}:
		p.logger.Debug("alert queued", "type", event.Type, "rule_id", rule.ID)
		return nil
	default:
		return fmt.Errorf("alert queue is full")
	}
}

func (p *AlertProcessor) getAdminEmail(ctx context.Context) (string, error) {
	if p.userStore == nil {
		return "", fmt.Errorf("user store not configured")
	}

	users, _, err := p.userStore.ListUsers(ctx, 1, 99999)
	if err != nil {
		return "", fmt.Errorf("failed to list users: %w", err)
	}

	for _, user := range users {
		if user.Role == "admin" && user.Email != "" {
			return user.Email, nil
		}
	}

	return "", fmt.Errorf("no admin user with email found")
}

func (p *AlertProcessor) updateHistoryStatus(ctx context.Context, id uint, status AlertStatus, errMsg string) {
	err := p.alertStore.UpdateAlertHistoryStatus(ctx, uint64(id), status, errMsg)
	if err != nil {
		p.logger.Error("failed to update alert history", "error", err)
	}
}

// Service provides a single entry point for the alert system. It provides a single entry point for the alert system and manages the lifecycle
// of evaluator, processor, scheduler, and digest generator.
type Service struct {
	mu sync.RWMutex

	// Core dependencies
	database  *db.Database
	logsDB    db.Querier
	encryptor *crypto.Encryptor
	logger    *slog.Logger

	// Store dependencies
	alertStore *store.AlertStore
	userStore  *store.UserStore

	// Injected lookups
	hostnameLookup PeerHostnameLookup

	// Alert components
	evaluator       *ConditionEvaluator
	processor       *AlertProcessor
	scheduler       *Scheduler
	digestGenerator *DigestGenerator

	// Email sender
	smtpSender *SMTPSender

	// Lifecycle management
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// Initialization state
	initialized bool
	started     bool
}

// NewService creates a new alert service. The service is created but not initialized - call Initialize() to set up components.
func NewService(database *db.Database, alertStore *store.AlertStore, userStore *store.UserStore) *Service {
	ctx, cancel := context.WithCancel(context.Background())

	return &Service{
		database:   database,
		alertStore: alertStore,
		userStore:  userStore,
		logger:     log.L().With("component", "alert_service"),
		ctx:        ctx,
		cancel:     cancel,
	}
}

// SetEncryptor sets the encryptor for the alert service. This must be called before Initialize() if encryption is needed.
func (s *Service) SetEncryptor(encryptor *crypto.Encryptor) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.encryptor = encryptor
}

// SetLogsDB sets the logs database for the alert service. This must be called before Initialize() if firewall_logs queries are needed.
func (s *Service) SetLogsDB(logsDB db.Querier) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.logsDB = logsDB
}

// SetHostnameLookup sets the hostname lookup function for resolving peer IDs to hostnames.
// This must be called before Initialize() so the lookup is available to the evaluator.
func (s *Service) SetHostnameLookup(lookup PeerHostnameLookup) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hostnameLookup = lookup
}

func (s *Service) SetLogger(logger *slog.Logger) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.logger = logger.With("component", "alert_service")
}

// Initialize initializes the alert service. This must be called before Start().
// Components are initialized in dependency order:
//  1. SMTPSender (no dependencies)
//  2. ConditionEvaluator (depends on DB)
//  3. AlertProcessor (depends on AlertStore, UserStore, SMTPSender)
//  4. Scheduler (depends on AlertStore, Evaluator, Processor)
//  5. DigestGenerator (depends on AlertStore, SMTPSender)
func (s *Service) Initialize() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.initialized {
		return fmt.Errorf("alert service already initialized")
	}

	s.logger.Info("initializing alert service")

	smtpConfig, err := s.loadSMTPConfig(s.ctx)
	if err != nil {
		s.logger.Warn("failed to load SMTP config, alerts will be disabled", "error", err)
		disabledConfig := SMTPConfig{Enabled: false}
		s.smtpSender = NewSMTPSender(&disabledConfig, s.encryptor, s.database)
	} else {
		s.smtpSender = NewSMTPSender(smtpConfig, s.encryptor, s.database)
		s.logger.Info("SMTP sender initialized",
			"host", smtpConfig.Host,
			"port", smtpConfig.Port,
			"enabled", smtpConfig.IsEnabled(),
		)
	}

	if s.logsDB == nil {
		s.logsDB = s.database
	}
	s.evaluator = NewConditionEvaluator(s.database, s.logsDB, s.hostnameLookup)
	s.logger.Debug("evaluator initialized")

	s.processor = NewAlertProcessor(s.alertStore, s.userStore, s.smtpSender)
	s.processor.SetLogger(s.logger)
	s.logger.Debug("processor initialized")

	s.scheduler = NewScheduler(s.alertStore, s.evaluator, s.processor)
	s.logger.Debug("scheduler initialized")

	s.digestGenerator = NewDigestGenerator(s.alertStore, s.smtpSender, s.encryptor)
	s.digestGenerator.SetDatabase(s.database)
	s.digestGenerator.SetLogger(s.logger)
	s.logger.Debug("digest generator initialized")

	s.initialized = true
	s.logger.Info("alert service initialized successfully")

	return nil
}

// Start starts the alert service. This starts the scheduler for periodic checks and the processor for sending alerts.
func (s *Service) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.initialized {
		return fmt.Errorf("alert service not initialized - call Initialize() first")
	}

	if s.started {
		return fmt.Errorf("alert service already started")
	}

	s.logger.Info("starting alert service")

	// Capture all variables needed by goroutines before spawning them
	// to avoid race condition when Stop() is called concurrently
	scheduler := s.scheduler
	processor := s.processor
	digestGenerator := s.digestGenerator
	ctx := s.ctx
	wg := &s.wg

	scheduler.Start(ctx)
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-ctx.Done()
		scheduler.Stop()
	}()

	if err := processor.Start(ctx); err != nil {
		s.cancel()
		return fmt.Errorf("failed to start processor: %w", err)
	}

	// processor.Run() spawns its own goroutine and returns immediately.
	// Call it synchronously to ensure wg.Add(1) inside Run() completes
	// before we release the lock, avoiding race with Stop().
	processor.Run()

	// digestGenerator.RunDaily() spawns its own goroutine and returns immediately.
	// Call it synchronously to ensure wg.Add(1) inside RunDaily() completes
	// before we release the lock, avoiding race with Stop().
	digestGenerator.RunDaily()

	s.started = true
	s.logger.Info("alert service started successfully")

	return nil
}

// Stop stops the alert service. It stops all components and waits for them to finish.
func (s *Service) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.started {
		return nil
	}

	s.logger.Info("stopping alert service")

	s.cancel()

	if s.scheduler != nil {
		s.scheduler.Stop()
	}
	if s.processor != nil {
		s.processor.Stop()
	}
	if s.digestGenerator != nil {
		s.digestGenerator.Stop()
	}

	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		s.logger.Info("alert service stopped successfully")
	case <-time.After(30 * time.Second):
		s.logger.Warn("alert service stop timeout, some components may not have shut down cleanly")
	}

	s.started = false
	return nil
}

// GetEvaluator returns the condition evaluator. Returns nil if the service hasn't been initialized.
func (s *Service) GetEvaluator() *ConditionEvaluator {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.evaluator
}

// GetProcessor returns the alert processor. Returns nil if the service hasn't been initialized.
func (s *Service) GetProcessor() *AlertProcessor {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.processor
}

// GetScheduler returns the alert scheduler. Returns nil if the service hasn't been initialized.
func (s *Service) GetScheduler() *Scheduler {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.scheduler
}

// GetDigestGenerator returns the digest generator. Returns nil if the service hasn't been initialized.
func (s *Service) GetDigestGenerator() *DigestGenerator {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.digestGenerator
}

// GetSMTPSender returns the SMTP sender. Returns nil if the service hasn't been initialized.
func (s *Service) GetSMTPSender() *SMTPSender {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.smtpSender
}

func (s *Service) IsStarted() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.started
}

func (s *Service) IsInitialized() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.initialized
}

func (s *Service) loadSMTPConfig(ctx context.Context) (*SMTPConfig, error) {
	if s.alertStore == nil {
		return &SMTPConfig{Enabled: false}, fmt.Errorf("alert store not configured")
	}

	smtpConfigView, err := s.alertStore.GetSMTPConfig(ctx)
	if err != nil {
		return &SMTPConfig{Enabled: false}, fmt.Errorf("failed to load SMTP config: %w", err)
	}

	config := &SMTPConfig{
		Host:        smtpConfigView.Host,
		Port:        smtpConfigView.Port,
		Username:    smtpConfigView.Username,
		Password:    smtpConfigView.Password, // encrypted; SMTPSender handles decryption
		UseTLS:      smtpConfigView.UseTLS,
		FromAddress: smtpConfigView.FromAddress,
		Enabled:     smtpConfigView.Enabled,
	}

	return config, nil
}

// TriggerAlert triggers an immediate alert for the given event. This is useful for immediate alerts outside the scheduled checks.
// It evaluates the event against matching rules and processes it if triggered.
func (s *Service) TriggerAlert(ctx context.Context, event *AlertEvent) error {
	s.mu.RLock()
	evaluator := s.evaluator
	processor := s.processor
	alertStore := s.alertStore
	s.mu.RUnlock()

	if evaluator == nil {
		return fmt.Errorf("alert service not initialized")
	}

	rules, err := alertStore.GetEnabledAlertRulesByType(ctx, event.Type)
	if err != nil {
		return fmt.Errorf("failed to get alert rules: %w", err)
	}

	for i := range rules {
		rule := &rules[i]

		if event.PeerID > 0 && !rule.AppliesToPeer(event.PeerID) {
			continue
		}

		if processor != nil {
			if err := processor.ProcessAlert(ctx, event, rule); err != nil {
				return fmt.Errorf("failed to process alert: %w", err)
			}
		}

		// Only process with first matching rule
		return nil
	}

	return nil
}

// CheckRuleNow checks a specific rule immediately. This is useful for testing rules or forcing a re-evaluation.
func (s *Service) CheckRuleNow(ctx context.Context, ruleID uint64) error {
	s.mu.RLock()
	scheduler := s.scheduler
	s.mu.RUnlock()

	if scheduler == nil {
		return fmt.Errorf("alert service not initialized")
	}

	return scheduler.CheckRule(ctx, ruleID)
}

func (s *Service) CheckAllRulesNow(ctx context.Context) {
	s.mu.RLock()
	scheduler := s.scheduler
	s.mu.RUnlock()

	if scheduler != nil {
		scheduler.CheckAllRules(ctx)
	}
}
