// Package alerts provides alert and notification functionality.
package alerts

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"runic/internal/crypto"
	"runic/internal/db"

	"runic/internal/common/log"
)

// AlertProcessor handles the processing and sending of alert notifications.
// It implements the Processor interface defined in scheduler.go.
type AlertProcessor struct {
	database  *db.Database
	smtp      *SMTPSender
	logger    *slog.Logger
	stopChan  chan struct{}
	wg        sync.WaitGroup
	alertChan chan alertTask
}

type alertTask struct {
	event *AlertEvent
	rule  *AlertRule
}

// NewAlertProcessor creates a new alert processor.
func NewAlertProcessor(database *db.Database, smtp *SMTPSender) *AlertProcessor {
	return &AlertProcessor{
		database:  database,
		smtp:      smtp,
		logger:    log.L().With("component", "alert_processor"),
		stopChan:  make(chan struct{}),
		alertChan: make(chan alertTask, 100),
	}
}

// SetLogger sets a custom logger for the processor.
func (p *AlertProcessor) SetLogger(logger *slog.Logger) {
	p.logger = logger.With("component", "alert_processor")
}

// ProcessAlert implements the Processor interface.
// It processes a triggered alert event by creating a history entry and sending notification.
func (p *AlertProcessor) ProcessAlert(ctx context.Context, event *AlertEvent, rule *AlertRule) error {
	// Create alert history entry
	history := event.CreateAlertHistory(rule.ID)
	if err := CreateAlertHistory(ctx, p.database, &history); err != nil {
		p.logger.Error("failed to create alert history", "error", err)
		return fmt.Errorf("failed to create alert history: %w", err)
	}

	// Get user email for notification
	email, err := p.getAdminEmail(ctx)
	if err != nil {
		p.logger.Warn("failed to get admin email", "error", err)
		// Don't return error - we still want to track the alert
	} else if email != "" {
		// Send the alert email
		if p.smtp != nil && p.smtp.config.IsEnabled() {
			if err := p.smtp.SendAlertEmail(email, event); err != nil {
				p.logger.Error("failed to send alert email", "error", err)
				// Update history status to failed
				p.updateHistoryStatus(ctx, history.ID, AlertStatusFailed, err.Error())
				return fmt.Errorf("failed to send alert email: %w", err)
			}
			p.logger.Info("alert email sent", "email", email, "alert_type", event.Type)
		}
	}

	// Update history status to sent
	p.updateHistoryStatus(ctx, history.ID, AlertStatusSent, "")
	p.logger.Info("alert processed successfully", "alert_id", history.ID, "rule_id", rule.ID)

	return nil
}

// Start initializes the processor for receiving alerts.
func (p *AlertProcessor) Start(ctx context.Context) error {
	p.logger.Info("alert processor started")
	return nil
}

// Run starts the processor's main loop.
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

// Stop stops the processor.
func (p *AlertProcessor) Stop() {
	close(p.stopChan)
	p.wg.Wait()
	p.logger.Info("processor stopped")
}

// QueueAlert queues an alert for asynchronous processing.
func (p *AlertProcessor) QueueAlert(ctx context.Context, event *AlertEvent, rule *AlertRule) error {
	select {
	case p.alertChan <- alertTask{event: event, rule: rule}:
		p.logger.Debug("alert queued", "type", event.Type, "rule_id", rule.ID)
		return nil
	default:
		return fmt.Errorf("alert queue is full")
	}
}

// getAdminEmail retrieves the admin user's email for notifications.
func (p *AlertProcessor) getAdminEmail(ctx context.Context) (string, error) {
	var email string
	err := p.database.QueryRowContext(ctx,
		"SELECT email FROM users WHERE role = 'admin' LIMIT 1",
	).Scan(&email)
	if err != nil {
		return "", fmt.Errorf("failed to get admin email: %w", err)
	}
	return email, nil
}

// updateHistoryStatus updates the status of an alert history entry.
func (p *AlertProcessor) updateHistoryStatus(ctx context.Context, id uint, status AlertStatus, errMsg string) {
	var nullErr interface{}
	if errMsg != "" {
		nullErr = errMsg
	}

	_, err := p.database.ExecContext(ctx,
		"UPDATE alert_history SET status = ?, error_message = ?, sent_at = ? WHERE id = ?",
		status, nullErr, time.Now(), id,
	)
	if err != nil {
		p.logger.Error("failed to update alert history", "error", err)
	}
}

// Service is the main alert service coordinator that orchestrates all alert components.
// It provides a single entry point for the alert system and manages the lifecycle
// of evaluator, processor, scheduler, and digest generator.
type Service struct {
	mu sync.RWMutex

	// Core dependencies
	database  *db.Database
	encryptor *crypto.Encryptor
	logger    *slog.Logger

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

// NewService creates a new alert service with the given database connection.
// The service is created but not initialized - call Initialize() to set up components.
func NewService(database *db.Database) *Service {
	ctx, cancel := context.WithCancel(context.Background())

	return &Service{
		database: database,
		logger:   log.L().With("component", "alert_service"),
		ctx:      ctx,
		cancel:   cancel,
	}
}

// SetEncryptor sets the encryptor for the service.
// This must be called before Initialize() if encryption is needed.
func (s *Service) SetEncryptor(encryptor *crypto.Encryptor) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.encryptor = encryptor
}

// SetLogger sets a custom logger for the service and all sub-components.
func (s *Service) SetLogger(logger *slog.Logger) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.logger = logger.With("component", "alert_service")
}

// Initialize sets up all alert components.
// This must be called before Start().
// Components are initialized in dependency order:
//  1. SMTPSender (no dependencies)
//  2. ConditionEvaluator (depends on DB)
//  3. AlertProcessor (depends on DB, SMTPSender)
//  4. Scheduler (depends on DB, Evaluator, Processor)
//  5. DigestGenerator (depends on DB, SMTPSender)
func (s *Service) Initialize() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.initialized {
		return fmt.Errorf("alert service already initialized")
	}

	s.logger.Info("initializing alert service")

	// 1. Initialize SMTP sender
	smtpConfig, err := s.loadSMTPConfig(s.ctx)
	if err != nil {
		s.logger.Warn("failed to load SMTP config, alerts will be disabled", "error", err)
		// Create a disabled SMTP sender
		disabledConfig := SMTPConfig{Enabled: false}
		s.smtpSender = NewSMTPSender(&disabledConfig, s.encryptor)
	} else {
		s.smtpSender = NewSMTPSender(smtpConfig, s.encryptor)
		s.logger.Info("SMTP sender initialized",
			"host", smtpConfig.Host,
			"port", smtpConfig.Port,
			"enabled", smtpConfig.IsEnabled(),
		)
	}

	// 2. Initialize ConditionEvaluator
	s.evaluator = NewConditionEvaluator(s.database)
	s.logger.Debug("evaluator initialized")

	// 3. Initialize AlertProcessor
	s.processor = NewAlertProcessor(s.database, s.smtpSender)
	s.processor.SetLogger(s.logger)
	s.logger.Debug("processor initialized")

	// 4. Initialize Scheduler
	s.scheduler = NewScheduler(s.database, s.evaluator, s.processor)
	s.logger.Debug("scheduler initialized")

	// 5. Initialize DigestGenerator
	s.digestGenerator = NewDigestGenerator(s.database, s.smtpSender, s.encryptor)
	s.digestGenerator.SetLogger(s.logger)
	s.logger.Debug("digest generator initialized")

	s.initialized = true
	s.logger.Info("alert service initialized successfully")

	return nil
}

// Start begins the alert service operation.
// This starts the scheduler for periodic checks and the processor for sending alerts.
// Start returns immediately; components run in background goroutines.
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

	// Start the scheduler for periodic alert evaluation
	scheduler.Start(ctx)
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-ctx.Done()
		scheduler.Stop()
	}()

	// Start the processor for sending pending alerts
	if err := processor.Start(ctx); err != nil {
		s.cancel()
		return fmt.Errorf("failed to start processor: %w", err)
	}

	// processor.Run() spawns its own goroutine and returns immediately.
	// Call it synchronously to ensure wg.Add(1) inside Run() completes
	// before we release the lock, avoiding race with Stop().
	processor.Run()

	// Start the digest generator for scheduled digests
	// digestGenerator.RunDaily() spawns its own goroutine and returns immediately.
	// Call it synchronously to ensure wg.Add(1) inside RunDaily() completes
	// before we release the lock, avoiding race with Stop().
	digestGenerator.RunDaily()

	s.started = true
	s.logger.Info("alert service started successfully")

	return nil
}

// Stop gracefully shuts down the alert service.
// It stops all components and waits for them to finish.
func (s *Service) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.started {
		return nil
	}

	s.logger.Info("stopping alert service")

	// Cancel context to signal all components to stop
	s.cancel()

	// Stop each component explicitly
	if s.scheduler != nil {
		s.scheduler.Stop()
	}
	if s.processor != nil {
		s.processor.Stop()
	}
	if s.digestGenerator != nil {
		s.digestGenerator.Stop()
	}

	// Wait for all goroutines to finish
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	// Wait with timeout
	select {
	case <-done:
		s.logger.Info("alert service stopped successfully")
	case <-time.After(30 * time.Second):
		s.logger.Warn("alert service stop timeout, some components may not have shut down cleanly")
	}

	s.started = false
	return nil
}

// GetEvaluator returns the alert evaluator.
// Returns nil if the service hasn't been initialized.
func (s *Service) GetEvaluator() *ConditionEvaluator {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.evaluator
}

// GetProcessor returns the alert processor.
// Returns nil if the service hasn't been initialized.
func (s *Service) GetProcessor() *AlertProcessor {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.processor
}

// GetScheduler returns the alert scheduler.
// Returns nil if the service hasn't been initialized.
func (s *Service) GetScheduler() *Scheduler {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.scheduler
}

// GetDigestGenerator returns the digest generator.
// Returns nil if the service hasn't been initialized.
func (s *Service) GetDigestGenerator() *DigestGenerator {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.digestGenerator
}

// GetSMTPSender returns the SMTP sender.
// Returns nil if the service hasn't been initialized.
func (s *Service) GetSMTPSender() *SMTPSender {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.smtpSender
}

// IsStarted returns true if the service is currently running.
func (s *Service) IsStarted() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.started
}

// IsInitialized returns true if the service has been initialized.
func (s *Service) IsInitialized() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.initialized
}

// loadSMTPConfig loads SMTP configuration from the database.
func (s *Service) loadSMTPConfig(ctx context.Context) (*SMTPConfig, error) {
	// Try to get SMTP config from system_config table
	var host, username, password, fromAddress string
	var port int
	var useTLS, enabled bool

	// Check if SMTP is enabled
	err := s.database.QueryRowContext(ctx,
		`SELECT value FROM system_config WHERE key = 'smtp_enabled'`,
	).Scan(&enabled)
	if err != nil {
		// SMTP not configured
		return &SMTPConfig{Enabled: false}, nil
	}

	// Load other SMTP settings
	err = s.database.QueryRowContext(ctx,
		`SELECT value FROM system_config WHERE key = 'smtp_host'`,
	).Scan(&host)
	if err != nil {
		return nil, fmt.Errorf("failed to load SMTP host: %w", err)
	}

	err = s.database.QueryRowContext(ctx,
		`SELECT value FROM system_config WHERE key = 'smtp_port'`,
	).Scan(&port)
	if err != nil {
		// Try as string and convert
		var portStr string
		if err = s.database.QueryRowContext(ctx,
			`SELECT value FROM system_config WHERE key = 'smtp_port'`,
		).Scan(&portStr); err != nil {
			return nil, fmt.Errorf("failed to load SMTP port: %w", err)
		}
		// Parse port string (simple conversion)
		port = 587 // default
		if portStr != "" {
			if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
				s.logger.Warn("failed to parse SMTP port", "value", portStr, "error", err)
				port = 587 // default on parse error
			}
		}
	}

	// Load optional SMTP settings (username, password, useTLS)
	if err := s.database.QueryRowContext(ctx,
		`SELECT value FROM system_config WHERE key = 'smtp_username'`,
	).Scan(&username); err != nil && err != sql.ErrNoRows {
		s.logger.Warn("failed to load SMTP username", "error", err)
	}

	if err := s.database.QueryRowContext(ctx,
		`SELECT value FROM system_config WHERE key = 'smtp_password'`,
	).Scan(&password); err != nil && err != sql.ErrNoRows {
		s.logger.Warn("failed to load SMTP password", "error", err)
	}

	if err := s.database.QueryRowContext(ctx,
		`SELECT value FROM system_config WHERE key = 'smtp_use_tls'`,
	).Scan(&useTLS); err != nil && err != sql.ErrNoRows {
		s.logger.Warn("failed to load SMTP use_tls", "error", err)
	}

	config := &SMTPConfig{
		Host:        host,
		Port:        port,
		Username:    username,
		Password:    password, // Will be decrypted by SMTPSender
		UseTLS:      useTLS,
		FromAddress: fromAddress,
		Enabled:     enabled,
	}

	return config, nil
}

// TriggerAlert allows manual triggering of an alert evaluation.
// This is useful for immediate alerts outside the scheduled checks.
// It evaluates the event against matching rules and processes it if triggered.
func (s *Service) TriggerAlert(ctx context.Context, event *AlertEvent) error {
	s.mu.RLock()
	evaluator := s.evaluator
	processor := s.processor
	s.mu.RUnlock()

	if evaluator == nil {
		return fmt.Errorf("alert service not initialized")
	}

	// Get enabled rules for this alert type
	rules, err := GetEnabledAlertRulesByType(ctx, s.database, event.Type)
	if err != nil {
		return fmt.Errorf("failed to get alert rules: %w", err)
	}

	// Find matching rules and process
	for i := range rules {
		rule := &rules[i]

		// Check if rule applies to this peer
		if event.PeerID > 0 && !rule.AppliesToPeer(event.PeerID) {
			continue
		}

		// Process the alert using the processor
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

// CheckRuleNow triggers an immediate check of a specific alert rule.
// This is useful for testing rules or forcing a re-evaluation.
func (s *Service) CheckRuleNow(ctx context.Context, ruleID uint) error {
	s.mu.RLock()
	scheduler := s.scheduler
	s.mu.RUnlock()

	if scheduler == nil {
		return fmt.Errorf("alert service not initialized")
	}

	return scheduler.CheckRule(ctx, ruleID)
}

// CheckAllRulesNow triggers an immediate check of all enabled alert rules.
func (s *Service) CheckAllRulesNow(ctx context.Context) {
	s.mu.RLock()
	scheduler := s.scheduler
	s.mu.RUnlock()

	if scheduler != nil {
		scheduler.CheckAllRules(ctx)
	}
}
