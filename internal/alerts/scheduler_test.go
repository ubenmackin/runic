package alerts

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"runic/internal/db"
	"runic/internal/store"
	"runic/internal/testutil"
)

func setupSchedulerTestDB(t *testing.T) (*sql.DB, func()) {
	t.Helper()
	database, cleanup := testutil.SetupTestDB(t)
	return database, cleanup
}

func newTestScheduler(t *testing.T, database *sql.DB) *Scheduler {
	t.Helper()
	databaseWrapper := db.New(database)
	alertStore := store.NewAlertStore(databaseWrapper)
	userStore := store.NewUserStore(databaseWrapper)
	evaluator := NewConditionEvaluator(databaseWrapper, databaseWrapper, newTestHostnameLookup(database))
	processor := NewAlertProcessor(alertStore, userStore, nil)
	return NewScheduler(alertStore, evaluator, processor)
}

func TestScheduler_NewScheduler(t *testing.T) {
	database, cleanup := setupSchedulerTestDB(t)
	defer cleanup()

	s := newTestScheduler(t, database)
	if s == nil {
		t.Fatal("expected non-nil scheduler")
	}
	if s.IsRunning() {
		t.Error("expected scheduler to not be running initially")
	}
	if s.interval != DefaultCheckInterval {
		t.Errorf("expected default interval %v, got %v", DefaultCheckInterval, s.interval)
	}
}

func TestScheduler_WithInterval(t *testing.T) {
	database, cleanup := setupSchedulerTestDB(t)
	defer cleanup()

	s := newTestScheduler(t, database)

	// Valid interval
	result := s.WithInterval(5 * time.Second)
	if result != s {
		t.Error("expected WithInterval to return the same scheduler for method chaining")
	}
	if s.interval != 5*time.Second {
		t.Errorf("expected interval 5s, got %v", s.interval)
	}

	// Zero interval — should not change
	s.WithInterval(0)
	if s.interval != 5*time.Second {
		t.Errorf("expected interval to remain 5s with zero input, got %v", s.interval)
	}

	// Negative interval — should not change
	s.WithInterval(-1 * time.Minute)
	if s.interval != 5*time.Second {
		t.Errorf("expected interval to remain 5s with negative input, got %v", s.interval)
	}
}

func TestScheduler_StartAndStop(t *testing.T) {
	database, cleanup := setupSchedulerTestDB(t)
	defer cleanup()

	s := newTestScheduler(t, database)
	s.WithInterval(100 * time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	s.Start(ctx)

	// Give it a moment to run the initial check
	time.Sleep(50 * time.Millisecond)

	if !s.IsRunning() {
		t.Error("expected scheduler to be running after Start()")
	}

	s.Stop()

	// Give it a moment to stop
	time.Sleep(50 * time.Millisecond)

	if s.IsRunning() {
		t.Error("expected scheduler to not be running after Stop()")
	}
}

func TestScheduler_IdempotentStart(t *testing.T) {
	database, cleanup := setupSchedulerTestDB(t)
	defer cleanup()

	s := newTestScheduler(t, database)
	s.WithInterval(10 * time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	s.Start(ctx)
	// Second Start should be a no-op (doesn't panic or start twice)
	s.Start(ctx)

	if !s.IsRunning() {
		t.Error("expected scheduler to be running")
	}

	s.Stop()
}

func TestScheduler_IdempotentStop(t *testing.T) {
	database, cleanup := setupSchedulerTestDB(t)
	defer cleanup()

	s := newTestScheduler(t, database)
	s.WithInterval(10 * time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	s.Start(ctx)
	s.Stop()
	// Second Stop should be a no-op (doesn't panic or close channel twice)
	s.Stop()
}

func TestScheduler_StopWithoutStart(t *testing.T) {
	database, cleanup := setupSchedulerTestDB(t)
	defer cleanup()

	s := newTestScheduler(t, database)
	// Stop without start — should not panic
	s.Stop()
}

func TestScheduler_ContextCancellation(t *testing.T) {
	database, cleanup := setupSchedulerTestDB(t)
	defer cleanup()

	s := newTestScheduler(t, database)
	s.WithInterval(100 * time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())

	s.Start(ctx)

	if !s.IsRunning() {
		t.Error("expected scheduler to be running after Start()")
	}

	// Cancel context
	cancel()
	time.Sleep(100 * time.Millisecond)

	if s.IsRunning() {
		t.Error("expected scheduler to not be running after context cancellation")
	}
}

func TestScheduler_CheckAllRules_EmptyRules(t *testing.T) {
	database, cleanup := setupSchedulerTestDB(t)
	defer cleanup()

	s := newTestScheduler(t, database)
	ctx := context.Background()

	// No rules exist — should complete without error
	s.CheckAllRules(ctx)
}

func TestScheduler_CheckAllRules_DisabledRulesSkipped(t *testing.T) {
	database, cleanup := setupSchedulerTestDB(t)
	defer cleanup()
	ctx := context.Background()

	databaseWrapper := db.New(database)
	alertStore := store.NewAlertStore(databaseWrapper)

	// Create a disabled rule
	rule := &AlertRule{
		Name:            "Disabled Rule",
		AlertType:       AlertTypePeerOffline,
		Enabled:         false,
		ThrottleMinutes: 5,
	}
	if err := alertStore.CreateAlertRule(ctx, rule); err != nil {
		t.Fatalf("CreateAlertRule failed: %v", err)
	}

	s := newTestScheduler(t, database)
	s.CheckAllRules(ctx)

	// No alert history should be created for disabled rules
	var count int
	err := database.QueryRowContext(ctx, "SELECT COUNT(*) FROM alert_history").Scan(&count)
	if err != nil {
		t.Fatalf("count alert_history: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 alert_history entries for disabled rule, got %d", count)
	}
}

func TestScheduler_isThrottled_NoThrottle(t *testing.T) {
	database, cleanup := setupSchedulerTestDB(t)
	defer cleanup()
	ctx := context.Background()

	databaseWrapper := db.New(database)
	alertStore := store.NewAlertStore(databaseWrapper)

	// Rule with ThrottleMinutes=0 (no throttling)
	rule := &AlertRule{
		Name:            "No Throttle Rule",
		AlertType:       AlertTypePeerOffline,
		Enabled:         true,
		ThrottleMinutes: 0,
	}
	if err := alertStore.CreateAlertRule(ctx, rule); err != nil {
		t.Fatalf("CreateAlertRule failed: %v", err)
	}

	s := newTestScheduler(t, database)
	if s.isThrottled(ctx, rule) {
		t.Error("expected no throttling for rule with ThrottleMinutes=0")
	}
}
