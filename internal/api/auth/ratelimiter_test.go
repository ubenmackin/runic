package auth

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestCheckAndRecordFailure_NoLockout(t *testing.T) {
	ResetRateLimitStore()

	username := "testuser_no_lockout"
	remoteAddr := "127.0.0.1"

	// Record 4 failures (below maxFailedAttempts=5), should all return nil
	for i := 0; i < 4; i++ {
		err := CheckAndRecordFailure(username, remoteAddr)
		if err != nil {
			t.Fatalf("iteration %d: expected nil error, got %v", i+1, err)
		}
	}

	// Verify entry exists with 4 failed attempts
	rateLimitMutex.Lock()
	entry, exists := rateLimitStore[username]
	rateLimitMutex.Unlock()

	if !exists {
		t.Fatal("expected rate limit entry to exist")
	}
	if entry.failedAttempts != 4 {
		t.Errorf("expected 4 failed attempts, got %d", entry.failedAttempts)
	}
	if !entry.lockedUntil.IsZero() {
		t.Errorf("expected lockedUntil to be zero, got %v", entry.lockedUntil)
	}
}

func TestCheckAndRecordFailure_TriggersLockout(t *testing.T) {
	ResetRateLimitStore()

	username := "testuser_triggers_lockout"
	remoteAddr := "127.0.0.1"

	// Record 5 failures, 5th should still return nil but set lockout
	for i := 0; i < 5; i++ {
		err := CheckAndRecordFailure(username, remoteAddr)
		if err != nil {
			t.Fatalf("iteration %d: expected nil error, got %v", i+1, err)
		}
	}

	// Verify entry exists with lockout set
	rateLimitMutex.Lock()
	entry, exists := rateLimitStore[username]
	rateLimitMutex.Unlock()

	if !exists {
		t.Fatal("expected rate limit entry to exist")
	}
	if entry.failedAttempts != 5 {
		t.Errorf("expected 5 failed attempts, got %d", entry.failedAttempts)
	}
	if entry.lockedUntil.IsZero() {
		t.Error("expected lockedUntil to be set")
	}
	if !entry.lockedUntil.After(time.Now()) {
		t.Error("expected lockedUntil to be in the future")
	}
}

func TestCheckAndRecordFailure_LockedOut(t *testing.T) {
	ResetRateLimitStore()

	username := "testuser_locked_out"
	remoteAddr := "127.0.0.1"

	// Record 5 failures to trigger lockout
	for i := 0; i < 5; i++ {
		_ = CheckAndRecordFailure(username, remoteAddr)
	}

	// 6th attempt should return error
	err := CheckAndRecordFailure(username, remoteAddr)
	if err == nil {
		t.Fatal("expected error for locked account, got nil")
	}
	if !errors.Is(err, ErrAccountLocked) {
		t.Errorf("expected ErrAccountLocked, got %v", err)
	}

	// Verify failedAttempts stays at 5 (no increment while locked)
	rateLimitMutex.Lock()
	entry := rateLimitStore[username]
	rateLimitMutex.Unlock()

	if entry.failedAttempts != 5 {
		t.Errorf("expected failedAttempts to stay at 5, got %d", entry.failedAttempts)
	}
}

func TestRecordSuccess_ClearsEntry(t *testing.T) {
	ResetRateLimitStore()

	username := "testuser_record_success"
	remoteAddr := "127.0.0.1"

	// Record 3 failures (below lockout threshold)
	for i := 0; i < 3; i++ {
		_ = CheckAndRecordFailure(username, remoteAddr)
	}

	// Verify entry exists
	rateLimitMutex.Lock()
	if _, exists := rateLimitStore[username]; !exists {
		t.Fatal("expected rate limit entry to exist")
	}
	rateLimitMutex.Unlock()

	// Record success should clear entry
	RecordSuccess(username)

	// Verify entry is removed
	rateLimitMutex.Lock()
	if _, exists := rateLimitStore[username]; exists {
		t.Error("expected rate limit entry to be removed after RecordSuccess")
	}
	rateLimitMutex.Unlock()

	// Should be able to login again without lockout
	err := CheckAndRecordFailure(username, remoteAddr)
	if err != nil {
		t.Errorf("expected nil error after clearing entry, got %v", err)
	}
}

func TestCleanupStaleEntries(t *testing.T) {
	ResetRateLimitStore()

	// Create entries with past lockedUntil
	rateLimitMutex.Lock()
	rateLimitStore["past_user1"] = &rateLimitEntry{
		failedAttempts: 5,
		lockedUntil:    time.Now().Add(-1 * time.Hour), // expired 1 hour ago
	}
	rateLimitStore["past_user2"] = &rateLimitEntry{
		failedAttempts: 5,
		lockedUntil:    time.Now().Add(-30 * time.Minute), // expired 30 minutes ago
	}
	rateLimitStore["active_user"] = &rateLimitEntry{
		failedAttempts: 3,
		lockedUntil:    time.Time{}, // zero time (no lockout)
	}
	rateLimitMutex.Unlock()

	CleanupStaleEntries()

	// Verify expired entries are removed
	rateLimitMutex.Lock()
	if _, exists := rateLimitStore["past_user1"]; exists {
		t.Error("expected past_user1 to be cleaned up")
	}
	if _, exists := rateLimitStore["past_user2"]; exists {
		t.Error("expected past_user2 to be cleaned up")
	}
	if _, exists := rateLimitStore["active_user"]; !exists {
		t.Error("expected active_user to remain (zero lockedUntil)")
	}
	rateLimitMutex.Unlock()
}

func TestCleanupStaleEntries_KeepsActiveLocks(t *testing.T) {
	ResetRateLimitStore()

	// Create entries with future lockedUntil
	rateLimitMutex.Lock()
	rateLimitStore["future_user1"] = &rateLimitEntry{
		failedAttempts: 5,
		lockedUntil:    time.Now().Add(1 * time.Hour), // locked for 1 hour
	}
	rateLimitStore["future_user2"] = &rateLimitEntry{
		failedAttempts: 5,
		lockedUntil:    time.Now().Add(10 * time.Minute), // locked for 10 minutes
	}
	rateLimitStore["zero_user"] = &rateLimitEntry{
		failedAttempts: 2,
		lockedUntil:    time.Time{}, // zero time (no lockout)
	}
	rateLimitMutex.Unlock()

	CleanupStaleEntries()

	// Verify active locks remain
	rateLimitMutex.Lock()
	if _, exists := rateLimitStore["future_user1"]; !exists {
		t.Error("expected future_user1 to remain (future lockout)")
	}
	if _, exists := rateLimitStore["future_user2"]; !exists {
		t.Error("expected future_user2 to remain (future lockout)")
	}
	if _, exists := rateLimitStore["zero_user"]; !exists {
		t.Error("expected zero_user to remain (zero lockedUntil)")
	}
	rateLimitMutex.Unlock()
}

func TestConcurrentAccess(t *testing.T) {
	ResetRateLimitStore()

	const goroutines = 100
	const username = "concurrent_user"
	remoteAddr := "127.0.0.1"

	var wg sync.WaitGroup
	wg.Add(goroutines)

	// Concurrently record failures
	for i := 0; i < goroutines; i++ {
		go func(iteration int) {
			defer wg.Done()
			_ = CheckAndRecordFailure(username, remoteAddr)
		}(i)
	}
	wg.Wait()

	// Verify that the entry exists and failedAttempts is reasonable
	// (between 5 and goroutines, but at least 5 due to lockout)
	rateLimitMutex.Lock()
	entry, exists := rateLimitStore[username]
	rateLimitMutex.Unlock()

	if !exists {
		t.Fatal("expected rate limit entry to exist after concurrent access")
	}
	if entry.failedAttempts < 5 {
		t.Errorf("expected at least 5 failed attempts, got %d", entry.failedAttempts)
	}
	if entry.lockedUntil.IsZero() {
		t.Error("expected lockout to be set after concurrent failures")
	}

	// Test concurrent cleanup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			CleanupStaleEntries()
		}()
	}
	wg.Wait()

	// Test concurrent RecordSuccess
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			RecordSuccess(username)
		}()
	}
	wg.Wait()

	// Verify entry is removed (at least one goroutine succeeded)
	rateLimitMutex.Lock()
	if _, exists := rateLimitStore[username]; exists {
		t.Error("expected entry to be removed after concurrent RecordSuccess")
	}
	rateLimitMutex.Unlock()
}

func TestCheckAndRecordFailure_DifferentUsers(t *testing.T) {
	ResetRateLimitStore()

	remoteAddr := "127.0.0.1"

	// User A gets 5 failures (lockout)
	for i := 0; i < 5; i++ {
		CheckAndRecordFailure("userA", remoteAddr)
	}

	// User B should still be able to login (different user)
	err := CheckAndRecordFailure("userB", remoteAddr)
	if err != nil {
		t.Errorf("expected nil error for different user, got %v", err)
	}

	// Verify userA is locked, userB is not
	rateLimitMutex.Lock()
	userA := rateLimitStore["userA"]
	userB := rateLimitStore["userB"]
	rateLimitMutex.Unlock()

	if userA.lockedUntil.IsZero() {
		t.Error("expected userA to be locked")
	}
	if !userB.lockedUntil.IsZero() {
		t.Error("expected userB to not be locked")
	}
}

func TestCheckAndRecordFailure_LockoutDuration(t *testing.T) {
	ResetRateLimitStore()

	username := "testuser_duration"
	remoteAddr := "127.0.0.1"

	before := time.Now()
	// Record 5 failures to trigger lockout
	for i := 0; i < 5; i++ {
		CheckAndRecordFailure(username, remoteAddr)
	}
	after := time.Now()

	rateLimitMutex.Lock()
	entry := rateLimitStore[username]
	lockedUntil := entry.lockedUntil
	rateLimitMutex.Unlock()

	// lockedUntil should be approximately lockoutDuration from now
	expectedMin := before.Add(lockoutDuration)
	expectedMax := after.Add(lockoutDuration)

	if lockedUntil.Before(expectedMin) || lockedUntil.After(expectedMax) {
		t.Errorf("lockedUntil %v not within expected range [%v, %v]",
			lockedUntil, expectedMin, expectedMax)
	}
}

func TestMain(m *testing.M) {
	// Run tests
	m.Run()
}

// Helper to print test coverage info
func TestCoverageHelper(t *testing.T) {
	fmt.Println("Rate limiter test coverage:")
	fmt.Println("- CheckAndRecordFailure: no lockout, triggers lockout, locked out")
	fmt.Println("- RecordSuccess: clears entry")
	fmt.Println("- CleanupStaleEntries: removes expired, keeps active")
	fmt.Println("- Concurrent access: thread safety")
}
