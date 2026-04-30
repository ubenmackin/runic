package auth

import (
	"context"
	"errors"
	"sync"
	"time"

	"runic/internal/common/constants"
	"runic/internal/common/log"
)

// rateLimitEntry tracks failed login attempts and lockout state for a user.
type rateLimitEntry struct {
	failedAttempts int
	lockedUntil    time.Time
}

const (
	maxFailedAttempts = 5
	lockoutDuration   = 15 * time.Minute
)

// ErrAccountLocked is returned when a login is attempted on a locked account.
var ErrAccountLocked = errors.New("account locked, try again later")

var (
	rateLimitStore map[string]*rateLimitEntry
	rateLimitMutex  sync.Mutex
	stopCleanup     chan struct{}
	stopCleanupOnce sync.Once
)

func init() {
	rateLimitStore = make(map[string]*rateLimitEntry)
	stopCleanup = make(chan struct{})

	// Start periodic cleanup
	go func() {
		ticker := time.NewTicker(constants.AuthRateLimitCleanupInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				CleanupStaleEntries()
			case <-stopCleanup:
				return
			}
		}
	}()
}

// StopCleanup stops the periodic rate limit cleanup goroutine.
// Call during graceful shutdown.
func StopCleanup() {
	stopCleanupOnce.Do(func() {
		close(stopCleanup)
	})
}

// CheckAndRecordFailure records a failed login attempt and returns an error
// if the account is currently locked out.
func CheckAndRecordFailure(username string, remoteAddr string) error {
	rateLimitMutex.Lock()
	defer rateLimitMutex.Unlock()

	entry, exists := rateLimitStore[username]
	if !exists {
		entry = &rateLimitEntry{}
		rateLimitStore[username] = entry
	}

	if entry.lockedUntil.After(time.Now()) {
		return ErrAccountLocked
	}

	entry.failedAttempts++

	if entry.failedAttempts >= maxFailedAttempts {
		entry.lockedUntil = time.Now().Add(lockoutDuration)
		log.WarnContext(context.Background(), "account locked due to failed login attempts",
			"username", username, "remote_addr", remoteAddr, "duration", lockoutDuration, "failed_attempts", entry.failedAttempts)
	}

	return nil
}

// RecordSuccess clears the rate limit entry for a user on successful login.
func RecordSuccess(username string) {
	rateLimitMutex.Lock()
	defer rateLimitMutex.Unlock()

	delete(rateLimitStore, username)
}

// CleanupStaleEntries removes rate limit entries whose lockout has expired.
func CleanupStaleEntries() {
	rateLimitMutex.Lock()
	defer rateLimitMutex.Unlock()

	now := time.Now()
	for username, entry := range rateLimitStore {
		// Only remove entries with an expired lockout (non-zero lockedUntil that's past).
		// Entries with zero lockedUntil (no lockout) are kept.
		if !entry.lockedUntil.IsZero() && entry.lockedUntil.Before(now) {
			delete(rateLimitStore, username)
		}
	}
}

// ResetRateLimitStore clears the global rate limit store.
// This is intended for testing to ensure test isolation.
func ResetRateLimitStore() {
	rateLimitMutex.Lock()
	defer rateLimitMutex.Unlock()
	rateLimitStore = make(map[string]*rateLimitEntry)
}
