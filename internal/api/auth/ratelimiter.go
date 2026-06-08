package auth

import (
	"context"
	"errors"
	"sync"
	"time"

	"runic/internal/common/constants"
	"runic/internal/common/log"
)

type rateLimitEntry struct {
	failedAttempts int
	lockedUntil    time.Time
	lastSeen       time.Time
}

const (
	maxFailedAttempts = 5
	lockoutDuration   = 15 * time.Minute
)

var ErrAccountLocked = errors.New("account locked, try again later")

var (
	// rateLimitStore is keyed by "username:remoteAddr" (see getRateLimitKey).
	rateLimitStore map[string]*rateLimitEntry
	// rateLimitByUser is a reverse index from username to the list of
	// rateLimitStore keys that include that username as a prefix. It allows
	// RecordSuccess to clear every (user, IP) entry in O(K) time, where K is
	// the number of distinct IPs the user has attempted to log in from,
	// rather than scanning the entire store.
	rateLimitByUser  map[string][]string
	rateLimitMutex   sync.Mutex
	stopCleanup      chan struct{}
	stopCleanupOnce  sync.Once
	cleanupStartOnce sync.Once
)

func init() {
	// NOTE: rateLimitStore is an in-memory map — all rate limit data is lost on
	// process restart. This is intentional: lockout state is ephemeral and does
	// not need to survive reboots. A restart also resets any accumulated failed
	// attempt counters.
	rateLimitStore = make(map[string]*rateLimitEntry)
	rateLimitByUser = make(map[string][]string)
	stopCleanup = make(chan struct{})
}

// StopCleanup stops the cleanup goroutine. Call during graceful shutdown.
func StopCleanup() {
	stopCleanupOnce.Do(func() {
		close(stopCleanup)
	})
}

// startCleanupLazy starts the background cleanup goroutine on the first call.
// Uses sync.Once so the goroutine is only spawned when the rate limiter is
// actually in use (e.g. after the first failed login), avoiding work for
// processes that never trigger auth failures (such as unit tests that
// instantiate the auth package for type definitions only).
func startCleanupLazy() {
	cleanupStartOnce.Do(func() {
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
	})
}

// getRateLimitKey returns a combined username+IP key for per-account-per-IP rate limiting.
// This prevents both single-account brute force and cross-account password spraying.
func getRateLimitKey(username, remoteAddr string) string {
	return username + ":" + remoteAddr
}

// CheckAndRecordFailure checks and records a failed login attempt, returning
// an error if the account is currently locked out. The ctx is used only for
// the lockout log line so the security event inherits the caller's deadline
// and trace context; the in-memory store mutation does not touch ctx because
// it must remain valid under the local rateLimitMutex even if the request
// has been canceled.
func CheckAndRecordFailure(ctx context.Context, username string, remoteAddr string) error {
	startCleanupLazy()

	rateLimitMutex.Lock()
	defer rateLimitMutex.Unlock()

	key := getRateLimitKey(username, remoteAddr)
	entry, exists := rateLimitStore[key]
	if !exists {
		entry = &rateLimitEntry{}
		rateLimitStore[key] = entry
		rateLimitByUser[username] = append(rateLimitByUser[username], key)
	}

	if entry.lockedUntil.After(time.Now()) {
		return ErrAccountLocked
	}

	entry.failedAttempts++
	entry.lastSeen = time.Now()

	if entry.failedAttempts >= maxFailedAttempts {
		entry.lockedUntil = time.Now().Add(lockoutDuration)
		log.WarnContext(ctx, "account locked due to failed login attempts",
			"username", username, "remote_addr", remoteAddr, "duration", lockoutDuration, "failed_attempts", entry.failedAttempts)
	}

	return nil
}

func RecordSuccess(username string) {
	startCleanupLazy()

	rateLimitMutex.Lock()
	defer rateLimitMutex.Unlock()

	// Look up every (username, IP) entry via the reverse index and clear
	// them in O(K) where K is the number of IPs the user has attempted to
	// log in from. Falls back to the legacy prefix scan if the reverse
	// index has not been populated for this username (defensive).
	keys := rateLimitByUser[username]
	if len(keys) == 0 {
		prefix := username + ":"
		for k := range rateLimitStore {
			if k == username || (len(k) > len(prefix) && k[:len(prefix)] == prefix) {
				keys = append(keys, k)
			}
		}
	}
	for _, key := range keys {
		delete(rateLimitStore, key)
	}
	delete(rateLimitByUser, username)
}

func CleanupStaleEntries() {
	rateLimitMutex.Lock()
	defer rateLimitMutex.Unlock()

	now := time.Now()
	// An entry is eligible for eviction when:
	//  - it has an expired lockout (lockedUntil is non-zero and in the past), or
	//  - it has been idle (no CheckAndRecordFailure / RecordSuccess) for longer
	//    than lockoutDuration, with no active lockout in place.
	idleCutoff := now.Add(-lockoutDuration)
	for key, entry := range rateLimitStore {
		if !entry.lockedUntil.IsZero() && entry.lockedUntil.Before(now) {
			evictRateLimitEntry(key)
			continue
		}
		if !entry.lastSeen.IsZero() && entry.lastSeen.Before(idleCutoff) {
			evictRateLimitEntry(key)
		}
	}
}

// evictRateLimitEntry removes a single entry from both the primary store and
// the reverse index. Must be called with rateLimitMutex held.
func evictRateLimitEntry(key string) {
	delete(rateLimitStore, key)
	// Recover the username from the key (everything before the first colon).
	username := key
	for i := 0; i < len(key); i++ {
		if key[i] == ':' {
			username = key[:i]
			break
		}
	}
	if keys, ok := rateLimitByUser[username]; ok {
		for i, k := range keys {
			if k == key {
				keys[i] = keys[len(keys)-1]
				rateLimitByUser[username] = keys[:len(keys)-1]
				break
			}
		}
		if len(rateLimitByUser[username]) == 0 {
			delete(rateLimitByUser, username)
		}
	}
}

// ResetRateLimitStore resets the rate limit store. This is intended for testing to ensure test isolation.
func ResetRateLimitStore() {
	rateLimitMutex.Lock()
	defer rateLimitMutex.Unlock()
	rateLimitStore = make(map[string]*rateLimitEntry)
	rateLimitByUser = make(map[string][]string)
}
