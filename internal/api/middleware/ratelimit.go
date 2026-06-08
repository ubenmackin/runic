// Package middleware provides API middlewares.
package middleware

import (
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"runic/internal/api/common"
	"runic/internal/common/constants"
)

// A RateLimiter provides sliding-window rate limiting per client IP.
// It supports both middleware and direct function call patterns.
type RateLimiter struct {
	mu          sync.Mutex
	requests    map[string][]time.Time
	limit       int
	window      time.Duration
	stopCleanup chan struct{}
	stopOnce    sync.Once
}

// NewRateLimiter creates a new RateLimiter with the given limit and window.
// limit: maximum number of requests allowed per IP within the window
// window: the time duration for the sliding window
func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	rl := &RateLimiter{
		requests:    make(map[string][]time.Time),
		limit:       limit,
		window:      window,
		stopCleanup: make(chan struct{}),
	}
	rl.startCleanup()
	return rl
}

// Check checks whether the given remote address is within the rate limit.
// This is the direct function call pattern for use outside of HTTP middleware.
func (rl *RateLimiter) Check(remoteAddr string) error {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	requests := rl.requests[remoteAddr]

	cutoff := now.Add(-rl.window)
	validRequests := []time.Time{}
	for _, ts := range requests {
		if ts.After(cutoff) {
			validRequests = append(validRequests, ts)
		}
	}

	if len(validRequests) >= rl.limit {
		return fmt.Errorf("rate limit exceeded")
	}

	rl.requests[remoteAddr] = append(validRequests, now)
	return nil
}

// Middleware returns an HTTP middleware that enforces the rate limit.
// It uses the client's IP address as the rate limit key.
// If the rate limit is exceeded, it responds with HTTP 429 Too Many Requests
// and a Retry-After header (in whole seconds) equal to the configured window.
func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := rl.getIP(r)
		if err := rl.Check(ip); err != nil {
			// RFC 7231 §7.1.3: Retry-After in delta-seconds. Round up so the
			// client doesn't immediately retry on a sub-second remainder.
			retryAfter := int(rl.window / time.Second)
			if retryAfter < 1 {
				retryAfter = 1
			}
			w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
			common.RespondError(w, http.StatusTooManyRequests, "rate limit exceeded")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (rl *RateLimiter) getIP(r *http.Request) string {
	return common.GetClientIP(r)
}

func (rl *RateLimiter) startCleanup() {
	go func() {
		ticker := time.NewTicker(constants.RateLimitCleanupInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				rl.cleanup()
			case <-rl.stopCleanup:
				return
			}
		}
	}()
}

func (rl *RateLimiter) cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Drop entries that have been idle for the full sliding window. If the
	// window is very small we still keep at least a 1-minute floor so a
	// long-lived RateLimiter doesn't hammer the cleanup path for clients
	// that just missed the limit.
	now := time.Now()
	cutoff := now.Add(-rl.window)
	if rl.window < time.Minute {
		cutoff = now.Add(-time.Minute)
	}

	for ip, requests := range rl.requests {
		validRequests := []time.Time{}
		for _, ts := range requests {
			if ts.After(cutoff) {
				validRequests = append(validRequests, ts)
			}
		}
		if len(validRequests) == 0 {
			delete(rl.requests, ip)
		} else {
			rl.requests[ip] = validRequests
		}
	}
}

func (rl *RateLimiter) Stop() {
	rl.stopOnce.Do(func() {
		close(rl.stopCleanup)
	})
}

func (rl *RateLimiter) Reset() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.requests = make(map[string][]time.Time)
}
