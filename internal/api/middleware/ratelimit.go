// Package middleware provides API middlewares.
package middleware

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"runic/internal/common/constants"
	"runic/internal/common/log"
)

// RateLimiter implements a configurable in-memory rate limiter using a sliding window algorithm.
// It supports both middleware and direct function call patterns.
type RateLimiter struct {
	mu          sync.Mutex
	requests    map[string][]time.Time
	limit       int
	window      time.Duration
	stopCleanup chan struct{}
	stopOnce    sync.Once
}

// NewRateLimiter creates a new RateLimiter with the specified limit and window.
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

// Check returns nil if allowed, error if rate limited.
// This is the direct function call pattern for use outside of HTTP middleware.
func (rl *RateLimiter) Check(remoteAddr string) error {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	requests := rl.requests[remoteAddr]

	// Filter out expired requests
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

// Middleware returns an http.Handler that wraps the next handler with rate limiting.
// It uses the client's IP address as the rate limit key.
// If the rate limit is exceeded, it responds with HTTP 429 Too Many Requests.
func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := rl.getIP(r)
		if err := rl.Check(ip); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			if err := json.NewEncoder(w).Encode(map[string]string{"error": "rate limit exceeded"}); err != nil {
				log.Warn("Failed to encode rate limit error", "error", err)
			}
			return
		}
		next.ServeHTTP(w, r)
	})
}

// getIP extracts the client IP from the request.
func (rl *RateLimiter) getIP(r *http.Request) string {
	return r.RemoteAddr
}

// startCleanup starts a goroutine that periodically cleans up stale entries.
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

// cleanup removes entries with no recent activity to prevent memory leaks.
func (rl *RateLimiter) cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-5 * time.Minute)

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

// Stop stops the cleanup goroutine. Useful for testing or graceful shutdown.
func (rl *RateLimiter) Stop() {
	rl.stopOnce.Do(func() {
		close(rl.stopCleanup)
	})
}

// Reset clears all rate limit state. This is intended for testing to ensure test isolation.
func (rl *RateLimiter) Reset() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.requests = make(map[string][]time.Time)
}
