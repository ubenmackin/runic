package middleware

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"runic/internal/common/constants"
)

// RateLimiter implements a configurable in-memory rate limiter using a sliding window algorithm.
// It supports both middleware and direct function call patterns, with optional X-Forwarded-For
// header parsing for reverse proxy scenarios.
type RateLimiter struct {
	mu             sync.Mutex
	requests       map[string][]time.Time
	limit          int
	window         time.Duration
	useXFF         bool
	trustedProxies map[string]bool
	stopCleanup    chan struct{}
}

// RateLimiterOption is a functional option for configuring a RateLimiter.
type RateLimiterOption func(*RateLimiter)

// UseXFF enables X-Forwarded-For header parsing for extracting real client IPs
// when behind a trusted reverse proxy.
func UseXFF() RateLimiterOption {
	return func(rl *RateLimiter) {
		rl.useXFF = true
	}
}

// WithTrustedProxies sets the trusted proxy IPs for X-Forwarded-For parsing.
// Only requests from these IPs will have their X-Forwarded-For header parsed.
func WithTrustedProxies(proxies []string) RateLimiterOption {
	return func(rl *RateLimiter) {
		rl.trustedProxies = make(map[string]bool)
		for _, p := range proxies {
			rl.trustedProxies[p] = true
		}
	}
}

// NewRateLimiter creates a new RateLimiter with the specified limit and window.
// limit: maximum number of requests allowed per IP within the window
// window: the time duration for the sliding window
// opts: optional configuration (UseXFF, WithTrustedProxies)
func NewRateLimiter(limit int, window time.Duration, opts ...RateLimiterOption) *RateLimiter {
	rl := &RateLimiter{
		requests:    make(map[string][]time.Time),
		limit:       limit,
		window:      window,
		stopCleanup: make(chan struct{}),
	}
	for _, opt := range opts {
		opt(rl)
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
// It uses the client's IP address (respecting X-Forwarded-For if enabled) as the rate limit key.
// If the rate limit is exceeded, it responds with HTTP 429 Too Many Requests.
func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := rl.getIP(r)
		if err := rl.Check(ip); err != nil {
			http.Error(w, err.Error(), http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// getIP extracts the client IP, respecting X-Forwarded-For if enabled.
// When XFF is enabled and the request comes from a trusted proxy, it extracts
// the real client IP from the X-Forwarded-For header (leftmost IP = original client).
func (rl *RateLimiter) getIP(r *http.Request) string {
	if rl.useXFF {
		// Check if request comes from a trusted proxy
		remoteIP, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			remoteIP = r.RemoteAddr
		}
		if remoteIP == "" {
			remoteIP = r.RemoteAddr
		}

		if rl.trustedProxies[remoteIP] {
			if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
				// X-Forwarded-For: client, proxy1, proxy2
				// Take the first IP (original client)
				ips := strings.Split(xff, ",")
				if len(ips) > 0 {
					return strings.TrimSpace(ips[0])
				}
			}
		}
	}
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
	close(rl.stopCleanup)
}
