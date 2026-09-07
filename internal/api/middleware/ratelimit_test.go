package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestCheck(t *testing.T) {
	tests := []struct {
		name       string
		limit      int
		window     time.Duration
		_requests  int // number of requests to make
		wantErr    bool
		errOnAfter int // which request number should start erroring (1-indexed)
	}{
		{
			name:      "allows requests under limit",
			limit:     5,
			window:    time.Minute,
			_requests: 4,
			wantErr:   false,
		},
		{
			name:       "blocks requests at limit",
			limit:      5,
			window:     time.Minute,
			_requests:  6,
			wantErr:    true,
			errOnAfter: 5,
		},
		{
			name:       "blocks requests over limit",
			limit:      2,
			window:     time.Minute,
			_requests:  10,
			wantErr:    true,
			errOnAfter: 2,
		},
		{
			name:      "limit of 1 allows single request",
			limit:     1,
			window:    time.Minute,
			_requests: 1,
			wantErr:   false,
		},
		{
			name:       "limit of 1 blocks second request",
			limit:      1,
			window:     time.Minute,
			_requests:  2,
			wantErr:    true,
			errOnAfter: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rl := NewRateLimiter(tt.limit, tt.window)
			defer rl.Stop()

			testIP := "192.168.1.1:12345"

			for i := 1; i <= tt._requests; i++ {
				err := rl.Check(testIP)
				if i <= tt.limit {
					if err != nil {
						t.Errorf("request %d: unexpected error: %v", i, err)
					}
				} else {
					if err == nil {
						t.Errorf("request %d: expected error, got nil", i)
					}
				}
			}
		})
	}
}

func TestCheckMultipleIPs(t *testing.T) {
	rl := NewRateLimiter(2, time.Minute)
	defer rl.Stop()

	// First IP hits limit
	if err := rl.Check("10.0.0.1:1000"); err != nil {
		t.Errorf("first request for 10.0.0.1 failed: %v", err)
	}
	if err := rl.Check("10.0.0.1:1000"); err != nil {
		t.Errorf("second request for 10.0.0.1 failed: %v", err)
	}
	if err := rl.Check("10.0.0.1:1000"); err == nil {
		t.Error("third request for 10.0.0.1 should have been rate limited")
	}

	// Different IP should still be allowed
	if err := rl.Check("10.0.0.2:2000"); err != nil {
		t.Errorf("first request for 10.0.0.2 failed: %v", err)
	}

	// Another different IP
	if err := rl.Check("10.0.0.3:3000"); err != nil {
		t.Errorf("first request for 10.0.0.3 failed: %v", err)
	}
}

func TestCheckWindowExpiry(t *testing.T) {
	// Use a very short window for testing
	window := 100 * time.Millisecond
	rl := NewRateLimiter(2, window)
	defer rl.Stop()

	testIP := "192.168.1.1:12345"

	// Make two requests (at limit)
	if err := rl.Check(testIP); err != nil {
		t.Errorf("first request failed: %v", err)
	}
	if err := rl.Check(testIP); err != nil {
		t.Errorf("second request failed: %v", err)
	}

	// Third request should be rate limited
	if err := rl.Check(testIP); err == nil {
		t.Error("third request should have been rate limited")
	}

	// Wait for window to expire
	time.Sleep(window + 50*time.Millisecond)

	// After window expires, should be allowed again
	if err := rl.Check(testIP); err != nil {
		t.Errorf("request after window expiry failed: %v", err)
	}
}

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

func TestMiddleware(t *testing.T) {
	tests := []struct {
		name          string
		limit         int
		window        time.Duration
		requests      int
		wantStatusOK  int // how many requests should return 200
		wantStatus429 int // how many requests should return 429
	}{
		{
			name:          "single request allowed",
			limit:         5,
			window:        time.Minute,
			requests:      1,
			wantStatusOK:  1,
			wantStatus429: 0,
		},
		{
			name:          "requests at limit allowed",
			limit:         3,
			window:        time.Minute,
			requests:      3,
			wantStatusOK:  3,
			wantStatus429: 0,
		},
		{
			name:          "requests over limit get 429",
			limit:         2,
			window:        time.Minute,
			requests:      5,
			wantStatusOK:  2,
			wantStatus429: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rl := NewRateLimiter(tt.limit, tt.window)
			defer rl.Stop()

			handler := rl.Middleware(okHandler())

			okCount := 0
			tooManyCount := 0

			for i := 0; i < tt.requests; i++ {
				req := httptest.NewRequest("GET", "/test", nil)
				req.RemoteAddr = "192.168.1.1:12345"
				rr := httptest.NewRecorder()

				handler.ServeHTTP(rr, req)

				if rr.Code == http.StatusOK {
					okCount++
				} else if rr.Code == http.StatusTooManyRequests {
					tooManyCount++
				}
			}

			if okCount != tt.wantStatusOK {
				t.Errorf("got %d OK responses, want %d", okCount, tt.wantStatusOK)
			}
			if tooManyCount != tt.wantStatus429 {
				t.Errorf("got %d 429 responses, want %d", tooManyCount, tt.wantStatus429)
			}
		})
	}
}

func TestMiddleware429Response(t *testing.T) {
	rl := NewRateLimiter(1, time.Minute)
	defer rl.Stop()

	handler := rl.Middleware(okHandler())

	// First request should succeed
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("first request: got status %d, want %d", rr.Code, http.StatusOK)
	}

	// Second request should be rate limited
	req2 := httptest.NewRequest("GET", "/test", nil)
	req2.RemoteAddr = "192.168.1.1:12345"
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)

	if rr2.Code != http.StatusTooManyRequests {
		t.Errorf("second request: got status %d, want %d", rr2.Code, http.StatusTooManyRequests)
	}

	contentType := rr2.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Content-Type = %q, want %q", contentType, "application/json")
	}

	var response map[string]string
	if err := json.NewDecoder(rr2.Body).Decode(&response); err != nil {
		t.Errorf("failed to decode response body: %v", err)
	}
	if response["error"] != "rate limit exceeded" {
		t.Errorf("error message = %q, want %q", response["error"], "rate limit exceeded")
	}
}

func TestGetIP(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		wantIP     string
	}{
		{
			name:       "basic remote addr",
			remoteAddr: "192.168.1.1:12345",
			wantIP:     "192.168.1.1:12345",
		},
		{
			name:       "remote addr with port",
			remoteAddr: "10.0.0.1:8080",
			wantIP:     "10.0.0.1:8080",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rl := NewRateLimiter(100, time.Minute)
			defer rl.Stop()

			req := httptest.NewRequest("GET", "/test", nil)
			req.RemoteAddr = tt.remoteAddr

			gotIP := rl.getIP(req)
			if gotIP != tt.wantIP {
				t.Errorf("getIP() = %q, want %q", gotIP, tt.wantIP)
			}
		})
	}
}

func TestStop(t *testing.T) {
	rl := NewRateLimiter(100, time.Minute)

	// Call Stop multiple times - should not panic
	rl.Stop()
	rl.Stop() // Second call should be no-op due to sync.Once

	// Verify it doesn't block forever
	done := make(chan struct{})
	go func() {
		rl.Stop()
		close(done)
	}()

	select {
	case <-done:
		// Success - Stop() returned quickly
	case <-time.After(time.Second):
		t.Error("Stop() took too long")
	}
}

func TestStopOnce(t *testing.T) {
	rl := NewRateLimiter(100, time.Minute)

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rl.Stop()
		}()
	}
	wg.Wait()

	// Should not panic or block
}

func TestConcurrentCheck(t *testing.T) {
	rl := NewRateLimiter(100, time.Minute)
	defer rl.Stop()

	var wg sync.WaitGroup
	errCount := 0
	mu := sync.Mutex{}

	// Spawn many goroutines that check the same IP
	for i := 0; i < 1000; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := rl.Check("192.168.1.1:12345")
			if err != nil {
				mu.Lock()
				errCount++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	// Exactly 100 requests should succeed, rest should be rate limited
	if errCount != 900 {
		t.Errorf("got %d rate limited requests, want 900", errCount)
	}
}

func TestMiddlewareDifferentIPs(t *testing.T) {
	rl := NewRateLimiter(2, time.Minute)
	defer rl.Stop()

	handler := rl.Middleware(okHandler())

	// First IP can make 2 requests
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("request %d for IP 1: got status %d, want %d", i+1, rr.Code, http.StatusOK)
		}
	}

	// Third request from first IP should be rate limited
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("third request for IP 1: got status %d, want %d", rr.Code, http.StatusTooManyRequests)
	}

	// Second IP should still be allowed
	req2 := httptest.NewRequest("GET", "/test", nil)
	req2.RemoteAddr = "192.168.1.2:12345"
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusOK {
		t.Errorf("first request for IP 2: got status %d, want %d", rr2.Code, http.StatusOK)
	}
}

func TestStrictMiddlewareIgnoresSpoofedXFF(t *testing.T) {
	rl := NewRateLimiter(5, time.Minute)
	defer rl.Stop()

	handler := rl.StrictMiddleware(okHandler())

	// Same TCP peer rotating X-Forwarded-For per request must still share one
	// bucket: the first 5 succeed, the 6th with a fresh spoofed header is 429.
	remoteAddr := "203.0.113.10:12345"
	spoofed := []string{
		"198.51.100.1",
		"198.51.100.2",
		"198.51.100.3",
		"198.51.100.4",
		"198.51.100.5",
	}
	for i, xff := range spoofed {
		req := httptest.NewRequest("POST", "/api/v1/auth/login", nil)
		req.RemoteAddr = remoteAddr
		req.Header.Set("X-Forwarded-For", xff)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("request %d with spoofed XFF %q: got status %d, want %d", i+1, xff, rr.Code, http.StatusOK)
		}
	}

	// 6th request with yet another spoofed XFF must still be limited.
	req := httptest.NewRequest("POST", "/api/v1/auth/login", nil)
	req.RemoteAddr = remoteAddr
	req.Header.Set("X-Forwarded-For", "198.51.100.99")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("6th request with rotated XFF: got status %d, want %d (XFF rotation bypassed StrictMiddleware)", rr.Code, http.StatusTooManyRequests)
	}
}

func TestStrictMiddlewareIgnoresSpoofedXRealIP(t *testing.T) {
	rl := NewRateLimiter(2, time.Minute)
	defer rl.Stop()

	handler := rl.StrictMiddleware(okHandler())
	remoteAddr := "203.0.113.11:12345"

	for i, realIP := range []string{"198.51.100.21", "198.51.100.22"} {
		req := httptest.NewRequest("POST", "/api/v1/auth/login", nil)
		req.RemoteAddr = remoteAddr
		req.Header.Set("X-Real-IP", realIP)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("request %d with spoofed X-Real-IP %q: got status %d, want %d", i+1, realIP, rr.Code, http.StatusOK)
		}
	}

	req := httptest.NewRequest("POST", "/api/v1/auth/login", nil)
	req.RemoteAddr = remoteAddr
	req.Header.Set("X-Real-IP", "198.51.100.99")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("3rd request with rotated X-Real-IP: got status %d, want %d", rr.Code, http.StatusTooManyRequests)
	}
}

func TestStrictMiddlewareStripsPort(t *testing.T) {
	rl := NewRateLimiter(2, time.Minute)
	defer rl.Stop()

	handler := rl.StrictMiddleware(okHandler())

	// Same IP with different ephemeral source ports shares one bucket, so a
	// new TCP connection per guess does not bypass the limit.
	for i, remoteAddr := range []string{"203.0.113.12:1001", "203.0.113.12:1002"} {
		req := httptest.NewRequest("POST", "/api/v1/auth/login", nil)
		req.RemoteAddr = remoteAddr
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("request %d from %q: got status %d, want %d", i+1, remoteAddr, rr.Code, http.StatusOK)
		}
	}

	req := httptest.NewRequest("POST", "/api/v1/auth/login", nil)
	req.RemoteAddr = "203.0.113.12:1003"
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("3rd request from same IP new port: got status %d, want %d", rr.Code, http.StatusTooManyRequests)
	}

	// A different IP is unaffected.
	req2 := httptest.NewRequest("POST", "/api/v1/auth/login", nil)
	req2.RemoteAddr = "203.0.113.13:1001"
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusOK {
		t.Errorf("first request from different IP: got status %d, want %d", rr2.Code, http.StatusOK)
	}
}

func TestMiddlewarePreservesProxyBucketing(t *testing.T) {
	// The legacy proxy-compatible Middleware intentionally keys on
	// X-Forwarded-For so deployments behind a reverse proxy keep per-client
	// buckets. Non-auth endpoints (downloads, etc.) keep this behavior.
	rl := NewRateLimiter(1, time.Minute)
	defer rl.Stop()

	handler := rl.Middleware(okHandler())

	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	req.Header.Set("X-Forwarded-For", "203.0.113.50")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("first request: got status %d, want %d", rr.Code, http.StatusOK)
	}

	// Same XFF from a different egress connection shares the bucket.
	req2 := httptest.NewRequest("GET", "/test", nil)
	req2.RemoteAddr = "10.0.0.1:54321"
	req2.Header.Set("X-Forwarded-For", "203.0.113.50")
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusTooManyRequests {
		t.Errorf("second request with same XFF: got status %d, want %d", rr2.Code, http.StatusTooManyRequests)
	}
}
