package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// TestCheck tests the Check method for rate limiting logic
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

// TestCheckMultipleIPs tests that rate limiting is tracked separately per IP
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

// TestCheckWindowExpiry tests that old requests expire from the sliding window
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

// okHandler returns a simple handler that always responds with 200 OK.
func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

// TestMiddleware tests the HTTP middleware function
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

// TestMiddleware429Response tests that rate limited requests return proper JSON response
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

	// Check Content-Type header
	contentType := rr2.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Content-Type = %q, want %q", contentType, "application/json")
	}

	// Check JSON body
	var response map[string]string
	if err := json.NewDecoder(rr2.Body).Decode(&response); err != nil {
		t.Errorf("failed to decode response body: %v", err)
	}
	if response["error"] != "rate limit exceeded" {
		t.Errorf("error message = %q, want %q", response["error"], "rate limit exceeded")
	}
}

// TestGetIP tests IP extraction from requests
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

// TestStop tests that Stop() properly cleans up the rate limiter
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

// TestStopOnce tests that Stop() only runs once even with concurrent calls
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

// TestConcurrentCheck tests that Check() is safe for concurrent use
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

// TestMiddlewareDifferentIPs tests that different IPs have separate rate limits
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
