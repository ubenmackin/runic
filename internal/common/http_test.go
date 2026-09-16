package common

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type mockRoundTripper struct {
	response *http.Response
	err      error
}

func (m *mockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.response, nil
}

func newMockClient(response *http.Response, err error) *http.Client {
	return &http.Client{
		Transport: &mockRoundTripper{
			response: response,
			err:      err,
		},
	}
}

func TestDoJSONRequest_SuccessGET(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request headers
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("expected Content-Type header to be application/json, got %s", r.Header.Get("Content-Type"))
		}
		if r.Header.Get("User-Agent") != "test-agent" {
			t.Errorf("expected User-Agent header to be test-agent, got %s", r.Header.Get("User-Agent"))
		}
		if r.Method != "GET" {
			t.Errorf("expected method GET, got %s", r.Method)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer server.Close()

	ctx := context.Background()
	client := server.Client()

	resp, err := DoJSONRequest(ctx, client, "GET", server.URL, nil, "test-token", "test-agent")
	if err != nil {
		t.Errorf("DoJSONRequest() unexpected error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("DoJSONRequest() status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	resp.Body.Close()
}

func TestDoJSONRequest_SuccessPOST(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected method POST, got %s", r.Method)
		}
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("expected Authorization header, got %s", r.Header.Get("Authorization"))
		}

		// Decode and verify body
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("failed to decode request body: %v", err)
		}
		if body["key"] != "value" {
			t.Errorf("expected body.key = value, got %s", body["key"])
		}

		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"id": "123"}`))
	}))
	defer server.Close()

	ctx := context.Background()
	client := server.Client()

	body := map[string]string{"key": "value"}
	resp, err := DoJSONRequest(ctx, client, "POST", server.URL, body, "test-token", "test-agent")
	if err != nil {
		t.Errorf("DoJSONRequest() unexpected error: %v", err)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("DoJSONRequest() status = %d, want %d", resp.StatusCode, http.StatusCreated)
	}
	resp.Body.Close()
}

func TestDoJSONRequest_WithoutToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Errorf("expected no Authorization header, got %s", r.Header.Get("Authorization"))
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	ctx := context.Background()
	client := server.Client()

	resp, err := DoJSONRequest(ctx, client, "GET", server.URL, nil, "", "test-agent")
	if err != nil {
		t.Errorf("DoJSONRequest() unexpected error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("DoJSONRequest() status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	resp.Body.Close()
}

func TestDoJSONRequest_WithoutUserAgent(t *testing.T) {
	var gotUA string
	// Use a mock client that captures headers directly, bypassing Transport's default UA
	mockClient := &mockHTTPClient{
		handler: func(req *http.Request) (*http.Response, error) {
			gotUA = req.Header.Get("User-Agent")
			return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
		},
	}

	ctx := context.Background()
	resp, err := DoJSONRequest(ctx, mockClient, "GET", "http://example.com", nil, "test-token", "")
	if err != nil {
		t.Errorf("DoJSONRequest() unexpected error: %v", err)
	}
	if gotUA != "" {
		t.Errorf("expected no User-Agent header, got %s", gotUA)
	}
	resp.Body.Close()
}

type mockHTTPClient struct {
	handler func(req *http.Request) (*http.Response, error)
}

func (m *mockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	return m.handler(req)
}

func TestDoJSONRequest_MarshalError(t *testing.T) {
	unmarshalable := map[string]interface{}{
		"func": func() {}, // functions cannot be marshaled to JSON
	}

	ctx := context.Background()
	client := &http.Client{}

	_, err := DoJSONRequest(ctx, client, "POST", "http://example.com", unmarshalable, "", "")
	if err == nil {
		t.Error("DoJSONRequest() expected error for unmarshalable body, got nil")
	}
	if !strings.Contains(err.Error(), "marshal request body") {
		t.Errorf("DoJSONRequest() error should contain 'marshal request body', got %v", err)
	}
}

func TestDoJSONRequest_NetworkError(t *testing.T) {
	ctx := context.Background()
	// Use mock client that returns network error
	mockErr := fmt.Errorf("network unreachable")
	client := newMockClient(nil, mockErr)

	_, err := DoJSONRequest(ctx, client, "GET", "http://example.com", nil, "", "")
	if err == nil {
		t.Error("DoJSONRequest() expected error for network failure, got nil")
	}
	if !strings.Contains(err.Error(), "execute request") {
		t.Errorf("DoJSONRequest() error should contain 'execute request', got %v", err)
	}
}

func TestDoJSONRequest_ContextCanceled(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond) // Simulate delay
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	client := server.Client()
	_, err := DoJSONRequest(ctx, client, "GET", server.URL, nil, "", "")
	if err == nil {
		t.Error("DoJSONRequest() expected error for canceled context, got nil")
	}
}

func TestDoJSONRequest_Timeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond) // Longer than context timeout
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	client := server.Client()
	_, err := DoJSONRequest(ctx, client, "GET", server.URL, nil, "", "")
	if err == nil {
		t.Error("DoJSONRequest() expected error for timeout, got nil")
	}
}

func TestDoJSONRequest_HTTPStatusErrors(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		wantErr    bool
	}{
		{"status 400 Bad Request", http.StatusBadRequest, true},
		{"status 401 Unauthorized", http.StatusUnauthorized, true},
		{"status 403 Forbidden", http.StatusForbidden, true},
		{"status 404 Not Found", http.StatusNotFound, true},
		{"status 500 Internal Server Error", http.StatusInternalServerError, true},
		{"status 502 Bad Gateway", http.StatusBadGateway, true},
		{"status 503 Service Unavailable", http.StatusServiceUnavailable, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
				w.Write([]byte("error response"))
			}))
			defer server.Close()

			ctx := context.Background()
			client := server.Client()

			_, err := DoJSONRequest(ctx, client, "GET", server.URL, nil, "", "")
			if err == nil {
				t.Errorf("DoJSONRequest() expected error for status %d, got nil", tt.statusCode)
			}

			// Verify error wraps HTTPStatusError
			var httpErr *HTTPStatusError
			if !strings.Contains(err.Error(), "request failed") {
				t.Errorf("DoJSONRequest() error should contain 'request failed', got %v", err)
			}
			// The error should have wrapped the HTTPStatusError
			if !strings.Contains(err.Error(), fmt.Sprintf("HTTP %d", tt.statusCode)) {
				t.Errorf("DoJSONRequest() error should contain status code %d, got %v", tt.statusCode, err)
			}

			httpErr = &HTTPStatusError{StatusCode: tt.statusCode}
			if !strings.Contains(httpErr.Error(), fmt.Sprintf("HTTP %d", tt.statusCode)) {
				t.Errorf("HTTPStatusError.Error() should contain status code %d", tt.statusCode)
			}
		})
	}
}

func TestDoJSONRequest_2xxStatusCodes(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
	}{
		{"status 200 OK", http.StatusOK},
		{"status 201 Created", http.StatusCreated},
		{"status 202 Accepted", http.StatusAccepted},
		{"status 204 No Content", http.StatusNoContent},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
			}))
			defer server.Close()

			ctx := context.Background()
			client := server.Client()

			resp, err := DoJSONRequest(ctx, client, "GET", server.URL, nil, "", "")
			if err != nil {
				t.Errorf("DoJSONRequest() unexpected error for status %d: %v", tt.statusCode, err)
			}
			if resp.StatusCode != tt.statusCode {
				t.Errorf("DoJSONRequest() status = %d, want %d", resp.StatusCode, tt.statusCode)
			}
			resp.Body.Close()
		})
	}
}

func TestDoJSONRequest_RetryAfterDeltaSeconds(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "2")
		w.WriteHeader(http.StatusTooManyRequests)
		w.Write([]byte("rate limited"))
	}))
	defer server.Close()

	_, err := DoJSONRequest(context.Background(), server.Client(), "GET", server.URL, nil, "", "")
	if err == nil {
		t.Fatal("DoJSONRequest() expected error for 429, got nil")
	}
	var httpErr *HTTPStatusError
	if !errors.As(err, &httpErr) {
		t.Fatalf("DoJSONRequest() error does not wrap *HTTPStatusError: %v", err)
	}
	if httpErr.StatusCode != http.StatusTooManyRequests {
		t.Errorf("StatusCode = %d, want 429", httpErr.StatusCode)
	}
	if httpErr.RetryAfter != 2*time.Second {
		t.Errorf("RetryAfter = %v, want 2s", httpErr.RetryAfter)
	}
	if !httpErr.HasRetryAfter {
		t.Errorf("HasRetryAfter = false, want true")
	}
	if httpErr.Body != "rate limited" {
		t.Errorf("Body = %q, want %q", httpErr.Body, "rate limited")
	}
	if !IsRateLimited(err) {
		t.Errorf("IsRateLimited() = false, want true")
	}
	if d, ok := RetryAfterOf(err); d != 2*time.Second || !ok {
		t.Errorf("RetryAfterOf() = (%v,%v), want (2s,true)", d, ok)
	}
	if got := httpErr.Error(); got != fmt.Sprintf("HTTP 429 GET %s", server.URL) {
		t.Errorf("Error() = %q, want stable format", got)
	}
}

func TestDoJSONRequest_RetryAfterMissing(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		w.Write([]byte("slow down"))
	}))
	defer server.Close()

	_, err := DoJSONRequest(context.Background(), server.Client(), "GET", server.URL, nil, "", "")
	if err == nil {
		t.Fatal("DoJSONRequest() expected error for 429, got nil")
	}
	if d, ok := RetryAfterOf(err); d != 0 || ok {
		t.Errorf("RetryAfterOf() = (%v,%v), want (0,false)", d, ok)
	}
	if !IsRateLimited(err) {
		t.Errorf("IsRateLimited() = false, want true")
	}
	var httpErr *HTTPStatusError
	if !errors.As(err, &httpErr) {
		t.Fatalf("error does not wrap *HTTPStatusError: %v", err)
	}
	if httpErr.HasRetryAfter {
		t.Errorf("HasRetryAfter = true, want false for missing header")
	}
	if httpErr.Body != "slow down" {
		t.Errorf("Body = %q, want %q", httpErr.Body, "slow down")
	}
}

func TestDoJSONRequest_RetryAfterUnparseable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "not-a-date")
		w.WriteHeader(http.StatusTooManyRequests)
		w.Write([]byte("slow down"))
	}))
	defer server.Close()

	_, err := DoJSONRequest(context.Background(), server.Client(), "GET", server.URL, nil, "", "")
	if err == nil {
		t.Fatal("DoJSONRequest() expected error, got nil")
	}
	if d, ok := RetryAfterOf(err); d != 0 || ok {
		t.Errorf("RetryAfterOf() = (%v,%v), want (0,false)", d, ok)
	}
}

func TestDoJSONRequest_RetryAfterZeroAndNegative(t *testing.T) {
	for _, hdr := range []string{"0", "-5"} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Retry-After", hdr)
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte("slow down"))
		}))

		_, err := DoJSONRequest(context.Background(), server.Client(), "GET", server.URL, nil, "", "")
		server.Close()
		if err == nil {
			t.Fatalf("DoJSONRequest() expected error for header %q, got nil", hdr)
		}
		if d, ok := RetryAfterOf(err); d != 0 || !ok {
			t.Errorf("header %q: RetryAfterOf() = (%v,%v), want (0,true)", hdr, d, ok)
		}
	}
}

func TestDoJSONRequest_RetryAfterHTTPDate(t *testing.T) {
	t.Run("future date yields positive duration", func(t *testing.T) {
		future := time.Now().Add(5 * time.Second).UTC().Format(http.TimeFormat)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Retry-After", future)
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte("slow down"))
		}))
		defer server.Close()

		_, err := DoJSONRequest(context.Background(), server.Client(), "GET", server.URL, nil, "", "")
		if err == nil {
			t.Fatal("DoJSONRequest() expected error, got nil")
		}
		d, ok := RetryAfterOf(err)
		if !ok {
			t.Fatalf("RetryAfterOf() ok = false, want true")
		}
		if d <= 0 || d > 6*time.Second {
			t.Errorf("RetryAfterOf() = %v, want (0,6s]", d)
		}
	})

	t.Run("past date yields (0,true)", func(t *testing.T) {
		past := time.Now().Add(-time.Hour).UTC().Format(http.TimeFormat)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Retry-After", past)
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte("slow down"))
		}))
		defer server.Close()

		_, err := DoJSONRequest(context.Background(), server.Client(), "GET", server.URL, nil, "", "")
		if err == nil {
			t.Fatal("DoJSONRequest() expected error, got nil")
		}
		if d, ok := RetryAfterOf(err); d != 0 || !ok {
			t.Errorf("RetryAfterOf() = (%v,%v), want (0,true)", d, ok)
		}
	})
}

func TestDoJSONRequest_401CapturesRetryAfter(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "3")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("unauthorized"))
	}))
	defer server.Close()

	_, err := DoJSONRequest(context.Background(), server.Client(), "GET", server.URL, nil, "", "")
	if err == nil {
		t.Fatal("DoJSONRequest() expected error for 401, got nil")
	}
	var httpErr *HTTPStatusError
	if !errors.As(err, &httpErr) {
		t.Fatalf("error does not wrap *HTTPStatusError: %v", err)
	}
	if httpErr.RetryAfter != 3*time.Second || !httpErr.HasRetryAfter {
		t.Errorf("401 RetryAfter = (%v,%v), want (3s,true)", httpErr.RetryAfter, httpErr.HasRetryAfter)
	}
	if httpErr.Body != "unauthorized" {
		t.Errorf("Body = %q, want %q", httpErr.Body, "unauthorized")
	}
	if !IsUnauthorized(err) {
		t.Errorf("IsUnauthorized(401 with RetryAfter) = false, want true")
	}
	if IsRateLimited(err) {
		t.Errorf("IsRateLimited(401) = true, want false")
	}
}

func TestDoJSONRequest_403NotUnauthorized(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("forbidden"))
	}))
	defer server.Close()

	_, err := DoJSONRequest(context.Background(), server.Client(), "GET", server.URL, nil, "", "")
	if err == nil {
		t.Fatal("DoJSONRequest() expected error for 403, got nil")
	}
	if IsUnauthorized(err) {
		t.Errorf("IsUnauthorized(403) = true, want false")
	}
	if IsRateLimited(err) {
		t.Errorf("IsRateLimited(403) = true, want false")
	}
}

func TestDoJSONRequest_BodyTruncated(t *testing.T) {
	big := strings.Repeat("x", 8192)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(big))
	}))
	defer server.Close()

	_, err := DoJSONRequest(context.Background(), server.Client(), "GET", server.URL, nil, "", "")
	if err == nil {
		t.Fatal("DoJSONRequest() expected error, got nil")
	}
	var httpErr *HTTPStatusError
	if !errors.As(err, &httpErr) {
		t.Fatalf("error does not wrap *HTTPStatusError: %v", err)
	}
	if len(httpErr.Body) > 4096 {
		t.Errorf("Body length = %d, want <= 4096", len(httpErr.Body))
	}
}

func TestParseRetryAfter(t *testing.T) {
	if got := ParseRetryAfter(""); got != 0 {
		t.Errorf("ParseRetryAfter(\"\") = %v, want 0", got)
	}
	if got := ParseRetryAfter("2"); got != 2*time.Second {
		t.Errorf("ParseRetryAfter(\"2\") = %v, want 2s", got)
	}
	if got := ParseRetryAfter("0"); got != 0 {
		t.Errorf("ParseRetryAfter(\"0\") = %v, want 0", got)
	}
	if got := ParseRetryAfter("not-a-date"); got != 0 {
		t.Errorf("ParseRetryAfter(\"not-a-date\") = %v, want 0", got)
	}
	if d, ok := ParseRetryAfterPresent(""); d != 0 || ok {
		t.Errorf("ParseRetryAfterPresent(\"\") = (%v,%v), want (0,false)", d, ok)
	}
	if d, ok := ParseRetryAfterPresent("not-a-date"); d != 0 || ok {
		t.Errorf("ParseRetryAfterPresent(\"not-a-date\") = (%v,%v), want (0,false)", d, ok)
	}
	if d, ok := ParseRetryAfterPresent("0"); d != 0 || !ok {
		t.Errorf("ParseRetryAfterPresent(\"0\") = (%v,%v), want (0,true)", d, ok)
	}
}
