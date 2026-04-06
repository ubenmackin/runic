package common

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// mockRoundTripper allows controlling HTTP client behavior for testing
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

// newMockClient creates an HTTP client with a mock transport
func newMockClient(response *http.Response, err error) *http.Client {
	return &http.Client{
		Transport: &mockRoundTripper{
			response: response,
			err:      err,
		},
	}
}

// TestDoJSONRequest_SuccessGET tests successful GET request
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

		// Return success response
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

// TestDoJSONRequest_SuccessPOST tests successful POST request with body
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

// TestDoJSONRequest_WithoutToken tests request without auth token
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

// TestDoJSONRequest_WithoutUserAgent tests request without custom user agent
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

// mockHTTPClient is a test HTTP client that calls a handler function
type mockHTTPClient struct {
	handler func(req *http.Request) (*http.Response, error)
}

func (m *mockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	return m.handler(req)
}

// TestDoJSONRequest_MarshalError tests error during body marshaling
func TestDoJSONRequest_MarshalError(t *testing.T) {
	// Create a value that cannot be marshaled to JSON
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

// TestDoJSONRequest_NetworkError tests network error during request
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

// TestDoJSONRequest_ContextCanceled tests context cancellation
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

// TestDoJSONRequest_Timeout tests request timeout
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

// TestDoJSONRequest_HTTPStatusErrors tests various non-2xx status codes
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

			// For testing purposes, also verify direct error unwrapping
			httpErr = &HTTPStatusError{StatusCode: tt.statusCode}
			if !strings.Contains(httpErr.Error(), fmt.Sprintf("HTTP %d", tt.statusCode)) {
				t.Errorf("HTTPStatusError.Error() should contain status code %d", tt.statusCode)
			}
		})
	}
}

// TestDoJSONRequest_2xxStatusCodes tests various 2xx success codes
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
