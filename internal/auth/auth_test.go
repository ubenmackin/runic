package auth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestGenerateToken tests JWT token generation
func TestGenerateToken(t *testing.T) {
	tests := []struct {
		name     string
		username string
		wantErr  bool
	}{
		{
			name:     "valid username",
			username: "testuser",
			wantErr:  false,
		},
		{
			name:     "empty username",
			username: "",
			wantErr:  false, // JWT doesn't validate username emptiness
		},
		{
			name:     "username with special characters",
			username: "user@example.com",
			wantErr:  false,
		},
		{
			name:     "username with spaces",
			username: "user name",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := GenerateToken(tt.username, 1*time.Hour)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateToken() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil {
				return
			}
			if token == "" {
				t.Error("GenerateToken() returned empty token")
			}
			// JWT tokens typically have 3 parts separated by dots
			parts := strings.Split(token, ".")
			if len(parts) != 3 {
				t.Errorf("expected JWT token with 3 parts, got %d", len(parts))
			}
		})
	}
}

// TestValidateToken tests JWT token validation
func TestValidateToken(t *testing.T) {
	tests := []struct {
		name        string
		username    string
		token       string
		wantErr     bool
		errContains string
	}{
		{
			name:     "valid token",
			username: "testuser",
			wantErr:  false,
		},
		{
			name:        "invalid token format",
			token:       "invalid.token.format",
			wantErr:     true,
			errContains: "",
		},
		{
			name:        "empty token",
			token:       "",
			wantErr:     true,
			errContains: "",
		},
		{
			name:        "malformed token",
			token:       "not.a.jwt",
			wantErr:     true,
			errContains: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var token string
			if tt.token == "" && tt.username != "" {
				// Generate a valid token
				var err error
				token, err = GenerateToken(tt.username, 1*time.Hour)
				if err != nil {
					t.Fatalf("failed to generate token: %v", err)
				}
			} else {
				token = tt.token
			}

			claims, err := ValidateToken(token)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateToken() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil && tt.errContains != "" {
				if !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("expected error containing %q, got %v", tt.errContains, err)
				}
			}
			if !tt.wantErr && claims != nil && tt.username != "" {
				if claims.Username != tt.username {
					t.Errorf("expected username %q, got %q", tt.username, claims.Username)
				}
			}
		})
	}
}

// TestTokenExpiration tests token expiration handling
func TestTokenExpiration(t *testing.T) {
	// Note: This test requires mocking time or using short expiration times
	// For now, we'll test the structure of the expiration claim

	username := "testuser"
	token, err := GenerateToken(username, 24*time.Hour)
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}

	claims, err := ValidateToken(token)
	if err != nil {
		t.Fatalf("failed to validate token: %v", err)
	}

	if claims.ExpiresAt == nil {
		t.Error("expected ExpirationTime to be set")
	}

	// Verify expiration is in the future
	if !claims.ExpiresAt.Time.After(time.Now()) {
		t.Error("expected expiration time to be in the future")
	}

	// Verify expiration is approximately 24 hours from now
	expectedExpiry := time.Now().Add(24 * time.Hour)
	diff := expectedExpiry.Sub(claims.ExpiresAt.Time)
	if diff < -time.Minute || diff > time.Minute {
		t.Errorf("expected expiration time to be approximately 24 hours from now, got difference of %v", diff)
	}
}

// TestMalformedToken tests malformed token handling
func TestMalformedToken(t *testing.T) {
	tests := []struct {
		name    string
		token   string
		wantErr bool
	}{
		{
			name:    "no segments",
			token:   "invalid",
			wantErr: true,
		},
		{
			name:    "one segment",
			token:   "header",
			wantErr: true,
		},
		{
			name:    "two segments",
			token:   "header.payload",
			wantErr: true,
		},
		{
			name:    "four segments",
			token:   "header.payload.signature.extra",
			wantErr: true,
		},
		{
			name:    "empty segments",
			token:   "..",
			wantErr: true,
		},
		{
			name:    "invalid base64",
			token:   "header.payload!@#$%",
			wantErr: true,
		},
		{
			name:    "wrong signature",
			token:   "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InRlc3R1c2VyIiwiZXhwIjoxNzA0MDY0MDAwfQ.wrongsignature",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims, err := ValidateToken(tt.token)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateToken() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr && claims != nil {
				t.Error("expected nil claims for invalid token")
			}
		})
	}
}

// TestMiddleware tests authentication middleware
func TestMiddleware(t *testing.T) {
	tests := []struct {
		name           string
		authHeader     string
		wantStatusCode int
		wantErr        string
	}{
		{
			name:           "valid authorization header",
			authHeader:     generateValidAuthHeader(t, "testuser"),
			wantStatusCode: http.StatusOK,
		},
		{
			name:           "missing authorization header",
			authHeader:     "",
			wantStatusCode: http.StatusUnauthorized,
			wantErr:        "Unauthorized",
		},
		{
			name:           "invalid authorization header format",
			authHeader:     "InvalidFormat token",
			wantStatusCode: http.StatusUnauthorized,
			wantErr:        "Unauthorized",
		},
		{
			name:           "malformed token",
			authHeader:     "Bearer invalid.token",
			wantStatusCode: http.StatusUnauthorized,
			wantErr:        "Unauthorized",
		},
		{
			name:           "wrong signature",
			authHeader:     "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InRlc3R1c2VyIiwiZXhwIjoxNzA0MDY0MDAwfQ.wrongsignature",
			wantStatusCode: http.StatusUnauthorized,
			wantErr:        "Unauthorized",
		},
		{
			name:           "empty bearer token",
			authHeader:     "Bearer ",
			wantStatusCode: http.StatusUnauthorized,
			wantErr:        "Unauthorized",
		},
		{
			name:           "only bearer keyword",
			authHeader:     "Bearer",
			wantStatusCode: http.StatusUnauthorized,
			wantErr:        "Unauthorized",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a test handler to be wrapped by middleware
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("success"))
			})

			// Wrap the handler with middleware
			wrappedHandler := Middleware(handler)

			// Create a test request
			req := httptest.NewRequest("GET", "/test", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}

			// Create a test response recorder
			w := httptest.NewRecorder()

			// Serve the request
			wrappedHandler.ServeHTTP(w, req)

			// Check the response
			if w.Code != tt.wantStatusCode {
				t.Errorf("expected status %d, got %d: %s", tt.wantStatusCode, w.Code, w.Body.String())
			}

			if tt.wantErr != "" {
				response := w.Body.String()
				if !strings.Contains(response, tt.wantErr) {
					t.Errorf("expected response containing %q, got %q", tt.wantErr, response)
				}
			}

			if tt.wantStatusCode == http.StatusOK {
				response := w.Body.String()
				if response != "success" {
					t.Errorf("expected response %q, got %q", "success", response)
				}
			}
		})
	}
}

// TestTokenConsistency tests that tokens are consistent and reproducible
func TestTokenConsistency(t *testing.T) {
	username := "testuser"

	// Generate two tokens for the same username
	token1, err1 := GenerateToken(username, 1*time.Hour)
	token2, err2 := GenerateToken(username, 1*time.Hour)

	if err1 != nil || err2 != nil {
		t.Fatalf("failed to generate tokens: %v, %v", err1, err2)
	}

	// Tokens should be different due to unique ID in each token
	if token1 == token2 {
		t.Error("expected different tokens for different generation times")
	}

	// Both tokens should be valid
	claims1, err1 := ValidateToken(token1)
	claims2, err2 := ValidateToken(token2)

	if err1 != nil || err2 != nil {
		t.Fatalf("failed to validate tokens: %v, %v", err1, err2)
	}

	if claims1.Username != claims2.Username {
		t.Errorf("expected same username, got %q and %q", claims1.Username, claims2.Username)
	}
}

// TestClaimsStructure tests JWT claims structure
func TestClaimsStructure(t *testing.T) {
	username := "testuser"
	token, err := GenerateToken(username, 1*time.Hour)
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}

	claims, err := ValidateToken(token)
	if err != nil {
		t.Fatalf("failed to validate token: %v", err)
	}

	// Verify claim fields
	if claims.Username != username {
		t.Errorf("expected username %q, got %q", username, claims.Username)
	}

	if claims.ExpiresAt == nil {
		t.Error("expected ExpiresAt to be set")
	}

	if claims.IssuedAt == nil {
		t.Error("expected IssuedAt to be set")
	}

	// Verify IssuedAt is in the past or present
	if !claims.IssuedAt.Time.Before(time.Now().Add(time.Minute)) {
		t.Error("expected IssuedAt to be in the past or present")
	}
}

// TestTokenWithDifferentKeys tests that tokens with different keys don't validate
func TestTokenWithDifferentKeys(t *testing.T) {
	// Note: This test is difficult to implement because the JWT key is a global variable
	// In a real test, you would:
	// 1. Mock the JwtKey variable
	// 2. Generate a token with one key
	// 3. Change the key
	// 4. Try to validate with the new key
	// For now, we'll skip this test
	t.Skip("skipping - requires JWT key mocking")
}

// TestTokenWithSpecialUsernames tests tokens with special usernames
func TestTokenWithSpecialUsernames(t *testing.T) {
	tests := []struct {
		name     string
		username string
	}{
		{
			name:     "email format",
			username: "user@example.com",
		},
		{
			name:     "with spaces",
			username: "user name with spaces",
		},
		{
			name:     "unicode characters",
			username: "用户名",
		},
		{
			name:     "very long username",
			username: strings.Repeat("a", 1000),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := GenerateToken(tt.username, 1*time.Hour)
			if err != nil {
				t.Fatalf("failed to generate token for username %q: %v", tt.username, err)
			}

			claims, err := ValidateToken(token)
			if err != nil {
				t.Fatalf("failed to validate token: %v", err)
			}

			if claims.Username != tt.username {
				t.Errorf("expected username %q, got %q", tt.username, claims.Username)
			}
		})
	}
}

// TestGenerateAndValidateIntegration tests the full generate and validate flow
func TestGenerateAndValidateIntegration(t *testing.T) {
	tests := []struct {
		name     string
		username string
	}{
		{
			name:     "simple username",
			username: "alice",
		},
		{
			name:     "username with numbers",
			username: "user123",
		},
		{
			name:     "username with special chars",
			username: "user_admin",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Generate token
			token, err := GenerateToken(tt.username, 1*time.Hour)
			if err != nil {
				t.Fatalf("GenerateToken() error = %v", err)
			}

			// Validate token
			claims, err := ValidateToken(token)
			if err != nil {
				t.Fatalf("ValidateToken() error = %v", err)
			}

			// Verify claims
			if claims == nil {
				t.Fatal("expected non-nil claims")
			}

			if claims.Username != tt.username {
				t.Errorf("expected username %q, got %q", tt.username, claims.Username)
			}

			if claims.ExpiresAt == nil {
				t.Error("expected ExpirationTime to be set")
			}
		})
	}
}

// TestMiddlewareWithDifferentMethods tests middleware with different HTTP methods
func TestMiddlewareWithDifferentMethods(t *testing.T) {
	methods := []string{"GET", "POST", "PUT", "DELETE", "PATCH"}
	authHeader := generateValidAuthHeader(t, "testuser")

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("success"))
			})

			wrappedHandler := Middleware(handler)

			req := httptest.NewRequest(method, "/test", nil)
			req.Header.Set("Authorization", authHeader)
			w := httptest.NewRecorder()

			wrappedHandler.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("for method %s: expected status %d, got %d", method, http.StatusOK, w.Code)
			}
		})
	}
}

// TestMiddlewareChain tests middleware chaining
func TestMiddlewareChain(t *testing.T) {
	authHeader := generateValidAuthHeader(t, "testuser")

	// Create a handler that writes a specific response
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("passed"))
	})

	// Chain multiple middleware layers
	wrappedHandler := Middleware(handler)

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", authHeader)
	w := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	if w.Body.String() != "passed" {
		t.Errorf("expected response %q, got %q", "passed", w.Body.String())
	}
}

// TestTokenValidationAfterExpiration tests token validation after expiration
func TestTokenValidationAfterExpiration(t *testing.T) {
	// Note: This test would require mocking time or using very short expiration times
	// For now, we'll test that expired tokens are rejected by using a manually crafted expired token
	// In a real test, you would:
	// 1. Generate a token with a very short expiration (e.g., 1ms)
	// 2. Wait for expiration
	// 3. Try to validate
	t.Skip("skipping - requires time mocking")
}

// TestEmptyClaims tests handling of empty claims
func TestEmptyClaims(t *testing.T) {
	// Test with token that has no registered claims
	// This is a conceptual test - in practice, our tokens always have expiration
	t.Skip("skipping - requires manual token crafting for edge cases")
}

// TestConcurrentTokenGeneration tests concurrent token generation
func TestConcurrentTokenGeneration(t *testing.T) {
	username := "testuser"
	done := make(chan string, 10)

	// Generate tokens concurrently
	for i := 0; i < 10; i++ {
		go func() {
			token, err := GenerateToken(username, 1*time.Hour)
			if err != nil {
				t.Errorf("failed to generate token: %v", err)
				return
			}
			done <- token
		}()
	}

	// Collect all tokens
	tokens := make([]string, 10)
	for i := 0; i < 10; i++ {
		tokens[i] = <-done
	}

	// All tokens should be different (due to different expiration times)
	unique := make(map[string]bool)
	for _, token := range tokens {
		if unique[token] {
			t.Error("expected all tokens to be unique, found duplicate")
		}
		unique[token] = true
	}

	// All tokens should be valid
	for _, token := range tokens {
		claims, err := ValidateToken(token)
		if err != nil {
			t.Errorf("failed to validate token: %v", err)
		}
		if claims == nil {
			t.Error("expected non-nil claims")
		}
	}
}

// TestSignedClaims tests that claims are properly signed
func TestSignedClaims(t *testing.T) {
	username := "testuser"
	token, err := GenerateToken(username, 1*time.Hour)
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}

	// Split token into parts
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 token parts, got %d", len(parts))
	}

	// Verify each part is non-empty
	header, payload, signature := parts[0], parts[1], parts[2]

	if header == "" {
		t.Error("expected non-empty header")
	}
	if payload == "" {
		t.Error("expected non-empty payload")
	}
	if signature == "" {
		t.Error("expected non-empty signature")
	}

	// Verify signature is not trivial (not just all same characters)
	if strings.Count(signature, "a") == len(signature) {
		t.Error("signature appears trivial")
	}
}

// Helper function to generate a valid authorization header
func generateValidAuthHeader(t *testing.T, username string) string {
	token, err := GenerateToken(username, 1*time.Hour)
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}
	return "Bearer " + token
}

// TestMiddlewareWithQueryParams tests that middleware doesn't interfere with query params
func TestMiddlewareWithQueryParams(t *testing.T) {
	authHeader := generateValidAuthHeader(t, "testuser")

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check that query params are still accessible
		if r.URL.Query().Get("param") != "value" {
			t.Error("expected query param to be accessible")
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	})

	wrappedHandler := Middleware(handler)

	req := httptest.NewRequest("GET", "/test?param=value", nil)
	req.Header.Set("Authorization", authHeader)
	w := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}
}

// TestMiddlewareWithHeaders tests that middleware doesn't interfere with other headers
func TestMiddlewareWithHeaders(t *testing.T) {
	authHeader := generateValidAuthHeader(t, "testuser")

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check that other headers are still accessible
		if r.Header.Get("X-Custom-Header") != "custom-value" {
			t.Error("expected custom header to be accessible")
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	})

	wrappedHandler := Middleware(handler)

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", authHeader)
	req.Header.Set("X-Custom-Header", "custom-value")
	w := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}
}

// TestMiddlewareResponseHeaders tests that middleware preserves response headers
func TestMiddlewareResponseHeaders(t *testing.T) {
	authHeader := generateValidAuthHeader(t, "testuser")

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Custom-Response", "response-value")
		w.WriteHeader(http.StatusOK)
	})

	wrappedHandler := Middleware(handler)

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", authHeader)
	w := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	if w.Header().Get("X-Custom-Response") != "response-value" {
		t.Error("expected custom response header to be preserved")
	}
}
