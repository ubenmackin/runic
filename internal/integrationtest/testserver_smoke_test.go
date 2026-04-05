package integrationtest

import (
	"encoding/json"
	"net/http"
	"testing"
)

// TestAPIServerSmoke is a smoke test that verifies the test server infrastructure works.
// It tests the three core requirements:
// 1. Setup endpoint responds (200 or 401)
// 2. Info endpoint without auth returns 401
// 3. Authenticated request to info returns 200
func TestAPIServerSmoke(t *testing.T) {
	// Create test server
	server, cleanup := NewTestAPIServer(t)
	defer cleanup()
	defer server.Close()

	// Test 1: Verify /api/v1/setup responds (200 or 401)
	t.Run("SetupEndpoint", func(t *testing.T) {
		req, err := http.NewRequest("GET", server.URL+"/api/v1/setup", nil)
		if err != nil {
			t.Fatalf("failed to create request: %v", err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("failed to execute request: %v", err)
		}
		defer resp.Body.Close()

		// Setup should respond with 200 (if already configured) or 401 (if not)
		if resp.StatusCode != 200 && resp.StatusCode != 401 {
			t.Errorf("expected status 200 or 401, got %d", resp.StatusCode)
		}
	})

	// Test 2: Verify /api/v1/info without auth returns 401
	t.Run("InfoWithoutAuth", func(t *testing.T) {
		req, err := http.NewRequest("GET", server.URL+"/api/v1/info", nil)
		if err != nil {
			t.Fatalf("failed to create request: %v", err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("failed to execute request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != 401 {
			t.Errorf("expected status 401 without auth, got %d", resp.StatusCode)
		}
	})

	// Test 3: Verify authenticated request to /api/v1/info returns 200
	t.Run("InfoWithAuth", func(t *testing.T) {
		resp := JSONRequest(t, server, "GET", "/api/v1/info", nil, "testuser", "admin")
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			t.Errorf("expected status 200 with auth, got %d", resp.StatusCode)
		}

		// Verify response is valid JSON with version info
		var info map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
			t.Errorf("failed to decode response: %v", err)
		}
		if info["version"] == nil {
			t.Error("expected version in response")
		}
	})
}
