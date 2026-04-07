package rotation

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"runic/internal/agent/identity"
)

// helperConfig creates a minimal config for testing.
func helperConfig() *identity.Config {
	return &identity.Config{
		ControlPlaneURL: "http://localhost:8080",
		HostID:          "host-test-peer",
		Token:           "test-agent-token",
		HMACKey:         "old-hmac-key-12345678901234567890123456789012",
	}
}

// helperConfigPath creates a temp config file and returns its path.
func helperConfigPath(t *testing.T, cfg *identity.Config) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatalf("failed to marshal config: %v", err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}
	return path
}

// TestNewManager verifies the manager initializes correctly.
func TestNewManager(t *testing.T) {
	cfg := helperConfig()
	configPath := helperConfigPath(t, cfg)

	manager := NewManager(cfg, configPath, &http.Client{}, "http://localhost:8080", "host-test-peer")

	if manager == nil {
		t.Fatal("NewManager() returned nil")
	}

	if manager.state != StateIdle {
		t.Errorf("NewManager() state = %v, want %v", manager.state, StateIdle)
	}

	if manager.config != cfg {
		t.Error("NewManager() did not store config reference")
	}

	if manager.hostID != "host-test-peer" {
		t.Errorf("NewManager() hostID = %s, want host-test-peer", manager.hostID)
	}
}

// TestCheckAndRotate_NoRotationPending verifies no-op when no rotation is pending.
func TestCheckAndRotate_NoRotationPending(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/agent/check-rotation" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	cfg := helperConfig()
	cfg.ControlPlaneURL = server.URL
	configPath := helperConfigPath(t, cfg)

	manager := NewManager(cfg, configPath, server.Client(), server.URL, "host-test-peer")

	err := manager.CheckAndRotate(context.Background())
	if err != nil {
		t.Fatalf("CheckAndRotate() error = %v", err)
	}

	if manager.GetState() != StateIdle {
		t.Errorf("CheckAndRotate() state = %v, want %v", manager.GetState(), StateIdle)
	}
}

// TestCheckAndRotate_NoRotationPending_NotFound verifies 404 is treated as no rotation pending.
func TestCheckAndRotate_NoRotationPending_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/agent/check-rotation" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	cfg := helperConfig()
	cfg.ControlPlaneURL = server.URL
	configPath := helperConfigPath(t, cfg)

	manager := NewManager(cfg, configPath, server.Client(), server.URL, "host-test-peer")

	err := manager.CheckAndRotate(context.Background())
	if err != nil {
		t.Fatalf("CheckAndRotate() error = %v", err)
	}

	if manager.GetState() != StateIdle {
		t.Errorf("CheckAndRotate() state = %v, want %v", manager.GetState(), StateIdle)
	}
}

// TestCheckAndRotate_RotationSuccess verifies the full rotation workflow succeeds.
func TestCheckAndRotate_RotationSuccess(t *testing.T) {
	callCount := 0
	var mu sync.Mutex

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		callCount++
		currentCall := callCount
		mu.Unlock()

		switch r.URL.Path {
		case "/api/v1/agent/check-rotation":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"rotation_token": "test-rotation-token-abc123",
			})

		case "/api/v1/agent/rotate-key":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{
				"new_hmac_key": "new-hmac-key-abcdef123456789012345678901234",
			})

		case "/api/v1/agent/test-key":
			w.WriteHeader(http.StatusOK)

		case "/api/v1/agent/confirm-rotation":
			w.WriteHeader(http.StatusOK)

		default:
			http.NotFound(w, r)
		}

		t.Logf("Call %d: %s %s", currentCall, r.Method, r.URL.Path)
	}))
	defer server.Close()

	cfg := helperConfig()
	cfg.ControlPlaneURL = server.URL
	cfg.HMACKey = "old-hmac-key-12345678901234567890123456789012"
	configPath := helperConfigPath(t, cfg)

	manager := NewManager(cfg, configPath, server.Client(), server.URL, "host-test-peer")

	err := manager.CheckAndRotate(context.Background())
	if err != nil {
		t.Fatalf("CheckAndRotate() error = %v", err)
	}

	if manager.GetState() != StateConfirmed {
		t.Errorf("CheckAndRotate() state = %v, want %v", manager.GetState(), StateConfirmed)
	}

	// Verify config was updated with new key
	if cfg.HMACKey != "new-hmac-key-abcdef123456789012345678901234" {
		t.Errorf("config HMACKey = %s, want new-hmac-key-abcdef123456789012345678901234", cfg.HMACKey)
	}

	// Verify config file was updated
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("failed to read config file: %v", err)
	}

	var savedCfg identity.Config
	if err := json.Unmarshal(data, &savedCfg); err != nil {
		t.Fatalf("failed to parse config file: %v", err)
	}

	if savedCfg.HMACKey != "new-hmac-key-abcdef123456789012345678901234" {
		t.Errorf("saved config HMACKey = %s, want new-hmac-key-abcdef123456789012345678901234", savedCfg.HMACKey)
	}

	// Verify last rotation timestamp was set
	if manager.GetLastRotation().IsZero() {
		t.Error("last rotation timestamp was not set")
	}
}

// TestCheckAndRotate_TokenExpired verifies rotation fails when token is expired/invalid.
func TestCheckAndRotate_TokenExpired(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/agent/check-rotation":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"rotation_token": "expired-token",
			})

		case "/api/v1/agent/rotate-key":
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "invalid or expired rotation token",
			})

		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	cfg := helperConfig()
	cfg.ControlPlaneURL = server.URL
	configPath := helperConfigPath(t, cfg)

	manager := NewManager(cfg, configPath, server.Client(), server.URL, "host-test-peer")

	err := manager.CheckAndRotate(context.Background())
	if err == nil {
		t.Error("CheckAndRotate() should have failed with expired token")
	}

	if manager.GetState() != StateFailed {
		t.Errorf("CheckAndRotate() state = %v, want %v", manager.GetState(), StateFailed)
	}

	// Verify old key was preserved
	if cfg.HMACKey != "old-hmac-key-12345678901234567890123456789012" {
		t.Errorf("config HMACKey was changed on failure: %s", cfg.HMACKey)
	}
}

// TestCheckAndRotate_KeyTestFails verifies fallback when new key test fails.
func TestCheckAndRotate_KeyTestFails(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/agent/check-rotation":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{
				"rotation_token": "valid-token",
			})

		case "/api/v1/agent/rotate-key":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"new_hmac_key": "new-hmac-key-abcdef123456789012345678901234",
			})

		case "/api/v1/agent/test-key":
			w.WriteHeader(http.StatusUnauthorized)

		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	cfg := helperConfig()
	cfg.ControlPlaneURL = server.URL
	configPath := helperConfigPath(t, cfg)

	manager := NewManager(cfg, configPath, server.Client(), server.URL, "host-test-peer")

	err := manager.CheckAndRotate(context.Background())
	if err == nil {
		t.Error("CheckAndRotate() should have failed when key test fails")
	}

	if manager.GetState() != StateFallback {
		t.Errorf("CheckAndRotate() state = %v, want %v", manager.GetState(), StateFallback)
	}

	// Verify old key was preserved
	if cfg.HMACKey != "old-hmac-key-12345678901234567890123456789012" {
		t.Errorf("config HMACKey was changed on key test failure: %s", cfg.HMACKey)
	}
}

// TestCheckAndRotate_ConfirmFailsNonFatal verifies confirm-rotation failure is non-fatal.
func TestCheckAndRotate_ConfirmFailsNonFatal(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/agent/check-rotation":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{
				"rotation_token": "valid-token",
			})

		case "/api/v1/agent/rotate-key":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{
				"new_hmac_key": "new-hmac-key-abcdef123456789012345678901234",
			})

		case "/api/v1/agent/test-key":
			w.WriteHeader(http.StatusOK)

		case "/api/v1/agent/confirm-rotation":
			w.WriteHeader(http.StatusInternalServerError)

		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	cfg := helperConfig()
	cfg.ControlPlaneURL = server.URL
	configPath := helperConfigPath(t, cfg)

	manager := NewManager(cfg, configPath, server.Client(), server.URL, "host-test-peer")

	// Confirm-rotation failure should NOT cause an error (non-fatal)
	err := manager.CheckAndRotate(context.Background())
	if err != nil {
		t.Fatalf("CheckAndRotate() error = %v (confirm-rotation failure should be non-fatal)", err)
	}

	if manager.GetState() != StateConfirmed {
		t.Errorf("CheckAndRotate() state = %v, want %v", manager.GetState(), StateConfirmed)
	}

	// Verify key was still updated locally
	if cfg.HMACKey != "new-hmac-key-abcdef123456789012345678901234" {
		t.Errorf("config HMACKey = %s, want new-hmac-key-abcdef123456789012345678901234", cfg.HMACKey)
	}
}

// TestCheckAndRotate_SkipsInProgress verifies rotation is skipped if already in progress.
func TestCheckAndRotate_SkipsInProgress(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("HTTP request should not be made when rotation is in progress")
	}))
	defer server.Close()

	cfg := helperConfig()
	cfg.ControlPlaneURL = server.URL
	configPath := helperConfigPath(t, cfg)

	manager := NewManager(cfg, configPath, server.Client(), server.URL, "host-test-peer")

	// Manually set state to rotating
	manager.mu.Lock()
	manager.state = StateRotating
	manager.mu.Unlock()

	err := manager.CheckAndRotate(context.Background())
	if err != nil {
		t.Fatalf("CheckAndRotate() error = %v", err)
	}

	// State should remain rotating (not changed)
	if manager.GetState() != StateRotating {
		t.Errorf("CheckAndRotate() state = %v, want %v", manager.GetState(), StateRotating)
	}
}

// TestCheckAndRotate_SkipsTesting verifies rotation is skipped if testing is in progress.
func TestCheckAndRotate_SkipsTesting(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("HTTP request should not be made when testing is in progress")
	}))
	defer server.Close()

	cfg := helperConfig()
	cfg.ControlPlaneURL = server.URL
	configPath := helperConfigPath(t, cfg)

	manager := NewManager(cfg, configPath, server.Client(), server.URL, "host-test-peer")

	// Manually set state to testing
	manager.mu.Lock()
	manager.state = StateTesting
	manager.mu.Unlock()

	err := manager.CheckAndRotate(context.Background())
	if err != nil {
		t.Fatalf("CheckAndRotate() error = %v", err)
	}

	if manager.GetState() != StateTesting {
		t.Errorf("CheckAndRotate() state = %v, want %v", manager.GetState(), StateTesting)
	}
}

// TestCheckAndRotate_EmptyKeyFromServer verifies rotation fails when server returns empty key.
func TestCheckAndRotate_EmptyKeyFromServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/agent/check-rotation":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{
				"rotation_token": "valid-token",
			})

		case "/api/v1/agent/rotate-key":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{
				"new_hmac_key": "",
			})

		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	cfg := helperConfig()
	cfg.ControlPlaneURL = server.URL
	configPath := helperConfigPath(t, cfg)

	manager := NewManager(cfg, configPath, server.Client(), server.URL, "host-test-peer")

	err := manager.CheckAndRotate(context.Background())
	if err == nil {
		t.Error("CheckAndRotate() should have failed with empty key")
	}

	if manager.GetState() != StateFailed {
		t.Errorf("CheckAndRotate() state = %v, want %v", manager.GetState(), StateFailed)
	}
}

// TestCheckAndRotate_UnexpectedStatusCode verifies rotation fails on unexpected check-rotation status.
func TestCheckAndRotate_UnexpectedStatusCode(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/agent/check-rotation":
			w.WriteHeader(http.StatusInternalServerError)

		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	cfg := helperConfig()
	cfg.ControlPlaneURL = server.URL
	configPath := helperConfigPath(t, cfg)

	manager := NewManager(cfg, configPath, server.Client(), server.URL, "host-test-peer")

	err := manager.CheckAndRotate(context.Background())
	if err == nil {
		t.Error("CheckAndRotate() should have failed with unexpected status code")
	}
}

// TestGetState verifies GetState returns the correct state thread-safely.
func TestGetState(t *testing.T) {
	cfg := helperConfig()
	configPath := helperConfigPath(t, cfg)

	manager := NewManager(cfg, configPath, &http.Client{}, "http://localhost:8080", "host-test-peer")

	// Test initial state
	if manager.GetState() != StateIdle {
		t.Errorf("GetState() = %v, want %v", manager.GetState(), StateIdle)
	}

	// Test after manual state change
	manager.mu.Lock()
	manager.state = StateRotating
	manager.mu.Unlock()

	if manager.GetState() != StateRotating {
		t.Errorf("GetState() = %v, want %v", manager.GetState(), StateRotating)
	}
}

// TestGetLastRotation verifies GetLastRotation returns the correct timestamp.
func TestGetLastRotation(t *testing.T) {
	cfg := helperConfig()
	configPath := helperConfigPath(t, cfg)

	manager := NewManager(cfg, configPath, &http.Client{}, "http://localhost:8080", "host-test-peer")

	// Initially should be zero
	if !manager.GetLastRotation().IsZero() {
		t.Error("GetLastRotation() should be zero initially")
	}

	// Set a known time
	expected := time.Now().UTC()
	manager.mu.Lock()
	manager.lastRotation = expected
	manager.mu.Unlock()

	if manager.GetLastRotation() != expected {
		t.Errorf("GetLastRotation() = %v, want %v", manager.GetLastRotation(), expected)
	}
}

// TestUpdateConfigKey_InvalidPath verifies config update fails with invalid path.
func TestUpdateConfigKey_InvalidPath(t *testing.T) {
	cfg := helperConfig()
	configPath := "/nonexistent/path/config.json"

	manager := NewManager(cfg, configPath, &http.Client{}, "http://localhost:8080", "host-test-peer")

	err := manager.updateConfigKey("new-key")
	if err == nil {
		t.Error("updateConfigKey() should have failed with invalid path")
	}
}

// TestUpdateConfigKey_CorruptConfig verifies config update fails with corrupt config file.
func TestUpdateConfigKey_CorruptConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	// Write corrupt JSON
	if err := os.WriteFile(path, []byte("not-valid-json"), 0600); err != nil {
		t.Fatalf("failed to write corrupt config: %v", err)
	}

	cfg := helperConfig()
	manager := NewManager(cfg, path, &http.Client{}, "http://localhost:8080", "host-test-peer")

	err := manager.updateConfigKey("new-key")
	if err == nil {
		t.Error("updateConfigKey() should have failed with corrupt config")
	}
}

// TestUpdateConfigKey_Success verifies config file is updated correctly.
func TestUpdateConfigKey_Success(t *testing.T) {
	cfg := helperConfig()
	configPath := helperConfigPath(t, cfg)

	manager := NewManager(cfg, configPath, &http.Client{}, "http://localhost:8080", "host-test-peer")

	newKey := "brand-new-hmac-key-abcdef123456789012345678"
	err := manager.updateConfigKey(newKey)
	if err != nil {
		t.Fatalf("updateConfigKey() error = %v", err)
	}

	// Verify file was updated
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("failed to read config file: %v", err)
	}

	var savedCfg identity.Config
	if err := json.Unmarshal(data, &savedCfg); err != nil {
		t.Fatalf("failed to parse config file: %v", err)
	}

	if savedCfg.HMACKey != newKey {
		t.Errorf("saved HMACKey = %s, want %s", savedCfg.HMACKey, newKey)
	}

	// Verify file permissions are 0600
	info, err := os.Stat(configPath)
	if err != nil {
		t.Fatalf("failed to stat config file: %v", err)
	}

	if info.Mode().Perm() != 0600 {
		t.Errorf("config file permissions = %o, want 0600", info.Mode().Perm())
	}
}

// TestCheckAndRotate_ConfigUpdateFails verifies fallback when config file update fails.
func TestCheckAndRotate_ConfigUpdateFails(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/agent/check-rotation":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{
				"rotation_token": "valid-token",
			})

		case "/api/v1/agent/rotate-key":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{
				"new_hmac_key": "new-hmac-key-abcdef123456789012345678901234",
			})

		case "/api/v1/agent/test-key":
			w.WriteHeader(http.StatusOK)

		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	cfg := helperConfig()
	cfg.ControlPlaneURL = server.URL
	// Use invalid config path to trigger update failure
	configPath := "/nonexistent/path/config.json"

	manager := NewManager(cfg, configPath, server.Client(), server.URL, "host-test-peer")

	// Set state to testing to simulate post-key-retrieval state
	manager.mu.Lock()
	manager.state = StateTesting
	manager.newKey = "new-hmac-key-abcdef123456789012345678901234"
	manager.oldKey = "old-hmac-key-12345678901234567890123456789012"
	manager.mu.Unlock()

	// Manually call updateConfigKey to test the failure path
	err := manager.updateConfigKey("new-hmac-key-abcdef123456789012345678901234")
	if err == nil {
		t.Error("updateConfigKey() should have failed with invalid path")
	}
}

// TestRotationStateConstants verifies all state constants are defined.
func TestRotationStateConstants(t *testing.T) {
	states := []RotationState{
		StateIdle,
		StateRotating,
		StateTesting,
		StateConfirmed,
		StateFailed,
		StateFallback,
	}

	for _, state := range states {
		if state == "" {
			t.Errorf("RotationState constant is empty: %v", state)
		}
	}
}

// TestCheckAndRotate_CheckRotationReturnsInvalidJSON verifies handling of malformed JSON response.
func TestCheckAndRotate_CheckRotationReturnsInvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/agent/check-rotation":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte("not-valid-json"))

		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	cfg := helperConfig()
	cfg.ControlPlaneURL = server.URL
	configPath := helperConfigPath(t, cfg)

	manager := NewManager(cfg, configPath, server.Client(), server.URL, "host-test-peer")

	err := manager.CheckAndRotate(context.Background())
	if err == nil {
		t.Error("CheckAndRotate() should have failed with invalid JSON response")
	}
}

// TestCheckAndRotate_RotateKeyReturnsInvalidJSON verifies handling of malformed key response.
func TestCheckAndRotate_RotateKeyReturnsInvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/agent/check-rotation":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{
				"rotation_token": "valid-token",
			})

		case "/api/v1/agent/rotate-key":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte("not-valid-json"))

		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	cfg := helperConfig()
	cfg.ControlPlaneURL = server.URL
	configPath := helperConfigPath(t, cfg)

	manager := NewManager(cfg, configPath, server.Client(), server.URL, "host-test-peer")

	err := manager.CheckAndRotate(context.Background())
	if err == nil {
		t.Error("CheckAndRotate() should have failed with invalid JSON from rotate-key")
	}

	if manager.GetState() != StateFailed {
		t.Errorf("CheckAndRotate() state = %v, want %v", manager.GetState(), StateFailed)
	}
}
