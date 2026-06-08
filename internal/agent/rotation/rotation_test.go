package rotation

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"runic/internal/agent/identity"
)

func helperConfig() *identity.Config {
	return &identity.Config{
		ControlPlaneURL: "http://localhost:8080",
		HostID:          "host-test-peer",
		Token:           "test-agent-token",
		HMACKey:         "old-hmac-key-12345678901234567890123456789012",
	}
}

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

func TestNewManager(t *testing.T) {
	cfg := helperConfig()
	configPath := helperConfigPath(t, cfg)

	manager := NewManager(configPath, &http.Client{}, "http://localhost:8080", "host-test-peer")

	if manager == nil {
		t.Fatal("NewManager() returned nil")
	}

	if manager.state != StateIdle {
		t.Errorf("NewManager() state = %v, want %v", manager.state, StateIdle)
	}

	if manager.hostID != "host-test-peer" {
		t.Errorf("NewManager() hostID = %s, want host-test-peer", manager.hostID)
	}
}

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

	manager := NewManager(configPath, server.Client(), server.URL, "host-test-peer")

	newKey, err := manager.CheckAndRotate(context.Background(), cfg.HMACKey, cfg.Token)
	if err != nil {
		t.Fatalf("CheckAndRotate() error = %v", err)
	}
	if newKey != "" {
		t.Errorf("CheckAndRotate() newKey = %s, want empty", newKey)
	}

	if manager.GetState() != StateIdle {
		t.Errorf("CheckAndRotate() state = %v, want %v", manager.GetState(), StateIdle)
	}
}

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

	manager := NewManager(configPath, server.Client(), server.URL, "host-test-peer")

	newKey, err := manager.CheckAndRotate(context.Background(), cfg.HMACKey, cfg.Token)
	if err != nil {
		t.Fatalf("CheckAndRotate() error = %v", err)
	}
	if newKey != "" {
		t.Errorf("CheckAndRotate() newKey = %s, want empty", newKey)
	}

	if manager.GetState() != StateIdle {
		t.Errorf("CheckAndRotate() state = %v, want %v", manager.GetState(), StateIdle)
	}
}

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

	manager := NewManager(configPath, server.Client(), server.URL, "host-test-peer")

	newKey, err := manager.CheckAndRotate(context.Background(), cfg.HMACKey, cfg.Token)
	if err != nil {
		t.Fatalf("CheckAndRotate() error = %v", err)
	}

	if manager.GetState() != StateConfirmed {
		t.Errorf("CheckAndRotate() state = %v, want %v", manager.GetState(), StateConfirmed)
	}

	if newKey != "new-hmac-key-abcdef123456789012345678901234" {
		t.Errorf("CheckAndRotate() newKey = %s, want new-hmac-key-abcdef123456789012345678901234", newKey)
	}

	// Verify old key was preserved (Manager no longer mutates config pointer)
	if cfg.HMACKey != "old-hmac-key-12345678901234567890123456789012" {
		t.Errorf("config HMACKey was mutated by Manager = %s, want old key preserved", cfg.HMACKey)
	}

	// Verify last rotation timestamp was set
	if manager.GetLastRotation().IsZero() {
		t.Error("last rotation timestamp was not set")
	}
}

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

	manager := NewManager(configPath, server.Client(), server.URL, "host-test-peer")

	_, err := manager.CheckAndRotate(context.Background(), cfg.HMACKey, cfg.Token)
	if err == nil {
		t.Error("CheckAndRotate() should have failed with expired token")
	}

	if manager.GetState() != StateFailed {
		t.Errorf("CheckAndRotate() state = %v, want %v", manager.GetState(), StateFailed)
	}

	// Verify old key was preserved (Manager no longer mutates config pointer)
	if cfg.HMACKey != "old-hmac-key-12345678901234567890123456789012" {
		t.Errorf("config HMACKey was changed on failure: %s", cfg.HMACKey)
	}
}

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

	manager := NewManager(configPath, server.Client(), server.URL, "host-test-peer")

	_, err := manager.CheckAndRotate(context.Background(), cfg.HMACKey, cfg.Token)
	if err == nil {
		t.Error("CheckAndRotate() should have failed when key test fails")
	}

	if manager.GetState() != StateFallback {
		t.Errorf("CheckAndRotate() state = %v, want %v", manager.GetState(), StateFallback)
	}

	// Verify old key was preserved (Manager no longer mutates config pointer)
	if cfg.HMACKey != "old-hmac-key-12345678901234567890123456789012" {
		t.Errorf("config HMACKey was changed on key test failure: %s", cfg.HMACKey)
	}
}

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

	manager := NewManager(configPath, server.Client(), server.URL, "host-test-peer")

	// Confirm-rotation failure IS now fatal (error state)
	_, err := manager.CheckAndRotate(context.Background(), cfg.HMACKey, cfg.Token)
	if err == nil {
		t.Fatal("CheckAndRotate() expected error when confirm-rotation fails")
	}
	if !strings.Contains(err.Error(), "confirm rotation") {
		t.Errorf("CheckAndRotate() error = %v, want 'confirm rotation'", err)
	}

	if manager.GetState() != StateFailed {
		t.Errorf("CheckAndRotate() state = %v, want %v", manager.GetState(), StateFailed)
	}
}

func TestCheckAndRotate_SkipsInProgress(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("HTTP request should not be made when rotation is in progress")
	}))
	defer server.Close()

	cfg := helperConfig()
	cfg.ControlPlaneURL = server.URL
	configPath := helperConfigPath(t, cfg)

	manager := NewManager(configPath, server.Client(), server.URL, "host-test-peer")

	// Manually set state to rotating
	manager.mu.Lock()
	manager.state = StateRotating
	manager.mu.Unlock()

	newKey, err := manager.CheckAndRotate(context.Background(), cfg.HMACKey, cfg.Token)
	if err != nil {
		t.Fatalf("CheckAndRotate() error = %v", err)
	}
	if newKey != "" {
		t.Errorf("CheckAndRotate() newKey = %s, want empty", newKey)
	}

	// State should remain rotating (not changed)
	if manager.GetState() != StateRotating {
		t.Errorf("CheckAndRotate() state = %v, want %v", manager.GetState(), StateRotating)
	}
}

func TestCheckAndRotate_SkipsTesting(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("HTTP request should not be made when testing is in progress")
	}))
	defer server.Close()

	cfg := helperConfig()
	cfg.ControlPlaneURL = server.URL
	configPath := helperConfigPath(t, cfg)

	manager := NewManager(configPath, server.Client(), server.URL, "host-test-peer")

	// Manually set state to testing
	manager.mu.Lock()
	manager.state = StateTesting
	manager.mu.Unlock()

	newKey, err := manager.CheckAndRotate(context.Background(), cfg.HMACKey, cfg.Token)
	if err != nil {
		t.Fatalf("CheckAndRotate() error = %v", err)
	}
	if newKey != "" {
		t.Errorf("CheckAndRotate() newKey = %s, want empty", newKey)
	}

	if manager.GetState() != StateTesting {
		t.Errorf("CheckAndRotate() state = %v, want %v", manager.GetState(), StateTesting)
	}
}

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

	manager := NewManager(configPath, server.Client(), server.URL, "host-test-peer")

	_, err := manager.CheckAndRotate(context.Background(), cfg.HMACKey, cfg.Token)
	if err == nil {
		t.Error("CheckAndRotate() should have failed with empty key")
	}

	if manager.GetState() != StateFailed {
		t.Errorf("CheckAndRotate() state = %v, want %v", manager.GetState(), StateFailed)
	}
}

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

	manager := NewManager(configPath, server.Client(), server.URL, "host-test-peer")

	_, err := manager.CheckAndRotate(context.Background(), cfg.HMACKey, cfg.Token)
	if err == nil {
		t.Error("CheckAndRotate() should have failed with unexpected status code")
	}
}

func TestGetState(t *testing.T) {
	configPath := helperConfigPath(t, helperConfig())

	manager := NewManager(configPath, &http.Client{}, "http://localhost:8080", "host-test-peer")

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

func TestGetLastRotation(t *testing.T) {
	configPath := helperConfigPath(t, helperConfig())

	manager := NewManager(configPath, &http.Client{}, "http://localhost:8080", "host-test-peer")

	// Initially should be zero
	if !manager.GetLastRotation().IsZero() {
		t.Error("GetLastRotation() should be zero initially")
	}

	expected := time.Now().UTC()
	manager.mu.Lock()
	manager.lastRotation = expected
	manager.mu.Unlock()

	if manager.GetLastRotation() != expected {
		t.Errorf("GetLastRotation() = %v, want %v", manager.GetLastRotation(), expected)
	}
}

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

	manager := NewManager(configPath, server.Client(), server.URL, "host-test-peer")

	_, err := manager.CheckAndRotate(context.Background(), cfg.HMACKey, cfg.Token)
	if err == nil {
		t.Error("CheckAndRotate() should have failed with invalid JSON response")
	}
}

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

	manager := NewManager(configPath, server.Client(), server.URL, "host-test-peer")

	_, err := manager.CheckAndRotate(context.Background(), cfg.HMACKey, cfg.Token)
	if err == nil {
		t.Error("CheckAndRotate() should have failed with invalid JSON from rotate-key")
	}

	if manager.GetState() != StateFailed {
		t.Errorf("CheckAndRotate() state = %v, want %v", manager.GetState(), StateFailed)
	}
}
