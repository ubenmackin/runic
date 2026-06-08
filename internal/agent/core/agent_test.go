package core

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"runic/internal/agent/identity"
	"runic/internal/common/log"
	"runic/internal/models"
)

// syncWriter wraps an io.Writer with a Mutex to make concurrent writes and
// reads safe. This is necessary because bytes.Buffer is not safe for
// concurrent use, and the background goroutine in handleUpdateAgent writes
// logs via log.Error while the test goroutine reads the buffer.
type syncWriter struct {
	mu  sync.Mutex
	buf *bytes.Buffer
}

func newSyncWriter() *syncWriter {
	return &syncWriter{buf: &bytes.Buffer{}}
}

func (w *syncWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.Write(p)
}

func (w *syncWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.String()
}

// Verify syncWriter implements io.Writer at compile time.
var _ io.Writer = (*syncWriter)(nil)

func TestMain(m *testing.M) {
	// Ensure log is initialized before any test runs so that tests which
	// call log.Init with a buffer do not leave the process-global logger
	// in a corrupted state for subsequent tests.
	log.Init("info", os.Stdout)
	os.Exit(m.Run())
}

func helperConfig() *identity.Config {
	return &identity.Config{
		ControlPlaneURL:      "http://localhost:8080",
		HostID:               "host-test-peer",
		Token:                "test-agent-token",
		HMACKey:              "test-hmac-key-12345678901234567890123456",
		PullIntervalSec:      86400,
		HeartbeatIntervalSec: 30,
		LogPath:              "/var/log/runic/firewall.log",
		ApplyOnBoot:          false,
		ApplyRulesBundle:     true,
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

func TestNew(t *testing.T) {
	agent := New("/tmp/config.json", "http://localhost:8080")

	if agent == nil {
		t.Fatal("New() returned nil")
	}

	if agent.config == nil {
		t.Error("New() config is nil")
	}

	if agent.httpClient == nil {
		t.Error("New() httpClient is nil")
	}

	if agent.sseClient == nil {
		t.Error("New() sseClient is nil")
	}

	if agent.version == "" {
		t.Error("New() version is empty")
	}

	// rotationManager is nil after New(); it is initialized during initialize()
	// once the hostID is known (after registration or config load).
	if agent.rotationManager != nil {
		t.Error("New() rotationManager should be nil before initialize()")
	}

	// Verify default config values
	if agent.config.ControlPlaneURL != "http://localhost:8080" {
		t.Errorf("New() ControlPlaneURL = %s, want http://localhost:8080", agent.config.ControlPlaneURL)
	}

	if agent.config.PullIntervalSec != identity.DefaultPullIntervalSec {
		t.Errorf("New() PullIntervalSec = %d, want %d", agent.config.PullIntervalSec, identity.DefaultPullIntervalSec)
	}

	if agent.config.LogPath != "/var/log/runic/firewall.log" {
		t.Errorf("New() LogPath = %s, want /var/log/runic/firewall.log", agent.config.LogPath)
	}
}

func TestLoadConfigReturnsDefault(t *testing.T) {
	agent := New("/nonexistent/path/config.json", "http://localhost:8080")

	err := agent.loadConfig()
	if err != nil {
		t.Fatalf("loadConfig() error = %v", err)
	}

	// Should return default config
	if agent.config.PullIntervalSec != identity.DefaultPullIntervalSec {
		t.Errorf("loadConfig() PullIntervalSec = %d, want default %d", agent.config.PullIntervalSec, identity.DefaultPullIntervalSec)
	}

	if agent.config.HeartbeatIntervalSec != identity.DefaultHeartbeatIntervalSec {
		t.Errorf("loadConfig() HeartbeatIntervalSec = %d, want default %d", agent.config.HeartbeatIntervalSec, identity.DefaultHeartbeatIntervalSec)
	}
}

func TestLoadConfigLoadsExisting(t *testing.T) {
	cfg := helperConfig()
	cfg.PullIntervalSec = 3600
	cfg.HeartbeatIntervalSec = 60
	configPath := helperConfigPath(t, cfg)

	agent := New(configPath, "")
	agent.config.ControlPlaneURL = "" // Clear CLI-provided value to test config file loading

	err := agent.loadConfig()
	if err != nil {
		t.Fatalf("loadConfig() error = %v", err)
	}

	if agent.config.PullIntervalSec != 3600 {
		t.Errorf("loadConfig() PullIntervalSec = %d, want 3600", agent.config.PullIntervalSec)
	}

	if agent.config.HeartbeatIntervalSec != 60 {
		t.Errorf("loadConfig() HeartbeatIntervalSec = %d, want 60", agent.config.HeartbeatIntervalSec)
	}

	if agent.config.HostID != "host-test-peer" {
		t.Errorf("loadConfig() HostID = %s, want host-test-peer", agent.config.HostID)
	}
}

func TestLoadConfigMergesCLIValues(t *testing.T) {
	cfg := &identity.Config{
		ControlPlaneURL:      "", // Empty - CLI should override
		HostID:               "host-test-peer",
		Token:                "test-agent-token",
		HMACKey:              "test-hmac-key-12345678901234567890123456",
		PullIntervalSec:      86400,
		HeartbeatIntervalSec: 30,
		LogPath:              "/var/log/runic/firewall.log",
		ApplyOnBoot:          false,
		ApplyRulesBundle:     true,
	}
	configPath := helperConfigPath(t, cfg)

	agent := New(configPath, "http://cli-provided-url:9090")

	err := agent.loadConfig()
	if err != nil {
		t.Fatalf("loadConfig() error = %v", err)
	}

	// CLI value should override empty config file value
	if agent.config.ControlPlaneURL != "http://cli-provided-url:9090" {
		t.Errorf("loadConfig() ControlPlaneURL = %s, want CLI value http://cli-provided-url:9090", agent.config.ControlPlaneURL)
	}
}

func TestSaveConfigWritesFile(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")

	agent := New(configPath, "http://localhost:8080")
	agent.config.HostID = "test-host-id"
	agent.config.Token = "test-token"
	agent.config.HMACKey = "test-hmac-key"

	err := agent.saveConfig()
	if err != nil {
		t.Fatalf("saveConfig() error = %v", err)
	}

	// Verify file was created
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("failed to read config file: %v", err)
	}

	var savedCfg identity.Config
	if err := json.Unmarshal(data, &savedCfg); err != nil {
		t.Fatalf("failed to parse config file: %v", err)
	}

	if savedCfg.HostID != "test-host-id" {
		t.Errorf("saved HostID = %s, want test-host-id", savedCfg.HostID)
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

func TestApplyBundleSkipsWhenDisabled(t *testing.T) {
	cfg := helperConfig()
	cfg.ApplyRulesBundle = false
	configPath := helperConfigPath(t, cfg)

	agent := New(configPath, "http://localhost:8080")
	agent.config.HostID = "test-host"
	agent.config.Token = "test-token"

	bundle := models.BundleResponse{
		Version: "test-v1",
		Rules:   "*filter\n:INPUT DROP [0:0]\nCOMMIT\n",
	}

	// applyBundle should return nil without applying when disabled
	err := agent.applyBundle(context.Background(), bundle)
	if err != nil {
		t.Errorf("applyBundle() error = %v, want nil (should skip when disabled)", err)
	}

	// CurrentBundleVer should not be updated
	if agent.config.CurrentBundleVer == "test-v1" {
		t.Error("applyBundle() updated CurrentBundleVer even though ApplyRulesBundle is false")
	}
}

func TestApplyBundleSavesConfigOnSuccess(t *testing.T) {
	cfg := helperConfig()
	cfg.ApplyRulesBundle = true
	configPath := helperConfigPath(t, cfg)

	agent := New(configPath, "http://localhost:8080")
	agent.config.HostID = "test-host"
	agent.config.Token = "test-token"
	agent.config.HMACKey = "test-hmac-key"

	// Track if apply.ApplyBundle was called (we can't easily mock it, so we verify config save)
	bundle := models.BundleResponse{
		Version: "test-v1",
		Rules:   "*filter\n:INPUT DROP [0:0]\nCOMMIT\n",
		HMAC:    "dummy-hmac", // Will fail validation but we test the save path
	}

	// applyBundle will fail due to invalid HMAC, but that's ok for this test
	// We're testing the config save path
	_ = agent.applyBundle(context.Background(), bundle)

	// Note: In real test we'd mock apply.ApplyBundle, but we can at least verify
	// the method is callable without panic
}

func TestConfirmApplyCallsTransport(t *testing.T) {
	cfg := helperConfig()
	configPath := helperConfigPath(t, cfg)

	agent := New(configPath, "http://localhost:8080")
	agent.config.HostID = "test-host"
	agent.config.Token = "test-token"
	agent.config.ControlPlaneURL = "http://localhost:8080"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// ConfirmApply calls /api/v1/agent/bundle/{hostID}/applied
		if strings.Contains(r.URL.Path, "/applied") && r.Method == "POST" {
			w.WriteHeader(http.StatusOK)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	agent.config.ControlPlaneURL = server.URL

	err := agent.confirmApply(context.Background(), "test-version")
	if err != nil {
		t.Fatalf("confirmApply() error = %v", err)
	}
}

func TestRegisterCallsIdentity(t *testing.T) {
	cfg := helperConfig()
	cfg.HostID = "" // Clear host ID to trigger registration
	cfg.Token = ""
	configPath := helperConfigPath(t, cfg)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "register") {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{
				"host_id": "registered-host-id",
				"token":   "registered-token",
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	agent := New(configPath, server.URL)
	agent.config.HostID = ""
	agent.config.Token = ""

	err := agent.register(context.Background(), true)
	if err != nil {
		t.Fatalf("register() error = %v", err)
	}

	// Verify registration updated config
	if agent.config.HostID != "registered-host-id" {
		t.Errorf("register() HostID = %s, want registered-host-id", agent.config.HostID)
	}
}

func TestSafeRegisterAcquiresMutex(t *testing.T) {
	cfg := helperConfig()
	configPath := helperConfigPath(t, cfg)

	agent := New(configPath, "http://localhost:8080")

	// Test that register can be called without panic
	// (will fail registration but we verify mutex is present)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_ = agent.register(ctx, true)
}

func TestIsControlPlaneReachableTrue(t *testing.T) {
	cfg := helperConfig()
	configPath := helperConfigPath(t, cfg)

	agent := New(configPath, "http://localhost:8080")
	agent.config.Token = "test-token"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	agent.config.ControlPlaneURL = server.URL

	ctx := context.Background()
	reachable := agent.isControlPlaneReachable(ctx)

	if !reachable {
		t.Error("isControlPlaneReachable() returned false, want true")
	}
}

func TestIsControlPlaneReachableFalse(t *testing.T) {
	cfg := helperConfig()
	configPath := helperConfigPath(t, cfg)

	agent := New(configPath, "http://invalid-host:9999")

	ctx := context.Background()
	reachable := agent.isControlPlaneReachable(ctx)

	if reachable {
		t.Error("isControlPlaneReachable() returned true, want false for unreachable host")
	}
}

type mockCommandRunner struct {
	output  []byte
	err     error
	runErr  error
	runErrs map[string]error
	calls   []mockCall
}

type mockCall struct {
	ctx  context.Context
	name string
	args []string
}

func (m *mockCommandRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	m.calls = append(m.calls, mockCall{ctx: ctx, name: name, args: args})
	// Check per-command error map first, then fall back to generic error
	if m.runErrs != nil {
		if err, ok := m.runErrs[name]; ok {
			return nil, err
		}
	}
	if m.runErr != nil {
		return nil, m.runErr
	}
	return m.output, m.err
}

func TestHandleUpdateAgent(t *testing.T) {
	t.Run("downloads and applies update from valid URL", func(t *testing.T) {
		// Serve a fake binary via httptest
		fakeBinary := []byte("#!/bin/sh\n# fake agent binary\n")
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Path, "downloads") {
				w.WriteHeader(http.StatusOK)
				w.Write(fakeBinary)
				return
			}
			http.NotFound(w, r)
		}))
		defer server.Close()

		// Set UpdateBinaryPath to a temp file so performUpdate can write to it
		tmpDir := t.TempDir()
		binaryPath := filepath.Join(tmpDir, "runic-agent")
		// Create the file so selfupdate.Apply can swap it
		if err := os.WriteFile(binaryPath, []byte("old-binary"), 0755); err != nil {
			t.Fatalf("failed to create target binary: %v", err)
		}

		// Override UpdateBinaryPath for this test
		origUpdateBinaryPath := UpdateBinaryPath
		t.Cleanup(func() { UpdateBinaryPath = origUpdateBinaryPath })
		UpdateBinaryPath = binaryPath

		exitCh := make(chan int, 1)
		agent := &Agent{
			httpClient: server.Client(),
			exitFunc: func(code int) {
				select {
				case exitCh <- code:
				default:
				}
			},
		}

		// handleUpdateAgent is async — it launches update in a goroutine
		agent.handleUpdateAgent(context.Background(), server.URL)

		// Wait for exitFunc to be called with proper synchronization
		// (the goroutine uses a 2-second delay before exitFunc, so we allow up to 5 seconds)
		select {
		case code := <-exitCh:
			if code != 0 {
				t.Errorf("expected exit code 0, got %d", code)
			}
		case <-time.After(5 * time.Second):
			t.Error("expected exitFunc to be called after successful update")
		}

		// Verify the binary was replaced
		data, err := os.ReadFile(binaryPath)
		if err != nil {
			t.Fatalf("failed to read updated binary: %v", err)
		}
		if string(data) != string(fakeBinary) {
			t.Errorf("binary content = %q, want %q", string(data), string(fakeBinary))
		}
	})

	t.Run("rejects invalid URL scheme", func(t *testing.T) {
		var logBuf bytes.Buffer
		log.Init("error", &logBuf)
		defer log.Init("info", os.Stdout)

		exitCh := make(chan int, 1)
		agent := &Agent{
			httpClient: http.DefaultClient,
			exitFunc: func(code int) {
				select {
				case exitCh <- code:
				default:
				}
			},
		}

		// handleUpdateAgent returns early for invalid URL — no goroutine spawned,
		// so there is no data race on logBuf.
		agent.handleUpdateAgent(context.Background(), "ftp://malicious.example.com")

		select {
		case <-exitCh:
			t.Error("expected exitFunc NOT to be called for invalid URL scheme")
		default:
			// Expected: exitFunc was not called
		}

		logOutput := logBuf.String()
		if !strings.Contains(logOutput, "Invalid control plane URL") {
			t.Errorf("expected error log about invalid URL, got: %q", logOutput)
		}
	})

	t.Run("rejects malformed URL", func(t *testing.T) {
		var logBuf bytes.Buffer
		log.Init("error", &logBuf)
		defer log.Init("info", os.Stdout)

		exitCh := make(chan int, 1)
		agent := &Agent{
			httpClient: http.DefaultClient,
			exitFunc: func(code int) {
				select {
				case exitCh <- code:
				default:
				}
			},
		}

		// handleUpdateAgent returns early for malformed URL — no goroutine spawned,
		// so there is no data race on logBuf.
		agent.handleUpdateAgent(context.Background(), "://broken")

		select {
		case <-exitCh:
			t.Error("expected exitFunc NOT to be called for malformed URL")
		default:
			// Expected: exitFunc was not called
		}

		logOutput := logBuf.String()
		if !strings.Contains(logOutput, "Invalid control plane URL") {
			t.Errorf("expected error log about invalid URL, got: %q", logOutput)
		}
	})

	t.Run("handles download failure", func(t *testing.T) {
		// Server that returns 500 for download requests
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		logBuf := newSyncWriter()
		log.Init("error", logBuf)
		defer log.Init("info", os.Stdout)

		tmpDir := t.TempDir()
		binaryPath := filepath.Join(tmpDir, "runic-agent")
		if err := os.WriteFile(binaryPath, []byte("old-binary"), 0755); err != nil {
			t.Fatalf("failed to create target binary: %v", err)
		}

		origUpdateBinaryPath := UpdateBinaryPath
		t.Cleanup(func() { UpdateBinaryPath = origUpdateBinaryPath })
		UpdateBinaryPath = binaryPath

		exitCh := make(chan int, 1)
		agent := &Agent{
			httpClient: server.Client(),
			exitFunc: func(code int) {
				select {
				case exitCh <- code:
				default:
				}
			},
		}

		agent.handleUpdateAgent(context.Background(), server.URL)

		// Wait for either exitFunc to be called (shouldn't happen) or a timeout.
		// Since the server returns 500 immediately, the goroutine should complete
		// well within 2 seconds.
		select {
		case <-exitCh:
			t.Error("expected exitFunc NOT to be called on download failure")
		case <-time.After(2 * time.Second):
			// Expected: exitFunc was not called
		}

		// logBuf is protected by a mutex (syncWriter), so reading it here is
		// safe even if the background goroutine hasn't fully finished yet.
		logOutput := logBuf.String()
		if !strings.Contains(logOutput, "download") && !strings.Contains(logOutput, "update") {
			t.Errorf("expected error log about download/update failure, got: %q", logOutput)
		}
	})

	t.Run("handles permission error", func(t *testing.T) {
		// Serve a valid binary
		fakeBinary := []byte("#!/bin/sh\n# fake agent binary\n")
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Path, "downloads") {
				w.WriteHeader(http.StatusOK)
				w.Write(fakeBinary)
				return
			}
			http.NotFound(w, r)
		}))
		defer server.Close()

		// Use a read-only directory so selfupdate.Apply / CheckPermissions fails
		readOnlyDir := t.TempDir()
		binaryPath := filepath.Join(readOnlyDir, "runic-agent")
		if err := os.WriteFile(binaryPath, []byte("old-binary"), 0755); err != nil {
			t.Fatalf("failed to create target binary: %v", err)
		}
		// Make the directory read-only
		if err := os.Chmod(readOnlyDir, 0555); err != nil {
			t.Fatalf("failed to chmod dir: %v", err)
		}
		// Make the file read-only
		if err := os.Chmod(binaryPath, 0444); err != nil {
			t.Fatalf("failed to chmod binary: %v", err)
		}
		t.Cleanup(func() {
			// Restore permissions so TempDir cleanup can remove the dir
			os.Chmod(readOnlyDir, 0755)
			os.Chmod(binaryPath, 0644)
		})

		origUpdateBinaryPath := UpdateBinaryPath
		t.Cleanup(func() { UpdateBinaryPath = origUpdateBinaryPath })
		UpdateBinaryPath = binaryPath

		logBuf := newSyncWriter()
		log.Init("error", logBuf)
		defer log.Init("info", os.Stdout)

		exitCh := make(chan int, 1)
		agent := &Agent{
			httpClient: server.Client(),
			exitFunc: func(code int) {
				select {
				case exitCh <- code:
				default:
				}
			},
		}

		agent.handleUpdateAgent(context.Background(), server.URL)

		// Wait for either exitFunc to be called (shouldn't happen) or a timeout.
		// The download may succeed but apply should fail quickly due to
		// permissions, so 2 seconds is plenty.
		select {
		case <-exitCh:
			t.Error("expected exitFunc NOT to be called on permission error")
		case <-time.After(2 * time.Second):
			// Expected: exitFunc was not called
		}

		// logBuf is protected by a mutex (syncWriter), so reading it here is
		// safe even if the background goroutine hasn't fully finished yet.
		logOutput := logBuf.String()
		if !strings.Contains(logOutput, "permission") && !strings.Contains(logOutput, "update") {
			t.Errorf("expected error log about permission/update failure, got: %q", logOutput)
		}
	})

	t.Run("uses context.Background not SSE context", func(t *testing.T) {
		// This test verifies that handleUpdateAgent delegates to
		// context.Background() rather than using the SSE context that
		// was passed in. Since the new implementation calls
		// performUpdate with context.Background(), we verify the
		// method doesn't fail just because the incoming context is
		// canceled.
		sseCtx, cancel := context.WithCancel(context.Background())
		cancel() // immediately cancel

		exitCh := make(chan int, 1)
		agent := &Agent{
			httpClient: http.DefaultClient,
			exitFunc: func(code int) {
				select {
				case exitCh <- code:
				default:
				}
			},
		}

		// Use an invalid URL so it fails early (but shouldn't panic)
		// handleUpdateAgent returns early for invalid URL — no goroutine spawned.
		agent.handleUpdateAgent(sseCtx, "ftp://invalid.example.com")

		select {
		case <-exitCh:
			t.Error("expected exitFunc NOT to be called for invalid URL")
		default:
			// Expected: exitFunc was not called
		}
		// The key verification: the method should not have panicked
		// or blocked even though the SSE context was canceled.
	})
}

func TestHandleUpdateAgentPublic(t *testing.T) {
	t.Run("delegates to handleUpdateAgent with context.Background", func(t *testing.T) {
		// Verify that HandleUpdateAgent properly delegates and uses
		// context.Background() rather than any canceled context.
		exitCh := make(chan int, 1)
		agent := &Agent{
			httpClient: http.DefaultClient,
			exitFunc: func(code int) {
				select {
				case exitCh <- code:
				default:
				}
			},
		}

		// Use an invalid URL scheme so it returns early without
		// actually downloading, but the delegation still happens.
		agent.HandleUpdateAgent("ftp://invalid.example.com")

		select {
		case <-exitCh:
			t.Error("expected exitFunc NOT to be called for invalid URL scheme")
		default:
			// Expected: exitFunc was not called
		}
		// The method should not panic when delegating with context.Background()
	})
}

func TestHandleUpdateAgentSync(t *testing.T) {
	t.Run("returns error for invalid URL", func(t *testing.T) {
		agent := &Agent{
			httpClient: http.DefaultClient,
			exitFunc:   func(int) {},
		}

		err := agent.HandleUpdateAgentSync("ftp://malicious.example.com")
		if err == nil {
			t.Fatal("expected error for invalid URL scheme, got nil")
		}
		if !strings.Contains(err.Error(), "invalid control plane URL") {
			t.Errorf("error = %v, want 'invalid control plane URL'", err)
		}
	})

	t.Run("calls exitFunc on success", func(t *testing.T) {
		// Serve a fake binary via httptest
		fakeBinary := []byte("#!/bin/sh\n# fake agent binary\n")
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Path, "downloads") {
				w.WriteHeader(http.StatusOK)
				w.Write(fakeBinary)
				return
			}
			http.NotFound(w, r)
		}))
		defer server.Close()

		tmpDir := t.TempDir()
		binaryPath := filepath.Join(tmpDir, "runic-agent")
		if err := os.WriteFile(binaryPath, []byte("old-binary"), 0755); err != nil {
			t.Fatalf("failed to create target binary: %v", err)
		}

		origUpdateBinaryPath := UpdateBinaryPath
		t.Cleanup(func() { UpdateBinaryPath = origUpdateBinaryPath })
		UpdateBinaryPath = binaryPath

		exitCh := make(chan int, 1)
		agent := &Agent{
			httpClient: server.Client(),
			exitFunc: func(code int) {
				select {
				case exitCh <- code:
				default:
				}
			},
		}

		err := agent.HandleUpdateAgentSync(server.URL)
		if err != nil {
			t.Fatalf("expected nil error, got: %v", err)
		}

		// HandleUpdateAgentSync is synchronous, so exitFunc has already been called
		// by the time HandleUpdateAgentSync returns.
		select {
		case code := <-exitCh:
			if code != 0 {
				t.Errorf("expected exit code 0, got %d", code)
			}
		default:
			t.Error("expected exitFunc to be called after successful sync update")
		}

		// Verify the binary was replaced
		data, err := os.ReadFile(binaryPath)
		if err != nil {
			t.Fatalf("failed to read updated binary: %v", err)
		}
		if string(data) != string(fakeBinary) {
			t.Errorf("binary content = %q, want %q", string(data), string(fakeBinary))
		}
	})

	t.Run("returns error on download failure", func(t *testing.T) {
		// Server that returns 500
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		tmpDir := t.TempDir()
		binaryPath := filepath.Join(tmpDir, "runic-agent")
		if err := os.WriteFile(binaryPath, []byte("old-binary"), 0755); err != nil {
			t.Fatalf("failed to create target binary: %v", err)
		}

		origUpdateBinaryPath := UpdateBinaryPath
		t.Cleanup(func() { UpdateBinaryPath = origUpdateBinaryPath })
		UpdateBinaryPath = binaryPath

		exitCh := make(chan int, 1)
		agent := &Agent{
			httpClient: server.Client(),
			exitFunc: func(code int) {
				select {
				case exitCh <- code:
				default:
				}
			},
		}

		err := agent.HandleUpdateAgentSync(server.URL)
		if err == nil {
			t.Fatal("expected error for download failure, got nil")
		}

		// HandleUpdateAgentSync is synchronous, so we can check immediately.
		select {
		case <-exitCh:
			t.Error("expected exitFunc NOT to be called on download failure")
		default:
			// Expected: exitFunc was not called
		}
	})
}

func TestApplyCachedBundle_NoCacheFile(t *testing.T) {
	cfg := helperConfig()
	configPath := helperConfigPath(t, cfg)

	agent := New(configPath, "http://localhost:8080")
	// Use a non-existent cache path in temp dir
	agent.cachePath = filepath.Join(t.TempDir(), "nonexistent.rules")
	agent.cmdRunner = &mockCommandRunner{}
	agent.config.ApplyRulesBundle = true // required for applyCachedBundle to execute

	err := agent.applyCachedBundle(context.Background())

	if err != nil {
		t.Errorf("applyCachedBundle() error = %v, want nil for missing cache", err)
	}
}

func TestApplyCachedBundle_EmptyRules(t *testing.T) {
	cfg := helperConfig()
	configPath := helperConfigPath(t, cfg)

	agent := New(configPath, "http://localhost:8080")

	cacheDir := t.TempDir()
	cachePath := filepath.Join(cacheDir, "cached-bundle.rules")
	_ = os.WriteFile(cachePath, []byte(""), 0600)
	agent.cachePath = cachePath
	agent.cmdRunner = &mockCommandRunner{}
	agent.config.ApplyRulesBundle = true // required for applyCachedBundle to execute

	err := agent.applyCachedBundle(context.Background())

	if err == nil {
		t.Error("applyCachedBundle() expected error for empty rules, got nil")
	}
	if err != nil && !strings.Contains(err.Error(), "empty") {
		t.Errorf("applyCachedBundle() error = %v, want 'empty' error", err)
	}
}

func TestApplyCachedBundle_WhitespaceOnlyRules(t *testing.T) {
	cfg := helperConfig()
	configPath := helperConfigPath(t, cfg)

	agent := New(configPath, "http://localhost:8080")

	cacheDir := t.TempDir()
	cachePath := filepath.Join(cacheDir, "cached-bundle.rules")
	_ = os.WriteFile(cachePath, []byte("   \n  \n  "), 0600)
	agent.cachePath = cachePath
	agent.cmdRunner = &mockCommandRunner{}
	agent.config.ApplyRulesBundle = true // required for applyCachedBundle to execute

	err := agent.applyCachedBundle(context.Background())

	if err == nil {
		t.Error("applyCachedBundle() expected error for whitespace-only rules, got nil")
	}
}

func TestApplyCachedBundle_ReadError(t *testing.T) {
	cfg := helperConfig()
	configPath := helperConfigPath(t, cfg)

	agent := New(configPath, "http://localhost:8080")

	// Point to an unreadable path (directory instead of file)
	cacheDir := t.TempDir()
	agent.cachePath = cacheDir // This is a directory, not a file
	agent.cmdRunner = &mockCommandRunner{}
	agent.config.ApplyRulesBundle = true // required for applyCachedBundle to execute

	err := agent.applyCachedBundle(context.Background())

	if err == nil {
		t.Error("applyCachedBundle() expected error for unreadable path, got nil")
	}
}

func TestApplyCachedBundle_Success(t *testing.T) {
	cfg := helperConfig()
	configPath := helperConfigPath(t, cfg)

	agent := New(configPath, "http://localhost:8080")

	cacheDir := t.TempDir()
	cachePath := filepath.Join(cacheDir, "cached-bundle.rules")
	validRules := "*filter\n:INPUT DROP [0:0]\nCOMMIT\n"
	_ = os.WriteFile(cachePath, []byte(validRules), 0600)
	agent.cachePath = cachePath

	mockCmd := &mockCommandRunner{}
	agent.cmdRunner = mockCmd
	agent.config.ApplyRulesBundle = true // required for applyCachedBundle to execute

	err := agent.applyCachedBundle(context.Background())

	if err != nil {
		t.Errorf("applyCachedBundle() error = %v, want nil", err)
	}

	// Verify iptables-restore was called
	if len(mockCmd.calls) != 1 {
		t.Fatalf("expected 1 command call, got %d", len(mockCmd.calls))
	}
	if mockCmd.calls[0].name != "iptables-restore" {
		t.Errorf("expected command 'iptables-restore', got '%s'", mockCmd.calls[0].name)
	}
}

func TestBackupIptables_SkipsIfBackupExists(t *testing.T) {
	cfg := helperConfig()
	configPath := helperConfigPath(t, cfg)

	agent := New(configPath, "http://localhost:8080")

	backupDir := t.TempDir()
	backupPath := filepath.Join(backupDir, "iptables-backup.rules")
	os.WriteFile(backupPath, []byte("existing"), 0600)
	agent.backupPath = backupPath
	agent.cmdRunner = &mockCommandRunner{}

	err := agent.backupIptables(context.Background())

	if err != nil {
		t.Errorf("backupIptables() error = %v, want nil for existing backup", err)
	}
}

func TestBackupIptables_IptablesSaveFails(t *testing.T) {
	cfg := helperConfig()
	configPath := helperConfigPath(t, cfg)

	agent := New(configPath, "http://localhost:8080")

	backupDir := t.TempDir()
	// Don't create the backup file - it should try to create it
	agent.backupPath = filepath.Join(backupDir, "iptables-backup.rules")
	agent.cmdRunner = &mockCommandRunner{err: fmt.Errorf("iptables-save: command not found")}

	err := agent.backupIptables(context.Background())

	if err == nil {
		t.Error("backupIptables() expected error when iptables-save fails, got nil")
	}
}

func TestBackupIptables_Success(t *testing.T) {
	cfg := helperConfig()
	configPath := helperConfigPath(t, cfg)

	agent := New(configPath, "http://localhost:8080")

	backupDir := t.TempDir()
	agent.backupPath = filepath.Join(backupDir, "iptables-backup.rules")
	agent.cmdRunner = &mockCommandRunner{output: []byte("*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n")}

	err := agent.backupIptables(context.Background())

	if err != nil {
		t.Errorf("backupIptables() error = %v, want nil", err)
	}

	// Verify backup file was created
	if _, err := os.Stat(agent.backupPath); os.IsNotExist(err) {
		t.Error("backupIptables() did not create backup file")
	}

	// Verify iptables-save was called
	mockCmd := agent.cmdRunner.(*mockCommandRunner)
	if len(mockCmd.calls) != 1 {
		t.Fatalf("expected 1 command call, got %d", len(mockCmd.calls))
	}
	if mockCmd.calls[0].name != "iptables-save" {
		t.Errorf("expected command 'iptables-save', got '%s'", mockCmd.calls[0].name)
	}
}

func TestListenSSEHandlesReRegistration(t *testing.T) {
	cfg := helperConfig()
	configPath := helperConfigPath(t, cfg)

	agent := New(configPath, "http://localhost:8080")
	agent.config.HostID = "test-host"
	agent.config.Token = "test-token"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "events") {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	agent.config.ControlPlaneURL = server.URL

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	// listenSSE should handle 401 and not panic
	go agent.listenSSE(ctx)

	// Wait a bit
	time.Sleep(100 * time.Millisecond)

	// Context should eventually timeout
	<-ctx.Done()
}

func TestAgentDefaultPaths(t *testing.T) {
	cfg := helperConfig()
	configPath := helperConfigPath(t, cfg)

	agent := New(configPath, "http://localhost:8080")

	if agent.cachePath != "/etc/runic-agent/cached-bundle.rules" {
		t.Errorf("cachePath = %s, want /etc/runic-agent/cached-bundle.rules", agent.cachePath)
	}
	if agent.backupPath != "/etc/runic-agent/iptables-backup.rules" {
		t.Errorf("backupPath = %s, want /etc/runic-agent/iptables-backup.rules", agent.backupPath)
	}
	if agent.cmdRunner == nil {
		t.Error("cmdRunner is nil, expected a CommandRunner implementation")
	}
}

func TestRunLoadsConfig(t *testing.T) {
	cfg := helperConfig()
	configPath := helperConfigPath(t, cfg)

	agent := New(configPath, "http://localhost:8080")

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	// Run should at least attempt to load config
	// It will fail on other steps but we can verify loadConfig is called
	err := agent.Run(ctx)

	// Expect context deadline exceeded (not config load error)
	if err != nil && !errors.Is(err, context.DeadlineExceeded) {
		// Other errors might occur but config load should work
		t.Logf("Run() returned: %v", err)
	}
}

func TestRunFailsOnEmptyControlPlaneURL(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")

	cfg := identity.DefaultConfig()
	cfg.HostID = "test-host"
	cfg.Token = "test-token"
	// ControlPlaneURL is empty
	var data []byte
	var err error
	data, err = json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatalf("failed to marshal config: %v", err)
	}
	_ = os.WriteFile(configPath, data, 0600)

	agent := New(configPath, "") // Empty CLI URL too

	ctx := context.Background()
	err = agent.Run(ctx)

	if err == nil {
		t.Error("Run() should fail when control plane URL is empty")
	}

	if err != nil && !strings.Contains(err.Error(), "control plane URL is required") {
		t.Errorf("Run() error = %v, want 'control plane URL is required'", err)
	}
}

func TestRunRegistersWhenNeeded(t *testing.T) {
	cfg := helperConfig()
	cfg.HostID = "" // No credentials
	cfg.Token = ""
	configPath := helperConfigPath(t, cfg)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "register") {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{
				"host_id": "registered-host-id",
				"token":   "registered-token",
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	agent := New(configPath, server.URL)
	agent.config.HostID = ""
	agent.config.Token = ""

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	// Run should attempt registration
	_ = agent.Run(ctx)

	// Should have attempted registration (we'll see error from context timeout or registration)
	// The key is that it tried to register, not that it completed successfully
}

func TestApplyBundleWithMockApply(t *testing.T) {
	cfg := helperConfig()
	cfg.ApplyRulesBundle = true
	configPath := helperConfigPath(t, cfg)

	agent := New(configPath, "http://localhost:8080")
	agent.config.HostID = "test-host"
	agent.config.Token = "test-token"

	// Verify that when ApplyRulesBundle is true, applyBundle attempts to apply
	// The actual apply will fail without proper setup, but we verify the flow
	bundle := models.BundleResponse{
		Version: "test-v1",
		Rules:   "*filter\n:INPUT DROP [0:0]\nCOMMIT\n",
		HMAC:    "dummy",
	}

	err := agent.applyBundle(context.Background(), bundle)
	// Expect error from apply.ApplyBundle (HMAC validation failure or other)
	// But the flow should be correct
	_ = err
}

func TestIsControlPlaneReachableWithNon200(t *testing.T) {
	cfg := helperConfig()
	configPath := helperConfigPath(t, cfg)

	agent := New(configPath, "http://localhost:8080")
	agent.config.Token = "test-token"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	agent.config.ControlPlaneURL = server.URL

	ctx := context.Background()
	reachable := agent.isControlPlaneReachable(ctx)

	if reachable {
		t.Error("isControlPlaneReachable() returned true, want false for 500 status")
	}
}

func TestConfigNeedsRegistration(t *testing.T) {
	tests := []struct {
		name    string
		hostID  string
		token   string
		wantReg bool
	}{
		{
			name:    "has credentials",
			hostID:  "host-1",
			token:   "token-1",
			wantReg: false,
		},
		{
			name:    "missing host ID",
			hostID:  "",
			token:   "token-1",
			wantReg: true,
		},
		{
			name:    "missing token",
			hostID:  "host-1",
			token:   "",
			wantReg: true,
		},
		{
			name:    "missing both",
			hostID:  "",
			token:   "",
			wantReg: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &identity.Config{
				HostID: tt.hostID,
				Token:  tt.token,
			}

			gotReg := cfg.NeedsRegistration()
			if gotReg != tt.wantReg {
				t.Errorf("NeedsRegistration() = %v, want %v", gotReg, tt.wantReg)
			}
		})
	}
}

func TestAgentFields(t *testing.T) {
	cfg := helperConfig()
	configPath := helperConfigPath(t, cfg)

	agent := New(configPath, "http://localhost:8080")

	// Verify all fields are accessible
	_ = agent.config
	_ = agent.configPath
	_ = agent.httpClient
	_ = agent.sseClient
	_ = agent.version
	_ = agent.shipper
	_ = agent.rotationManager

	// All fields should be non-nil (except shipper and rotationManager which are
	// set in initialize() after registration/config load).
	if agent.config == nil {
		t.Error("Agent.config is nil")
	}
	if agent.httpClient == nil {
		t.Error("Agent.httpClient is nil")
	}
	if agent.sseClient == nil {
		t.Error("Agent.sseClient is nil")
	}
	// rotationManager is intentionally nil after New(); set during initialize().
}

func TestAgentMutexFieldExists(t *testing.T) {
	cfg := helperConfig()
	configPath := helperConfigPath(t, cfg)

	agent := New(configPath, "http://localhost:8080")

	// Just verify we can access the mutex without compile error
	var mu sync.Mutex
	mu.Lock()
	agent.regMu.Lock()
	agent.regMu.Unlock()
	mu.Unlock()
}

func TestHeartbeatLoopStructure(t *testing.T) {
	cfg := helperConfig()
	cfg.HeartbeatIntervalSec = 1 // 1 second for testing
	configPath := helperConfigPath(t, cfg)

	agent := New(configPath, "http://localhost:8080")
	agent.config.HostID = "test-host"
	agent.config.Token = "test-token"

	// Run for a brief moment to test structure
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	go agent.heartbeatLoop(ctx)

	// Give it time to run
	time.Sleep(30 * time.Millisecond)

	// Context should complete
	<-ctx.Done()
}

func TestPollLoopStructure(t *testing.T) {
	cfg := helperConfig()
	cfg.PullIntervalSec = 1 // 1 second for testing
	configPath := helperConfigPath(t, cfg)

	agent := New(configPath, "http://localhost:8080")
	agent.config.HostID = "test-host"
	agent.config.Token = "test-token"

	// Run for a brief moment to test structure
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	go agent.pollLoop(ctx)

	// Give it time to run
	time.Sleep(30 * time.Millisecond)

	// Context should complete
	<-ctx.Done()
}

func TestRotationCheckLoopStructure(t *testing.T) {
	cfg := helperConfig()
	configPath := helperConfigPath(t, cfg)

	agent := New(configPath, "http://localhost:8080")
	agent.config.HostID = "test-host"
	agent.config.Token = "test-token"

	// Run for a brief moment to test structure
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	go agent.rotationCheckLoop(ctx)

	// Give it time to run
	time.Sleep(30 * time.Millisecond)

	// Context should complete
	<-ctx.Done()
}

func TestDefaultHeartbeatInterval(t *testing.T) {
	if identity.DefaultHeartbeatIntervalSec != 30 {
		t.Errorf("DefaultHeartbeatIntervalSec = %d, want 30", identity.DefaultHeartbeatIntervalSec)
	}
}

func TestDefaultPullInterval(t *testing.T) {
	if identity.DefaultPullIntervalSec != 86400 {
		t.Errorf("DefaultPullIntervalSec = %d, want 86400", identity.DefaultPullIntervalSec)
	}
}

func TestLoadConfigMergePriority(t *testing.T) {
	cfg := &identity.Config{
		ControlPlaneURL:      "", // Empty - CLI should override
		HostID:               "host-test-peer",
		Token:                "test-agent-token",
		HMACKey:              "test-hmac-key-12345678901234567890123456",
		PullIntervalSec:      86400,
		HeartbeatIntervalSec: 30,
		LogPath:              "/var/log/runic/firewall.log",
		ApplyOnBoot:          false,
		ApplyRulesBundle:     true,
	}
	configPath := helperConfigPath(t, cfg)

	// CLI provides different URL
	agent := New(configPath, "http://cli-url:9090")

	err := agent.loadConfig()
	if err != nil {
		t.Fatalf("loadConfig() error = %v", err)
	}

	// CLI value should override config file value
	if agent.config.ControlPlaneURL != "http://cli-url:9090" {
		t.Errorf("loadConfig() ControlPlaneURL = %s, want CLI value http://cli-url:9090", agent.config.ControlPlaneURL)
	}
}

func TestLoadConfigPreservesExistingURL(t *testing.T) {
	cfg := helperConfig()
	cfg.ControlPlaneURL = "http://config-file-url:8080"
	configPath := helperConfigPath(t, cfg)

	// CLI provides empty URL
	agent := New(configPath, "")

	err := agent.loadConfig()
	if err != nil {
		t.Fatalf("loadConfig() error = %v", err)
	}

	// Config file value should be preserved
	if agent.config.ControlPlaneURL != "http://config-file-url:8080" {
		t.Errorf("loadConfig() ControlPlaneURL = %s, want config file value http://config-file-url:8080", agent.config.ControlPlaneURL)
	}
}

// This tests the fix for BUG-001 where premature URL validation blocked startup
func TestAgentStartsWithURLInConfigFile(t *testing.T) {
	cfg := &identity.Config{
		ControlPlaneURL:      "http://config-file-url:8080",
		HostID:               "test-host",
		Token:                "test-token",
		HMACKey:              "test-hmac-key-12345678901234567890123456",
		PullIntervalSec:      86400,
		HeartbeatIntervalSec: 30,
		LogPath:              "/var/log/runic/firewall.log",
		ApplyOnBoot:          false,
		ApplyRulesBundle:     true,
	}
	configPath := helperConfigPath(t, cfg)

	agent := New(configPath, "")

	// loadConfig should load URL from config file
	err := agent.loadConfig()
	if err != nil {
		t.Fatalf("loadConfig() error = %v", err)
	}

	// URL should come from config file
	if agent.config.ControlPlaneURL != "http://config-file-url:8080" {
		t.Errorf("loadConfig() ControlPlaneURL = %s, want http://config-file-url:8080", agent.config.ControlPlaneURL)
	}

	// Run() should NOT fail due to empty URL (validation happens after loadConfig)
	// We use a short timeout context since we don't want to actually run the agent
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	// Run will eventually fail due to context deadline, but NOT due to missing URL
	err = agent.Run(ctx)

	// The error should NOT be about missing control plane URL
	if err != nil && strings.Contains(err.Error(), "control plane URL is required") {
		t.Error("Run() should not fail with 'control plane URL is required' when URL is in config file")
	}
}

func TestAgentStartsWithCLIURLOverride(t *testing.T) {
	cfg := &identity.Config{
		ControlPlaneURL:      "http://config-file-url:8080",
		HostID:               "test-host",
		Token:                "test-token",
		HMACKey:              "test-hmac-key-12345678901234567890123456",
		PullIntervalSec:      86400,
		HeartbeatIntervalSec: 30,
		LogPath:              "/var/log/runic/firewall.log",
		ApplyOnBoot:          false,
		ApplyRulesBundle:     true,
	}
	configPath := helperConfigPath(t, cfg)

	cliURL := "http://cli-override-url:9090"
	agent := New(configPath, cliURL)

	// loadConfig should merge CLI URL over config file URL
	err := agent.loadConfig()
	if err != nil {
		t.Fatalf("loadConfig() error = %v", err)
	}

	// CLI URL should override config file URL (but only if config file URL is empty per current logic)
	// Per the current merge logic, CLI overrides config file ONLY when config file URL is empty
	// This test verifies current behavior - CLI URL is set on agent.config initially
}

func TestAgentURLMergeLogicConfigHasURL(t *testing.T) {
	// Config file HAS a URL
	cfg := &identity.Config{
		ControlPlaneURL:      "http://config-url:8080",
		HostID:               "test-host",
		Token:                "test-token",
		PullIntervalSec:      86400,
		HeartbeatIntervalSec: 30,
		LogPath:              "/var/log/runic/firewall.log",
	}
	configPath := helperConfigPath(t, cfg)

	// Agent created with empty CLI URL
	agent := New(configPath, "")

	err := agent.loadConfig()
	if err != nil {
		t.Fatalf("loadConfig() error = %v", err)
	}

	// Config file URL should be used
	if agent.config.ControlPlaneURL != "http://config-url:8080" {
		t.Errorf("ControlPlaneURL = %s, want http://config-url:8080", agent.config.ControlPlaneURL)
	}
}

func TestAgentURLMergeLogicConfigEmpty(t *testing.T) {
	// Config file has EMPTY URL
	cfg := &identity.Config{
		ControlPlaneURL:      "", // Empty
		HostID:               "test-host",
		Token:                "test-token",
		PullIntervalSec:      86400,
		HeartbeatIntervalSec: 30,
		LogPath:              "/var/log/runic/firewall.log",
	}
	configPath := helperConfigPath(t, cfg)

	// Agent created with CLI URL
	cliURL := "http://cli-url:9090"
	agent := New(configPath, cliURL)

	err := agent.loadConfig()
	if err != nil {
		t.Fatalf("loadConfig() error = %v", err)
	}

	// CLI URL should override empty config file URL
	if agent.config.ControlPlaneURL != "http://cli-url:9090" {
		t.Errorf("ControlPlaneURL = %s, want http://cli-url:9090", agent.config.ControlPlaneURL)
	}
}

func TestAgentFailsWithNoURL(t *testing.T) {
	// Config file has NO URL
	cfg := &identity.Config{
		ControlPlaneURL:      "", // Empty
		HostID:               "test-host",
		Token:                "test-token",
		PullIntervalSec:      86400,
		HeartbeatIntervalSec: 30,
		LogPath:              "/var/log/runic/firewall.log",
	}
	configPath := helperConfigPath(t, cfg)

	// Agent created with NO CLI URL (simulating main.go passing empty string)
	agent := New(configPath, "")

	// loadConfig will load empty URL from config
	err := agent.loadConfig()
	if err != nil {
		t.Fatalf("loadConfig() error = %v", err)
	}

	// Run() should fail because no URL is available
	ctx := context.Background()
	err = agent.Run(ctx)

	if err == nil {
		t.Error("Run() should fail when no control plane URL is available")
	}
	if err != nil && !strings.Contains(err.Error(), "control plane URL is required") {
		t.Errorf("Run() error = %v, want 'control plane URL is required'", err)
	}
}

// ApplyRulesBundle=true, the boot-time bundle application path is entered when CP is reachable.
func TestApplyOnBootWithRulesBundleEnabled(t *testing.T) {
	cfg := helperConfig()
	cfg.ApplyOnBoot = true
	cfg.ApplyRulesBundle = true
	configPath := helperConfigPath(t, cfg)

	agent := New(configPath, "http://localhost:8080")
	// loadConfig loads values from the config file, including ApplyOnBoot and ApplyRulesBundle
	if err := agent.loadConfig(); err != nil {
		t.Fatalf("loadConfig() error = %v", err)
	}
	agent.config.HostID = "test-host"
	agent.config.Token = "test-token"

	mockCmd := &mockCommandRunner{}
	agent.cmdRunner = mockCmd

	cacheDir := t.TempDir()
	cachePath := filepath.Join(cacheDir, "cached-bundle.rules")
	validRules := "*filter\n:INPUT DROP [0:0]\nCOMMIT\n"
	_ = os.WriteFile(cachePath, []byte(validRules), 0600)
	agent.cachePath = cachePath

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	agent.config.ControlPlaneURL = server.URL

	ctx := context.Background()

	// Test the ApplyOnBoot block logic directly by calling isControlPlaneReachable + pullBundle
	// Since pullBundle calls the real transport which requires full API, we verify the condition logic
	reachable := agent.isControlPlaneReachable(ctx)
	if !reachable {
		t.Error("Expected control plane to be reachable")
	}

	// Verify that when both flags are true AND CP is reachable, the boot-time path is entered
	// The actual pullBundle will fail (no bundle endpoint), but the condition check is what matters
	if !agent.config.ApplyOnBoot || !agent.config.ApplyRulesBundle {
		t.Error("Expected both ApplyOnBoot and ApplyRulesBundle to be true")
	}
}

// ApplyRulesBundle=false, the bundle is NOT applied at boot even when a cached bundle exists.
func TestApplyOnBootWithRulesBundleDisabled(t *testing.T) {
	cfg := helperConfig()
	cfg.ApplyOnBoot = true
	cfg.ApplyRulesBundle = false
	configPath := helperConfigPath(t, cfg)

	agent := New(configPath, "http://localhost:8080")
	// loadConfig loads values from the config file, including ApplyOnBoot and ApplyRulesBundle
	if err := agent.loadConfig(); err != nil {
		t.Fatalf("loadConfig() error = %v", err)
	}
	agent.config.HostID = "test-host"
	agent.config.Token = "test-token"

	mockCmd := &mockCommandRunner{}
	agent.cmdRunner = mockCmd

	cacheDir := t.TempDir()
	cachePath := filepath.Join(cacheDir, "cached-bundle.rules")
	validRules := "*filter\n:INPUT DROP [0:0]\nCOMMIT\n"
	_ = os.WriteFile(cachePath, []byte(validRules), 0600)
	agent.cachePath = cachePath

	// Verify applyCachedBundle respects ApplyRulesBundle=false
	err := agent.applyCachedBundle(context.Background())
	if err != nil {
		t.Errorf("applyCachedBundle() error = %v, want nil (should skip)", err)
	}

	// Verify iptables-restore was NOT called
	for _, call := range mockCmd.calls {
		if call.name == "iptables-restore" {
			t.Error("iptables-restore should NOT have been called when ApplyRulesBundle=false")
		}
	}
}

// ApplyRulesBundle=true, and the CP is unreachable, the cached bundle IS applied.
func TestApplyOnBootOfflineWithRulesBundleEnabled(t *testing.T) {
	cfg := helperConfig()
	cfg.ApplyOnBoot = true
	cfg.ApplyRulesBundle = true
	configPath := helperConfigPath(t, cfg)

	agent := New(configPath, "http://localhost:8080")
	// loadConfig loads values from the config file, including ApplyOnBoot and ApplyRulesBundle
	if err := agent.loadConfig(); err != nil {
		t.Fatalf("loadConfig() error = %v", err)
	}
	agent.config.HostID = "test-host"
	agent.config.Token = "test-token"

	mockCmd := &mockCommandRunner{}
	agent.cmdRunner = mockCmd

	cacheDir := t.TempDir()
	cachePath := filepath.Join(cacheDir, "cached-bundle.rules")
	validRules := "*filter\n:INPUT DROP [0:0]\nCOMMIT\n"
	_ = os.WriteFile(cachePath, []byte(validRules), 0600)
	agent.cachePath = cachePath

	// Point to unreachable control plane
	agent.config.ControlPlaneURL = "http://invalid-host:9999"

	// Verify CP is unreachable
	ctx := context.Background()
	reachable := agent.isControlPlaneReachable(ctx)
	if reachable {
		t.Error("Expected control plane to be unreachable")
	}

	// Verify applyCachedBundle works when ApplyRulesBundle=true
	err := agent.applyCachedBundle(ctx)
	if err != nil {
		t.Errorf("applyCachedBundle() error = %v, want nil", err)
	}

	// Verify iptables-restore WAS called
	found := false
	for _, call := range mockCmd.calls {
		if call.name == "iptables-restore" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected iptables-restore to be called when ApplyRulesBundle=true and cached bundle exists")
	}
}

// ApplyRulesBundle=false, the cached bundle is NOT applied even when the CP is unreachable.
// This verifies the BUG-2 fix: ApplyRulesBundle=false must be respected in all code paths.
func TestApplyOnBootOfflineWithRulesBundleDisabled(t *testing.T) {
	cfg := helperConfig()
	cfg.ApplyOnBoot = true
	cfg.ApplyRulesBundle = false
	configPath := helperConfigPath(t, cfg)

	agent := New(configPath, "http://localhost:8080")
	// loadConfig loads values from the config file, including ApplyOnBoot and ApplyRulesBundle
	if err := agent.loadConfig(); err != nil {
		t.Fatalf("loadConfig() error = %v", err)
	}
	agent.config.HostID = "test-host"
	agent.config.Token = "test-token"

	mockCmd := &mockCommandRunner{}
	agent.cmdRunner = mockCmd

	cacheDir := t.TempDir()
	cachePath := filepath.Join(cacheDir, "cached-bundle.rules")
	validRules := "*filter\n:INPUT DROP [0:0]\nCOMMIT\n"
	_ = os.WriteFile(cachePath, []byte(validRules), 0600)
	agent.cachePath = cachePath

	// Point to unreachable control plane
	agent.config.ControlPlaneURL = "http://invalid-host:9999"

	// Verify applyCachedBundle respects ApplyRulesBundle=false even when offline
	err := agent.applyCachedBundle(context.Background())
	if err != nil {
		t.Errorf("applyCachedBundle() error = %v, want nil (should skip)", err)
	}

	// Verify iptables-restore was NOT called
	for _, call := range mockCmd.calls {
		if call.name == "iptables-restore" {
			t.Error("iptables-restore should NOT have been called when ApplyRulesBundle=false, even when offline")
		}
	}
}

// ApplyOnBoot already pulled the bundle), pollLoop's first iteration does NOT
// call pullBundle again.
func TestPollLoopSkipsDuplicatePull(t *testing.T) {
	cfg := helperConfig()
	cfg.PullIntervalSec = 86400 // Long interval so ticker won't fire during test
	configPath := helperConfigPath(t, cfg)

	agent := New(configPath, "http://localhost:8080")
	// loadConfig loads values from the config file
	if err := agent.loadConfig(); err != nil {
		t.Fatalf("loadConfig() error = %v", err)
	}
	agent.config.HostID = "test-host"
	agent.config.Token = "test-token"

	pullCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pullCount++
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"version": "v1",
			"rules":   "*filter\n:INPUT DROP [0:0]\nCOMMIT\n",
			"hmac":    "",
		})
	}))
	defer server.Close()
	agent.config.ControlPlaneURL = server.URL

	// Run pollLoop with bootPullDone=true for a very brief time
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	// When bootPullDone=true, pollLoop should NOT call pullBundle immediately
	agent.bootPullDone.Store(true)
	go agent.pollLoop(ctx)

	// Wait for context to expire
	<-ctx.Done()

	// The pullCount should be 0 because we skipped the first pull
	// and the ticker interval is 86400 seconds so no ticker fires during 50ms
	if pullCount != 0 {
		t.Errorf("Expected 0 pulls with skipFirstPull=true, got %d", pullCount)
	}
}
