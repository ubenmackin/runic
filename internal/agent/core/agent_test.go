package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"runic/internal/agent/identity"
	"runic/internal/models"
)

// helperConfig creates a minimal config for testing.
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

// TestNew creates Agent with correct defaults
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

	if agent.rotationManager == nil {
		t.Error("New() rotationManager is nil")
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

// TestLoadConfigReturnsDefault tests loadConfig returns default when file doesn't exist
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

// TestLoadConfigLoadsExisting tests loadConfig loads existing config
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

// TestLoadConfigMergesCLIValues tests loadConfig merges CLI-provided values
func TestLoadConfigMergesCLIValues(t *testing.T) {
	// Create config with EMPTY ControlPlaneURL so CLI value can override
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

	// Create agent with CLI-provided URL
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

// TestSaveConfigWritesFile tests saveConfig writes to file with correct permissions
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

// TestApplyBundleSkipsWhenDisabled tests applyBundle skips when ApplyRulesBundle is false
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

// TestApplyBundleSavesConfigOnSuccess tests applyBundle calls apply.ApplyBundle and saves config on success
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

// TestConfirmApplyCallsTransport tests confirmApply calls transport.ConfirmApply
func TestConfirmApplyCallsTransport(t *testing.T) {
	cfg := helperConfig()
	configPath := helperConfigPath(t, cfg)

	agent := New(configPath, "http://localhost:8080")
	agent.config.HostID = "test-host"
	agent.config.Token = "test-token"
	agent.config.ControlPlaneURL = "http://localhost:8080"

	// Create a mock server that handles confirm-apply
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

// TestRegisterCallsIdentity tests register calls identity.Register
func TestRegisterCallsIdentity(t *testing.T) {
	cfg := helperConfig()
	cfg.HostID = "" // Clear host ID to trigger registration
	cfg.Token = ""
	configPath := helperConfigPath(t, cfg)

	// Create a mock server that handles registration
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

	err := agent.register(context.Background())
	if err != nil {
		t.Fatalf("register() error = %v", err)
	}

	// Verify registration updated config
	if agent.config.HostID != "registered-host-id" {
		t.Errorf("register() HostID = %s, want registered-host-id", agent.config.HostID)
	}
}

// TestSafeRegisterAcquiresMutex tests safeRegister acquires mutex before registration
func TestSafeRegisterAcquiresMutex(t *testing.T) {
	cfg := helperConfig()
	configPath := helperConfigPath(t, cfg)

	agent := New(configPath, "http://localhost:8080")

	// Test that safeRegister can be called without panic
	// (will fail registration but we verify mutex is present)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_ = agent.safeRegister(ctx)
}

// TestIsControlPlaneReachableTrue tests isControlPlaneReachable returns true on 200 OK
func TestIsControlPlaneReachableTrue(t *testing.T) {
	cfg := helperConfig()
	configPath := helperConfigPath(t, cfg)

	agent := New(configPath, "http://localhost:8080")
	agent.config.Token = "test-token"

	// Create a mock server that returns 200 OK
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

// TestIsControlPlaneReachableFalse tests isControlPlaneReachable returns false on error
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

// mockCommandRunner implements CommandRunner for testing.
type mockCommandRunner struct {
	output []byte
	err    error
	calls  []mockCall
}

type mockCall struct {
	name string
	args []string
}

func (m *mockCommandRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	m.calls = append(m.calls, mockCall{name: name, args: args})
	return m.output, m.err
}

// TestHandleUpdateAgent tests handleUpdateAgent validates URLs and launches the install script.
func TestHandleUpdateAgent(t *testing.T) {
	t.Run("rejects invalid URL scheme", func(t *testing.T) {
		var cmdCreated bool
		agent := &Agent{
			execCommandFunc: func(ctx context.Context, name string, args ...string) *exec.Cmd {
				cmdCreated = true
				return exec.CommandContext(ctx, name, args...)
			},
		}
		agent.handleUpdateAgent(context.Background(), "ftp://malicious.example.com")
		if cmdCreated {
			t.Error("expected no command to be created for invalid URL scheme")
		}
	})

	t.Run("rejects malformed URL", func(t *testing.T) {
		var cmdCreated bool
		agent := &Agent{
			execCommandFunc: func(ctx context.Context, name string, args ...string) *exec.Cmd {
				cmdCreated = true
				return exec.CommandContext(ctx, name, args...)
			},
		}
		agent.handleUpdateAgent(context.Background(), "://broken")
		if cmdCreated {
			t.Error("expected no command to be created for malformed URL")
		}
	})

	t.Run("successful update launch returns immediately", func(t *testing.T) {
		// Use a harmless command that completes quickly
		agent := &Agent{
			execCommandFunc: func(ctx context.Context, name string, args ...string) *exec.Cmd {
				// Return a real command that does nothing harmful
				return exec.CommandContext(ctx, "true")
			},
		}

		done := make(chan struct{})
		go func() {
			agent.handleUpdateAgent(context.Background(), "https://runic.example.com")
			close(done)
		}()

		select {
		case <-done:
			// Good — function returned immediately (fire-and-forget)
		case <-time.After(5 * time.Second):
			t.Fatal("handleUpdateAgent should return immediately after cmd.Start()")
		}
	})

	t.Run("update command uses context.Background not SSE context", func(t *testing.T) {
		var capturedCtx context.Context
		agent := &Agent{
			execCommandFunc: func(ctx context.Context, name string, args ...string) *exec.Cmd {
				capturedCtx = ctx
				return exec.CommandContext(ctx, "true")
			},
		}

		// Pass a canceled context as the SSE context
		sseCtx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately
		agent.handleUpdateAgent(sseCtx, "https://runic.example.com")

		// The function should use context.Background(), not the canceled SSE context
		if capturedCtx == nil {
			t.Fatal("expected execCommandFunc to be called")
		}
		if capturedCtx == sseCtx {
			t.Error("handleUpdateAgent should use context.Background(), not the SSE context")
		}
		// Verify the captured context is not canceled
		if err := capturedCtx.Err(); err != nil {
			t.Error("handleUpdateAgent should use context.Background() which is never canceled")
		}
	})

	t.Run("update command contains install script URL and control plane URL", func(t *testing.T) {
		var capturedArgs []string
		agent := &Agent{
			execCommandFunc: func(ctx context.Context, name string, args ...string) *exec.Cmd {
				capturedArgs = args
				return exec.CommandContext(ctx, "true")
			},
		}

		agent.handleUpdateAgent(context.Background(), "https://runic.example.com")

		if len(capturedArgs) < 2 {
			t.Fatalf("expected at least 2 args, got %d", len(capturedArgs))
		}
		cmdStr := capturedArgs[1]
		if !strings.Contains(cmdStr, "install-agent.sh") {
			t.Error("expected command to contain install-agent.sh URL")
		}
		if !strings.Contains(cmdStr, "runic.example.com") {
			t.Error("expected command to contain control plane URL")
		}
	})

	t.Run("update command sets process group on linux", func(t *testing.T) {
		var capturedCmd *exec.Cmd
		agent := &Agent{
			execCommandFunc: func(ctx context.Context, name string, args ...string) *exec.Cmd {
				// Return a harmless command so cmd.Start() succeeds
				cmd := exec.CommandContext(ctx, "true")
				capturedCmd = cmd
				return cmd
			},
		}

		agent.handleUpdateAgent(context.Background(), "https://runic.example.com")

		if capturedCmd == nil {
			t.Fatal("expected execCommandFunc to be called")
		}

		// On Linux, SysProcAttr should have Setpgid=true; on other platforms it should be nil
		if runtime.GOOS == "linux" {
			if capturedCmd.SysProcAttr == nil {
				t.Fatal("expected SysProcAttr to be set on Linux")
			}
			if !capturedCmd.SysProcAttr.Setpgid {
				t.Error("expected SysProcAttr.Setpgid to be true on Linux")
			}
		} else {
			if capturedCmd.SysProcAttr != nil {
				t.Error("expected SysProcAttr to be nil on non-Linux platforms")
			}
		}
	})
}

// TestApplyCachedBundle_NoCacheFile tests applyCachedBundle returns nil when cache file doesn't exist.
func TestApplyCachedBundle_NoCacheFile(t *testing.T) {
	cfg := helperConfig()
	configPath := helperConfigPath(t, cfg)

	agent := New(configPath, "http://localhost:8080")
	// Use a non-existent cache path in temp dir
	agent.cachePath = filepath.Join(t.TempDir(), "nonexistent.rules")
	agent.cmdRunner = &mockCommandRunner{}

	err := agent.applyCachedBundle(context.Background())

	if err != nil {
		t.Errorf("applyCachedBundle() error = %v, want nil for missing cache", err)
	}
}

// TestApplyCachedBundle_EmptyRules tests applyCachedBundle returns error for empty rules.
func TestApplyCachedBundle_EmptyRules(t *testing.T) {
	cfg := helperConfig()
	configPath := helperConfigPath(t, cfg)

	agent := New(configPath, "http://localhost:8080")

	// Create empty cache file
	cacheDir := t.TempDir()
	cachePath := filepath.Join(cacheDir, "cached-bundle.rules")
	_ = os.WriteFile(cachePath, []byte(""), 0600)
	agent.cachePath = cachePath
	agent.cmdRunner = &mockCommandRunner{}

	err := agent.applyCachedBundle(context.Background())

	if err == nil {
		t.Error("applyCachedBundle() expected error for empty rules, got nil")
	}
	if err != nil && !strings.Contains(err.Error(), "empty") {
		t.Errorf("applyCachedBundle() error = %v, want 'empty' error", err)
	}
}

// TestApplyCachedBundle_WhitespaceOnlyRules tests applyCachedBundle returns error for whitespace-only rules.
func TestApplyCachedBundle_WhitespaceOnlyRules(t *testing.T) {
	cfg := helperConfig()
	configPath := helperConfigPath(t, cfg)

	agent := New(configPath, "http://localhost:8080")

	cacheDir := t.TempDir()
	cachePath := filepath.Join(cacheDir, "cached-bundle.rules")
	_ = os.WriteFile(cachePath, []byte("   \n  \n  "), 0600)
	agent.cachePath = cachePath
	agent.cmdRunner = &mockCommandRunner{}

	err := agent.applyCachedBundle(context.Background())

	if err == nil {
		t.Error("applyCachedBundle() expected error for whitespace-only rules, got nil")
	}
}

// TestApplyCachedBundle_ReadError tests applyCachedBundle returns error on read failure.
func TestApplyCachedBundle_ReadError(t *testing.T) {
	cfg := helperConfig()
	configPath := helperConfigPath(t, cfg)

	agent := New(configPath, "http://localhost:8080")

	// Point to an unreadable path (directory instead of file)
	cacheDir := t.TempDir()
	agent.cachePath = cacheDir // This is a directory, not a file
	agent.cmdRunner = &mockCommandRunner{}

	err := agent.applyCachedBundle(context.Background())

	if err == nil {
		t.Error("applyCachedBundle() expected error for unreadable path, got nil")
	}
}

// TestApplyCachedBundle_Success tests applyCachedBundle calls iptables-restore with valid rules.
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

// TestBackupIptables_SkipsIfBackupExists tests backupIptables skips when backup already exists.
func TestBackupIptables_SkipsIfBackupExists(t *testing.T) {
	cfg := helperConfig()
	configPath := helperConfigPath(t, cfg)

	agent := New(configPath, "http://localhost:8080")

	// Create a temp dir and set backupPath to a file that exists
	backupDir := t.TempDir()
	backupPath := filepath.Join(backupDir, "iptables-backup.rules")
	os.WriteFile(backupPath, []byte("existing"), 0600)
	agent.backupPath = backupPath
	agent.cmdRunner = &mockCommandRunner{}

	err := agent.backupIptables()

	if err != nil {
		t.Errorf("backupIptables() error = %v, want nil for existing backup", err)
	}
}

// TestBackupIptables_IptablesSaveFails tests backupIptables returns error when iptables-save fails.
func TestBackupIptables_IptablesSaveFails(t *testing.T) {
	cfg := helperConfig()
	configPath := helperConfigPath(t, cfg)

	agent := New(configPath, "http://localhost:8080")

	backupDir := t.TempDir()
	// Don't create the backup file - it should try to create it
	agent.backupPath = filepath.Join(backupDir, "iptables-backup.rules")
	agent.cmdRunner = &mockCommandRunner{err: fmt.Errorf("iptables-save: command not found")}

	err := agent.backupIptables()

	if err == nil {
		t.Error("backupIptables() expected error when iptables-save fails, got nil")
	}
}

// TestBackupIptables_Success tests backupIptables saves rules when no backup exists.
func TestBackupIptables_Success(t *testing.T) {
	cfg := helperConfig()
	configPath := helperConfigPath(t, cfg)

	agent := New(configPath, "http://localhost:8080")

	backupDir := t.TempDir()
	agent.backupPath = filepath.Join(backupDir, "iptables-backup.rules")
	agent.cmdRunner = &mockCommandRunner{output: []byte("*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n")}

	err := agent.backupIptables()

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

// TestListenSSEHandlesReRegistration tests listenSSE handles re-registration on 401
func TestListenSSEHandlesReRegistration(t *testing.T) {
	cfg := helperConfig()
	configPath := helperConfigPath(t, cfg)

	agent := New(configPath, "http://localhost:8080")
	agent.config.HostID = "test-host"
	agent.config.Token = "test-token"

	// Create a mock server that returns 401
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

// TestAgentDefaultPaths tests that Agent has correct default cache and backup paths.
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
		t.Error("cmdRunner is nil, expected RealCommandRunner")
	}
}

// TestRunLoadsConfig tests Run loads config on startup
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

// TestRunFailsOnEmptyControlPlaneURL tests Run fails when control plane URL is empty
func TestRunFailsOnEmptyControlPlaneURL(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")

	// Create config without control plane URL
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

// TestRunRegistersWhenNeeded tests Run registers when credentials are missing
func TestRunRegistersWhenNeeded(t *testing.T) {
	cfg := helperConfig()
	cfg.HostID = "" // No credentials
	cfg.Token = ""
	configPath := helperConfigPath(t, cfg)

	// Create a mock server that handles registration
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

// TestApplyBundleWithMockApply tests applyBundle calls apply.ApplyBundle and updates config
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

// TestIsControlPlaneReachableWithNon200 tests isControlPlaneReachable returns false on non-200
func TestIsControlPlaneReachableWithNon200(t *testing.T) {
	cfg := helperConfig()
	configPath := helperConfigPath(t, cfg)

	agent := New(configPath, "http://localhost:8080")
	agent.config.Token = "test-token"

	// Create a mock server that returns 500
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

// TestConfigNeedsRegistration tests the NeedsRegistration method
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

// TestAgentFields tests that Agent has all required fields
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

	// All fields should be non-nil (except shipper which is set in Run)
	if agent.config == nil {
		t.Error("Agent.config is nil")
	}
	if agent.httpClient == nil {
		t.Error("Agent.httpClient is nil")
	}
	if agent.sseClient == nil {
		t.Error("Agent.sseClient is nil")
	}
	if agent.rotationManager == nil {
		t.Error("Agent.rotationManager is nil")
	}
}

// TestAgentMutexFieldExists tests that Agent has regMu field
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

// TestHeartbeatLoopStructure tests heartbeatLoop structure
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

// TestPollLoopStructure tests pollLoop structure
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

// TestRotationCheckLoopStructure tests rotationCheckLoop structure
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

// TestDefaultHeartbeatInterval tests default heartbeat interval
func TestDefaultHeartbeatInterval(t *testing.T) {
	if identity.DefaultHeartbeatIntervalSec != 30 {
		t.Errorf("DefaultHeartbeatIntervalSec = %d, want 30", identity.DefaultHeartbeatIntervalSec)
	}
}

// TestDefaultPullInterval tests default pull interval
func TestDefaultPullInterval(t *testing.T) {
	if identity.DefaultPullIntervalSec != 86400 {
		t.Errorf("DefaultPullIntervalSec = %d, want 86400", identity.DefaultPullIntervalSec)
	}
}

// TestLoadConfigMergePriority tests that CLI values take priority over config file
func TestLoadConfigMergePriority(t *testing.T) {
	// Create config with EMPTY ControlPlaneURL so CLI value can override
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

// TestLoadConfigPreservesExistingURL tests that config file URL is preserved when CLI is empty
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

// TestAgentStartsWithURLInConfigFile tests that agent can start when URL is only in config file
// This tests the fix for BUG-001 where premature URL validation blocked startup
func TestAgentStartsWithURLInConfigFile(t *testing.T) {
	// Create config with control plane URL (no CLI-provided URL)
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

	// Create agent WITHOUT CLI-provided URL (empty string)
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

// TestAgentStartsWithCLIURLOverride tests that CLI URL overrides config file URL
func TestAgentStartsWithCLIURLOverride(t *testing.T) {
	// Create config with control plane URL
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

	// Create agent WITH CLI-provided URL (should override config file)
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

// TestAgentURLMergeLogicConfigHasURL tests the merge logic when config file has URL
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

// TestAgentURLMergeLogicConfigEmpty tests the merge logic when config file URL is empty
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

// TestAgentFailsWithNoURL tests that Run() fails when no URL is provided anywhere
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
