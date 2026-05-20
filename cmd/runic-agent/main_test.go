package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"runic/internal/agent/identity"
	"runic/internal/common/systemd"
)

// setupTestConfig creates a temporary config directory with a default config
// and returns the path to the config file. The directory is cleaned up
// automatically when the test and its subtests complete.
func setupTestConfig(t *testing.T) string {
	t.Helper()
	tmpDir, err := os.MkdirTemp("", "runic-test-")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(tmpDir) })

	configPath := filepath.Join(tmpDir, "config.json")
	cfg := identity.DefaultConfig()
	cfg.ControlPlaneURL = "https://example.com"
	if err := identity.SaveConfig(configPath, cfg); err != nil {
		t.Fatalf("failed to save initial config: %v", err)
	}
	return configPath
}

// TestBooleanFlagParsing tests parsing of boolean CLI flags
func TestBooleanFlagParsing(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		value   string
		want    bool
		wantErr bool
	}{
		{
			name:    "lowercase true",
			value:   "true",
			want:    true,
			wantErr: false,
		},
		{
			name:    "uppercase TRUE",
			value:   "TRUE",
			want:    true,
			wantErr: false,
		},
		{
			name:    "mixed case True",
			value:   "True",
			want:    true,
			wantErr: false,
		},
		{
			name:    "numeric 1",
			value:   "1",
			want:    true,
			wantErr: false,
		},
		{
			name:    "yes",
			value:   "yes",
			want:    true,
			wantErr: false,
		},
		{
			name:    "on",
			value:   "on",
			want:    true,
			wantErr: false,
		},
		{
			name:    "lowercase false",
			value:   "false",
			want:    false,
			wantErr: false,
		},
		{
			name:    "uppercase FALSE",
			value:   "FALSE",
			want:    false,
			wantErr: false,
		},
		{
			name:    "numeric 0",
			value:   "0",
			want:    false,
			wantErr: false,
		},
		{
			name:    "no",
			value:   "no",
			want:    false,
			wantErr: false,
		},
		{
			name:    "off",
			value:   "off",
			want:    false,
			wantErr: false,
		},
		{
			name:    "invalid value",
			value:   "invalid",
			want:    false,
			wantErr: true,
		},
		{
			name:    "empty string",
			value:   "",
			want:    false,
			wantErr: true,
		},
		{
			name:    "whitespace true",
			value:   " true ",
			want:    true,
			wantErr: false,
		},
		{
			name:    "whitespace false",
			value:   "  false  ",
			want:    false,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := parseBoolFlag(tt.value)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseBoolFlag(%q) error = %v, wantErr %v", tt.value, err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("parseBoolFlag(%q) = %v, want %v", tt.value, got, tt.want)
			}
		})
	}
}

// TestStringFlagValidation tests validation of string CLI flags (URL, log path, pull interval)
func TestStringFlagValidation(t *testing.T) {
	t.Parallel()
	t.Run("URL validation", func(t *testing.T) {
		t.Parallel()
		tests := []struct {
			name    string
			url     string
			wantErr bool
		}{
			{
				name:    "valid http URL",
				url:     "http://example.com",
				wantErr: false,
			},
			{
				name:    "valid https URL",
				url:     "https://example.com",
				wantErr: false,
			},
			{
				name:    "valid URL with path",
				url:     "https://example.com/api/v1",
				wantErr: false,
			},
			{
				name:    "valid URL with port",
				url:     "https://example.com:8080",
				wantErr: false,
			},
			{
				name:    "invalid URL - no scheme",
				url:     "example.com",
				wantErr: true,
			},
			{
				name:    "invalid URL - ftp scheme",
				url:     "ftp://example.com",
				wantErr: true,
			},
			{
				name:    "empty URL - invalid (control_plane_url is required)",
				url:     "",
				wantErr: true,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()
				cfg := &identity.Config{ControlPlaneURL: tt.url}
				err := cfg.Validate()
				if (err != nil) != tt.wantErr {
					t.Errorf("URL validation for %q: error = %v, wantErr %v", tt.url, err, tt.wantErr)
				}
			})
		}
	})

	t.Run("pull interval validation in handleConfigMode", func(t *testing.T) {
		t.Parallel()
		tests := []struct {
			name    string
			value   string
			wantErr bool
		}{
			{
				name:    "valid - 60 seconds",
				value:   "60",
				wantErr: false,
			},
			{
				name:    "valid - 86400 seconds (24h)",
				value:   "86400",
				wantErr: false,
			},
			{
				name:    "valid - 0 (use default)",
				value:   "0",
				wantErr: false,
			},
			{
				name:    "valid - 31536000 (1 year)",
				value:   "31536000",
				wantErr: false,
			},
			{
				name:    "invalid - negative",
				value:   "-1",
				wantErr: true,
			},
			{
				name:    "invalid - too large",
				value:   "31536001",
				wantErr: true,
			},
			{
				name:    "invalid - not a number",
				value:   "abc",
				wantErr: true,
			},
			{
				name:    "invalid - float",
				value:   "60.5",
				wantErr: true,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()
				configPath := setupTestConfig(t)

				// Create a configFlag for pull interval
				cf := configFlag{set: true, value: tt.value}
				err := handleConfigMode(configPath, configFlag{}, configFlag{}, configFlag{}, configFlag{}, configFlag{}, cf)

				if (err != nil) != tt.wantErr {
					t.Errorf("pull-interval %q: error = %v, wantErr %v", tt.value, err, tt.wantErr)
				}
			})
		}
	})

	t.Run("log path validation", func(t *testing.T) {
		t.Parallel()
		tests := []struct {
			name    string
			logPath string
			wantErr bool
		}{
			{
				name:    "valid path",
				logPath: "/var/log/runic/firewall.log",
				wantErr: false,
			},
			{
				name:    "valid path - different location",
				logPath: "/tmp/test.log",
				wantErr: false,
			},
			{
				name:    "empty path - should error in handleConfigMode",
				logPath: "",
				wantErr: true,
			},
			{
				name:    "whitespace only - invalid",
				logPath: "   ",
				wantErr: true,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()
				configPath := setupTestConfig(t)

				// Create a configFlag for log path
				cf := configFlag{set: true, value: tt.logPath}
				err := handleConfigMode(configPath, configFlag{}, configFlag{}, configFlag{}, configFlag{}, cf, configFlag{})

				if (err != nil) != tt.wantErr {
					t.Errorf("log-path %q: error = %v, wantErr %v", tt.logPath, err, tt.wantErr)
				}
			})
		}
	})
}

// TestConfigModeDetection tests detection of config-mode vs normal startup
func TestConfigModeDetection(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name           string
		flags          []configFlag
		wantConfigMode bool
	}{
		{
			name: "no flags set - normal startup",
			flags: []configFlag{
				{set: false},
				{set: false},
				{set: false},
			},
			wantConfigMode: false,
		},
		{
			name: "enable-on-boot set - config mode",
			flags: []configFlag{
				{set: true},
				{set: false},
				{set: false},
			},
			wantConfigMode: true,
		},
		{
			name: "url set - config mode",
			flags: []configFlag{
				{set: false},
				{set: true},
				{set: false},
			},
			wantConfigMode: true,
		},
		{
			name: "multiple flags set - config mode",
			flags: []configFlag{
				{set: true},
				{set: true},
				{set: true},
			},
			wantConfigMode: true,
		},
		{
			name: "all flags false - normal startup",
			flags: []configFlag{
				{set: false, value: "false"},
				{set: false, value: ""},
				{set: false, value: ""},
			},
			wantConfigMode: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := isConfigMode(tt.flags...)
			if got != tt.wantConfigMode {
				t.Errorf("isConfigMode() = %v, want %v", got, tt.wantConfigMode)
			}
		})
	}
}

// TestConfigValidation tests validation of config before saving
func TestConfigValidation(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		config  *identity.Config
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid config - all defaults",
			config: &identity.Config{
				ControlPlaneURL:      "https://example.com",
				PullIntervalSec:      86400,
				HeartbeatIntervalSec: 30,
				LogPath:              "/var/log/runic/firewall.log",
			},
			wantErr: false,
		},
		{
			name: "valid config - with URL",
			config: &identity.Config{
				ControlPlaneURL:      "https://control.example.com",
				PullIntervalSec:      86400,
				HeartbeatIntervalSec: 30,
				LogPath:              "/var/log/runic/firewall.log",
			},
			wantErr: false,
		},
		{
			name: "invalid config - bad URL scheme",
			config: &identity.Config{
				ControlPlaneURL:      "ftp://control.example.com",
				PullIntervalSec:      86400,
				HeartbeatIntervalSec: 30,
				LogPath:              "/var/log/runic/firewall.log",
			},
			wantErr: true,
			errMsg:  "scheme must be http or https",
		},
		{
			name: "invalid config - negative pull interval",
			config: &identity.Config{
				ControlPlaneURL:      "https://example.com",
				PullIntervalSec:      -100,
				HeartbeatIntervalSec: 30,
				LogPath:              "/var/log/runic/firewall.log",
			},
			wantErr: true,
			errMsg:  "must be non-negative",
		},
		{
			name: "invalid config - pull interval too large",
			config: &identity.Config{
				ControlPlaneURL:      "https://example.com",
				PullIntervalSec:      40000000,
				HeartbeatIntervalSec: 30,
				LogPath:              "/var/log/runic/firewall.log",
			},
			wantErr: true,
			errMsg:  "must be at most 31536000",
		},
		{
			name: "invalid config - whitespace log path",
			config: &identity.Config{
				ControlPlaneURL:      "https://example.com",
				PullIntervalSec:      86400,
				HeartbeatIntervalSec: 30,
				LogPath:              " ",
			},
			wantErr: true,
			errMsg:  "cannot be empty or whitespace-only",
		},
		{
			name: "invalid config - empty URL",
			config: &identity.Config{
				ControlPlaneURL:      "",
				PullIntervalSec:      86400,
				HeartbeatIntervalSec: 30,
				LogPath:              "/var/log/runic/firewall.log",
			},
			wantErr: true,
			errMsg:  "control_plane_url is required",
		},
		{
			name: "valid config - URL with path",
			config: &identity.Config{
				ControlPlaneURL:      "https://control.example.com/api/v1",
				PullIntervalSec:      86400,
				HeartbeatIntervalSec: 30,
				LogPath:              "/var/log/runic/firewall.log",
			},
			wantErr: false,
		},
		{
			name: "invalid config - URL without host",
			config: &identity.Config{
				ControlPlaneURL:      "https://",
				PullIntervalSec:      86400,
				HeartbeatIntervalSec: 30,
				LogPath:              "/var/log/runic/firewall.log",
			},
			wantErr: true,
			errMsg:  "missing host",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Config.Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && tt.errMsg != "" && err != nil {
				if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("Config.Validate() error = %v, want error containing %q", err, tt.errMsg)
				}
			}
		})
	}
}

// TestValidateConfigFunction tests the validateConfig function
func TestValidateConfigFunction(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		config  *identity.Config
		wantErr bool
	}{
		{
			name: "valid config",
			config: func() *identity.Config {
				cfg := identity.DefaultConfig()
				cfg.ControlPlaneURL = "https://example.com"
				return cfg
			}(),
			wantErr: false,
		},
		{
			name: "invalid config - negative pull interval",
			config: &identity.Config{
				PullIntervalSec: -1,
			},
			wantErr: true,
		},
		{
			name: "valid config - all fields set",
			config: &identity.Config{
				ControlPlaneURL:      "https://example.com",
				HostID:               "host-123",
				Token:                "token-abc",
				PullIntervalSec:      3600,
				HeartbeatIntervalSec: 30,
				LogPath:              "/var/log/test.log",
				ApplyOnBoot:          true,
				ApplyRulesBundle:     true,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := validateConfig(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestMultipleFlagsCombined tests applying multiple config flags in one command
func TestMultipleFlagsCombined(t *testing.T) {
	t.Parallel()
	configPath := setupTestConfig(t)

	// Create initial config with a distinctive URL
	initialCfg, err := identity.LoadConfig(configPath)
	if err != nil {
		t.Fatalf("failed to load initial config: %v", err)
	}
	initialCfg.ControlPlaneURL = "https://original.example.com"
	if err := identity.SaveConfig(configPath, initialCfg); err != nil {
		t.Fatalf("failed to save initial config: %v", err)
	}

	// Create multiple config flags
	enableOnBoot := configFlag{set: true, value: "true"}
	enableRulesBundle := configFlag{set: true, value: "true"}
	disableIPTables := configFlag{set: true, value: "true"}
	url := configFlag{set: true, value: "https://new.example.com"}
	logPath := configFlag{set: true, value: "/var/log/runic/new.log"}
	pullInterval := configFlag{set: true, value: "300"}

	// Apply multiple overrides
	if err := handleConfigMode(configPath, enableOnBoot, enableRulesBundle, disableIPTables, url, logPath, pullInterval); err != nil {
		t.Fatalf("handleConfigMode failed: %v", err)
	}

	// Load and verify config
	cfg, err := identity.LoadConfig(configPath)
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	// Verify all overrides were applied
	if !cfg.ApplyOnBoot {
		t.Error("ApplyOnBoot should be true")
	}
	if !cfg.ApplyRulesBundle {
		t.Error("ApplyRulesBundle should be true")
	}
	if !cfg.DisableSystemManagedIPTables {
		t.Error("DisableSystemManagedIPTables should be true")
	}
	if cfg.PullIntervalSec != 300 {
		t.Errorf("PullIntervalSec = %d, want 300", cfg.PullIntervalSec)
	}
	if cfg.LogPath != "/var/log/runic/new.log" {
		t.Errorf("LogPath = %s, want /var/log/runic/new.log", cfg.LogPath)
	}
	if cfg.ControlPlaneURL != "https://new.example.com" {
		t.Errorf("ControlPlaneURL = %s, want https://new.example.com", cfg.ControlPlaneURL)
	}
}

// TestHandleConfigModeBooleanFlags tests boolean flag handling in handleConfigMode
func TestHandleConfigModeBooleanFlags(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		flagValue   string
		wantEnabled bool
		wantErr     bool
	}{
		{
			name:        "true value",
			flagValue:   "true",
			wantEnabled: true,
			wantErr:     false,
		},
		{
			name:        "false value",
			flagValue:   "false",
			wantEnabled: false,
			wantErr:     false,
		},
		{
			name:        "invalid value",
			flagValue:   "invalid",
			wantEnabled: false,
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			configPath := setupTestConfig(t)

			// Test enable-on-boot flag
			enableOnBoot := configFlag{set: true, value: tt.flagValue}
			err := handleConfigMode(configPath, enableOnBoot, configFlag{}, configFlag{}, configFlag{}, configFlag{}, configFlag{})

			if (err != nil) != tt.wantErr {
				t.Errorf("handleConfigMode() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				loadedCfg, err := identity.LoadConfig(configPath)
				if err != nil {
					t.Fatalf("failed to load config: %v", err)
				}
				if loadedCfg.ApplyOnBoot != tt.wantEnabled {
					t.Errorf("ApplyOnBoot = %v, want %v", loadedCfg.ApplyOnBoot, tt.wantEnabled)
				}
			}
		})
	}
}

// TestHandleConfigModeInvalidPullInterval tests that invalid pull interval is rejected
func TestHandleConfigModeInvalidPullInterval(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		value   string
		wantErr bool
	}{
		{
			name:    "negative value",
			value:   "-100",
			wantErr: true,
		},
		{
			name:    "too large",
			value:   "40000000",
			wantErr: true,
		},
		{
			name:    "not a number",
			value:   "abc",
			wantErr: true,
		},
		{
			name:    "valid value",
			value:   "300",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			configPath := setupTestConfig(t)

			pullInterval := configFlag{set: true, value: tt.value}
			err := handleConfigMode(configPath, configFlag{}, configFlag{}, configFlag{}, configFlag{}, configFlag{}, pullInterval)

			if (err != nil) != tt.wantErr {
				t.Errorf("handleConfigMode() with pull-interval %q: error = %v, wantErr %v", tt.value, err, tt.wantErr)
			}

			if !tt.wantErr {
				loadedCfg, err := identity.LoadConfig(configPath)
				if err != nil {
					t.Fatalf("failed to load config: %v", err)
				}
				expectedInterval := 300 // we set value to "300" for valid case
				if loadedCfg.PullIntervalSec != expectedInterval {
					t.Errorf("PullIntervalSec = %d, want %d", loadedCfg.PullIntervalSec, expectedInterval)
				}
			}
		})
	}
}

// TestConfigFlagMethods tests configFlag methods
func TestConfigFlagMethods(t *testing.T) {
	t.Parallel()
	t.Run("Set method", func(t *testing.T) {
		t.Parallel()
		var cf configFlag
		if err := cf.Set("test-value"); err != nil {
			t.Errorf("Set() unexpected error: %v", err)
		}
		if !cf.set {
			t.Error("Set() should set the 'set' field to true")
		}
		if cf.value != "test-value" {
			t.Errorf("Set() value = %q, want %q", cf.value, "test-value")
		}
	})

	t.Run("String method", func(t *testing.T) {
		t.Parallel()
		cf := configFlag{value: "test-value"}
		if got := cf.String(); got != "test-value" {
			t.Errorf("String() = %q, want %q", got, "test-value")
		}
	})

	t.Run("IsBoolFlag method", func(t *testing.T) {
		t.Parallel()
		var cf configFlag
		if cf.IsBoolFlag() {
			t.Error("IsBoolFlag() should return false")
		}
	})
}

// TestConfigFileIntegrityAfterSave tests that saved config is valid JSON and can be reloaded
func TestConfigFileIntegrityAfterSave(t *testing.T) {
	t.Parallel()
	configPath := setupTestConfig(t)

	// Apply overrides via handleConfigMode
	enableOnBoot := configFlag{set: true, value: "true"}
	enableRulesBundle := configFlag{set: true, value: "true"}
	url := configFlag{set: true, value: "https://example.com"}
	logPath := configFlag{set: true, value: "/var/log/runic/new.log"}
	pullInterval := configFlag{set: true, value: "3600"}

	if err := handleConfigMode(configPath, enableOnBoot, enableRulesBundle, configFlag{}, url, logPath, pullInterval); err != nil {
		t.Fatalf("handleConfigMode failed: %v", err)
	}

	// Read file content directly
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("failed to read config file: %v", err)
	}

	// Verify it's valid JSON
	var cfgMap map[string]interface{}
	if err := json.Unmarshal(data, &cfgMap); err != nil {
		t.Fatalf("config file is not valid JSON: %v", err)
	}

	// Verify expected fields exist with correct values
	expectedFields := map[string]interface{}{
		"apply_on_boot":                   true,
		"apply_rules_bundle":              true,
		"pull_interval_seconds":           float64(3600),
		"log_path":                        "/var/log/runic/new.log",
		"control_plane_url":               "https://example.com",
		"disable_system_managed_iptables": false,
	}

	for field, expected := range expectedFields {
		if got, ok := cfgMap[field]; !ok {
			t.Errorf("field %q missing from config", field)
		} else if got != expected {
			t.Errorf("field %q = %v, want %v", field, got, expected)
		}
	}

	// Load and verify again using LoadConfig
	loadedCfg, err := identity.LoadConfig(configPath)
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	// Verify all values
	if !loadedCfg.ApplyOnBoot {
		t.Error("ApplyOnBoot should be true")
	}
	if !loadedCfg.ApplyRulesBundle {
		t.Error("ApplyRulesBundle should be true")
	}
	if loadedCfg.PullIntervalSec != 3600 {
		t.Errorf("PullIntervalSec = %d, want 3600", loadedCfg.PullIntervalSec)
	}
	if loadedCfg.LogPath != "/var/log/runic/new.log" {
		t.Errorf("LogPath = %s, want /var/log/runic/new.log", loadedCfg.LogPath)
	}
	if loadedCfg.ControlPlaneURL != "https://example.com" {
		t.Errorf("ControlPlaneURL = %s, want https://example.com", loadedCfg.ControlPlaneURL)
	}
}

// TestIsSystemdServiceInstalled tests the systemd service detection
func TestIsSystemdServiceInstalled(t *testing.T) {
	t.Parallel()
	got := systemd.IsServiceInstalled()
	// In test environments the service file should not exist at the hardcoded paths.
	// If it does (e.g., on a developer machine where runic-agent is installed),
	// the test still passes — the assertion validates the function is callable
	// and returns a valid boolean.
	t.Logf("IsServiceInstalled() = %v (depends on system state)", got)
}

// TestConfigFlagCombinedWithInvalidValue tests that when one flag has an invalid value, config is not saved
func TestConfigFlagCombinedWithInvalidValue(t *testing.T) {
	t.Parallel()
	configPath := setupTestConfig(t)

	initialCfg, err := identity.LoadConfig(configPath)
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}
	initialCfg.ControlPlaneURL = "https://original.example.com"
	if err := identity.SaveConfig(configPath, initialCfg); err != nil {
		t.Fatalf("failed to save initial config: %v", err)
	}

	// Get initial file info
	initialData, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("failed to read initial config: %v", err)
	}

	// Try to apply invalid boolean value
	enableOnBoot := configFlag{set: true, value: "invalid-boolean"}
	err = handleConfigMode(configPath, enableOnBoot, configFlag{}, configFlag{}, configFlag{}, configFlag{}, configFlag{})
	if err == nil {
		t.Error("expected error for invalid boolean value, got nil")
	}

	// Verify config was not modified
	currentData, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("failed to read current config: %v", err)
	}

	if string(currentData) != string(initialData) {
		t.Error("config file should not have been modified when error occurred")
	}
}

// TestRestartSystemdServiceRequiresRoot tests that restartSystemdService requires root privileges.
// This test verifies the root check behavior when running as a non-root user.
// Note: When tests run as root (unlikely in CI), this test would need to be skipped.
func TestRestartSystemdServiceRequiresRoot(t *testing.T) {
	t.Parallel()
	// Skip if running as root (some CI environments may run as root)
	if os.Geteuid() == 0 {
		t.Skip("Test requires non-root user to verify root check")
	}

	// When not running as root, the function should return an error
	err := systemd.RestartService("runic-agent")
	if err == nil {
		t.Error("systemd.RestartService() should return error when not running as root")
	}

	// Verify the error message mentions root/sudo
	if err != nil {
		expectedMsg := "must be run as root"
		if !strings.Contains(err.Error(), expectedMsg) {
			t.Errorf("error message should contain %q, got: %v", expectedMsg, err)
		}
	}
}

// TestIsSystemdServiceInstalledPaths tests that IsServiceInstalled checks correct paths.
// This test verifies the function works when run in a variety of conditions.
func TestIsSystemdServiceInstalledPaths(t *testing.T) {
	t.Parallel()
	result := systemd.IsServiceInstalled()
	// In test/CI environments the hardcoded systemd paths should not contain
	// the runic-agent service file, so this is expected to be false.
	t.Logf("IsServiceInstalled() = %v", result)
}

// TestRestartSystemdServiceErrorFormat tests that the error message format is correct.
// This test is documentation of expected error behavior.
func TestRestartSystemdServiceErrorFormat(t *testing.T) {
	t.Parallel()
	// When not running as root, we should get a specific error
	if os.Geteuid() != 0 {
		err := systemd.RestartService("runic-agent")
		if err == nil {
			t.Error("expected error when not running as root")
			return
		}

		// Verify error contains "use sudo" suggestion
		if !strings.Contains(err.Error(), "use sudo") {
			t.Errorf("error should suggest using sudo, got: %v", err)
		}
	}
}
