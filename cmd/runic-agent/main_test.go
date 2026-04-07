package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"runic/internal/agent/identity"
)

// TestBooleanFlagParsing tests parsing of boolean CLI flags
func TestBooleanFlagParsing(t *testing.T) {
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
	t.Run("URL validation", func(t *testing.T) {
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
				name:    "empty URL - valid (will use env or prompt)",
				url:     "",
				wantErr: false,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				cfg := &identity.Config{ControlPlaneURL: tt.url}
				err := cfg.Validate()
				if (err != nil) != tt.wantErr {
					t.Errorf("URL validation for %q: error = %v, wantErr %v", tt.url, err, tt.wantErr)
				}
			})
		}
	})

	t.Run("pull interval validation in handleConfigMode", func(t *testing.T) {
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
				tmpDir, err := os.MkdirTemp("", "runic-test-")
				if err != nil {
					t.Fatalf("failed to create temp dir: %v", err)
				}
				defer os.RemoveAll(tmpDir)

				configPath := filepath.Join(tmpDir, "config.json")
				cfg := identity.DefaultConfig()
				if err := identity.SaveConfig(configPath, cfg); err != nil {
					t.Fatalf("failed to save initial config: %v", err)
				}

				// Create a configFlag for pull interval
				cf := configFlag{set: true, value: tt.value}
				err = handleConfigMode(configPath, configFlag{}, configFlag{}, configFlag{}, configFlag{}, configFlag{}, cf)

				if (err != nil) != tt.wantErr {
					t.Errorf("pull-interval %q: error = %v, wantErr %v", tt.value, err, tt.wantErr)
				}
			})
		}
	})

	t.Run("log path validation", func(t *testing.T) {
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
				tmpDir, err := os.MkdirTemp("", "runic-test-")
				if err != nil {
					t.Fatalf("failed to create temp dir: %v", err)
				}
				defer os.RemoveAll(tmpDir)

				configPath := filepath.Join(tmpDir, "config.json")
				cfg := identity.DefaultConfig()
				if err := identity.SaveConfig(configPath, cfg); err != nil {
					t.Fatalf("failed to save initial config: %v", err)
				}

				// Create a configFlag for log path
				cf := configFlag{set: true, value: tt.logPath}
				err = handleConfigMode(configPath, configFlag{}, configFlag{}, configFlag{}, configFlag{}, cf, configFlag{})

				if (err != nil) != tt.wantErr {
					t.Errorf("log-path %q: error = %v, wantErr %v", tt.logPath, err, tt.wantErr)
				}
			})
		}
	})
}

// TestConfigModeDetection tests detection of config-mode vs normal startup
func TestConfigModeDetection(t *testing.T) {
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
			got := isConfigMode(tt.flags...)
			if got != tt.wantConfigMode {
				t.Errorf("isConfigMode() = %v, want %v", got, tt.wantConfigMode)
			}
		})
	}
}

// TestConfigValidation tests validation of config before saving
func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		config  *identity.Config
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid config - all defaults",
			config: &identity.Config{
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
				PullIntervalSec:      86400,
				HeartbeatIntervalSec: 30,
				LogPath:              "   ",
			},
			wantErr: true,
			errMsg:  "cannot be empty or whitespace-only",
		},
		{
			name: "valid config - empty URL (will use env)",
			config: &identity.Config{
				ControlPlaneURL:      "",
				PullIntervalSec:      86400,
				HeartbeatIntervalSec: 30,
				LogPath:              "/var/log/runic/firewall.log",
			},
			wantErr: false,
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
	tests := []struct {
		name    string
		config  *identity.Config
		wantErr bool
	}{
		{
			name:    "valid config",
			config:  identity.DefaultConfig(),
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
			_, err := validateConfig(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestMultipleFlagsCombined tests applying multiple config flags in one command
func TestMultipleFlagsCombined(t *testing.T) {
	// Create temporary config directory
	tmpDir, err := os.MkdirTemp("", "runic-test-")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	configPath := filepath.Join(tmpDir, "config.json")

	// Create initial config
	initialCfg := identity.DefaultConfig()
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
	err = handleConfigMode(configPath, enableOnBoot, enableRulesBundle, disableIPTables, url, logPath, pullInterval)
	if err != nil {
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
			tmpDir, err := os.MkdirTemp("", "runic-test-")
			if err != nil {
				t.Fatalf("failed to create temp dir: %v", err)
			}
			defer os.RemoveAll(tmpDir)

			configPath := filepath.Join(tmpDir, "config.json")
			cfg := identity.DefaultConfig()
			if err := identity.SaveConfig(configPath, cfg); err != nil {
				t.Fatalf("failed to save initial config: %v", err)
			}

			// Test enable-on-boot flag
			enableOnBoot := configFlag{set: true, value: tt.flagValue}
			err = handleConfigMode(configPath, enableOnBoot, configFlag{}, configFlag{}, configFlag{}, configFlag{}, configFlag{})

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
			tmpDir, err := os.MkdirTemp("", "runic-test-")
			if err != nil {
				t.Fatalf("failed to create temp dir: %v", err)
			}
			defer os.RemoveAll(tmpDir)

			configPath := filepath.Join(tmpDir, "config.json")
			cfg := identity.DefaultConfig()
			if err := identity.SaveConfig(configPath, cfg); err != nil {
				t.Fatalf("failed to save initial config: %v", err)
			}

			pullInterval := configFlag{set: true, value: tt.value}
			err = handleConfigMode(configPath, configFlag{}, configFlag{}, configFlag{}, configFlag{}, configFlag{}, pullInterval)

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
	t.Run("Set method", func(t *testing.T) {
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
		cf := configFlag{value: "test-value"}
		if got := cf.String(); got != "test-value" {
			t.Errorf("String() = %q, want %q", got, "test-value")
		}
	})

	t.Run("IsBoolFlag method", func(t *testing.T) {
		var cf configFlag
		if cf.IsBoolFlag() {
			t.Error("IsBoolFlag() should return false")
		}
	})
}

// TestConfigFileIntegrityAfterSave tests that saved config is valid JSON and can be reloaded
func TestConfigFileIntegrityAfterSave(t *testing.T) {
	// Create temporary config directory
	tmpDir, err := os.MkdirTemp("", "runic-test-")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	configPath := filepath.Join(tmpDir, "config.json")

	// Create initial config
	initialCfg := identity.DefaultConfig()
	if err := identity.SaveConfig(configPath, initialCfg); err != nil {
		t.Fatalf("failed to save initial config: %v", err)
	}

	// Apply overrides via handleConfigMode
	enableOnBoot := configFlag{set: true, value: "true"}
	enableRulesBundle := configFlag{set: true, value: "true"}
	url := configFlag{set: true, value: "https://example.com"}
	logPath := configFlag{set: true, value: "/var/log/runic/new.log"}
	pullInterval := configFlag{set: true, value: "3600"}

	err = handleConfigMode(configPath, enableOnBoot, enableRulesBundle, configFlag{}, url, logPath, pullInterval)
	if err != nil {
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
	// This test just verifies the function doesn't panic
	// The actual result depends on the system state
	_ = isSystemdServiceInstalled()
}

// TestConfigFlagCombinedWithInvalidValue tests that when one flag has an invalid value, config is not saved
func TestConfigFlagCombinedWithInvalidValue(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "runic-test-")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	configPath := filepath.Join(tmpDir, "config.json")
	initialCfg := identity.DefaultConfig()
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
