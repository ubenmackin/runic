// Package identity handles agent authentication.
package identity

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// DefaultPullIntervalSec is the default polling interval (24 hours).
// SSE is the primary notification mechanism; polling is a fallback.
const DefaultPullIntervalSec = 86400 // 24 hours (SSE is primary)

// DefaultHeartbeatIntervalSec is the default heartbeat interval (30 seconds).
// Must be less than OfflineThresholdSeconds (90s) to prevent false offline detection.
const DefaultHeartbeatIntervalSec = 30

// Config holds the agent configuration.
type Config struct {
	ControlPlaneURL              string `json:"control_plane_url"`
	HostID                       string `json:"host_id"`
	Token                        string `json:"token"`
	PullIntervalSec              int    `json:"pull_interval_seconds"`
	HeartbeatIntervalSec         int    `json:"heartbeat_interval_seconds"`
	LogPath                      string `json:"log_path"`
	CurrentBundleVer             string `json:"current_bundle_version"`
	HMACKey                      string `json:"hmac_key"`
	ApplyOnBoot                  bool   `json:"apply_on_boot"`
	ApplyRulesBundle             bool   `json:"apply_rules_bundle"`
	RegistrationToken            string `json:"registration_token,omitempty"`
	DisableSystemManagedIPTables bool   `json:"disable_system_managed_iptables"`
}

// DefaultConfig returns a config with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		PullIntervalSec:              DefaultPullIntervalSec,
		HeartbeatIntervalSec:         DefaultHeartbeatIntervalSec,
		LogPath:                      "/var/log/runic/firewall.log",
		ApplyOnBoot:                  false,
		ApplyRulesBundle:             false,
		DisableSystemManagedIPTables: false,
	}
}

// LoadConfig reads config from the given path.
// If the file does not exist, returns a default config.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return DefaultConfig(), nil
		}
		return nil, fmt.Errorf("read config: %w", err)
	}

	cfg := DefaultConfig()
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	return cfg, nil
}

// SaveConfig writes the config to disk with 0600 permissions.
// Creates the directory if needed. Validates the config before saving.
func SaveConfig(path string, cfg *Config) error {
	// Validate config before saving
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("config validation failed: %w", err)
	}

	dir := filepath.Dir(path)

	// Ensure directory exists with 0700 permissions
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}

	return nil
}

// HasCredentials returns true if the config has both host_id and token.
func (c *Config) HasCredentials() bool {
	return c.HostID != "" && c.Token != ""
}

// NeedsRegistration returns true if the agent needs to register.
func (c *Config) NeedsRegistration() bool {
	return !c.HasCredentials()
}

// Validate checks that the config has valid values.
// Returns an error describing the first validation failure, or nil if valid.
func (c *Config) Validate() error {
	// Validate ControlPlaneURL if provided
	if c.ControlPlaneURL != "" {
		// Check that it's a valid URL
		parsedURL, err := url.Parse(c.ControlPlaneURL)
		if err != nil {
			return fmt.Errorf("invalid control_plane_url: %w", err)
		}
		// Must have a scheme (http or https)
		if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
			return fmt.Errorf("invalid control_plane_url: scheme must be http or https, got %q", parsedURL.Scheme)
		}
		// Must have a host
		if parsedURL.Host == "" {
			return fmt.Errorf("invalid control_plane_url: missing host")
		}
	}

	// Validate PullIntervalSec
	if c.PullIntervalSec < 0 {
		return fmt.Errorf("invalid pull_interval_seconds: must be non-negative, got %d", c.PullIntervalSec)
	}
	if c.PullIntervalSec > 31536000 { // 1 year in seconds
		return fmt.Errorf("invalid pull_interval_seconds: must be at most 31536000 (1 year), got %d", c.PullIntervalSec)
	}

	// Validate HeartbeatIntervalSec
	if c.HeartbeatIntervalSec < 0 {
		return fmt.Errorf("invalid heartbeat_interval_seconds: must be non-negative, got %d", c.HeartbeatIntervalSec)
	}
	if c.HeartbeatIntervalSec > 3600 { // 1 hour
		return fmt.Errorf("invalid heartbeat_interval_seconds: must be at most 3600 (1 hour), got %d", c.HeartbeatIntervalSec)
	}

	// Validate LogPath if provided
	if c.LogPath != "" {
		// Check for empty or whitespace-only path
		if strings.TrimSpace(c.LogPath) == "" {
			return fmt.Errorf("invalid log_path: cannot be empty or whitespace-only")
		}
		// Check that parent directory exists or can be created
		logDir := filepath.Dir(c.LogPath)
		if logDir != "" && logDir != "." {
			// Check if the directory exists
			if _, err := os.Stat(logDir); err != nil {
				if !os.IsNotExist(err) {
					return fmt.Errorf("invalid log_path: cannot access parent directory %q: %w", logDir, err)
				}
				// Directory doesn't exist, but we'll create it on save, so this is okay
			}
		}
	}

	return nil
}
