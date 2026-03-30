package core

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"runic/internal/agent/apply"
	"runic/internal/agent/identity"
	"runic/internal/agent/metrics"
	"runic/internal/agent/rotation"
	"runic/internal/agent/transport"
	"runic/internal/common/constants"
	"runic/internal/common/log"
	"runic/internal/models"
)

// Version is the agent version, set at build time.
var Version = "0.3.0"

// Agent is the main agent struct.
type Agent struct {
	config          *identity.Config
	configPath      string
	httpClient      *http.Client
	sseClient       *http.Client
	version         string
	shipper         *transport.Shipper
	rotationManager *rotation.Manager
}

// New creates a new Agent instance.
func New(configPath, controlPlaneURL string) *Agent {
	// Create HTTP client with timeouts and retry logic
	httpClient := &http.Client{
		Timeout: constants.HTTPClientTimeout,
	}

	// SSE client has no timeout (long-lived connection)
	sseClient := &http.Client{
		Timeout: 0,
	}

	cfg := &identity.Config{
		ControlPlaneURL: controlPlaneURL,
		PullIntervalSec: 30,
		LogPath:         "/var/log/runic/firewall.log",
	}

	agent := &Agent{
		config:     cfg,
		configPath: configPath,
		httpClient: httpClient,
		sseClient:  sseClient,
		version:    Version,
	}

	// Initialize rotation manager (hostID will be set after registration/load)
	agent.rotationManager = rotation.NewManager(cfg, configPath, httpClient, cfg.ControlPlaneURL, "")

	return agent
}

// Run starts the agent main loop.
func (a *Agent) Run(ctx context.Context) error {
	// 1. Load or create config
	if err := a.loadConfig(); err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	// Validate control plane URL
	if a.config.ControlPlaneURL == "" {
		return fmt.Errorf("control plane URL is required: set via --url flag or RUNIC_CONTROL_PLANE_URL env var")
	}

	log.Info("Runic agent starting", "version", a.version)
	log.Info("Control plane URL", "url", a.config.ControlPlaneURL)

	// 2. If no host_id/token, run registration
	if a.config.NeedsRegistration() {
		log.Info("No credentials found, registering with control plane")
		if err := a.register(ctx); err != nil {
			return fmt.Errorf("registration failed: %w", err)
		}
	}

	// Update rotation manager with host ID after registration/load
	a.rotationManager = rotation.NewManager(a.config, a.configPath, a.httpClient, a.config.ControlPlaneURL, a.config.HostID)

	// 3. Backup iptables on first install (before any rule changes)
	if err := a.backupIptables(); err != nil {
		log.Warn("Failed to backup iptables", "error", err)
	}

	// 4. Apply cached bundle on startup if control plane is unreachable
	if a.config.ApplyOnBoot {
		if !a.isControlPlaneReachable(ctx) {
			log.Info("Control plane unreachable, applying cached bundle")
			if err := a.applyCachedBundle(ctx); err != nil {
				log.Warn("Failed to apply cached bundle on startup", "error", err)
			}
		} else {
			log.Info("Control plane reachable, will fetch latest bundle")
		}
	}

	// 5. Initialize shipper
	a.shipper = transport.NewShipper(a.httpClient, a.config.ControlPlaneURL, a.config.Token, a.config.HostID, a.config.LogPath)

	// 6. Start background goroutines
	bgCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Heartbeat ticker
	go a.heartbeatLoop(bgCtx)

	// Bundle poller
	go a.pollLoop(bgCtx)

	// Log shipper
	go a.shipper.Run(bgCtx)

	// SSE listener
	go a.listenSSE(bgCtx)

	// Key rotation checker
	go a.rotationCheckLoop(bgCtx)

	// 7. Block on context
	log.Info("Agent running. Press Ctrl+C to stop.")
	<-ctx.Done()
	log.Info("Agent shutting down")
	return nil
}

// backupIptables saves the current iptables rules on first install.
func (a *Agent) backupIptables() error {
	const backupPath = "/etc/runic-agent/iptables-backup.rules"

	// Check if backup already exists
	if _, err := os.Stat(backupPath); err == nil {
		log.Info("iptables backup already exists, skipping")
		return nil
	}

	// Create directory
	dir := filepath.Dir(backupPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create backup dir: %w", err)
	}

	// Dump current rules
	out, err := exec.Command("iptables-save").Output()
	if err != nil {
		return fmt.Errorf("iptables-save: %w", err)
	}

	// Write to backup file
	if err := os.WriteFile(backupPath, out, 0600); err != nil {
		return fmt.Errorf("write backup: %w", err)
	}

	log.Info("iptables rules backed up", "path", backupPath)
	return nil
}

func (a *Agent) loadConfig() error {
	cfg, err := identity.LoadConfig(a.configPath)
	if err != nil {
		return err
	}

	// Merge CLI-provided values over config file
	if a.config != nil {
		if cfg.ControlPlaneURL == "" && a.config.ControlPlaneURL != "" {
			cfg.ControlPlaneURL = a.config.ControlPlaneURL
		}
	}

	*a.config = *cfg
	return nil
}

// saveConfig persists the current config.
func (a *Agent) saveConfig() error {
	return identity.SaveConfig(a.configPath, a.config)
}

// post sends a JSON POST request with retry logic.
func (a *Agent) post(ctx context.Context, path string, body interface{}) (*http.Response, error) {
	return a.doRequestWithRetry(ctx, "POST", path, body)
}

// get sends a GET request with retry logic.
func (a *Agent) get(ctx context.Context, path string) (*http.Response, error) {
	return a.doRequestWithRetry(ctx, "GET", path, nil)
}

func (a *Agent) doRequestWithRetry(ctx context.Context, method, path string, body interface{}) (*http.Response, error) {
	var reqBody io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal request: %w", err)
		}
		reqBody = bytes.NewReader(data)
	}

	url := a.config.ControlPlaneURL + path
	var lastErr error

	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(1<<uint(attempt)) * time.Second
			log.Warn("Request failed, retrying", "attempt", attempt+1, "method", method, "path", path, "backoff", backoff)
			time.Sleep(backoff)
		}

		req, err := http.NewRequestWithContext(ctx, method, url, reqBody)
		if err != nil {
			lastErr = fmt.Errorf("create request: %w", err)
			continue
		}

		req.Header.Set("User-Agent", "runic-agent/"+a.version)
		req.Header.Set("Content-Type", "application/json")
		if a.config.Token != "" {
			req.Header.Set("Authorization", "Bearer "+a.config.Token)
		}

		resp, err := a.httpClient.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("request failed: %w", err)
			continue
		}

		return resp, nil
	}

	return nil, fmt.Errorf("all retries exhausted for %s %s: %w", method, path, lastErr)
}

// heartbeatLoop sends heartbeats at the configured interval.
func (a *Agent) heartbeatLoop(ctx context.Context) {
	ticker := time.NewTicker(time.Duration(a.config.PullIntervalSec) * time.Second)
	defer ticker.Stop()

	// Send first heartbeat immediately
	a.sendHeartbeat(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := a.sendHeartbeat(ctx); err != nil {
				log.Error("Heartbeat failed", "error", err)
			}
		}
	}
}

// sendHeartbeat sends a heartbeat to the control plane.
func (a *Agent) sendHeartbeat(ctx context.Context) error {
	return metrics.SendHeartbeat(ctx, a.httpClient, a.config.ControlPlaneURL, a.config.HostID, a.config.CurrentBundleVer, a.config.Token, a.version)
}

// pollLoop polls for bundle updates at the configured interval.
func (a *Agent) pollLoop(ctx context.Context) {
	ticker := time.NewTicker(time.Duration(a.config.PullIntervalSec) * time.Second)
	defer ticker.Stop()

	// Poll immediately on start
	a.pullBundle(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := a.pullBundle(ctx); err != nil {
				log.Error("Bundle poll failed", "error", err)
			}
		}
	}
}

// pullBundle fetches the latest bundle from the control plane.
func (a *Agent) pullBundle(ctx context.Context) error {
	return transport.PullBundle(ctx, a.httpClient, a.config.ControlPlaneURL, a.config.HostID, a.config.Token, a.config.CurrentBundleVer, a.version, a.applyBundle)
}

// applyBundle applies a new bundle with auto-revert protection.
func (a *Agent) applyBundle(ctx context.Context, bundle models.BundleResponse) error {
	err := apply.ApplyBundle(ctx, bundle, a.config.HMACKey, a.config.ControlPlaneURL, a.config.Token, a.version, a.confirmApply)
	if err == nil {
		// Update config with new bundle version
		a.config.CurrentBundleVer = bundle.Version
		if err := a.saveConfig(); err != nil {
			log.Warn("Failed to save config after applying bundle", "error", err)
		}
	}
	return err
}

// confirmApply notifies the control plane that a bundle was applied.
func (a *Agent) confirmApply(ctx context.Context, version string) error {
	return transport.ConfirmApply(ctx, a.httpClient, a.config.ControlPlaneURL, a.config.HostID, a.config.Token, a.version, version)
}

// register performs initial registration with the control plane.
func (a *Agent) register(ctx context.Context) error {
	return identity.Register(ctx, a.httpClient, a.config, a.version, a.saveConfig)
}

// isControlPlaneReachable checks if the control plane is reachable via a quick HTTP request.
func (a *Agent) isControlPlaneReachable(ctx context.Context) bool {
	client := &http.Client{
		Timeout: constants.ReachabilityTimeout,
	}
	url := fmt.Sprintf("%s/api/v1/agent/heartbeat", a.config.ControlPlaneURL)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return false
	}
	req.Header.Set("Authorization", "Bearer "+a.config.Token)
	req.Header.Set("User-Agent", "runic-agent/"+a.version)

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// applyCachedBundle applies the cached bundle from disk on startup.
func (a *Agent) applyCachedBundle(ctx context.Context) error {
	const cachePath = "/etc/runic-agent/cached-bundle.rules"

	// Read cached bundle
	data, err := os.ReadFile(cachePath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Info("No cached bundle found, skipping apply-on-boot")
			return nil
		}
		return fmt.Errorf("read cached bundle: %w", err)
	}

	rules := string(data)

	// Validate the rules
	if strings.TrimSpace(rules) == "" {
		return fmt.Errorf("cached bundle is empty")
	}

	// Apply via iptables-restore
	tmpFile, err := os.CreateTemp("", "runic-cached-*.rules")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	if _, err := tmpFile.WriteString(rules); err != nil {
		tmpFile.Close()
		return fmt.Errorf("write cached bundle to temp file: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}

	cmd := exec.CommandContext(ctx, "iptables-restore", "--noflush", tmpPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("iptables-restore failed: %s: %w", string(output), err)
	}

	log.Info("Applied cached bundle on startup", "path", cachePath)
	return nil
}

// listenSSE maintains a persistent SSE connection to receive push notifications.
func (a *Agent) listenSSE(ctx context.Context) {
	transport.ListenSSE(ctx, a.sseClient, a.config.ControlPlaneURL, a.config.HostID, a.config.Token, a.version, func(sseCtx context.Context) {
		if err := a.pullBundle(sseCtx); err != nil {
			log.Error("SSE-triggered bundle pull failed", "error", err)
		}
	})
}

// rotationCheckLoop periodically checks for pending key rotations.
func (a *Agent) rotationCheckLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute) // Check every 5 minutes
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := a.rotationManager.CheckAndRotate(); err != nil {
				log.Warn("Key rotation check failed", "error", err)
			}
		}
	}
}
