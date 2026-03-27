package core

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"runic/internal/agent/apply"
	"runic/internal/agent/identity"
	"runic/internal/agent/metrics"
	"runic/internal/agent/transport"
	"runic/internal/common/log"
	"runic/internal/models"
)

// Version is the agent version, set at build time.
var Version = "0.2.0"

// Agent is the main agent struct.
type Agent struct {
	config     *identity.Config
	configPath string
	httpClient *http.Client
	sseClient  *http.Client
	version    string
	shipper    *transport.Shipper
}

// New creates a new Agent instance.
func New(configPath, controlPlaneURL string) *Agent {
	// Create HTTP client with timeouts and retry logic
	httpClient := &http.Client{
		Timeout: 30 * time.Second,
	}

	// SSE client has no timeout (long-lived connection)
	sseClient := &http.Client{
		Timeout: 0,
	}

	cfg := &identity.Config{
		ControlPlaneURL: controlPlaneURL,
		PullIntervalSec: 30,
		LogPath:         "/var/log/firewall",
	}

	agent := &Agent{
		config:     cfg,
		configPath: configPath,
		httpClient: httpClient,
		sseClient:  sseClient,
		version:    Version,
	}

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

	// 3. Initialize shipper
	a.shipper = transport.NewShipper(a.httpClient, a.config.ControlPlaneURL, a.config.Token, a.config.HostID, a.config.LogPath)

	// 4. Start background goroutines
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

	// 5. Block on context
	log.Info("Agent running. Press Ctrl+C to stop.")
	<-ctx.Done()
	log.Info("Agent shutting down")
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

// listenSSE maintains a persistent SSE connection to receive push notifications.
func (a *Agent) listenSSE(ctx context.Context) {
	transport.ListenSSE(ctx, a.sseClient, a.config.ControlPlaneURL, a.config.HostID, a.config.Token, a.version, func(sseCtx context.Context) {
		if err := a.pullBundle(sseCtx); err != nil {
			log.Error("SSE-triggered bundle pull failed", "error", err)
		}
	})
}
