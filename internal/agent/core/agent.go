// Package core provides the main agent loop.
package core

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"

	"runic/internal/agent/apply"
	"runic/internal/agent/identity"
	"runic/internal/agent/metrics"
	"runic/internal/agent/rotation"
	"runic/internal/agent/transport"
	"runic/internal/common"
	"runic/internal/common/constants"
	"runic/internal/common/log"
	"runic/internal/models"
)

// Version is the agent version, set at build time.
var Version = "0.5.1"

// CommandRunner abstracts exec.Command for testability.
type CommandRunner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

// RealCommandRunner wraps exec.CommandContext for production use.
type RealCommandRunner struct{}

func (r *RealCommandRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	return cmd.CombinedOutput()
}

// Agent is the main agent struct.
type Agent struct {
	config          *identity.Config
	configPath      string
	httpClient      *http.Client
	sseClient       *http.Client
	version         string
	shipper         *transport.Shipper
	rotationManager *rotation.Manager
	regMu           sync.Mutex // protects re-registration from concurrent calls
	cmdRunner       CommandRunner
	cachePath       string
	backupPath      string
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
		PullIntervalSec: identity.DefaultPullIntervalSec, // 24 hours (SSE is primary)
		LogPath:         "/var/log/runic/firewall.log",
	}

	agent := &Agent{
		config:     cfg,
		configPath: configPath,
		httpClient: httpClient,
		sseClient:  sseClient,
		version:    Version,
	}

	agent.cmdRunner = &RealCommandRunner{}
	agent.cachePath = "/etc/runic-agent/cached-bundle.rules"
	agent.backupPath = "/etc/runic-agent/iptables-backup.rules"

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

	// 6. Start background goroutines with coordinated lifecycle
	g, gCtx := errgroup.WithContext(ctx)

	g.Go(func() error {
		a.heartbeatLoop(gCtx)
		return nil
	})
	g.Go(func() error {
		a.pollLoop(gCtx)
		return nil
	})
	g.Go(func() error {
		a.shipper.Run(gCtx)
		return nil
	})
	g.Go(func() error {
		a.listenSSE(gCtx)
		return nil
	})
	g.Go(func() error {
		a.rotationCheckLoop(gCtx)
		return nil
	})

	// 7. Wait for all goroutines to complete
	log.Info("Agent running. Press Ctrl+C to stop.")
	return g.Wait()
}

// backupIptables saves the current iptables rules on first install.
func (a *Agent) backupIptables() error {
	// Check if backup already exists
	if _, err := os.Stat(a.backupPath); err == nil {
		log.Info("iptables backup already exists, skipping")
		return nil
	}

	// Create directory
	dir := filepath.Dir(a.backupPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create backup dir: %w", err)
	}

	// Dump current rules
	out, err := a.cmdRunner.Run(context.Background(), "iptables-save")
	if err != nil {
		return fmt.Errorf("iptables-save: %w", err)
	}

	// Write to backup file
	if err := os.WriteFile(a.backupPath, out, 0600); err != nil {
		return fmt.Errorf("write backup: %w", err)
	}

	log.Info("iptables rules backed up", "path", a.backupPath)
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

// heartbeatLoop sends heartbeats at the configured heartbeat interval.
// This is separate from bundle polling to ensure agents stay online even when PullIntervalSec is long.
func (a *Agent) heartbeatLoop(ctx context.Context) {
	// Use dedicated heartbeat interval, defaulting to 30s if not set
	heartbeatInterval := a.config.HeartbeatIntervalSec
	if heartbeatInterval <= 0 {
		heartbeatInterval = identity.DefaultHeartbeatIntervalSec
	}

	ticker := time.NewTicker(time.Duration(heartbeatInterval) * time.Second)
	defer ticker.Stop()

	// Send first heartbeat immediately
	if err := a.sendHeartbeat(ctx); err != nil {
		log.Error("Initial heartbeat failed", "error", err)
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := a.sendHeartbeat(ctx); err != nil {
				log.Error("Heartbeat failed", "error", err)
				if errors.Is(err, common.ErrUnauthorized) {
					log.Warn("Received 401 on heartbeat, triggering re-registration")
					if regErr := a.safeRegister(ctx); regErr != nil {
						log.Error("Re-registration failed", "error", regErr)
					}
				}
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
	if err := a.pullBundle(ctx); err != nil {
		log.Error("Initial bundle pull failed", "error", err)
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := a.pullBundle(ctx); err != nil {
				log.Error("Bundle poll failed", "error", err)
				if errors.Is(err, common.ErrUnauthorized) {
					log.Warn("Received 401 on bundle poll, triggering re-registration")
					if regErr := a.safeRegister(ctx); regErr != nil {
						log.Error("Re-registration failed", "error", regErr)
					}
				}
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
	// Check if bundle application is enabled
	if !a.config.ApplyRulesBundle {
		log.Info("Bundle application disabled (apply_rules_bundle=false), skipping", "version", bundle.Version)
		return nil
	}
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

// safeRegister performs re-registration with mutex protection to prevent
// thundering herd when multiple loops detect 401 errors simultaneously.
func (a *Agent) safeRegister(ctx context.Context) error {
	a.regMu.Lock()
	defer a.regMu.Unlock()
	log.Info("Attempting re-registration (mutex acquired)")
	return a.register(ctx)
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
	defer func() {
		if cErr := resp.Body.Close(); cErr != nil {
			log.Warn("close err", "err", cErr)
		}
	}()
	return resp.StatusCode == http.StatusOK
}

// applyCachedBundle applies the cached bundle from disk on startup.
func (a *Agent) applyCachedBundle(ctx context.Context) error {
	// Read cached bundle
	data, err := os.ReadFile(a.cachePath)
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
	defer func() {
		if err := os.Remove(tmpPath); err != nil {
			log.Warn("remove err", "err", err)
		}
	}()

	if _, err := tmpFile.WriteString(rules); err != nil {
		if err := tmpFile.Close(); err != nil {
			log.Warn("Failed to close download file", "error", err)
		}
		return fmt.Errorf("write cached bundle to temp file: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}

	output, err := a.cmdRunner.Run(ctx, "iptables-restore", "--noflush", tmpPath)
	if err != nil {
		return fmt.Errorf("iptables-restore failed: %s: %w", string(output), err)
	}

	log.Info("Applied cached bundle on startup", "path", a.cachePath)
	return nil
}

// listenSSE maintains a persistent SSE connection to receive push notifications.
// It handles 401 Unauthorized responses by triggering re-registration.
func (a *Agent) listenSSE(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		err := transport.ListenSSE(ctx, a.sseClient, a.config.ControlPlaneURL, a.config.HostID, a.config.Token, a.version, func(sseCtx context.Context) {
			if pullErr := a.pullBundle(sseCtx); pullErr != nil {
				log.Error("SSE-triggered bundle pull failed", "error", pullErr)
			}
		})

		if err != nil {
			if errors.Is(err, common.ErrUnauthorized) {
				log.Warn("Received 401 on SSE connection, triggering re-registration")
				if regErr := a.safeRegister(ctx); regErr != nil {
					log.Error("Re-registration failed", "error", regErr)
				}
				// After re-registration, continue the loop to reconnect with new token
				continue
			}
			// For other errors (context canceled, etc.), check if we should continue
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return
			}
			// For unexpected errors, log and continue retrying
			log.Error("SSE listener returned unexpected error, retrying", "error", err)
		}
	}
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
			if err := a.rotationManager.CheckAndRotate(ctx); err != nil {
				log.Warn("Key rotation check failed", "error", err)
			}
		}
	}
}
