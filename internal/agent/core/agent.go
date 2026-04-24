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

// Version is the agent version, set at build time via ldflags.
var Version = "dev"

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
	if err := a.loadConfig(); err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	if a.config.ControlPlaneURL == "" {
		return fmt.Errorf("control plane URL is required: set via --url flag or RUNIC_CONTROL_PLANE_URL env var")
	}

	log.Info("Runic agent starting", "version", a.version)
	log.Info("Control plane URL", "url", a.config.ControlPlaneURL)

	if err := a.DisableSystemIPTablesIfConfigured(); err != nil {
		log.Warn("Failed to disable system iptables services", "error", err)
	}

	if a.config.NeedsRegistration() {
		log.Info("No credentials found, registering with control plane")
		if err := a.register(ctx); err != nil {
			return fmt.Errorf("registration failed: %w", err)
		}
	}

	a.rotationManager = rotation.NewManager(a.config, a.configPath, a.httpClient, a.config.ControlPlaneURL, a.config.HostID)

	if err := a.backupIptables(); err != nil {
		log.Warn("Failed to backup iptables", "error", err)
	}

	if a.config.ApplyOnBoot {
		if !a.isControlPlaneReachable(ctx) {
			log.Info("Control plane unreachable, applying cached bundle")
			if err := a.applyCachedBundle(ctx); err != nil {
				log.Warn("Failed to apply cached bundle on startup", "error", err)
			}
		} else {
			log.Info("Control plane reachable, pulling and applying latest bundle")
			if err := a.pullBundle(ctx); err != nil {
				log.Warn("Failed to pull latest bundle, applying cached bundle", "error", err)
				if err := a.applyCachedBundle(ctx); err != nil {
					log.Warn("Failed to apply cached bundle on startup", "error", err)
				}
			}
		}
	}

	a.shipper = transport.NewShipper(a.httpClient, a.config.ControlPlaneURL, a.config.Token, a.config.HostID, a.config.LogPath)

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

	log.Info("Agent running. Press Ctrl+C to stop.")
	return g.Wait()
}

// backupIptables saves the current iptables rules on first install.
func (a *Agent) backupIptables() error {
	if _, err := os.Stat(a.backupPath); err == nil {
		log.Info("iptables backup already exists, skipping")
		return nil
	}

	dir := filepath.Dir(a.backupPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create backup dir: %w", err)
	}

	out, err := a.cmdRunner.Run(context.Background(), "iptables-save")
	if err != nil {
		return fmt.Errorf("iptables-save: %w", err)
	}

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

// DisableSystemIPTablesIfConfigured disables system-managed iptables services
// if the DisableSystemManagedIPTables config option is set to true.
// This prevents conflicts between runic's firewall management and system services
// like netfilter-persistent, iptables-persistent, firewalld, etc.
func (a *Agent) DisableSystemIPTablesIfConfigured() error {
	if !a.config.DisableSystemManagedIPTables {
		return nil
	}

	log.Info("DisableSystemManagedIPTables is enabled, detecting OS and disabling services")

	osType, err := detectOS()
	if err != nil {
		return fmt.Errorf("detect OS: %w", err)
	}

	log.Info("Detected OS type", "os", osType)

	var services []string
	switch osType {
	case "ubuntu", "debian", "linuxmint", "pop":
		services = []string{"netfilter-persistent", "iptables-persistent"}
	case "arch", "archarm", "manjaro", "endeavouros":
		services = []string{"iptables", "ip6tables"}
	case "opensuse", "suse", "sled", "sles":
		services = []string{"firewalld", "SuSEfirewall2"}
	case "fedora", "rhel", "centos", "rocky", "almalinux", "ol":
		services = []string{"firewalld", "iptables-services"}
	default:
		services = []string{"netfilter-persistent", "iptables-persistent", "firewalld"}
	}

	for _, svc := range services {
		if err := a.disableService(svc); err != nil {
			log.Warn("Failed to disable service", "service", svc, "error", err)
			continue
		}
		log.Info("Disabled system iptables service", "service", svc)
	}

	return nil
}

// detectOS detects the Linux distribution by reading /etc/os-release.
func detectOS() (string, error) {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return "", fmt.Errorf("read os-release: %w", err)
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "ID=") {
			id := strings.TrimPrefix(line, "ID=")
			id = strings.Trim(id, `"`)
			return id, nil
		}
	}

	return "", fmt.Errorf("could not detect OS from os-release")
}

// disableService stops, disables, and masks a systemd service.
func (a *Agent) disableService(service string) error {
	ctx := context.Background()

	checkActive, _ := a.cmdRunner.Run(ctx, "systemctl", "is-active", service)   // intentionally discarded - checking if service exists
	checkEnabled, _ := a.cmdRunner.Run(ctx, "systemctl", "is-enabled", service) // intentionally discarded - checking if service exists

	isActive := strings.TrimSpace(string(checkActive)) == "active"
	isEnabled := strings.TrimSpace(string(checkEnabled)) == "enabled"

	if !isActive && !isEnabled {
		return nil
	}

	if _, err := a.cmdRunner.Run(ctx, "systemctl", "stop", service); err != nil {
		log.Warn("Failed to stop service", "service", service, "error", err)
	}

	if _, err := a.cmdRunner.Run(ctx, "systemctl", "disable", service); err != nil {
		log.Warn("Failed to disable service", "service", service, "error", err)
	}

	if _, err := a.cmdRunner.Run(ctx, "systemctl", "mask", service); err != nil {
		log.Warn("Failed to mask service", "service", service, "error", err)
	}

	return nil
}

// heartbeatLoop sends heartbeats at the configured heartbeat interval.
// This is separate from bundle polling to ensure agents stay online even when PullIntervalSec is long.
func (a *Agent) heartbeatLoop(ctx context.Context) {
	heartbeatInterval := a.config.HeartbeatIntervalSec
	if heartbeatInterval <= 0 {
		heartbeatInterval = identity.DefaultHeartbeatIntervalSec
	}

	ticker := time.NewTicker(time.Duration(heartbeatInterval) * time.Second)
	defer ticker.Stop()

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
	if !a.config.ApplyRulesBundle {
		log.Info("Bundle application disabled (apply_rules_bundle=false), skipping", "version", bundle.Version)
		return nil
	}
	err := apply.ApplyBundle(ctx, bundle, a.config.HMACKey, a.config.ControlPlaneURL, a.config.Token, a.version, a.confirmApply)
	if err == nil {
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
	data, err := os.ReadFile(a.cachePath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Info("No cached bundle found, skipping apply-on-boot")
			return nil
		}
		return fmt.Errorf("read cached bundle: %w", err)
	}

	rules := string(data)

	if strings.TrimSpace(rules) == "" {
		return fmt.Errorf("cached bundle is empty")
	}

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
		}, func(sseCtx context.Context) {
			a.handleFetchBackup(sseCtx)
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
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return
			}
			log.Error("SSE listener returned unexpected error, retrying", "error", err)
		}
	}
}

// handleFetchBackup reads the backup and ipset data, then POSTs it to the control plane.
func (a *Agent) handleFetchBackup(ctx context.Context) {
	backup, err := a.readBackup()
	if err != nil {
		log.Error("Failed to read iptables backup", "error", err)
		return
	}
	ipsets, _ := a.readIpsets() // non-fatal if this fails
	if err := transport.PostBackup(ctx, a.httpClient, a.config.ControlPlaneURL, a.config.HostID, a.config.Token, a.version, backup, ipsets); err != nil {
		log.Error("Failed to post backup to control plane", "error", err)
	}
}

// readBackup reads the pre-Runic iptables backup file.
func (a *Agent) readBackup() (string, error) {
	data, err := os.ReadFile(a.backupPath)
	if err != nil {
		return "", fmt.Errorf("read backup: %w", err)
	}
	return string(data), nil
}

// readIpsets runs ipset list and returns the output.
// If ipset is not installed, returns empty string (non-fatal).
func (a *Agent) readIpsets() (string, error) {
	out, err := a.cmdRunner.Run(context.Background(), "ipset", "list")
	if err != nil {
		log.Warn("ipset list failed (ipset may not be installed)", "error", err)
		return "", nil // non-fatal
	}
	return string(out), nil
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
