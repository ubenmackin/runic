// Package core provides the main agent loop.
package core

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/errgroup"

	"runic/internal/agent/apply"
	"runic/internal/agent/firewall"
	"runic/internal/agent/identity"
	"runic/internal/agent/metrics"
	"runic/internal/agent/rotation"
	"runic/internal/agent/transport"
	"runic/internal/common"
	"runic/internal/common/constants"
	"runic/internal/common/log"
	"runic/internal/common/version"
	"runic/internal/models"
)

type Agent struct {
	config          *identity.Config
	configMu        sync.RWMutex // protects config for concurrent read/write across goroutines
	configPath      string
	httpClient      *http.Client
	sseClient       *http.Client
	version         string
	shipper         *transport.Shipper
	rotationManager *rotation.Manager
	regMu           sync.Mutex // protects re-registration from concurrent calls
	cmdRunner       firewall.CommandRunner
	cachePath       string
	backupPath      string
	exitFunc        func(int)   // for testing; defaults to os.Exit
	bootPullDone    atomic.Bool // tracks whether a fresh bundle pull was done during initialization
}

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
		version:    version.AgentVersion,
	}

	agent.cmdRunner = &firewall.RealCommandRunner{}
	agent.exitFunc = os.Exit
	agent.cachePath = "/etc/runic-agent/cached-bundle.rules"
	agent.backupPath = "/etc/runic-agent/iptables-backup.rules"

	return agent
}

// getConfig returns a snapshot of the current config for read-only access.
// It copies the config under a read lock so callers hold an isolated value
// that remains safe after the lock is released.
func (a *Agent) getConfig() identity.Config {
	a.configMu.RLock()
	defer a.configMu.RUnlock()
	if a.config == nil {
		return identity.Config{}
	}
	return *a.config
}

// updateConfig acquires the write lock and applies fn to the config.
// Use this for any mutation of config fields (e.g. CurrentBundleVer,
// HMACKey) to avoid data races with readers in other goroutines.
func (a *Agent) updateConfig(fn func(*identity.Config)) {
	a.configMu.Lock()
	defer a.configMu.Unlock()
	if a.config == nil {
		return
	}
	fn(a.config)
}

func (a *Agent) Run(ctx context.Context) error {
	if err := a.initialize(ctx); err != nil {
		return fmt.Errorf("initialize: %w", err)
	}
	return a.startLoops(ctx)
}

// initialize handles agent startup: loading config, validating, disabling
// system iptables services, registering, backing up iptables, and applying
// the boot bundle.
func (a *Agent) initialize(ctx context.Context) error {
	if err := a.loadConfig(); err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	if err := a.validateConfig(); err != nil {
		return fmt.Errorf("validate config: %w", err)
	}

	cfg := a.getConfig()
	log.Info("Runic agent starting", "version", a.version)
	log.Info("Control plane URL", "url", cfg.ControlPlaneURL)

	if err := a.disableSystemServices(ctx); err != nil {
		log.Warn("Failed to disable system iptables services", "error", err)
	}

	if err := a.registerIfNeeded(ctx); err != nil {
		return fmt.Errorf("register if needed: %w", err)
	}

	cfg = a.getConfig()
	a.rotationManager = rotation.NewManager(a.configPath, a.httpClient, cfg.ControlPlaneURL, cfg.HostID)

	if err := a.backupIptables(ctx); err != nil {
		log.Warn("Failed to backup iptables", "error", err)
	}

	bootPullDone, _ := a.applyBootBundle(ctx)
	a.bootPullDone.Store(bootPullDone)

	cfg = a.getConfig()
	a.shipper = transport.NewShipper(a.httpClient, cfg.ControlPlaneURL, cfg.Token, cfg.HostID, cfg.LogPath, a.version)

	return nil
}

// startLoops starts all background goroutines (heartbeat, poll, shipper, SSE, rotation)
// and blocks until the context is canceled or a goroutine returns an error.
func (a *Agent) startLoops(ctx context.Context) error {
	g, gCtx := errgroup.WithContext(ctx)

	// errgroup wrappers return nil because heartbeatLoop, pollLoop, and
	// rotationCheckLoop run indefinitely (until ctx is canceled) and never
	// return a non-nil error. Returning nil here ensures the errgroup does
	// not cancel sibling goroutines on expected context cancellation.
	g.Go(func() error {
		a.heartbeatLoop(gCtx)
		return nil
	})
	g.Go(func() error {
		a.pollLoop(gCtx)
		return nil
	})
	g.Go(func() error {
		return a.shipper.Run(gCtx)
	})
	g.Go(func() error {
		return a.listenSSE(gCtx)
	})
	g.Go(func() error {
		a.rotationCheckLoop(gCtx)
		return nil
	})

	log.Info("Agent running. Press Ctrl+C to stop.")
	return g.Wait()
}

// validateConfig checks that the loaded configuration is valid for agent operation.
func (a *Agent) validateConfig() error {
	cfg := a.getConfig()
	if cfg.ControlPlaneURL == "" {
		return fmt.Errorf("control plane URL is required: set via --url flag or RUNIC_CONTROL_PLANE_URL env var")
	}
	return nil
}

// disableSystemServices disables system iptables services if configured.
func (a *Agent) disableSystemServices(ctx context.Context) error {
	return a.DisableSystemIPTablesIfConfigured(ctx)
}

// registerIfNeeded registers the agent with the control plane if credentials are missing.
func (a *Agent) registerIfNeeded(ctx context.Context) error {
	if err := a.register(ctx, false); err != nil {
		return fmt.Errorf("register: %w", err)
	}
	return nil
}

func (a *Agent) backupIptables(ctx context.Context) error {
	if _, err := os.Stat(a.backupPath); err == nil {
		log.Info("Firewall backup already exists, skipping")
		return nil
	}

	dir := filepath.Dir(a.backupPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create backup dir: %w", err)
	}

	out, err := firewall.DumpRules(ctx, a.cmdRunner)
	if err != nil {
		return fmt.Errorf("dump rules: %w", err)
	}

	if err := os.WriteFile(a.backupPath, []byte(out), 0600); err != nil {
		return fmt.Errorf("write backup: %w", err)
	}

	log.Info("Firewall rules backed up", "path", a.backupPath)
	return nil
}

// applyBootBundle handles the boot-time bundle application logic.
// It returns (true, nil) if a fresh pull was performed, (false, nil) if
// a cached bundle was applied or no action was needed, and (false, err) on error.
func (a *Agent) applyBootBundle(ctx context.Context) (bool, error) {
	cfg := a.getConfig()
	if !cfg.ApplyOnBoot || !cfg.ApplyRulesBundle {
		if cfg.ApplyOnBoot {
			log.Info("apply_on_boot enabled but apply_rules_bundle disabled, skipping boot-time bundle application")
		}
		return false, nil
	}

	if !a.isControlPlaneReachable(ctx) {
		log.Info("Control plane unreachable, applying cached bundle")
		if err := a.applyCachedBundle(ctx); err != nil {
			log.Warn("Failed to apply cached bundle on startup", "error", err)
		}
		return false, nil
	}

	log.Info("Control plane reachable, pulling and applying latest bundle")
	if err := a.pullBundle(ctx); err != nil {
		log.Warn("Failed to pull latest bundle, applying cached bundle", "error", err)
		if err := a.applyCachedBundle(ctx); err != nil {
			log.Warn("Failed to apply cached bundle on startup", "error", err)
		}
		return false, nil
	}
	return true, nil
}

func (a *Agent) loadConfig() error {
	cfg, err := identity.LoadConfig(a.configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	a.configMu.Lock()
	defer a.configMu.Unlock()
	if a.config != nil {
		// Preserve CLI-provided values over config file values.
		// CLI values take precedence only when the config file value is empty/zero.
		if cfg.ControlPlaneURL == "" && a.config.ControlPlaneURL != "" {
			cfg.ControlPlaneURL = a.config.ControlPlaneURL
		}
		if cfg.LogPath == "" && a.config.LogPath != "" {
			cfg.LogPath = a.config.LogPath
		}
	}

	if a.config == nil {
		a.config = cfg
	} else {
		*a.config = *cfg
	}
	return nil
}

func (a *Agent) saveConfig() error {
	a.configMu.RLock()
	if a.config == nil {
		a.configMu.RUnlock()
		return fmt.Errorf("save config: no config loaded")
	}
	snapshot := *a.config
	a.configMu.RUnlock()
	return identity.SaveConfig(a.configPath, &snapshot)
}

// DisableSystemIPTablesIfConfigured disables system iptables if the DisableSystemManagedIPTables config option is set to true.
// This prevents conflicts between runic's firewall management and system services
// like netfilter-persistent, iptables-persistent, firewalld, etc.
func (a *Agent) DisableSystemIPTablesIfConfigured(ctx context.Context) error {
	cfg := a.getConfig()
	if !cfg.DisableSystemManagedIPTables {
		return nil
	}

	log.Info("DisableSystemManagedIPTables is enabled, detecting OS and disabling services")

	osID, err := identity.DetectOS()
	if err != nil {
		return fmt.Errorf("detect OS: %w", err)
	}
	osType := identity.NormalizeOS(osID)

	log.Info("Detected OS type", "os", osType)

	var services []string
	switch osType {
	case "ubuntu", "debian":
		services = []string{"netfilter-persistent", "iptables-persistent"}
	case "arch":
		services = []string{"iptables", "ip6tables"}
	case "opensuse":
		services = []string{"firewalld", "SuSEfirewall2"}
	case "rhel":
		services = []string{"firewalld", "iptables-services"}
	case "raspbian":
		services = []string{"netfilter-persistent", "iptables-persistent"}
	default:
		services = []string{"netfilter-persistent", "iptables-persistent", "firewalld"}
	}

	for _, svc := range services {
		if err := a.disableService(ctx, svc); err != nil {
			log.Warn("Failed to disable service", "service", svc, "error", err)
			continue
		}
		log.Info("Disabled system iptables service", "service", svc)
	}

	return nil
}

func (a *Agent) disableService(ctx context.Context, service string) error {

	checkActive, err := a.cmdRunner.Run(ctx, "systemctl", "is-active", service)
	if err != nil {
		log.Debug("systemctl is-active check failed", "service", service, "error", err)
	}
	checkEnabled, err := a.cmdRunner.Run(ctx, "systemctl", "is-enabled", service)
	if err != nil {
		log.Debug("systemctl is-enabled check failed", "service", service, "error", err)
	}

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

// This is separate from bundle polling to ensure agents stay online even when PullIntervalSec is long.
func (a *Agent) heartbeatLoop(ctx context.Context) {
	cfg := a.getConfig()
	heartbeatInterval := cfg.HeartbeatIntervalSec
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
					if regErr := a.register(ctx, true); regErr != nil {
						log.Error("Re-registration failed", "error", regErr)
					}
				}
			}
		}
	}
}

func (a *Agent) detectIPStrings() []string {
	allIPs := detectHostIPs(a.cmdRunner)
	ips := make([]string, len(allIPs))
	for i, ipInfo := range allIPs {
		ips[i] = ipInfo.IP
	}
	return ips
}

func (a *Agent) sendHeartbeat(ctx context.Context) error {
	cfg := a.getConfig()
	return metrics.SendHeartbeat(ctx, a.httpClient, cfg.ControlPlaneURL, cfg.HostID, cfg.CurrentBundleVer, cfg.Token, a.version, a.detectIPStrings())
}

func (a *Agent) pollLoop(ctx context.Context) {
	cfg := a.getConfig()
	ticker := time.NewTicker(time.Duration(cfg.PullIntervalSec) * time.Second)
	defer ticker.Stop()

	if !a.bootPullDone.Load() {
		if err := a.pullBundle(ctx); err != nil {
			log.Error("Initial bundle pull failed", "error", err)
		}
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
					if regErr := a.register(ctx, true); regErr != nil {
						log.Error("Re-registration failed", "error", regErr)
					}
				}
			}
		}
	}
}

func (a *Agent) pullBundle(ctx context.Context) error {
	cfg := a.getConfig()
	return transport.PullBundle(ctx, a.httpClient, cfg.ControlPlaneURL, cfg.HostID, cfg.Token, cfg.CurrentBundleVer, a.version, a.applyBundle)
}

func (a *Agent) applyBundle(ctx context.Context, bundle models.BundleResponse) error {
	cfg := a.getConfig()
	if !cfg.ApplyRulesBundle {
		log.Info("Bundle application disabled (apply_rules_bundle=false), skipping", "version", bundle.Version)
		return nil
	}
	err := apply.ApplyBundle(ctx, bundle, cfg.HMACKey, cfg.ControlPlaneURL, cfg.Token, a.version, a.confirmApply)
	if err == nil {
		a.updateConfig(func(c *identity.Config) {
			c.CurrentBundleVer = bundle.Version
		})
		if err := a.saveConfig(); err != nil {
			log.Warn("Failed to save config after applying bundle", "error", err)
		}
	}
	return err
}

func (a *Agent) confirmApply(ctx context.Context, version string) error {
	cfg := a.getConfig()
	return transport.ConfirmApply(ctx, a.httpClient, cfg.ControlPlaneURL, cfg.HostID, cfg.Token, a.version, version)
}

// register performs agent registration. When force is true, it always attempts
// registration; when false, it only registers if credentials are missing.
// The regMu prevents thundering herd when multiple loops detect 401 simultaneously.
func (a *Agent) register(ctx context.Context, force bool) error {
	a.regMu.Lock()
	defer a.regMu.Unlock()

	if !force {
		cfg := a.getConfig()
		if !cfg.NeedsRegistration() {
			return nil
		}
	}

	log.Info("Attempting registration", "force", force)

	// Snapshot config, release, perform HTTP, re-acquire.
	cfg := a.getConfig()

	if err := identity.Register(ctx, a.httpClient, &cfg, a.version, func() error {
		return identity.SaveConfig(a.configPath, &cfg)
	}, a.detectIPStrings()); err != nil {
		return fmt.Errorf("register agent: %w", err)
	}

	// Swap the new config under write lock.
	a.configMu.Lock()
	if a.config == nil {
		a.config = &cfg
	} else {
		*a.config = cfg
	}
	a.configMu.Unlock()
	return nil
}

func (a *Agent) isControlPlaneReachable(ctx context.Context) bool {
	cfg := a.getConfig()
	url := fmt.Sprintf("%s/api/v1/agent/heartbeat", cfg.ControlPlaneURL)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return false
	}
	req.Header.Set("Authorization", "Bearer "+cfg.Token)
	req.Header.Set("User-Agent", "runic-agent/"+a.version)

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return false
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		if cErr := resp.Body.Close(); cErr != nil {
			log.Warn("close err", "err", cErr)
		}
	}()
	return resp.StatusCode == http.StatusOK
}

func (a *Agent) applyCachedBundle(ctx context.Context) error {
	cfg := a.getConfig()
	if !cfg.ApplyRulesBundle {
		log.Info("apply_rules_bundle disabled, skipping cached bundle application")
		return nil
	}
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
		return fmt.Errorf("write cached bundle to temp file: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}

	// Use detached context so a watchdog or parent cancellation does not kill
	// the restore mid-flight, which could leave the system in a broken state.
	restoreCtx := context.WithoutCancel(ctx)

	// Detect content format and use appropriate restore tool.
	if apply.IsNftFormat(rules) {
		output, err := a.cmdRunner.Run(restoreCtx, "nft", "-f", tmpPath)
		if err != nil {
			return fmt.Errorf("nft -f restore failed: %s: %w", string(output), err)
		}
	} else {
		// We use --noflush here because this is a warm boot from cache —
		// the running rules already match the cached state, so flushing
		// would cause unnecessary downtime by briefly dropping all
		// iptables rules before restoring. On cold boot where the cache
		// is stale, ApplyBundle with flush is used instead.
		output, err := a.cmdRunner.Run(restoreCtx, "iptables-restore", "--noflush", tmpPath)
		if err != nil {
			return fmt.Errorf("iptables-restore failed: %s: %w", string(output), err)
		}
	}

	log.Info("Applied cached bundle on startup", "path", a.cachePath)
	return nil
}

// It handles 401 Unauthorized responses by triggering re-registration.
func (a *Agent) listenSSE(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		cfg := a.getConfig()
		err := transport.ListenSSE(ctx, a.sseClient, cfg.ControlPlaneURL, cfg.HostID, cfg.Token, a.version, func(sseCtx context.Context) {
			if pullErr := a.pullBundle(sseCtx); pullErr != nil {
				log.Error("SSE-triggered bundle pull failed", "error", pullErr)
			}
		}, func(sseCtx context.Context) {
			a.handleFetchBackup(sseCtx)
		}, func(sseCtx context.Context, controlPlaneURL string) {
			a.handleUpdateAgent(sseCtx, controlPlaneURL)
		})

		if err != nil {
			if errors.Is(err, common.ErrUnauthorized) {
				log.Warn("Received 401 on SSE connection, triggering re-registration")
				if regErr := a.register(ctx, true); regErr != nil {
					log.Error("Re-registration failed", "error", regErr)
				}
				// After re-registration, continue the loop to reconnect with new token
				continue
			}
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return nil
			}
			log.Error("SSE listener returned unexpected error, propagating to errgroup", "error", err)
			return fmt.Errorf("SSE listener error: %w", err)
		}
	}
}

func (a *Agent) handleFetchBackup(ctx context.Context) {
	backup, err := a.readBackup()
	if err != nil {
		log.Error("Failed to read iptables backup", "error", err)
		return
	}
	ipsets, _ := a.readIpsets(ctx) // non-fatal if this fails
	cfg := a.getConfig()
	if err := transport.PostBackup(ctx, a.httpClient, cfg.ControlPlaneURL, cfg.HostID, cfg.Token, a.version, backup, ipsets); err != nil {
		log.Error("Failed to post backup to control plane", "error", err)
	}
}

// validateUpdateURL checks that the update URL is well-formed, pins its host
// to the configured control plane host, and requires https except for
// loopback test hosts.
func validateUpdateURL(updateURL, configuredURL string) (string, error) {
	parsed, err := url.Parse(updateURL)
	if err != nil {
		return "", fmt.Errorf("invalid control plane URL %q: %w", updateURL, err)
	}
	if parsed.Host == "" {
		return "", fmt.Errorf("invalid control plane URL %q: missing host", updateURL)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", fmt.Errorf("invalid control plane URL %q: scheme must be http or https", updateURL)
	}
	hostname := parsed.Hostname()
	isLoopback := hostname == "localhost" || hostname == "127.0.0.1" || hostname == "::1"
	if !isLoopback && parsed.Scheme != "https" {
		return "", fmt.Errorf("invalid control plane URL %q: scheme must be https", updateURL)
	}
	if configuredURL != "" {
		configured, err := url.Parse(configuredURL)
		if err != nil {
			return "", fmt.Errorf("invalid configured control plane URL %q: %w", configuredURL, err)
		}
		if configured.Host == "" {
			return "", fmt.Errorf("invalid configured control plane URL %q: missing host", configuredURL)
		}
		if !strings.EqualFold(parsed.Hostname(), configured.Hostname()) {
			return "", fmt.Errorf("invalid control plane URL %q: host %q does not match configured host %q", updateURL, parsed.Hostname(), configured.Hostname())
		}
		if effectiveUpdateURLPort(parsed) != effectiveUpdateURLPort(configured) {
			return "", fmt.Errorf("invalid control plane URL %q: port %q does not match configured port %q", updateURL, parsed.Port(), configured.Port())
		}
	}
	return parsed.String(), nil
}

// effectiveUpdateURLPort returns the explicit port if present, otherwise the
// default port for the URL scheme (80 for http, 443 for https) so that
// URLs with implicit default ports compare equal to URLs with explicit ones.
func effectiveUpdateURLPort(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	switch strings.ToLower(u.Scheme) {
	case "http":
		return "80"
	case "https":
		return "443"
	default:
		return ""
	}
}

// handleUpdateAgent performs an in-process self-update. It downloads the new
// binary via HTTP and applies it in-place using selfupdate.Apply, then exits
// the process so the service manager can restart with the new binary.
//
// The update runs in a goroutine because the caller (SSE event handler) must
// not block. After a successful apply, the agent waits 2 seconds for the SSE
// acknowledgment to be sent, then calls exitFunc(0) (os.Exit in production).
func (a *Agent) handleUpdateAgent(ctx context.Context, controlPlaneURL string) {
	log.Info("Starting agent self-update", "control_plane_url", controlPlaneURL)

	cfg := a.getConfig()
	normalizedURL, err := validateUpdateURL(controlPlaneURL, cfg.ControlPlaneURL)
	if err != nil {
		log.Error("Invalid control plane URL received in update_agent event", "url", controlPlaneURL, "error", err)
		return
	}

	go func() {
		detachedCtx := context.WithoutCancel(ctx)
		if err := performUpdate(detachedCtx, a.httpClient, normalizedURL); err != nil {
			// Update failed — do NOT exit the process. The agent stays
			// running so the operator can investigate and retry via a
			// subsequent update_agent event.
			log.Error("Agent self-update failed, not exiting for restart", "error", err)
			return
		}
		select {
		case <-ctx.Done():
			log.Info("Agent shutting down, skipping exit after update")
			return
		default:
		}
		log.Info("Agent update applied, exiting for restart in 2s")
		timer := time.NewTimer(2 * time.Second)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			log.Info("Agent shutting down, skipping exit after update")
			return
		case <-timer.C:
		}
		a.exitFunc(0)
	}()
}

// HandleUpdateAgent triggers the agent self-update process. It is the public
// equivalent of handleUpdateAgent, exposed for CLI and integration test use.
func (a *Agent) HandleUpdateAgent(controlPlaneURL string) {
	a.handleUpdateAgent(context.Background(), controlPlaneURL)
}

// HandleUpdateAgentSync triggers the agent self-update synchronously.
// It blocks until the update process completes or fails, returning any error.
// On success, it calls exitFunc(0) to exit the process for restart.
// This is intended for CLI use (e.g., `runic-agent -update`) where the caller
// needs to know whether the update succeeded. For SSE-triggered updates,
// use HandleUpdateAgent (async) instead.
func (a *Agent) HandleUpdateAgentSync(controlPlaneURL string) error {
	return a.handleUpdateAgentSync(context.Background(), controlPlaneURL)
}

func (a *Agent) handleUpdateAgentSync(ctx context.Context, controlPlaneURL string) error {
	log.Info("Starting agent self-update (synchronous)", "control_plane_url", controlPlaneURL)

	cfg := a.getConfig()
	normalizedURL, err := validateUpdateURL(controlPlaneURL, cfg.ControlPlaneURL)
	if err != nil {
		return fmt.Errorf("validate update URL: %w", err)
	}

	if err := performUpdate(ctx, a.httpClient, normalizedURL); err != nil {
		return fmt.Errorf("agent self-update failed: %w", err)
	}

	log.Info("Agent update applied successfully, exiting for restart")
	a.exitFunc(0)
	return nil
}

func (a *Agent) readBackup() (string, error) {
	data, err := os.ReadFile(a.backupPath)
	if err != nil {
		return "", fmt.Errorf("read backup: %w", err)
	}
	return string(data), nil
}

// If ipset is not installed, returns empty string (non-fatal).
func (a *Agent) readIpsets(ctx context.Context) (string, error) {
	out, err := a.cmdRunner.Run(ctx, "ipset", "list")
	if err != nil {
		log.Warn("ipset list failed (ipset may not be installed)", "error", err)
		return "", nil // non-fatal
	}
	return string(out), nil
}

func (a *Agent) rotationCheckLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute) // Check every 5 minutes
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cfg := a.getConfig()
			newKey, err := a.rotationManager.CheckAndRotate(ctx, cfg.HMACKey, cfg.Token)
			if err != nil {
				log.Warn("Key rotation check failed", "error", err)
				continue
			}
			if newKey != "" {
				a.updateConfig(func(c *identity.Config) {
					c.HMACKey = newKey
				})
				if err := a.saveConfig(); err != nil {
					log.Warn("Failed to save config after key rotation", "error", err)
				}
			}
		}
	}
}

type HostIPInfo struct {
	IP        string
	Interface string
	IsPrimary bool
}

// Docker, and bridge interfaces. It returns the list of valid IPs with the
// primary IP (from the default route interface) first.
func detectHostIPs(runner firewall.CommandRunner) []HostIPInfo {
	// Determine the default route interface for primary IP detection
	ctx := context.Background()
	defaultIface := detectDefaultRouteInterface(ctx, runner)

	ifaces, err := net.Interfaces()
	if err != nil {
		log.Warn("Failed to list network interfaces", "error", err)
		return nil
	}

	dockerSubnets := getDockerSubnets(ctx, runner)

	var results []HostIPInfo

	for _, iface := range ifaces {
		// Skip interfaces that are down or loopback
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		// Skip filtered interface names
		if isFilteredInterface(iface.Name) {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			default:
				continue
			}

			// Skip loopback and link-local addresses
			if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
				continue
			}

			// Skip Docker subnet IPs
			if isInDockerSubnet(ip, dockerSubnets) {
				log.Debug("Skipping IP in Docker subnet", "ip", ip.String(), "interface", iface.Name)
				continue
			}

			isPrimary := iface.Name == defaultIface
			results = append(results, HostIPInfo{
				IP:        ip.String(),
				Interface: iface.Name,
				IsPrimary: isPrimary,
			})
		}
	}

	// Sort: primary IPs first
	sortHostIPs(results)

	return results
}

func detectDefaultRouteInterface(ctx context.Context, runner firewall.CommandRunner) string {
	out, err := runner.Run(ctx, "ip", "route", "show", "default")
	if err != nil {
		log.Warn("Failed to detect default route interface", "error", err)
		return ""
	}

	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "default") {
			continue
		}
		parts := strings.Fields(line)
		for i, part := range parts {
			if part == "dev" && i+1 < len(parts) {
				return parts[i+1]
			}
		}
	}

	return ""
}

func isFilteredInterface(name string) bool {
	filteredPrefixes := []string{"lo", "docker0", "br-", "veth"}
	for _, prefix := range filteredPrefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

type dockerSubnet struct {
	*net.IPNet
}

// If Docker is not available, returns an empty list.
func getDockerSubnets(ctx context.Context, runner firewall.CommandRunner) []dockerSubnet {
	var subnets []dockerSubnet

	// List Docker networks
	out, err := runner.Run(ctx, "docker", "network", "ls", "--format", "{{.Name}}")
	if err != nil {
		// Docker not available, skip filtering
		return subnets
	}

	networkNames := strings.Split(strings.TrimSpace(string(out)), "\n")
	for _, name := range networkNames {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}

		// Inspect each network to get subnets
		inspectOut, err := runner.Run(ctx, "docker", "network", "inspect", name, "--format", "{{range .IPAM.Config}}{{.Subnet}}{{end}}")
		if err != nil {
			log.Debug("Failed to inspect Docker network", "network", name, "error", err)
			continue
		}

		for _, subnetStr := range strings.Split(strings.TrimSpace(string(inspectOut)), "\n") {
			subnetStr = strings.TrimSpace(subnetStr)
			if subnetStr == "" {
				continue
			}
			_, ipNet, err := net.ParseCIDR(subnetStr)
			if err != nil {
				log.Debug("Failed to parse Docker subnet", "subnet", subnetStr, "error", err)
				continue
			}
			subnets = append(subnets, dockerSubnet{IPNet: ipNet})
		}
	}

	return subnets
}

func isInDockerSubnet(ip net.IP, subnets []dockerSubnet) bool {
	for _, subnet := range subnets {
		if subnet.Contains(ip) {
			return true
		}
	}
	return false
}

func sortHostIPs(ips []HostIPInfo) {
	slices.SortFunc(ips, func(a, b HostIPInfo) int {
		// Primary IPs first
		if a.IsPrimary && !b.IsPrimary {
			return -1
		}
		if !a.IsPrimary && b.IsPrimary {
			return 1
		}
		return 0
	})
}
