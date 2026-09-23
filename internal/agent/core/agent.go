// Package core provides the main agent loop.
package core

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
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
	regMu           sync.Mutex // protects re-registration from concurrent calls and guards lastRegAttempt/sseAuthFailures/lastRetryAfter
	lastRegAttempt  time.Time  // last re-registration attempt time for cooldown throttling
	sseAuthFailures int        // consecutive SSE 401 failures for exponential backoff
	// lastRetryAfter preserves the most recent parsed Retry-After hint from a
	// failed registration so a later cooldown skip can still honor the 429
	// delay instead of falling back to the base backoff.
	lastRetryAfter    time.Duration // last Retry-After hint from failed registration
	hasLastRetryAfter bool          // whether lastRetryAfter holds a present and parseable hint
	cmdRunner         firewall.CommandRunner
	cachePath         string
	backupPath        string
	exitFunc          func(int)   // for testing; defaults to os.Exit
	bootPullDone      atomic.Bool // tracks whether a fresh bundle pull was done during initialization
	updateRunning     atomic.Bool // singleflight for self-update; only one performUpdate may run at a time
	lastUpdateErrMu   sync.RWMutex
	lastUpdateErr     string // last self-update failure reason, reported on the next heartbeat
}

// reRegisterCooldown is the minimum interval between re-registration
// attempts. It is a var (not const) so unit tests can shorten the wait.
var reRegisterCooldown = constants.ReRegisterCooldown

// sseReauthBaseDelay is the base delay for SSE 401 re-auth backoff.
// It is a var (not const) so unit tests can shorten the wait.
var sseReauthBaseDelay = constants.SSEReconnectDelay

// sseReauthMaxDelay caps the exponential SSE re-auth backoff.
// It is a var (not const) so unit tests can shorten the wait.
var sseReauthMaxDelay = constants.SSEReauthMaxDelay

// maxLastUpdateErrLen caps the stored self-update failure reason so a long
// server response cannot grow memory or heartbeat payloads without bound.
const maxLastUpdateErrLen = 1024

// setLastUpdateError records the last self-update failure reason for
// reporting on the next heartbeat. An empty message clears the stored error.
func (a *Agent) setLastUpdateError(msg string) {
	if len(msg) > maxLastUpdateErrLen {
		msg = common.TruncateString(msg, maxLastUpdateErrLen)
	}
	a.lastUpdateErrMu.Lock()
	defer a.lastUpdateErrMu.Unlock()
	a.lastUpdateErr = msg
}

// getLastUpdateError returns the stored self-update failure reason, or empty
// when the last update succeeded or no update has been attempted.
func (a *Agent) getLastUpdateError() string {
	a.lastUpdateErrMu.RLock()
	defer a.lastUpdateErrMu.RUnlock()
	return a.lastUpdateErr
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
	agent.cachePath = apply.CachedBundlePath
	agent.backupPath = apply.StartupBackupPath

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

	a.rotationManager = rotation.NewManager(a.httpClient)

	// Upgrade migration: copy legacy /etc/runic-agent persistent files to
	// their /var successors when the new path is missing so crash-recovery
	// state is not orphaned. Fallback reads cover any file missed here.
	apply.MigrateLegacyFiles()

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

// ensureBackupMigrated migrates the legacy /etc/runic-agent boot backup
// forward when the agent uses the default /var path and the new file is
// missing. It reports true when the caller should skip a fresh dump
// (migrated successfully or primary already exists), false when a fresh
// dump is needed. A directory at the new path (syscall.EISDIR from
// MigrateLegacyFile) is distinct from an existing file and returns false so
// the caller attempts a fresh dump instead of skipping. It shares the
// MigrateLegacyFile primitive with the MigrateLegacyFiles startup path,
// adding the isDefaultBackupPath guard plus the EISDIR-vs-Exist mapping and
// WARN so a custom backupPath or directory case takes a fresh dump instead
// of skipping.
func (a *Agent) ensureBackupMigrated() bool {
	if !isDefaultBackupPath(a.backupPath) {
		return false
	}
	err := apply.MigrateLegacyFile(apply.LegacyStartupBackupPath, a.backupPath)
	switch {
	case err == nil:
		return true
	case errors.Is(err, syscall.EISDIR):
		log.Warn("Legacy backup migration skipped, new path is a directory, taking fresh backup", "path", a.backupPath, "error", err)
		return false
	case os.IsExist(err):
		return true
	case !os.IsNotExist(err):
		log.Warn("Legacy backup migration failed, taking fresh backup", "error", err)
	}
	return false
}

func (a *Agent) backupIptables(ctx context.Context) error {
	if fi, err := os.Stat(a.backupPath); err == nil {
		if fi.IsDir() {
			return fmt.Errorf("backup path is a directory: %s", a.backupPath)
		}
		log.Info("Firewall backup already exists, skipping")
		return nil
	} else if !os.IsNotExist(err) {
		log.Warn("Failed to stat backup path, attempting backup", "path", a.backupPath, "error", err)
	}

	// Upgrade migration: a pre-/var install left its boot backup under
	// /etc/runic-agent. If the new path is missing but the legacy file
	// exists, migrate it forward instead of dumping fresh rules.
	if a.ensureBackupMigrated() {
		return nil
	}

	out, err := firewall.DumpRules(ctx, a.cmdRunner)
	if err != nil {
		return fmt.Errorf("dump rules: %w", err)
	}

	if err := apply.WriteFileAtomic(a.backupPath, []byte(out), 0600); err != nil {
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
					skipped, regErr := a.throttledRegister(ctx, true)
					if skipped {
						log.Debug("Re-registration skipped, cooldown not expired after 401 on heartbeat")
					} else {
						log.Warn("Received 401 on heartbeat, triggering re-registration")
						if regErr != nil {
							log.Error("Re-registration failed", "error", regErr)
						}
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
	return metrics.SendHeartbeat(ctx, a.httpClient, cfg.ControlPlaneURL, cfg.HostID, cfg.CurrentBundleVer, cfg.Token, a.version, a.detectIPStrings(), a.getLastUpdateError())
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
					skipped, regErr := a.throttledRegister(ctx, true)
					if skipped {
						log.Debug("Re-registration skipped, cooldown not expired after 401 on bundle poll")
					} else {
						log.Warn("Received 401 on bundle poll, triggering re-registration")
						if regErr != nil {
							log.Error("Re-registration failed", "error", regErr)
						}
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

// refreshDependentClients pushes fresh in-memory credentials to long-lived
// clients that snapshot credentials at construction time (the log shipper).
// The caller passes the authoritative just-swapped config value through so
// the refresh cannot interleave with a concurrent updateConfig between the
// swap and a re-read. Heartbeat, pull, rotation, and SSE paths read the
// current config via getConfig on each call and already observe the swapped
// config; this hook covers clients that hold their own copies. It is a
// no-op when the shipper is nil (pre-initialize, unit tests), and the token
// refresh stays in one place.
func (a *Agent) refreshDependentClients(cfg *identity.Config) {
	if a.shipper != nil {
		a.shipper.SetCredentials(cfg.ControlPlaneURL, cfg.Token, cfg.HostID)
	}
}

// swapConfig replaces the in-memory config under write lock. Both the
// persist-failure path and the success path in doRegister share this helper
// so the swap cannot drift.
func (a *Agent) swapConfig(cfg *identity.Config) {
	a.configMu.Lock()
	defer a.configMu.Unlock()
	if a.config == nil {
		cp := *cfg
		a.config = &cp
	} else {
		*a.config = *cfg
	}
}

// doRegister performs the registration network I/O and swaps the new config
// into place. It must be called without holding regMu; it uses configMu
// internally for the swap. Both register and throttledRegister share this
// helper so identity.Register + SaveConfig + config swap cannot drift.
func (a *Agent) doRegister(ctx context.Context) error {
	cfg := a.getConfig()

	if err := identity.Register(ctx, a.httpClient, &cfg, a.version, func() error {
		return identity.SaveConfig(a.configPath, &cfg)
	}, a.detectIPStrings()); err != nil {
		if errors.Is(err, identity.ErrPersistAfterRegister) {
			// Registration succeeded server-side but persisting the config
			// failed (e.g. read-only /etc/runic-agent/config.json). The
			// mutated copy already holds the fresh HostID, Token, HMACKey,
			// AgentKey with RegistrationToken cleared, so retain it
			// in-memory under write lock; persist failure is non-fatal.
			// Returning nil keeps heartbeatLoop from logging
			// "Re-registration failed" and breaks the permanent 401 loop.
			a.swapConfig(&cfg)
			log.Warn("Failed to persist config after registration, continuing with in-memory credentials", "path", a.configPath, "error", err)
			a.refreshDependentClients(&cfg)
			return nil
		}
		return fmt.Errorf("register agent: %w", err)
	}

	// Swap the new config under write lock.
	a.swapConfig(&cfg)
	a.refreshDependentClients(&cfg)
	return nil
}

// storeRetryAfterLocked records the Retry-After hint carried by err, or
// clears any stored hint when err carries none (including nil on success).
// It must be called with regMu held.
func (a *Agent) storeRetryAfterLocked(err error) {
	if retryAfter, ok := common.RetryAfterOf(err); ok {
		a.lastRetryAfter = retryAfter
		a.hasLastRetryAfter = true
		return
	}
	// Latest attempt carried no hint; drop any stale hint so a later
	// cooldown skip does not honor an outdated 429 delay.
	a.lastRetryAfter = 0
	a.hasLastRetryAfter = false
}

// register performs agent registration. When force is true, it always attempts
// registration; when false, it only registers if credentials are missing.
// It delegates to registerInner with the cooldown bypassed so the Register +
// SaveConfig + config swap stays in one place. This startup path does not
// consult the re-registration cooldown, but it publishes lastRegAttempt and
// the Retry-After hint handling so a 401 shortly after startup still observes
// the cooldown (see throttledRegister); use throttledRegister for
// 401-triggered retries.
func (a *Agent) register(ctx context.Context, force bool) error {
	_, err := a.registerInner(ctx, force, true)
	return err
}

// throttledRegister attempts registration unless a recent attempt is still
// within reRegisterCooldown. It returns (true, nil) when the attempt was
// skipped due to cooldown, (false, nil) on success or when no registration
// was needed, and (false, err) when registration was attempted and failed.
// It delegates to registerInner with the cooldown enforced; see registerInner
// for the shared NeedsRegistration check, lastRegAttempt publish, doRegister,
// and Retry-After handling. sseAuthFailures is intentionally NOT reset here
// so heartbeat/poll-triggered registrations do not couple to SSE backoff;
// the SSE loop resets its own counter after an SSE-triggered success (see
// listenSSE), since all paths share the same refreshed token.
func (a *Agent) throttledRegister(ctx context.Context, force bool) (bool, error) {
	return a.registerInner(ctx, force, false)
}

// registerInner is the single shared registration helper for register and
// throttledRegister so the NeedsRegistration check, lastRegAttempt publish,
// doRegister + storeRetryAfterLocked cannot drift between paths. When
// bypassCooldown is true the cooldown is not consulted but the attempt time
// is still published before I/O; when false a recent attempt within
// reRegisterCooldown skips with (true, nil). The cooldown check and
// lastRegAttempt publish hold regMu only briefly; network I/O runs without
// holding regMu so heartbeat/poll/SSE loops never block on sseAuthFailures
// updates for up to HTTPClientTimeout. Every real attempt publishes
// lastRegAttempt before I/O so concurrent 401s observe the cooldown and
// skip. A failed attempt with a present Retry-After hint stores it so a
// later cooldown skip can still honor the 429 delay. A successful attempt
// clears the stored hint.
func (a *Agent) registerInner(ctx context.Context, force bool, bypassCooldown bool) (bool, error) {
	if !force {
		cfg := a.getConfig()
		if !cfg.NeedsRegistration() {
			return false, nil
		}
	}

	a.regMu.Lock()
	if !bypassCooldown {
		last := a.lastRegAttempt
		var since time.Duration
		shouldSkip := false
		if !last.IsZero() {
			since = time.Since(last)
			if since < reRegisterCooldown {
				shouldSkip = true
			}
		}
		if shouldSkip {
			cooldown := reRegisterCooldown
			a.regMu.Unlock()
			log.Debug("Skipping re-registration, cooldown not expired", "since", since.String(), "cooldown", cooldown.String())
			return true, nil
		}
	}
	// Publish the attempt time before I/O so coincident 401s observe the
	// cooldown and skip instead of stampeding the control plane.
	a.lastRegAttempt = time.Now()
	a.regMu.Unlock()

	log.Info("Attempting registration", "force", force)

	err := a.doRegister(ctx)

	a.regMu.Lock()
	defer a.regMu.Unlock()
	a.storeRetryAfterLocked(err)
	if err != nil {
		return false, err
	}
	return false, nil
}

// sseReauthDelay returns the backoff before the next SSE re-registration
// retry. The delay grows exponentially as base*2^(failures-1) capped at
// sseReauthMaxDelay, plus jitter (up to 10% of the delay capped at 1s).
// A present Retry-After hint overrides the computed delay when larger,
// plus its own jitter (up to 10% of the hint capped at 1s) so coincident
// 429s do not retry in lockstep. Callers that skipped registration due to
// cooldown must pass the stored lastRetryAfter hint directly (see
// listenSSE) instead of synthesizing an error, or the 429 delay is lost.
func sseReauthDelay(failures int, retryAfter time.Duration, hasHint bool) time.Duration {
	if failures < 1 {
		failures = 1
	}
	base := sseReauthBaseDelay
	for i := 1; i < failures; i++ {
		base *= 2
		if base >= sseReauthMaxDelay {
			base = sseReauthMaxDelay
			break
		}
	}
	if base > sseReauthMaxDelay {
		base = sseReauthMaxDelay
	}
	if hasHint && retryAfter > base {
		return common.AddJitter(retryAfter)
	}
	return common.AddJitter(base)
}

// sleepWithContext sleeps for d or returns early when ctx is done.
// It is the single shared interruptible-sleep helper for the core package;
// updater.sleepWithUpdateContext delegates here so the timer+select logic
// stays in one place.
func sleepWithContext(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
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
			log.Warn("Failed to close heartbeat response body", "url", url, "error", cErr)
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
	data, err := a.readCachedBundle()
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
		if err := os.Remove(tmpPath); err != nil && !os.IsNotExist(err) {
			log.Warn("Failed to remove temp file", "path", tmpPath, "error", err)
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

// listenSSE maintains the long-lived SSE connection.
// transport.ListenSSE only returns 401 Unauthorized (credential expiry) or a
// context error; non-401 stream drops reconnect internally. Each 401
// increments sseAuthFailures, attempts throttled re-registration, and backs
// off via sseReauthDelay. A successful SSE-triggered registration resets
// sseAuthFailures so the next 401 starts at the base delay; registrations
// triggered by heartbeat/poll paths do not reset it (see throttledRegister).
func (a *Agent) listenSSE(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		cfg := a.getConfig()
		start := time.Now()
		err := transport.ListenSSE(ctx, a.sseClient, cfg.ControlPlaneURL, cfg.HostID, cfg.Token, a.version, func(sseCtx context.Context) {
			if pullErr := a.pullBundle(sseCtx); pullErr != nil {
				log.Error("SSE-triggered bundle pull failed", "error", pullErr)
			}
		}, func(sseCtx context.Context) {
			a.handleFetchBackup(sseCtx)
		}, func(sseCtx context.Context, controlPlaneURL string) {
			a.handleUpdateAgent(sseCtx, controlPlaneURL)
		})

		if ctx.Err() != nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil
		}
		if !errors.Is(err, common.ErrUnauthorized) {
			// Defensive: unreachable per the transport contract, which
			// reconnects non-401 drops internally. Back off before
			// reconnecting so a contract violation cannot hot-loop
			// spamming Error and burning CPU.
			log.Error("SSE listener returned unexpected error, reconnecting", "error", err)
			if sleepErr := sleepWithContext(ctx, sseReauthBaseDelay); sleepErr != nil {
				return nil
			}
			continue
		}

		elapsed := time.Since(start)
		a.regMu.Lock()
		if elapsed >= sseReauthMaxDelay {
			// Long-lived connection: prior failures are stale.
			a.sseAuthFailures = 0
		}
		a.sseAuthFailures++
		failures := a.sseAuthFailures
		a.regMu.Unlock()

		skipped, regErr := a.throttledRegister(ctx, true)
		var retryAfter time.Duration
		var hasHint bool
		switch {
		case skipped:
			// Cooldown skip carries no error, which would lose the last 429
			// hint. Reuse the stored hint so this backoff still honors
			// Retry-After instead of falling back to the base delay.
			a.regMu.Lock()
			retryAfter, hasHint = a.lastRetryAfter, a.hasLastRetryAfter
			a.regMu.Unlock()
		case regErr != nil:
			retryAfter, hasHint = common.RetryAfterOf(regErr)
		default:
			// SSE-triggered registration succeeded with fresh credentials.
			a.regMu.Lock()
			a.sseAuthFailures = 0
			a.regMu.Unlock()
		}
		delay := sseReauthDelay(failures, retryAfter, hasHint)
		switch {
		case !skipped && regErr == nil:
			log.Info("SSE re-registration succeeded, backing off before reconnect", "attempt", failures, "delay", delay.String(), "sseError", err)
		case skipped:
			log.Warn("Received 401 on SSE connection, re-registration skipped (cooldown), backing off before retry", "attempt", failures, "delay", delay.String(), "sseError", err, "retryAfter", retryAfter.String(), "hasRetryAfter", hasHint)
		default:
			log.Warn("Received 401 on SSE connection, backing off before re-registration retry", "attempt", failures, "delay", delay.String(), "sseError", err, "error", regErr)
		}
		if sleepErr := sleepWithContext(ctx, delay); sleepErr != nil {
			return nil
		}
		// After re-registration, continue the loop to reconnect with new token
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
// loopback test hosts. It delegates to the canonical transport validator so
// host/port pinning stays in one place.
func validateUpdateURL(updateURL, configuredURL string) (string, error) {
	return transport.ValidateUpdateURL(updateURL, configuredURL)
}

// handleUpdateAgent performs an in-process self-update. It downloads the new
// binary via HTTP and applies it in-place using selfupdate.Apply, then exits
// the process so the service manager can restart with the new binary.
//
// The whole update runs synchronously on the caller's goroutine under the
// SSE callback guard, on a context detached from the SSE stream so a
// canceled or reconnected stream cannot interrupt the download or suppress
// the restart. Exit decisions never read the stream context. Running
// synchronously (never spawning a detached goroutine and returning) is what
// keeps the transport sseCallbackGuard's running flag held until the update
// completes; returning early would release the guard while performUpdate is
// still racing on the binary file. An agent-level singleflight
// (updateRunning) additionally serializes concurrent events across SSE
// reconnects and CLI triggers: duplicates while an update is in flight are
// skipped so parallel performUpdate calls and double exitFunc calls cannot
// happen. After a successful apply, the agent waits 2 seconds for the SSE
// acknowledgment to flush, then calls exitFunc(0) (os.Exit in production)
// for a systemd restart. Failures are recorded for reporting on the next
// heartbeat; the agent stays running so the operator can retry via a later
// event.
func (a *Agent) handleUpdateAgent(ctx context.Context, controlPlaneURL string) {
	detachedCtx := context.WithoutCancel(ctx)
	beforeVersion := a.version
	log.Info("Starting agent self-update", "control_plane_url", controlPlaneURL, "current_version", beforeVersion)

	cfg := a.getConfig()
	normalizedURL, err := validateUpdateURL(controlPlaneURL, cfg.ControlPlaneURL)
	if err != nil {
		log.Error("Invalid control plane URL received in update_agent event", "url", controlPlaneURL, "error", err)
		a.setLastUpdateError(fmt.Sprintf("validate update URL: %v", err))
		return
	}

	if !a.updateRunning.CompareAndSwap(false, true) {
		log.Warn("Agent self-update already in progress, skipping duplicate update_agent event")
		return
	}
	defer a.updateRunning.Store(false)

	if err := performUpdate(detachedCtx, a.httpClient, normalizedURL); err != nil {
		// Update failed — do NOT exit the process. The agent stays
		// running so the operator can investigate and retry via a
		// subsequent update_agent event. The reason is reported back
		// on the next heartbeat instead of failing silently.
		log.Error("Agent self-update failed, not exiting for restart", "error", err, "current_version", beforeVersion)
		a.setLastUpdateError(err.Error())
		return
	}
	a.setLastUpdateError("")
	log.Info("Agent update applied, exiting for restart in 2s", "previous_version", beforeVersion)
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	<-timer.C
	a.exitFunc(0)
}

// HandleUpdateAgent triggers the agent self-update process. It is the public
// equivalent of handleUpdateAgent, exposed for CLI and integration test use.
// It runs synchronously under the same update singleflight as the SSE path,
// so concurrent triggers cannot run parallel updates.
func (a *Agent) HandleUpdateAgent(controlPlaneURL string) {
	a.handleUpdateAgent(context.Background(), controlPlaneURL)
}

// HandleUpdateAgentSync triggers the agent self-update synchronously.
// It blocks until the update process completes or fails, returning any error.
// On success, it calls exitFunc(0) to exit the process for restart.
// This is intended for CLI use (e.g., `runic-agent -update`) where the caller
// needs to know whether the update succeeded. For SSE-triggered updates,
// use HandleUpdateAgent instead. Both paths share the same update
// singleflight, so a CLI trigger while an SSE update is in flight (or vice
// versa) fails fast instead of running parallel updates.
func (a *Agent) HandleUpdateAgentSync(controlPlaneURL string) error {
	return a.handleUpdateAgentSync(context.Background(), controlPlaneURL)
}

func (a *Agent) handleUpdateAgentSync(ctx context.Context, controlPlaneURL string) error {
	beforeVersion := a.version
	log.Info("Starting agent self-update (synchronous)", "control_plane_url", controlPlaneURL, "current_version", beforeVersion)

	cfg := a.getConfig()
	normalizedURL, err := validateUpdateURL(controlPlaneURL, cfg.ControlPlaneURL)
	if err != nil {
		a.setLastUpdateError(fmt.Sprintf("validate update URL: %v", err))
		return fmt.Errorf("validate update URL: %w", err)
	}

	if !a.updateRunning.CompareAndSwap(false, true) {
		return fmt.Errorf("agent self-update already in progress")
	}
	defer a.updateRunning.Store(false)

	if err := performUpdate(ctx, a.httpClient, normalizedURL); err != nil {
		a.setLastUpdateError(err.Error())
		return fmt.Errorf("agent self-update failed: %w", err)
	}

	a.setLastUpdateError("")
	log.Info("Agent update applied successfully, exiting for restart", "previous_version", beforeVersion)
	a.exitFunc(0)
	return nil
}

// isCanonicalPath reports whether configured equals the canonical default
// path after cleaning. Cleaning handles trailing slashes and dot segments
// while still respecting test overrides: custom temp-dir paths never equal
// the /var defaults so legacy fallback stays disabled for them. It
// delegates to the single shared apply.IsCanonicalPath helper so the
// canonical-path check cannot drift between packages.
func isCanonicalPath(configured, canonical string) bool {
	return apply.IsCanonicalPath(configured, canonical)
}

// isDefaultBackupPath reports whether p is the default startup-backup path.
func isDefaultBackupPath(p string) bool {
	return isCanonicalPath(p, apply.StartupBackupPath)
}

// readCachedBundle reads the cached bundle from the configured cachePath,
// falling back to the legacy /etc/runic-agent location when the agent still
// uses the default /var path. A fallback hit migrates the content forward
// so the next boot hits the primary location.
func (a *Agent) readCachedBundle() ([]byte, error) {
	return apply.ReadFileWithFallback(a.cachePath, apply.LegacyCachedBundlePath)
}

func (a *Agent) readBackup() (string, error) {
	data, err := apply.ReadFileWithFallback(a.backupPath, apply.LegacyStartupBackupPath)
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
			// Snapshot all credentials from a single getConfig generation so
			// the rotation request cannot mix a fresh token with a stale
			// URL/hostID (or vice versa) across a concurrent re-registration.
			cfg := a.getConfig()
			newKey, err := a.rotationManager.CheckAndRotate(ctx, cfg.HMACKey, cfg.Token, cfg.ControlPlaneURL, cfg.HostID)
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
