// Package core provides the main agent loop.
package core

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
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

var Version = "dev"

const InstallScriptURL = "https://raw.githubusercontent.com/ubenmackin/runic/main/scripts/install-agent.sh"

type CommandRunner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
	StartDetached(ctx context.Context, name string, args ...string) error
}

type RealCommandRunner struct{}

func (r *RealCommandRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	return cmd.CombinedOutput()
}

func (r *RealCommandRunner) StartDetached(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	// Redirect stdout/stderr to /dev/null so the child doesn't block on I/O
	devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("open /dev/null: %w", err)
	}
	defer func() {
		_ = devNull.Close()
	}()
	cmd.Stdout = devNull
	cmd.Stderr = devNull
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start detached command: %w", err)
	}
	// Release the process so it doesn't become a zombie when the parent exits.
	// The child runs in its own session (via setsid as the direct command) and will
	// complete independently of the agent's lifecycle.
	if err := cmd.Process.Release(); err != nil {
		return fmt.Errorf("release detached process: %w", err)
	}
	return nil
}

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

	bootPullDone := false

	if a.config.ApplyOnBoot && a.config.ApplyRulesBundle {
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
			} else {
				bootPullDone = true
			}
		}
	} else if a.config.ApplyOnBoot {
		log.Info("apply_on_boot enabled but apply_rules_bundle disabled, skipping boot-time bundle application")
	}

	a.shipper = transport.NewShipper(a.httpClient, a.config.ControlPlaneURL, a.config.Token, a.config.HostID, a.config.LogPath)

	g, gCtx := errgroup.WithContext(ctx)

	g.Go(func() error {
		a.heartbeatLoop(gCtx)
		return nil
	})
	g.Go(func() error {
		a.pollLoop(gCtx, bootPullDone)
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

func (a *Agent) saveConfig() error {
	return identity.SaveConfig(a.configPath, a.config)
}

// DisableSystemIPTablesIfConfigured disables system iptables if the DisableSystemManagedIPTables config option is set to true.
// This prevents conflicts between runic's firewall management and system services
// like netfilter-persistent, iptables-persistent, firewalld, etc.
func (a *Agent) DisableSystemIPTablesIfConfigured() error {
	if !a.config.DisableSystemManagedIPTables {
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
		if err := a.disableService(svc); err != nil {
			log.Warn("Failed to disable service", "service", svc, "error", err)
			continue
		}
		log.Info("Disabled system iptables service", "service", svc)
	}

	return nil
}

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

func (a *Agent) sendHeartbeat(ctx context.Context) error {
	allIPs := detectHostIPs(a.cmdRunner)
	var ipStrings []string
	for _, ipInfo := range allIPs {
		ipStrings = append(ipStrings, ipInfo.IP)
	}
	return metrics.SendHeartbeat(ctx, a.httpClient, a.config.ControlPlaneURL, a.config.HostID, a.config.CurrentBundleVer, a.config.Token, a.version, ipStrings)
}

func (a *Agent) pollLoop(ctx context.Context, skipFirstPull bool) {
	ticker := time.NewTicker(time.Duration(a.config.PullIntervalSec) * time.Second)
	defer ticker.Stop()

	if !skipFirstPull {
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
					if regErr := a.safeRegister(ctx); regErr != nil {
						log.Error("Re-registration failed", "error", regErr)
					}
				}
			}
		}
	}
}

func (a *Agent) pullBundle(ctx context.Context) error {
	return transport.PullBundle(ctx, a.httpClient, a.config.ControlPlaneURL, a.config.HostID, a.config.Token, a.config.CurrentBundleVer, a.version, a.applyBundle)
}

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

func (a *Agent) confirmApply(ctx context.Context, version string) error {
	return transport.ConfirmApply(ctx, a.httpClient, a.config.ControlPlaneURL, a.config.HostID, a.config.Token, a.version, version)
}

func (a *Agent) register(ctx context.Context) error {
	allIPs := detectHostIPs(a.cmdRunner)
	var ipStrings []string
	for _, ipInfo := range allIPs {
		ipStrings = append(ipStrings, ipInfo.IP)
	}
	return identity.Register(ctx, a.httpClient, a.config, a.version, a.saveConfig, ipStrings)
}

// thundering herd when multiple loops detect 401 errors simultaneously.
func (a *Agent) safeRegister(ctx context.Context) error {
	a.regMu.Lock()
	defer a.regMu.Unlock()
	log.Info("Attempting re-registration (mutex acquired)")
	return a.register(ctx)
}

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

func (a *Agent) applyCachedBundle(ctx context.Context) error {
	if !a.config.ApplyRulesBundle {
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
		}, func(sseCtx context.Context, controlPlaneURL string) {
			a.handleUpdateAgent(sseCtx, controlPlaneURL)
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

// The install command is launched via systemd-run --scope so it runs in its
// own cgroup outside the agent's service unit. When the install script calls
// "systemctl stop runic-agent", systemd only kills processes in the service's
// cgroup — the scope unit survives and the script completes the update
// (download, file move, service restart). If systemd-run is unavailable (e.g.
// non-systemd environments), fall back to the setsid approach.
func (a *Agent) handleUpdateAgent(_ context.Context, controlPlaneURL string) {
	log.Info("Starting agent self-update", "control_plane_url", controlPlaneURL)

	parsedURL, err := url.Parse(controlPlaneURL)
	if err != nil || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") {
		log.Error("Invalid control plane URL received in update_agent event", "url", controlPlaneURL, "error", err)
		return
	}

	// Build the install command: curl downloads the script, sudo runs it with the control plane URL.
	cmd := fmt.Sprintf("curl -sL %s | sudo bash -s -- %s", InstallScriptURL, shellSafeArg(parsedURL.String()))

	// Use systemd-run --scope to launch the update in its own cgroup, outside the
	// agent's service unit. When the install script calls "systemctl stop runic-agent",
	// systemd only kills processes in the service's cgroup — the scope survives.
	ctx := context.Background()
	_, err = a.cmdRunner.Run(ctx, "systemd-run", "--scope", "--unit=runic-agent-update", "bash", "-c", cmd)
	if err != nil {
		// Fall back to setsid if systemd-run is unavailable (non-systemd environments)
		log.Warn("systemd-run --scope failed, falling back to setsid", "error", err)
		err = a.cmdRunner.StartDetached(ctx, "setsid", "bash", "-c", fmt.Sprintf(
			"nohup curl -sL %s | sudo bash -s -- %s >/dev/null 2>&1 &",
			InstallScriptURL,
			shellSafeArg(parsedURL.String()),
		),
		)
		if err != nil {
			log.Error("Failed to launch update process (both systemd-run and setsid failed)", "error", err)
			return
		}
	}

	log.Info("Update process launched, agent will be restarted by the install script")
}

// HandleUpdateAgent triggers the agent self-update process. It is the public
// equivalent of handleUpdateAgent, exposed for CLI and integration test use.
func (a *Agent) HandleUpdateAgent(controlPlaneURL string) {
	a.handleUpdateAgent(context.Background(), controlPlaneURL)
}

// This prevents shell injection by treating the value as a literal string.
func shellSafeArg(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}

func (a *Agent) readBackup() (string, error) {
	data, err := os.ReadFile(a.backupPath)
	if err != nil {
		return "", fmt.Errorf("read backup: %w", err)
	}
	return string(data), nil
}

// If ipset is not installed, returns empty string (non-fatal).
func (a *Agent) readIpsets() (string, error) {
	out, err := a.cmdRunner.Run(context.Background(), "ipset", "list")
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
			if err := a.rotationManager.CheckAndRotate(ctx); err != nil {
				log.Warn("Key rotation check failed", "error", err)
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
func detectHostIPs(runner CommandRunner) []HostIPInfo {
	// Determine the default route interface for primary IP detection
	defaultIface := detectDefaultRouteInterface(runner)

	ifaces, err := net.Interfaces()
	if err != nil {
		log.Warn("Failed to list network interfaces", "error", err)
		return nil
	}

	dockerSubnets := getDockerSubnets(runner)

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
			case *net.TCPAddr:
				ip = v.IP
			case *net.UDPAddr:
				ip = v.IP
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

func detectDefaultRouteInterface(runner CommandRunner) string {
	out, err := runner.Run(context.Background(), "ip", "route", "show", "default")
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
func getDockerSubnets(runner CommandRunner) []dockerSubnet {
	var subnets []dockerSubnet

	// List Docker networks
	out, err := runner.Run(context.Background(), "docker", "network", "ls", "--format", "{{.Name}}")
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
		inspectOut, err := runner.Run(context.Background(), "docker", "network", "inspect", name, "--format", "{{range .IPAM.Config}}{{.Subnet}}{{end}}")
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
	// Simple bubble sort - list is typically small
	for i := 0; i < len(ips); i++ {
		for j := i + 1; j < len(ips); j++ {
			if ips[j].IsPrimary && !ips[i].IsPrimary {
				ips[i], ips[j] = ips[j], ips[i]
			}
		}
	}
}
