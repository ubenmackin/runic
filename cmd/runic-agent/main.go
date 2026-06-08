package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/term"

	"runic/internal/agent"
	"runic/internal/agent/identity"
	runiclog "runic/internal/common/log"
	"runic/internal/common/signal"
	"runic/internal/common/systemd"
	"runic/internal/common/version"
)

type configFlag struct {
	set   bool
	value string
}

func (cf *configFlag) Set(value string) error {
	cf.value = value
	cf.set = true
	return nil
}

func (cf *configFlag) String() string {
	return cf.value
}

func (cf *configFlag) IsBoolFlag() bool {
	return false
}

func parseBoolFlag(value string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "true", "1", "yes", "on":
		return true, nil
	case "false", "0", "no", "off":
		return false, nil
	default:
		return false, fmt.Errorf("invalid boolean value: %q (expected true/false)", value)
	}
}

func main() {
	configPath := flag.String("config", "/etc/runic-agent/config.json", "Config file path")

	uninstall := flag.Bool("uninstall", false, "Uninstall the agent from this system")
	purge := flag.Bool("purge", false, "Also remove config files (use with --uninstall)")
	versionFlag := flag.Bool("version", false, "Print version and exit")
	update := flag.Bool("update", false, "Trigger a self-update using the configured control plane URL and exit")
	setup := flag.Bool("setup", false, "Run interactive setup wizard")

	// Config-mode flags (these trigger config-update mode when set)
	// Boolean flags accept true/false arguments
	var enableOnBoot, enableRulesBundle, disableSystemIPTables configFlag
	flag.Var(&enableOnBoot, "enable-on-boot", "Enable applying rules on boot (true/false)\nExample: -enable-on-boot true")
	flag.Var(&enableRulesBundle, "enable-rules-bundle", "Enable automatic bundle application (true/false)\nExample: -enable-rules-bundle true")
	flag.Var(&disableSystemIPTables, "disable-system-iptables", "Disable system-managed iptables services (true/false)\nExample: -disable-system-iptables true")

	// String flags (also config-mode)
	var controlPlaneURL, logPath configFlag
	flag.Var(&controlPlaneURL, "url", "Control plane URL\nExample: -url https://control.example.com")
	flag.Var(&logPath, "log-path", "Log file path\nExample: -log-path /var/log/runic/firewall.log")

	// Integer flags (also config-mode)
	var pullInterval configFlag
	flag.Var(&pullInterval, "pull-interval", "Pull interval in seconds (0 = use default)\nExample: -pull-interval 30")

	flag.Parse()

	logLevel := os.Getenv("LOG_LEVEL")
	if logLevel == "" {
		logLevel = "info"
	}
	runiclog.Init(logLevel, os.Stderr)

	if *versionFlag {
		version.PrintVersion("runic-agent", version.AgentVersion)
	}

	if *setup {
		defaultURL := resolveControlPlaneURL(controlPlaneURL)
		if err := runSetupWizard(*configPath, defaultURL); err != nil {
			runiclog.Fatal("Setup failed", "error", err)
		}
		fmt.Println("Configuration saved.")
		systemd.PromptRestart()
		fmt.Println("\nRun without -setup to start the agent.")
		return
	}

	if *uninstall {
		if err := uninstallAgent(*purge); err != nil {
			runiclog.Fatal("Uninstall failed", "error", err)
		}
		fmt.Println("Runic agent uninstalled successfully.")
		return
	}

	// -update mode: trigger self-update and exit
	// Must be checked before isConfigMode() so that -update -url <url>
	// triggers an update (using -url as the URL override) rather than
	// entering config mode (which -url would otherwise activate).
	if *update {
		cfg, err := identity.LoadConfig(*configPath)
		if err != nil {
			runiclog.Fatal("Update: failed to load config", "error", err)
		}
		updateURL := resolveControlPlaneURL(controlPlaneURL)
		if updateURL == "" && cfg.ControlPlaneURL != "" {
			updateURL = cfg.ControlPlaneURL
		}
		if updateURL == "" {
			runiclog.Fatal("Update: control plane URL not configured")
		}
		a := agent.New(*configPath, updateURL)
		if err := a.HandleUpdateAgentSync(updateURL); err != nil {
			runiclog.Fatal("Update failed", "error", err)
		}
		return
	}

	if isConfigMode(enableOnBoot, enableRulesBundle, disableSystemIPTables, controlPlaneURL, logPath, pullInterval) {
		if err := handleConfigMode(*configPath, enableOnBoot, enableRulesBundle, disableSystemIPTables, controlPlaneURL, logPath, pullInterval); err != nil {
			runiclog.Fatal("Config update failed", "error", err)
		}
		return
	}

	// Normal agent startup
	// Pass CLI-provided URL to agent (will be merged with config file URL in loadConfig)
	// If no CLI URL, check environment variable
	cliURL := resolveControlPlaneURL(controlPlaneURL)
	a := agent.New(*configPath, cliURL)

	// Context that cancels on SIGINT/SIGTERM
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		<-signal.ShutdownSignal()
		runiclog.Info("Received shutdown signal — stopping agent...")
		cancel()
	}()

	runiclog.Info("Starting runic-agent", "version", version.AgentVersion)

	if err := a.Run(ctx); err != nil {
		runiclog.Warn("Agent error", "error", err)
	}
}

func isConfigMode(flags ...configFlag) bool {
	for _, f := range flags {
		if f.set {
			return true
		}
	}
	return false
}

func resolveControlPlaneURL(cliFlag configFlag) string {
	if url := cliFlag.String(); url != "" {
		return url
	}
	return os.Getenv("RUNIC_CONTROL_PLANE_URL")
}

// handleConfigMode updates individual config fields from CLI flags.
// NOTE: This round-trips the config through LoadConfig/SaveConfig, which
// means fields not represented in the JSON schema (computed or ephemeral)
// are lost on save. This is acceptable for config-mode usage since those
// fields are re-derived at agent startup.
func handleConfigMode(configPath string, enableOnBoot, enableRulesBundle, disableSystemIPTables, controlPlaneURL, logPath, pullInterval configFlag) error {
	cfg, err := identity.LoadConfig(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	changes := []string{}

	// Process boolean flags
	if enableOnBoot.set {
		val, err := parseBoolFlag(enableOnBoot.value)
		if err != nil {
			return fmt.Errorf("-enable-on-boot: %w", err)
		}
		cfg.ApplyOnBoot = val
		changes = append(changes, fmt.Sprintf("enable-on-boot: %v", val))
	}

	if enableRulesBundle.set {
		val, err := parseBoolFlag(enableRulesBundle.value)
		if err != nil {
			return fmt.Errorf("-enable-rules-bundle: %w", err)
		}
		cfg.ApplyRulesBundle = val
		changes = append(changes, fmt.Sprintf("enable-rules-bundle: %v", val))
	}

	if disableSystemIPTables.set {
		val, err := parseBoolFlag(disableSystemIPTables.value)
		if err != nil {
			return fmt.Errorf("-disable-system-iptables: %w", err)
		}
		cfg.DisableSystemManagedIPTables = val
		changes = append(changes, fmt.Sprintf("disable-system-iptables: %v", val))
	}

	// Process string flags
	if controlPlaneURL.set {
		url := strings.TrimSpace(controlPlaneURL.value)
		if url == "" {
			return fmt.Errorf("-url cannot be empty")
		}
		cfg.ControlPlaneURL = url
		changes = append(changes, fmt.Sprintf("url: %s", url))
	}

	if logPath.set {
		path := strings.TrimSpace(logPath.value)
		if path == "" {
			return fmt.Errorf("-log-path cannot be empty")
		}
		cfg.LogPath = path
		changes = append(changes, fmt.Sprintf("log-path: %s", path))
	}

	// Process integer flags
	if pullInterval.set {
		interval, err := strconv.Atoi(strings.TrimSpace(pullInterval.value))
		if err != nil {
			return fmt.Errorf("-pull-interval: invalid integer value %q", pullInterval.value)
		}
		if interval < 0 || interval > 31536000 {
			return fmt.Errorf("-pull-interval: must be between 0 and 31536000 (1 year)")
		}
		cfg.PullIntervalSec = interval
		changes = append(changes, fmt.Sprintf("pull-interval: %d", interval))
	}

	// Validate config before saving
	if err := validateConfig(cfg); err != nil {
		return fmt.Errorf("config validation failed: %w", err)
	}

	// Save config
	if err := identity.SaveConfig(configPath, cfg); err != nil {
		return fmt.Errorf("save config: %w", err)
	}

	fmt.Println("Configuration updated successfully:")
	for _, change := range changes {
		fmt.Printf("  - %s\n", change)
	}
	fmt.Printf("Config saved to: %s\n", configPath)
	systemd.PromptRestart()
	return nil
}

// perform field-level validation on the config.
func validateConfig(cfg *identity.Config) error {
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("config validation failed: %w", err)
	}

	return nil
}

func uninstallAgent(purge bool) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("must be run as root (use sudo)")
	}

	fmt.Println("Stopping runic-agent service...")
	if err := systemd.StopService("runic-agent"); err != nil {
		fmt.Printf("Warning: failed to stop service: %v\n", err)
	}
	if err := systemd.DisableService("runic-agent"); err != nil {
		fmt.Printf("Warning: failed to disable service: %v\n", err)
	}

	fmt.Println("Removing systemd service file...")
	if err := os.Remove(systemd.ServicePath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove service file: %w", err)
	}
	if err := systemd.DaemonReload(); err != nil {
		fmt.Printf("Warning: failed to daemon-reload: %v\n", err)
	}

	fmt.Println("Removing runic-agent binary...")
	if err := os.Remove("/usr/local/bin/runic-agent"); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove binary: %w", err)
	}

	if purge {
		fmt.Println("Removing config files...")
		if err := os.RemoveAll("/etc/runic-agent"); err != nil {
			fmt.Printf("Warning: failed to remove /etc/runic-agent: %v\n", err)
		}
		if err := os.RemoveAll("/var/log/runic"); err != nil {
			fmt.Printf("Warning: failed to remove /var/log/runic: %v\n", err)
		}
	} else {
		fmt.Println("Config files preserved. Use --purge to remove them.")
	}

	return nil
}

// promptControlPlaneURL reads a control plane URL from the user, using the provided default.
func promptControlPlaneURL(reader *bufio.Reader, defaultURL string) (string, error) {
	fmt.Print("Control Plane URL")
	if defaultURL != "" {
		fmt.Printf(" [%s]: ", defaultURL)
	} else {
		fmt.Print(": ")
	}
	input, err := reader.ReadString('\n')
	if err != nil {
		runiclog.Warn("Failed to read control plane URL input", "error", err)
	}
	input = strings.TrimSpace(input)
	if input != "" {
		return input, nil
	}
	if defaultURL == "" {
		return "", fmt.Errorf("control plane URL is required")
	}
	return defaultURL, nil
}

// promptYesNo reads a y/n answer and returns the resulting value based on the provided default.
func promptYesNo(reader *bufio.Reader, prompt string, currentDefault bool) bool {
	if currentDefault {
		fmt.Printf("%s [Y/n]: ", prompt)
	} else {
		fmt.Printf("%s [y/N]: ", prompt)
	}
	input, err := reader.ReadString('\n')
	if err != nil {
		runiclog.Warn("Failed to read input for %q", "error", err)
		return currentDefault
	}
	input = strings.TrimSpace(strings.ToLower(input))
	switch input {
	case "y":
		return true
	case "n":
		return false
	case "":
		return currentDefault
	default:
		runiclog.Warn("Invalid input received, using default value")
		return currentDefault
	}
}

// promptPullInterval reads a pull interval in seconds from the user.
func promptPullInterval(reader *bufio.Reader, currentDefault int) int {
	if currentDefault == 0 {
		currentDefault = 86400
	}
	fmt.Printf("Pull interval in seconds (default %d): ", currentDefault)
	input, err := reader.ReadString('\n')
	if err != nil {
		runiclog.Warn("Failed to read pull interval input", "error", err)
		return currentDefault
	}
	input = strings.TrimSpace(input)
	if input == "" {
		return currentDefault
	}
	var newVal int
	if _, err := fmt.Sscanf(input, "%d", &newVal); err != nil {
		runiclog.Warn("Invalid pull interval format", "error", err)
		return currentDefault
	}
	return newVal
}

// promptLogPath reads a log file path from the user.
func promptLogPath(reader *bufio.Reader, currentDefault string) string {
	if currentDefault == "" {
		currentDefault = "/var/log/runic/firewall.log"
	}
	fmt.Printf("Log path (default %s): ", currentDefault)
	input, err := reader.ReadString('\n')
	if err != nil {
		runiclog.Warn("Failed to read log path input", "error", err)
		return currentDefault
	}
	input = strings.TrimSpace(input)
	if input == "" {
		return currentDefault
	}
	return input
}

func runSetupWizard(configPath string, defaultControlPlaneURL string) error {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return fmt.Errorf("setup wizard requires interactive terminal. Use -url flag or config file instead")
	}

	reader := bufio.NewReader(os.Stdin)

	// Load existing config at start to use its values as defaults
	cfg, err := identity.LoadConfig(configPath)
	if err != nil {
		cfg = &identity.Config{}
	}

	// Build default URL from CLI/env first, falling back to config value
	urlDefault := defaultControlPlaneURL
	if urlDefault == "" && cfg.ControlPlaneURL != "" {
		urlDefault = cfg.ControlPlaneURL
	}

	controlPlaneURL, err := promptControlPlaneURL(reader, urlDefault)
	if err != nil {
		return err
	}
	applyOnBoot := promptYesNo(reader, "Enable apply on boot", cfg.ApplyOnBoot)
	applyRulesBundle := promptYesNo(reader, "Enable automatic bundle application", cfg.ApplyRulesBundle)
	pullInterval := promptPullInterval(reader, cfg.PullIntervalSec)
	logPath := promptLogPath(reader, cfg.LogPath)
	disableSystemIPTables := promptYesNo(reader, "Disable system-managed iptables services", cfg.DisableSystemManagedIPTables)

	// Preserve existing config values for host_id, token, hmac_key (already loaded)
	cfg.ControlPlaneURL = controlPlaneURL
	cfg.ApplyOnBoot = applyOnBoot
	cfg.ApplyRulesBundle = applyRulesBundle
	cfg.PullIntervalSec = pullInterval
	cfg.LogPath = logPath
	cfg.DisableSystemManagedIPTables = disableSystemIPTables

	// Save config
	if err := identity.SaveConfig(configPath, cfg); err != nil {
		return fmt.Errorf("save config: %w", err)
	}

	return nil
}
