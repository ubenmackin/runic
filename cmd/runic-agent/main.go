package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/term"

	"runic/internal/agent"
	"runic/internal/agent/core"
	"runic/internal/agent/identity"
)

const (
	systemdServicePath    = "/etc/systemd/system/runic-agent.service"
	systemdLibServicePath = "/lib/systemd/system/runic-agent.service"
)

// configFlag tracks whether a config flag was explicitly set
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

// parseBoolFlag parses "true" or "false" string to boolean
// Returns error for invalid values
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
	// Config file path (not a config-mode flag)
	configPath := flag.String("config", "/etc/runic-agent/config.json", "Config file path")

	// Action flags (not config-mode flags)
	uninstall := flag.Bool("uninstall", false, "Uninstall the agent from this system")
	purge := flag.Bool("purge", false, "Also remove config files (use with --uninstall)")
	version := flag.Bool("version", false, "Print version and exit")
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

	// Handle version flag
	if *version {
		fmt.Printf("runic-agent version %s\n", core.Version)
		return
	}

	// Handle interactive setup wizard
	if *setup {
		// Get default URL from flag or env
		defaultURL := controlPlaneURL.String()
		if defaultURL == "" {
			defaultURL = os.Getenv("RUNIC_CONTROL_PLANE_URL")
		}
		if err := runSetupWizard(*configPath, defaultURL); err != nil {
			log.Fatalf("setup failed: %v", err)
		}
		fmt.Println("Configuration saved.")

		// Check if systemd service is installed and prompt for restart
		if isSystemdServiceInstalled() {
			fmt.Println("\nThe runic-agent systemd service is installed.")
			fmt.Print("Would you like to restart the service now? (sudo systemctl restart runic-agent) [y/N]: ")

			reader := bufio.NewReader(os.Stdin)
			input, err := reader.ReadString('\n')
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: failed to read stdin: %v\n", err)
				fmt.Printf("\nNote: Could not read input. Restart manually with: sudo systemctl restart runic-agent\n")
				return
			}

			input = strings.TrimSpace(strings.ToLower(input))
			if input == "y" || input == "yes" {
				if err := restartSystemdService(); err != nil {
					fmt.Printf("Failed to restart service: %v\n", err)
					fmt.Println("Restart manually with: sudo systemctl restart runic-agent")
				} else {
					fmt.Println("Service restarted successfully.")
				}
			} else {
				fmt.Println("\nTo apply changes, restart the service with: sudo systemctl restart runic-agent")
			}
		} else {
			fmt.Println("\nNote: runic-agent systemd service is not installed.")
			fmt.Println("To apply changes, restart the agent manually.")
		}
		fmt.Println("\nRun without -setup to start the agent.")
		return
	}

	// Handle uninstall
	if *uninstall {
		if err := uninstallAgent(*purge); err != nil {
			log.Fatalf("uninstall failed: %v", err)
		}
		fmt.Println("Runic agent uninstalled successfully.")
		return
	}

	// Check if any config flags were set - enter config-update mode
	if isConfigMode(enableOnBoot, enableRulesBundle, disableSystemIPTables, controlPlaneURL, logPath, pullInterval) {
		if err := handleConfigMode(*configPath, enableOnBoot, enableRulesBundle, disableSystemIPTables, controlPlaneURL, logPath, pullInterval); err != nil {
			log.Fatalf("config update failed: %v", err)
		}
		return
	}

	// Normal agent startup
	// Pass CLI-provided URL to agent (will be merged with config file URL in loadConfig)
	// If no CLI URL, check environment variable
	cliURL := controlPlaneURL.String()
	if cliURL == "" {
		cliURL = os.Getenv("RUNIC_CONTROL_PLANE_URL")
	}
	a := agent.New(*configPath, cliURL)

	// Context that cancels on SIGINT/SIGTERM
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		log.Println("Received shutdown signal — stopping agent...")
		cancel()
	}()

	log.Printf("Starting runic-agent version %s", core.Version)

	if err := a.Run(ctx); err != nil {
		log.Printf("agent error: %v", err)
	}
}

// isConfigMode returns true if any config flag was explicitly set
func isConfigMode(flags ...configFlag) bool {
	for _, f := range flags {
		if f.set {
			return true
		}
	}
	return false
}

// handleConfigMode processes config flags, updates config file, and prompts for service restart
func handleConfigMode(configPath string, enableOnBoot, enableRulesBundle, disableSystemIPTables, controlPlaneURL, logPath, pullInterval configFlag) error {
	// Load existing config
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
	if _, err := validateConfig(cfg); err != nil {
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

	// Check if systemd service is installed and prompt for restart
	if isSystemdServiceInstalled() {
		fmt.Println("\nThe runic-agent systemd service is installed.")
		fmt.Print("Would you like to restart the service now? (sudo systemctl restart runic-agent) [y/N]: ")

		reader := bufio.NewReader(os.Stdin)
		input, err := reader.ReadString('\n')
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to read stdin: %v\n", err)
			fmt.Printf("\nNote: Could not read input. Restart manually with: sudo systemctl restart runic-agent\n")
			return nil
		}

		input = strings.TrimSpace(strings.ToLower(input))
		if input == "y" || input == "yes" {
			if err := restartSystemdService(); err != nil {
				fmt.Printf("Failed to restart service: %v\n", err)
				fmt.Println("Restart manually with: sudo systemctl restart runic-agent")
			} else {
				fmt.Println("Service restarted successfully.")
			}
		} else {
			fmt.Println("\nTo apply changes, restart the service with: sudo systemctl restart runic-agent")
		}
	} else {
		fmt.Println("\nNote: runic-agent systemd service is not installed.")
		fmt.Println("To apply changes, restart the agent manually.")
	}

	return nil
}

// validateConfig validates that the config is valid.
// It performs both JSON marshaling check and field-level validation.
func validateConfig(cfg *identity.Config) (bool, error) {
	// Try to marshal to verify JSON is valid
	_, err := json.Marshal(cfg)
	if err != nil {
		return false, fmt.Errorf("config is not valid JSON: %w", err)
	}

	// Perform field-level validation
	if err := cfg.Validate(); err != nil {
		return false, fmt.Errorf("config validation failed: %w", err)
	}

	return true, nil
}

// isSystemdServiceInstalled checks if runic-agent.service is installed
func isSystemdServiceInstalled() bool {
	// Check if systemd service file exists
	if _, err := os.Stat(systemdServicePath); err == nil {
		return true
	}
	// Also check systemd directory
	if _, err := os.Stat(systemdLibServicePath); err == nil {
		return true
	}
	return false
}

// restartSystemdService restarts the runic-agent service.
//
// Testing Note: This function is intentionally difficult to unit test because:
//  1. It requires root privileges (os.Geteuid() check) - running as root in test environments
//     is not recommended for security reasons
//  2. It calls an external system command (systemctl) which requires systemd to be installed
//     and the runic-agent service to be registered
//  3. Integration tests in a real or containerized environment (with systemd) would be more
//     appropriate for testing this functionality
//
// The root privilege check is tested via TestRestartSystemdServiceRequiresRoot.
// Full integration tests should be run in a VM or container with systemd.
func restartSystemdService() error {
	// Check if running as root
	if os.Geteuid() != 0 {
		return fmt.Errorf("must be run as root to restart service (use sudo)")
	}

	cmd := exec.Command("systemctl", "restart", "runic-agent")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, string(output))
	}
	return nil
}

func uninstallAgent(purge bool) error {
	// Must be run as root
	if os.Geteuid() != 0 {
		return fmt.Errorf("must be run as root (use sudo)")
	}

	// Stop and disable service
	fmt.Println("Stopping runic-agent service...")
	if err := exec.Command("systemctl", "stop", "runic-agent").Run(); err != nil {
		fmt.Printf("Warning: failed to stop service: %v\n", err)
	}
	if err := exec.Command("systemctl", "disable", "runic-agent").Run(); err != nil {
		fmt.Printf("Warning: failed to disable service: %v\n", err)
	}

	// Remove service file
	fmt.Println("Removing systemd service file...")
	if err := os.Remove(systemdServicePath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove service file: %w", err)
	}
	if err := exec.Command("systemctl", "daemon-reload").Run(); err != nil {
		fmt.Printf("Warning: failed to daemon-reload: %v\n", err)
	}

	// Remove binary
	fmt.Println("Removing runic-agent binary...")
	if err := os.Remove("/usr/local/bin/runic-agent"); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove binary: %w", err)
	}

	// Optionally remove config
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

// runSetupWizard runs an interactive setup wizard to configure the agent.
func runSetupWizard(configPath string, defaultControlPlaneURL string) error {
	// Check if stdin is a terminal (not a pipe/file)
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return fmt.Errorf("setup wizard requires interactive terminal. Use -url flag or config file instead")
	}

	reader := bufio.NewReader(os.Stdin)

	// Load existing config at start to use its values as defaults
	cfg, err := identity.LoadConfig(configPath)
	if err != nil {
		// Config file doesn't exist yet, create a new one
		cfg = &identity.Config{}
	}

	// Control plane URL - use CLI/env default first, fall back to config value
	controlPlaneURL := defaultControlPlaneURL
	if controlPlaneURL == "" && cfg.ControlPlaneURL != "" {
		controlPlaneURL = cfg.ControlPlaneURL
	}
	fmt.Print("Control Plane URL")
	if controlPlaneURL != "" {
		fmt.Printf(" [%s]: ", controlPlaneURL)
	} else {
		fmt.Print(": ")
	}
	input, err := reader.ReadString('\n')
	if err != nil {
		log.Printf("Warning: failed to read control plane URL input: %v", err)
	}
	input = strings.TrimSpace(input)
	if input != "" {
		controlPlaneURL = input
	}
	if controlPlaneURL == "" {
		return fmt.Errorf("control plane URL is required")
	}

	// Enable apply on boot - use config value as default
	fmt.Print("Enable apply on boot ")
	if cfg.ApplyOnBoot {
		fmt.Print("[Y/n]: ")
	} else {
		fmt.Print("[y/N]: ")
	}
	input, err = reader.ReadString('\n')
	if err != nil {
		log.Printf("Warning: failed to read apply on boot input: %v", err)
	}
	input = strings.TrimSpace(strings.ToLower(input))
	applyOnBoot := cfg.ApplyOnBoot // default to current config value
	switch input {
	case "y":
		applyOnBoot = true
	case "n":
		applyOnBoot = false
	case "":
		// Keep default
	default:
		// Invalid input, keep default
		log.Printf("Warning: invalid input, using default value")
	}

	// Enable rules bundle - use config value as default
	fmt.Print("Enable automatic bundle application ")
	if cfg.ApplyRulesBundle {
		fmt.Print("[Y/n]: ")
	} else {
		fmt.Print("[y/N]: ")
	}
	input, err = reader.ReadString('\n')
	if err != nil {
		log.Printf("Warning: failed to read rules bundle input: %v", err)
	}
	input = strings.TrimSpace(strings.ToLower(input))
	applyRulesBundle := cfg.ApplyRulesBundle // default to current config value
	switch input {
	case "y":
		applyRulesBundle = true
	case "n":
		applyRulesBundle = false
	case "":
		// Keep default
	default:
		log.Printf("Warning: invalid input, using default value")
	}

	// Pull interval - use config value as default
	pullInterval := cfg.PullIntervalSec
	if pullInterval == 0 {
		pullInterval = 86400 // default if not set in config
	}
	fmt.Printf("Pull interval in seconds (default %d): ", pullInterval)
	input, err = reader.ReadString('\n')
	if err != nil {
		log.Printf("Warning: failed to read pull interval input: %v", err)
	}
	input = strings.TrimSpace(input)
	if input != "" {
		newVal := 0
		if _, err := fmt.Sscanf(input, "%d", &newVal); err != nil {
			log.Printf("Warning: invalid pull interval format: %v", err)
		} else {
			pullInterval = newVal
		}
	}

	// Log path - use config value as default
	logPath := cfg.LogPath
	if logPath == "" {
		logPath = "/var/log/runic/firewall.log" // default if not set in config
	}
	fmt.Printf("Log path (default %s): ", logPath)
	input, err = reader.ReadString('\n')
	if err != nil {
		log.Printf("Warning: failed to read log path input: %v", err)
	}
	input = strings.TrimSpace(input)
	if input != "" {
		logPath = input
	}

	// Disable system iptables - use config value as default
	fmt.Print("Disable system-managed iptables services ")
	if cfg.DisableSystemManagedIPTables {
		fmt.Print("[Y/n]: ")
	} else {
		fmt.Print("[y/N]: ")
	}
	input, err = reader.ReadString('\n')
	if err != nil {
		log.Printf("Warning: failed to read disable system iptables input: %v", err)
	}
	input = strings.TrimSpace(strings.ToLower(input))
	disableSystemIPTables := cfg.DisableSystemManagedIPTables // default to current config value
	switch input {
	case "y":
		disableSystemIPTables = true
	case "n":
		disableSystemIPTables = false
	case "":
		// Keep default
	default:
		log.Printf("Warning: invalid input, using default value")
	}

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
