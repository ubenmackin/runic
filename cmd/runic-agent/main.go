package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"golang.org/x/term"

	"runic/internal/agent"
	"runic/internal/agent/core"
	"runic/internal/agent/identity"
)

func main() {
	controlPlaneURL := flag.String("url", "", "Control plane URL (or RUNIC_CONTROL_PLANE_URL env)")
	configPath := flag.String("config", "/etc/runic-agent/config.json", "Config file path")
	uninstall := flag.Bool("uninstall", false, "Uninstall the agent from this system")
	purge := flag.Bool("purge", false, "Also remove config files (use with --uninstall)")
	version := flag.Bool("version", false, "Print version and exit")
	enableOnBoot := flag.Bool("enable-on-boot", false, "Enable applying rules on boot")
	enableRulesBundle := flag.Bool("enable-rules-bundle", false, "Enable automatic bundle application")
	pullInterval := flag.Int("pull-interval", 0, "Pull interval in seconds (0 = use default)")
	logPath := flag.String("log-path", "", "Log file path")
	disableSystemIPTables := flag.Bool("disable-system-iptables", false, "Disable system-managed iptables services")
	setup := flag.Bool("setup", false, "Run interactive setup wizard")
	flag.Parse()

	// Handle interactive setup wizard
	if *setup {
		if err := runSetupWizard(*configPath, *controlPlaneURL); err != nil {
			log.Fatalf("setup failed: %v", err)
		}
		fmt.Println("Configuration saved. Run without -setup to start the agent.")
		return
	}

	if *version {
		fmt.Printf("runic-agent version %s\n", core.Version)
		return
	}

	if *uninstall {
		if err := uninstallAgent(*purge); err != nil {
			log.Fatalf("uninstall failed: %v", err)
		}
		fmt.Println("Runic agent uninstalled successfully.")
		return
	}

	if *controlPlaneURL == "" {
		*controlPlaneURL = os.Getenv("RUNIC_CONTROL_PLANE_URL")
	}

	a := agent.New(*configPath, *controlPlaneURL)

	// Override config with CLI flags if provided
	if err := applyCLIOverrides(*configPath, *enableOnBoot, *enableRulesBundle, *pullInterval, *logPath, *disableSystemIPTables); err != nil {
		log.Printf("warning: failed to apply CLI overrides: %v", err)
	}

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
	if err := os.Remove("/etc/systemd/system/runic-agent.service"); err != nil && !os.IsNotExist(err) {
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

	// Control plane URL
	controlPlaneURL := defaultControlPlaneURL
	fmt.Print("Control Plane URL: ")
	if controlPlaneURL != "" {
		fmt.Printf(" [%s]: ", controlPlaneURL)
	} else {
		fmt.Print(": ")
	}
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)
	if input != "" {
		controlPlaneURL = input
	}
	if controlPlaneURL == "" {
		return fmt.Errorf("control plane URL is required")
	}

	// Enable apply on boot
	fmt.Print("Enable apply on boot (y/n, default n): ")
	input, _ = reader.ReadString('\n')
	input = strings.TrimSpace(strings.ToLower(input))
	applyOnBoot := input == "y"

	// Enable rules bundle
	fmt.Print("Enable automatic bundle application (y/n, default n): ")
	input, _ = reader.ReadString('\n')
	input = strings.TrimSpace(strings.ToLower(input))
	applyRulesBundle := input == "y"

	// Pull interval
	pullInterval := 86400
	fmt.Print("Pull interval in seconds (default 86400): ")
	input, _ = reader.ReadString('\n')
	input = strings.TrimSpace(input)
	if input != "" {
		fmt.Sscanf(input, "%d", &pullInterval)
	}

	// Log path
	logPath := "/var/log/runic/firewall.log"
	fmt.Printf("Log path (default %s): ", logPath)
	input, _ = reader.ReadString('\n')
	input = strings.TrimSpace(input)
	if input != "" {
		logPath = input
	}

	// Disable system iptables
	fmt.Print("Disable system-managed iptables services (y/n, default n): ")
	input, _ = reader.ReadString('\n')
	input = strings.TrimSpace(strings.ToLower(input))
	disableSystemIPTables := input == "y"

	// Create config
	cfg := identity.DefaultConfig()
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

// applyCLIOverrides loads the config and overrides fields if CLI flags are set.
func applyCLIOverrides(configPath string, enableOnBoot, enableRulesBundle bool, pullInterval int, logPath string, disableSystemIPTables bool) error {
	cfg, err := identity.LoadConfig(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	overridden := false

	// Validate pullInterval if provided (must be 0 or between 1 and 31536000 seconds)
	if pullInterval != 0 {
		if pullInterval < 0 || pullInterval > 31536000 {
			return fmt.Errorf("pull-interval must be between 0 and 31536000 (1 year)")
		}
		cfg.PullIntervalSec = pullInterval
		overridden = true
	}

	// Validate logPath if provided (must not be empty after trimming)
	if logPath != "" {
		if strings.TrimSpace(logPath) == "" {
			return fmt.Errorf("log-path cannot be empty")
		}
		cfg.LogPath = logPath
		overridden = true
	}

	if enableOnBoot {
		cfg.ApplyOnBoot = true
		overridden = true
	}
	if enableRulesBundle {
		cfg.ApplyRulesBundle = true
		overridden = true
	}
	if disableSystemIPTables {
		cfg.DisableSystemManagedIPTables = true
		overridden = true
	}

	if overridden {
		// Save config and return error if it fails (critical failure)
		if err := identity.SaveConfig(configPath, cfg); err != nil {
			return fmt.Errorf("failed to save config: %w", err)
		}
	}
	return nil
}
