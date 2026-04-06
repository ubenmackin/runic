package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"runic/internal/agent"
	"runic/internal/agent/core"
)

func main() {
	controlPlaneURL := flag.String("url", "", "Control plane URL (or RUNIC_CONTROL_PLANE_URL env)")
	configPath := flag.String("config", "/etc/runic-agent/config.json", "Config file path")
	uninstall := flag.Bool("uninstall", false, "Uninstall the agent from this system")
	purge := flag.Bool("purge", false, "Also remove config files (use with --uninstall)")
	version := flag.Bool("version", false, "Print version and exit")
	flag.Parse()

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
