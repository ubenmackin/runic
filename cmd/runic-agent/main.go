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
)

func main() {
	controlPlaneURL := flag.String("url", "", "Control plane URL (or RUNIC_CONTROL_PLANE_URL env)")
	configPath := flag.String("config", "/etc/runic-agent/config.json", "Config file path")
	uninstall := flag.Bool("uninstall", false, "Uninstall the agent from this system")
	purge := flag.Bool("purge", false, "Also remove config files (use with --uninstall)")
	flag.Parse()

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

	if err := a.Run(ctx); err != nil {
		log.Fatalf("agent error: %v", err)
	}
}

func uninstallAgent(purge bool) error {
	// Must be run as root
	if os.Geteuid() != 0 {
		return fmt.Errorf("must be run as root (use sudo)")
	}

	// Stop and disable service
	fmt.Println("Stopping runic-agent service...")
	exec.Command("systemctl", "stop", "runic-agent").Run()
	exec.Command("systemctl", "disable", "runic-agent").Run()

	// Remove service file
	fmt.Println("Removing systemd service file...")
	if err := os.Remove("/etc/systemd/system/runic-agent.service"); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove service file: %w", err)
	}
	exec.Command("systemctl", "daemon-reload").Run()

	// Remove binary
	fmt.Println("Removing runic-agent binary...")
	if err := os.Remove("/usr/local/bin/runic-agent"); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove binary: %w", err)
	}

	// Optionally remove config
	if purge {
		fmt.Println("Removing config files...")
		os.RemoveAll("/etc/runic-agent")
		os.RemoveAll("/var/log/firewall")
	} else {
		fmt.Println("Config files preserved. Use --purge to remove them.")
	}

	return nil
}
