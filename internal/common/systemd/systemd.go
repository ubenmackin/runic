// Package systemd provides utilities for detecting and interacting with systemd services.
package systemd

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

const (
	// ServicePath is the systemd service file path in /etc/systemd/system.
	ServicePath    = "/etc/systemd/system/runic-agent.service"
	libServicePath = "/lib/systemd/system/runic-agent.service"
)

// IsServiceInstalled checks whether the runic-agent systemd service file exists
// in either /etc/systemd/system or /lib/systemd/system.
func IsServiceInstalled() bool {
	if _, err := os.Stat(ServicePath); err == nil {
		return true
	}
	if _, err := os.Stat(libServicePath); err == nil {
		return true
	}
	return false
}

// RestartService restarts the named systemd service.
// The caller must have root privileges.
func RestartService(name string) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("must be run as root to restart service (use sudo)")
	}

	cmd := exec.Command("systemctl", "restart", name)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, string(output))
	}
	return nil
}

// StopService stops the named systemd service.
// The caller must have root privileges.
func StopService(name string) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("must be run as root to stop service (use sudo)")
	}

	cmd := exec.Command("systemctl", "stop", name)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, string(output))
	}
	return nil
}

// DisableService disables the named systemd service so it no longer starts on boot.
// The caller must have root privileges.
func DisableService(name string) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("must be run as root to disable service (use sudo)")
	}

	cmd := exec.Command("systemctl", "disable", name)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, string(output))
	}
	return nil
}

// DaemonReload runs systemctl daemon-reload to reload systemd manager configuration.
// The caller must have root privileges.
func DaemonReload() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("must be run as root to reload systemd (use sudo)")
	}

	cmd := exec.Command("systemctl", "daemon-reload")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, string(output))
	}
	return nil
}

// PromptRestart checks if the runic-agent systemd service is installed, prompts
// the user to restart it, and handles the restart if the user agrees. This
// consolidates the duplicated restart-prompt logic that previously appeared
// in both the setup wizard and config-mode paths.
func PromptRestart() {
	if !IsServiceInstalled() {
		fmt.Println("\nNote: runic-agent systemd service is not installed.")
		fmt.Println("To apply changes, restart the agent manually.")
		return
	}

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
		if err := RestartService("runic-agent"); err != nil {
			fmt.Printf("Failed to restart service: %v\n", err)
			fmt.Println("Restart manually with: sudo systemctl restart runic-agent")
		} else {
			fmt.Println("Service restarted successfully.")
		}
	} else {
		fmt.Println("\nTo apply changes, restart the service with: sudo systemctl restart runic-agent")
	}
}
