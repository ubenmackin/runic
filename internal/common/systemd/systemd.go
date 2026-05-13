// Package systemd provides utilities for detecting and interacting with systemd services.
package systemd

import (
	"fmt"
	"os"
	"os/exec"
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
