// Package systemd provides utilities for detecting and interacting with systemd services.
package systemd

import (
	"bufio"
	"context"
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

// runSystemctl is the shared helper for the four public service-management
// functions. It enforces the root-privilege requirement, executes
// `systemctl <verb> <noun>`, and surfaces a wrapped error including the
// combined stdout/stderr output on failure. The provided context is
// attached to the command so callers can apply timeouts and cancellation.
func runSystemctl(ctx context.Context, verb, noun string) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("must be run as root to %s service (use sudo)", verb)
	}

	var cmd *exec.Cmd
	if noun == "" {
		cmd = exec.CommandContext(ctx, "systemctl", verb)
	} else {
		cmd = exec.CommandContext(ctx, "systemctl", verb, noun)
	}
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, string(output))
	}
	return nil
}

// ctxOrBackground returns the first non-nil context in ctxs, or
// context.Background() if ctxs is empty. Used by the variadic-ctx wrappers
// below to keep the original positional signatures working while still
// letting new callers opt in to context propagation.
func ctxOrBackground(ctxs []context.Context) context.Context {
	for _, c := range ctxs {
		if c != nil {
			return c
		}
	}
	return context.Background()
}

// RestartService restarts the named systemd service.
// The caller must have root privileges. An optional context may be passed as
// the second argument to enable cancellation and timeouts.
func RestartService(name string, ctx ...context.Context) error {
	return runSystemctl(ctxOrBackground(ctx), "restart", name)
}

// StopService stops the named systemd service.
// The caller must have root privileges. An optional context may be passed as
// the second argument to enable cancellation and timeouts.
func StopService(name string, ctx ...context.Context) error {
	return runSystemctl(ctxOrBackground(ctx), "stop", name)
}

// DisableService disables the named systemd service so it no longer starts on
// boot. The caller must have root privileges. An optional context may be
// passed as the second argument to enable cancellation and timeouts.
func DisableService(name string, ctx ...context.Context) error {
	return runSystemctl(ctxOrBackground(ctx), "disable", name)
}

// DaemonReload runs systemctl daemon-reload to reload systemd manager
// configuration. The caller must have root privileges. An optional context
// may be passed as the only argument to enable cancellation and timeouts.
func DaemonReload(ctx ...context.Context) error {
	return runSystemctl(ctxOrBackground(ctx), "daemon-reload", "")
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
		// Use Background for the interactive restart prompt: there is no
		// upstream context to propagate, and the user expects the operation
		// to run to completion or surface its own error.
		if err := RestartService("runic-agent", context.Background()); err != nil {
			fmt.Printf("Failed to restart service: %v\n", err)
			fmt.Println("Restart manually with: sudo systemctl restart runic-agent")
		} else {
			fmt.Println("Service restarted successfully.")
		}
	} else {
		fmt.Println("\nTo apply changes, restart the service with: sudo systemctl restart runic-agent")
	}
}
