// Package firewall provides shared firewall rule dumping and restoration utilities.
package firewall

import (
	"context"
	"fmt"

	"runic/internal/common/log"
)

// CommandRunner is the interface for executing shell commands.
type CommandRunner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

// DumpRules dumps the current firewall rules, trying iptables-save first
// and falling back to nft list ruleset if iptables-save is unavailable.
func DumpRules(ctx context.Context, runner CommandRunner) (string, error) {
	out, err := runner.Run(ctx, "iptables-save")
	if err == nil {
		return string(out), nil
	}
	log.Info("iptables-save unavailable, trying nft list ruleset", "error", err)
	out, err = runner.Run(ctx, "nft", "list", "ruleset")
	if err != nil {
		return "", fmt.Errorf("firewall dump failed (tried iptables-save and nft list ruleset): %w", err)
	}
	return string(out), nil
}
