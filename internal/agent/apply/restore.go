package apply

import (
	"context"
	"fmt"
	"os"
	"os/exec"
)

// restoreFromFile applies firewall rules from a file using the appropriate
// backend based on the content format.
func restoreFromFile(ctx context.Context, path, content string) error {
	if IsNftFormat(content) {
		cmd := exec.CommandContext(ctx, "nft", "-f", path)
		output, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("nft -f restore failed: %s: %w", string(output), err)
		}
		return nil
	}

	cmd := exec.CommandContext(ctx, "iptables-restore", "--noflush", path)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("iptables-restore failed: %s: %w", string(output), err)
	}
	return nil
}

// writeTempFile creates a temporary file with the given pattern, writes content to it,
// then closes it. Returns the path to the temp file. The caller is responsible for
// removing the file (e.g. defer os.Remove(path)).
func writeTempFile(pattern, content string) (string, error) {
	tmp, err := os.CreateTemp("", pattern)
	if err != nil {
		return "", fmt.Errorf("create temp file: %w", err)
	}
	path := tmp.Name()
	if _, err := tmp.WriteString(content); err != nil {
		_ = tmp.Close()
		_ = os.Remove(path)
		return "", fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(path)
		return "", fmt.Errorf("close temp file: %w", err)
	}
	return path, nil
}
