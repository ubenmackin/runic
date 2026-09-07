package apply

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"runic/internal/agent/firewall"
	"runic/internal/common/log"
)

func revertRules(backup string) error {
	// If the in-memory backup is empty, try reading the persistent backup.
	if strings.TrimSpace(backup) == "" {
		var err error
		backup, err = readPersistedBackup()
		if err != nil {
			return fmt.Errorf("read persisted backup: %w", err)
		}
		if strings.TrimSpace(backup) == "" {
			return fmt.Errorf("no backup available to revert (in-memory empty and no persisted backup)")
		}
		log.Info("Using persisted backup for revert", "path", LocalBackupPath)
	}

	tmpPath, err := writeTempFile("runic-revert-*.rules", backup)
	if err != nil {
		return fmt.Errorf("write backup: %w", err)
	}

	defer func() {
		if err := os.Remove(tmpPath); err != nil {
			log.Warn("Failed to remove temp file", "path", tmpPath, "error", err)
		}
	}()

	// Use a bounded context so watchdog cancellation does not kill the restore.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if IsNftFormat(backup) {
		cmd := exec.CommandContext(ctx, "nft", "-f", tmpPath)
		output, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("nft -f revert: %s: %w", string(output), err)
		}
		return nil
	}

	cmd := exec.CommandContext(ctx, "iptables-restore", "--noflush", tmpPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("iptables-restore revert: %s: %w", string(output), err)
	}

	return nil
}

func dumpCurrentRules() (string, error) {
	ctx := context.Background()
	runner := &firewall.RealCommandRunner{}
	return firewall.DumpRules(ctx, runner)
}

// persistBackup writes the backup content to a persistent file so crash
// recovery can still restore rules.
func persistBackup(content string) error {
	dir := filepath.Dir(LocalBackupPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create backup dir: %w", err)
	}
	if err := os.WriteFile(LocalBackupPath, []byte(content), 0600); err != nil {
		return fmt.Errorf("write backup: %w", err)
	}
	log.Info("Backup persisted for crash recovery", "path", LocalBackupPath)
	return nil
}

// readPersistedBackup reads the backup file from disk; returns empty string
// and nil error if no backup exists.
func readPersistedBackup() (string, error) {
	data, err := os.ReadFile(LocalBackupPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", fmt.Errorf("read persisted backup: %w", err)
	}
	return string(data), nil
}

// scheduleRevert starts an auto-revert timer. If the revert fires before
// the returned CancelFunc is called, it restores the previous rules.
// Uses context.WithCancel so cancellation is immediate and the timer
// goroutine exits without executing.
func scheduleRevert(backup string, delay time.Duration, controlPlaneURL, token, version string) context.CancelFunc {
	revertCtx, cancel := context.WithCancel(context.Background())

	go func() {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-revertCtx.Done():
			return
		case <-timer.C:
			log.Warn("Auto-revert triggered, restoring previous rules", "delay", delay)
			if err := revertRules(backup); err != nil {
				log.Error("Auto-revert failed", "error", err)
			} else {
				log.Info("Rules reverted successfully")
			}
		}
	}()

	return cancel
}

// This is done before destroying ipsets to release references to them.
// The order is: flush rules (-F) first, then delete custom chains (-X).
// Falls back to nft flush ruleset when iptables is unavailable.
func flushIPTables(ctx context.Context) error {
	// Check if iptables is available; if not, fall back to nft.
	if _, err := exec.LookPath("iptables"); err != nil {
		log.Info("iptables not found, using nft flush ruleset")
		flushCtx := context.WithoutCancel(ctx)
		cmd := exec.CommandContext(flushCtx, "nft", "flush", "ruleset")
		output, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("nft flush ruleset: %s: %w", string(output), err)
		}
		log.Info("Flushed nftables ruleset")
		return nil
	}

	cmd := exec.CommandContext(ctx, "iptables", "-t", "filter", "-F")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("flush iptables filter: %w", err)
	}

	delCmd := exec.CommandContext(ctx, "iptables", "-t", "filter", "-X")
	if err := delCmd.Run(); err != nil {
		log.Warn("Failed to delete custom filter chains, continuing", "error", err)
	}

	natCmd := exec.CommandContext(ctx, "iptables", "-t", "nat", "-F")
	if err := natCmd.Run(); err != nil {
		log.Warn("Failed to flush NAT table, continuing", "error", err)
	}

	natDelCmd := exec.CommandContext(ctx, "iptables", "-t", "nat", "-X")
	if err := natDelCmd.Run(); err != nil {
		log.Warn("Failed to delete custom NAT chains, continuing", "error", err)
	}

	log.Info("Flushed iptables rules and deleted custom chains to release ipset references")
	return nil
}
