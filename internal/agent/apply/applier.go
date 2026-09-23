// Package apply provides the application applier.
package apply

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"runic/internal/common/constants"
	"runic/internal/common/log"
	"runic/internal/engine"
	"runic/internal/models"
)

const (
	// LocalBackupPath is the persistent path where pre-apply firewall rules
	// are written so that a crash mid-apply does not lose the backup.
	LocalBackupPath = "/var/backups/runic-agent/pre-apply-backup.rules"
	// CachedBundlePath is the persistent path where the last applied bundle
	// is cached for apply-on-boot.
	CachedBundlePath = "/var/cache/runic-agent/cached-bundle.rules"
	// StartupBackupPath is the persistent path where the agent's boot-time
	// iptables backup is stored (taken once at startup before any bundle
	// apply). It is distinct from LocalBackupPath, which is the
	// pre-apply crash-recovery backup rewritten on every ApplyBundle.
	StartupBackupPath = "/var/backups/runic-agent/iptables-backup.rules"
	// Legacy persistent paths from before the /var migration. Installs
	// predating the move wrote these files under /etc/runic-agent; readers
	// fall back to them when the new path is missing and migrate the
	// content forward so crash-recovery state is not orphaned on upgrade.
	LegacyCachedBundlePath  = "/etc/runic-agent/cached-bundle.rules"
	LegacyLocalBackupPath   = "/etc/runic-agent/pre-apply-backup.rules"
	LegacyStartupBackupPath = "/etc/runic-agent/iptables-backup.rules"
	// LegacyMigrationLog is the single log message used for every legacy
	// forward-migration so callers do not pass free-form string literals.
	LegacyMigrationLog = "Migrated legacy file"
)

// smokeBadRequestError reports a 4xx from the heartbeat smoke test. Any 4xx
// (400 payload rejected, 401 expired/ invalid token, 403 forbidden, 405, 413,
// 429, etc.) proves OUTPUT connectivity: the packet left the host, reached
// the control plane, and drew an application-layer response. Reverting on a
// 4xx would discard good rules due to a credential or application issue, so
// the caller logs it without reverting. Revert is reserved for network
// errors, timeouts, and 5xx/unexpected statuses where OUTPUT may genuinely be
// broken.
type smokeBadRequestError struct {
	status int
}

func (e *smokeBadRequestError) Error() string {
	return fmt.Sprintf("smoke test returned status %d", e.status)
}

// IsNftFormat returns true when the content looks like nftables ruleset
// (starts with "table" rather than containing "*filter").
func IsNftFormat(content string) bool {
	return strings.Contains(content, "table ") && !strings.Contains(content, "*filter")
}

// ApplyBundle uses the confirmFunc callback to notify the control plane after successful apply.
func ApplyBundle(ctx context.Context, bundle models.BundleResponse, hmacKey, controlPlaneURL, token, version string, confirmFunc func(context.Context, string) error) error {
	log.Info("Received bundle version, verifying HMAC", "version", bundle.Version)

	if !engine.VerifyWithVersion(bundle.Rules, hmacKey, bundle.HMAC, bundle.VersionNumber) {
		return fmt.Errorf("HMAC verification failed — refusing to apply bundle %s", bundle.Version)
	}

	if err := validateRules(bundle.Rules); err != nil {
		return fmt.Errorf("rule validation failed: %w", err)
	}

	backup, err := dumpCurrentRules()
	if err != nil {
		return fmt.Errorf("could not dump current rules for backup: %w", err)
	}

	// Persist backup to disk BEFORE any state modification so crash mid-apply
	// does not lose the ability to restore.
	if err := persistBackup(backup); err != nil {
		log.Warn("Failed to persist backup to disk", "error", err)
	}

	revertCancel := scheduleRevert(backup, constants.AutoRevertDelay, controlPlaneURL, token, version)

	// Write bundle to temp file BEFORE flushing so the restore payload is ready
	// and the unprotected window between flush and restore is minimized.
	tmpPath, err := writeTempFile("runic-bundle-*.rules", stripIpsetSection(bundle.Rules))
	if err != nil {
		revertCancel()
		return fmt.Errorf("write bundle: %w", err)
	}
	defer func() {
		if err := os.Remove(tmpPath); err != nil && !os.IsNotExist(err) {
			log.Warn("Failed to remove temp file", "path", tmpPath, "error", err)
		}
	}()

	// Flush iptables FIRST to release ipset references before destroying ipsets
	// This prevents "ipset in use" errors during ipset recreate
	if err := flushIPTables(ctx); err != nil {
		revertCancel()
		return fmt.Errorf("flush firewall: %w", err)
	}

	// Apply ipset definitions if present (after iptables flushed - can now destroy safely)
	if strings.Contains(bundle.Rules, "# --- Ipset Definitions ---") {
		if err := applyIpsets(ctx, bundle.Rules); err != nil {
			revertCancel()
			if revertErr := revertRules(backup); revertErr != nil {
				log.Error("Revert failed", "error", revertErr)
			}
			return fmt.Errorf("ipset apply failed: %w", err)
		}
	}

	// Use detached context for the critical restore operation so that a watchdog
	// or parent cancellation does not kill iptables-restore mid-flight, which
	// could leave the system in a broken state.
	// --noflush flag ensures atomic replacement without an intermediate empty state.
	restoreCtx := context.WithoutCancel(ctx)
	if err := restoreFromFile(restoreCtx, tmpPath, stripIpsetSection(bundle.Rules)); err != nil {
		revertCancel()
		return fmt.Errorf("rule restore failed: %w", err)
	}

	if hasDocker() {
		log.Info("Restarting Docker to reset internal chains")
		if err := restartDocker(ctx); err != nil {
			log.Warn("Docker restart failed (rules still applied)", "error", err)
		}
	}

	if err := smokeTest(ctx, controlPlaneURL, token, version); err != nil {
		var badReq *smokeBadRequestError
		if errors.As(err, &badReq) {
			// 4xx means the control plane answered at the application layer
			// (payload rejected, expired token, forbidden, etc.), which proves
			// OUTPUT connectivity. Log and continue without reverting.
			log.Warn("Smoke test returned client error (application-layer response proves OUTPUT connectivity, not reverting)", "status", badReq.status, "error", err)
		} else {
			log.Warn("Smoke test failed after apply, reverting", "error", err)
			if revertErr := revertRules(backup); revertErr != nil {
				log.Error("Revert failed", "error", revertErr)
			} else {
				log.Info("Rules reverted successfully")
			}
			revertCancel()
			return fmt.Errorf("smoke test failed, reverted: %w", err)
		}
	}

	revertCancel()

	// Remove persisted backup on success so a subsequent crash does not restore
	// stale rules. Also remove the legacy duplicate so crash-recovery state
	// does not survive success under /etc/runic-agent.
	if err := os.Remove(LocalBackupPath); err != nil && !os.IsNotExist(err) {
		log.Warn("Failed to remove persisted backup", "error", err)
	}
	removeLegacyFile(LegacyLocalBackupPath)

	if confirmFunc != nil {
		confirmCtx, confirmCancel := context.WithTimeout(context.Background(), 10*time.Second)
		if err := confirmFunc(confirmCtx, bundle.Version); err != nil {
			log.Warn("Failed to confirm apply to control plane", "error", err)
		}
		confirmCancel()
	}

	if err := CacheBundle(bundle.Rules); err != nil {
		log.Warn("Failed to cache bundle", "error", err)
	}

	log.Info("Applied bundle successfully", "version", bundle.Version)
	return nil
}

func CacheBundle(rules string) error {
	return cacheBundle(rules, CachedBundlePath, LegacyCachedBundlePath)
}

// cacheBundle is the injectable CacheBundle implementation so tests can
// exercise the production path (write + legacy cleanup) with temp-dir
// overrides without touching /var/...; production callers pass the
// CachedBundlePath/LegacyCachedBundlePath defaults via CacheBundle.
func cacheBundle(rules, cachePath, legacyPath string) error {
	if err := CacheBundleToPath(rules, cachePath); err != nil {
		return err
	}
	// Best-effort legacy cleanup so a migrated install does not leave a
	// stale duplicate under /etc/runic-agent.
	removeLegacyFile(legacyPath)
	return nil
}

// CacheBundleToPath writes the bundle cache to an explicit path with 0600;
// the caller passes CachedBundlePath. The write is atomic (temp file in the
// same directory + rename) so a crash mid-write never leaves a partial
// cache that boots as corrupt.
func CacheBundleToPath(rules, path string) error {
	if err := WriteFileAtomic(path, []byte(rules), 0600); err != nil {
		return fmt.Errorf("write cache: %w", err)
	}

	log.Info("Bundle cached for apply-on-boot", "path", path)
	return nil
}

// WriteFileAtomic writes data to path atomically via a temp file in the
// same directory followed by rename, so a crash mid-write leaves either
// the old content or the new content but never a partial file. It is the
// shared helper for all overwriting persistent writes (bundle cache,
// pre-apply backup, boot backup); migration writes that must not clobber a
// freshly written primary keep using WriteFileExclusive (O_EXCL).
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create dir for atomic write %s: %w", path, err)
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*.rules")
	if err != nil {
		return fmt.Errorf("create temp file for atomic write %s: %w", path, err)
	}
	tmpName := tmp.Name()
	defer func() {
		_ = os.Remove(tmpName)
	}()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp file for atomic write %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp file for atomic write %s: %w", path, err)
	}
	if err := os.Chmod(tmpName, perm); err != nil {
		return fmt.Errorf("chmod temp file for atomic write %s: %w", path, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename temp file for atomic write %s: %w", path, err)
	}
	return nil
}

// removeLegacyFile best-effort removes a legacy /etc/runic-agent file after
// its content has been migrated forward. Missing files are skipped
// silently; other failures are logged and the caller continues.
func removeLegacyFile(legacyPath string) {
	if err := os.Remove(legacyPath); err != nil && !os.IsNotExist(err) {
		log.Warn("Failed to remove legacy file", "path", legacyPath, "error", err)
	}
}

// WriteFileExclusive creates newPath with the given content, failing with
// os.IsExist when the file already exists. The O_EXCL flag closes the
// TOCTOU window between the existence check and the write so a concurrent
// migration cannot silently overwrite a freshly written primary file.
func WriteFileExclusive(newPath string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(newPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(newPath)
		return fmt.Errorf("write exclusive file %s: %w", newPath, err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(newPath)
		return fmt.Errorf("close exclusive file %s: %w", newPath, err)
	}
	return nil
}

// IsCanonicalPath reports whether configured equals the canonical default
// path after cleaning. Cleaning handles trailing slashes and dot segments
// while still respecting test overrides: custom temp-dir paths never equal
// the /var defaults so legacy fallback stays disabled for them. It is the
// single shared path-equality helper for the apply and core packages so the
// canonical-path check cannot drift between isDefaultPersistentPath and the
// agent's backup-path guard.
func IsCanonicalPath(configured, canonical string) bool {
	return filepath.Clean(configured) == filepath.Clean(canonical)
}

// isDefaultPersistentPath reports whether newPath is one of the canonical
// /var persistent files. Legacy fallback is only allowed for these
// defaults; test overrides with custom temp-dir paths never fall back to
// /etc/runic-agent so tests stay hermetic.
func isDefaultPersistentPath(newPath string) bool {
	for _, canonical := range []string{CachedBundlePath, LocalBackupPath, StartupBackupPath} {
		if IsCanonicalPath(newPath, canonical) {
			return true
		}
	}
	return false
}

// migrateBytes is the shared helper for legacy forward-migration writes.
// It creates the parent directory, writes data with WriteFileExclusive
// (O_EXCL, so a concurrent agent-created primary is never truncated),
// logs the migration, and removes the legacy file. Mkdir and non-Exist
// write failures are logged here so MigrateLegacyFile and
// ReadFileWithFallback cannot drift; Exist is returned silently so callers
// can treat a raced primary as a skip. It returns nil on success.
func migrateBytes(oldPath, newPath string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(newPath), 0700); err != nil {
		log.Warn("Failed to create dir for legacy migration", "path", newPath, "error", err)
		return err
	}
	if err := WriteFileExclusive(newPath, data, 0600); err != nil {
		if !os.IsExist(err) {
			log.Warn("Failed to migrate legacy file", "old", oldPath, "new", newPath, "error", err)
		}
		return err
	}
	log.Info(LegacyMigrationLog, "old", oldPath, "new", newPath)
	// Copies forward then removes the legacy file so a stale duplicate does
	// not remain under /etc/runic-agent. Best-effort: log on failure.
	removeLegacyFile(oldPath)
	return nil
}

// MigrateLegacyFiles copies legacy /etc/runic-agent persistent files to
// their /var successors when the new path is missing. It is best-effort:
// missing legacy files are skipped silently and copy failures are logged.
func MigrateLegacyFiles() {
	_ = MigrateLegacyFile(LegacyCachedBundlePath, CachedBundlePath)
	_ = MigrateLegacyFile(LegacyLocalBackupPath, LocalBackupPath)
	_ = MigrateLegacyFile(LegacyStartupBackupPath, StartupBackupPath)
}

// MigrateLegacyFile copies a single legacy /etc/runic-agent file to its /var
// successor when the new path is missing. It is best-effort: missing legacy
// files are skipped silently and copy failures are logged. It returns nil on
// success, an os.IsExist error when the new path already exists, a
// syscall.EISDIR-wrapped error when the new path is a directory (distinct
// from Exists so callers do not conflate a directory with a present file),
// an os.IsNotExist error when the legacy file is missing, or the underlying
// failure otherwise.
func MigrateLegacyFile(oldPath, newPath string) error {
	if fi, err := os.Stat(newPath); err == nil {
		if fi.IsDir() {
			log.Warn("Skipping legacy migration, new path is a directory", "new", newPath)
			return &os.PathError{Op: "migrate", Path: newPath, Err: syscall.EISDIR}
		}
		return os.ErrExist
	} else if !os.IsNotExist(err) {
		log.Warn("Failed to stat new path for legacy migration, skipping", "new", newPath, "error", err)
		return err
	}
	data, err := os.ReadFile(oldPath)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Warn("Failed to read legacy file for migration", "old", oldPath, "error", err)
		}
		return err
	}
	if err := migrateBytes(oldPath, newPath, data); err != nil {
		return err
	}
	return nil
}

// ReadFileWithFallback reads newPath, falling back to the legacy
// /etc/runic-agent path when the new path is missing and newPath is one of
// the canonical /var persistent files. Custom test-override paths never
// fall back so tests stay hermetic. On a fallback hit it best-effort
// migrates the content forward to newPath so the next read hits the primary
// location, then removes the legacy file so a stale duplicate does not
// remain. Permission errors on either path are returned as-is and never
// masked as NotExist.
func ReadFileWithFallback(newPath, legacyPath string) ([]byte, error) {
	data, err := os.ReadFile(newPath)
	if err == nil {
		return data, nil
	}
	if !os.IsNotExist(err) {
		return nil, err
	}
	if !isDefaultPersistentPath(newPath) {
		return nil, err
	}
	legacyData, legacyErr := os.ReadFile(legacyPath)
	if legacyErr != nil {
		if os.IsNotExist(legacyErr) {
			return nil, err
		}
		return nil, legacyErr
	}
	// Best-effort forward migration so the next read hits the primary
	// location. migrateBytes logs mkdir and non-Exist write failures and
	// silently returns Exist on a raced primary; the error is ignored here
	// because the legacy content is returned regardless.
	_ = migrateBytes(legacyPath, newPath, legacyData)
	return legacyData, nil
}

func smokeTest(ctx context.Context, controlPlaneURL, token, version string) error {
	client := &http.Client{
		Timeout: constants.SmokeTestTimeout,
	}

	url := fmt.Sprintf("%s/api/v1/agent/heartbeat", controlPlaneURL)

	// POST with an explicit empty JSON body: GET with a body is unusual and
	// some intermediaries drop it, while an empty body without Content-Type
	// risks a 400 from strict JSON handlers. The server keeps the GET route
	// for compatibility.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader("{}"))
	if err != nil {
		return fmt.Errorf("create smoke test request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", "runic-agent/"+version)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("smoke test request failed: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		if err := resp.Body.Close(); err != nil {
			log.Warn("Failed to close response body", "error", err)
		}
	}()

	if resp.StatusCode >= http.StatusOK && resp.StatusCode < http.StatusMultipleChoices {
		return nil
	}
	if resp.StatusCode >= http.StatusBadRequest && resp.StatusCode < http.StatusInternalServerError {
		return &smokeBadRequestError{status: resp.StatusCode}
	}
	return fmt.Errorf("smoke test returned status %d", resp.StatusCode)
}
