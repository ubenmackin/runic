// Package downloads provides downloads functionality.
package downloads

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"runic/internal/common/arch"
)

// RequiredAgentBinaries lists the per-arch agent binaries that a server
// deploy must rebuild and stage into downloadsDir before an update fan-out
// may honestly report sent. A stale downloads dir (for example after a
// version bump without re-staging) makes agents 404 on download while the
// server already reported sent, which is the silent failure behind bulk
// Update All downloading nothing. Call MissingBinaries before fanning out
// and report failed_validation instead of sent when any entry is absent.
// Canonical set lives in arch.UpdateArchs; this var is derived from it so
// the freshness check can never drift from the agent updater.
var RequiredAgentBinaries = arch.RequiredAgentBinaries()

func isAllowedFile(filename string) bool {
	return arch.IsServableFile(filename)
}

// MissingBinaries reports which of RequiredAgentBinaries are absent from
// downloadsDir (missing file or directory in its place). It returns nil
// when every required binary is staged and ready to serve.
func MissingBinaries(downloadsDir string) []string {
	if downloadsDir == "" {
		return append([]string(nil), RequiredAgentBinaries...)
	}
	var missing []string
	for _, name := range RequiredAgentBinaries {
		info, err := os.Stat(filepath.Join(downloadsDir, name))
		if err != nil || info.IsDir() {
			missing = append(missing, name)
		}
	}
	return missing
}

// Handler returns an HTTP handler for serving whitelisted download files.
// It extracts the filename from the URL path /downloads/{filename} and serves the file
// with appropriate security checks to prevent directory traversal attacks.
func Handler(downloadsDir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// The route is expected to be /downloads/{filename}
		filename := r.URL.Path
		if strings.HasPrefix(filename, "/downloads/") {
			filename = strings.TrimPrefix(filename, "/downloads/")
		} else if strings.HasPrefix(filename, "/downloads") {
			filename = strings.TrimPrefix(filename, "/downloads")
		}

		// Security: reject empty filename
		if filename == "" {
			http.Error(w, "filename is required", http.StatusBadRequest)
			return
		}

		// Security: prevent directory traversal attacks
		if strings.Contains(filename, "..") || strings.Contains(filename, "/") {
			http.Error(w, "invalid filename", http.StatusBadRequest)
			return
		}

		// Security: whitelist-based file validation
		if !isAllowedFile(filename) {
			http.Error(w, "file not found", http.StatusNotFound)
			return
		}

		filePath := filepath.Join(downloadsDir, filename)

		info, err := os.Stat(filePath)
		if err != nil {
			if os.IsNotExist(err) {
				http.Error(w, "file not found", http.StatusNotFound)
				return
			}
			http.Error(w, "failed to access file", http.StatusInternalServerError)
			return
		}

		// Security: ensure we're serving a file, not a directory
		if info.IsDir() {
			http.Error(w, "invalid filename", http.StatusBadRequest)
			return
		}

		http.ServeFile(w, r, filePath)
	}
}
