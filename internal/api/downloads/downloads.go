package downloads

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// Handler returns an http.HandlerFunc that serves static files from the downloads directory.
// It extracts the filename from the URL path /downloads/{filename} and serves the file
// with appropriate security checks to prevent directory traversal attacks.
func Handler(downloadsDir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract filename from URL path
		// The route is expected to be /downloads/{filename}
		filename := r.URL.Path
		// Remove the "/downloads/" prefix if present
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
		// Reject any filename containing ".." or "/"
		if strings.Contains(filename, "..") || strings.Contains(filename, "/") {
			http.Error(w, "invalid filename", http.StatusBadRequest)
			return
		}

		// Construct the full file path using filepath.Join for cross-platform compatibility
		filePath := filepath.Join(downloadsDir, filename)

		// Check if the file exists
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

		// Serve the file with proper headers
		http.ServeFile(w, r, filePath)
	}
}
