package downloads

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// =============================================================================
// Test isAllowedFile
// =============================================================================

func TestIsAllowedFile(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		want     bool
	}{
		{
			name:     "amd64 allowed",
			filename: "runic-agent-amd64",
			want:     true,
		},
		{
			name:     "arm allowed",
			filename: "runic-agent-arm",
			want:     true,
		},
		{
			name:     "arm64 allowed",
			filename: "runic-agent-arm64",
			want:     true,
		},
		{
			name:     "armv6 allowed",
			filename: "runic-agent-armv6",
			want:     true,
		},
		{
			name:     "service file allowed",
			filename: "runic-agent.service",
			want:     true,
		},
		{
			name:     "disallowed filename not in whitelist",
			filename: "malware.exe",
			want:     false,
		},
		{
			name:     "empty string not allowed",
			filename: "",
			want:     false,
		},
		{
			name:     "random text not allowed",
			filename: "random-file",
			want:     false,
		},
		{
			name:     "similar but different not allowed",
			filename: "runic-agent-amd64-old",
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isAllowedFile(tt.filename)
			if got != tt.want {
				t.Errorf("isAllowedFile(%q) = %v, want %v", tt.filename, got, tt.want)
			}
		})
	}
}

// =============================================================================
// Test Handler Security Cases
// =============================================================================

func TestHandler(t *testing.T) {
	// Create a temporary directory for downloads
	tempDir, err := os.MkdirTemp("", "downloads-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	handler := Handler(tempDir)

	tests := []struct {
		name           string
		path           string
		setupFile      func(dir string) error
		wantStatusCode int
	}{
		{
			name:           "empty filename returns 400",
			path:           "/downloads/",
			setupFile:      nil,
			wantStatusCode: http.StatusBadRequest,
		},
		{
			name:           "just downloads prefix returns 400",
			path:           "/downloads",
			setupFile:      nil,
			wantStatusCode: http.StatusBadRequest,
		},
		{
			name:           "directory traversal with double dots returns 400",
			path:           "/downloads/../../etc/passwd",
			setupFile:      nil,
			wantStatusCode: http.StatusBadRequest,
		},
		{
			name:           "directory traversal with .. in middle returns 400",
			path:           "/downloads/..etc/passwd",
			setupFile:      nil,
			wantStatusCode: http.StatusBadRequest,
		},
		{
			name:           "forward slash in filename returns 400",
			path:           "/downloads/path/to/file",
			setupFile:      nil,
			wantStatusCode: http.StatusBadRequest,
		},
		{
			name:           "forward slash alone returns 400",
			path:           "/downloads/",
			setupFile:      nil,
			wantStatusCode: http.StatusBadRequest,
		},
		{
			name:           "disallowed filename returns 404",
			path:           "/downloads/malware.exe",
			setupFile:      nil,
			wantStatusCode: http.StatusNotFound,
		},
		{
			name:           "random filename returns 404",
			path:           "/downloads/random-file.txt",
			setupFile:      nil,
			wantStatusCode: http.StatusNotFound,
		},
		{
			name:           "allowed file but does not exist returns 404",
			path:           "/downloads/runic-agent-amd64",
			setupFile:      nil,
			wantStatusCode: http.StatusNotFound,
		},
		{
			name: "allowed file exists returns 200",
			path: "/downloads/runic-agent-amd64",
			setupFile: func(dir string) error {
				f, err := os.Create(filepath.Join(dir, "runic-agent-amd64"))
				if err != nil {
					return err
				}
				f.WriteString("mock binary content")
				f.Close()
				return nil
			},
			wantStatusCode: http.StatusOK,
		},
		{
			name: "service file exists returns 200",
			path: "/downloads/runic-agent.service",
			setupFile: func(dir string) error {
				f, err := os.Create(filepath.Join(dir, "runic-agent.service"))
				if err != nil {
					return err
				}
				f.WriteString("[Unit]")
				f.Close()
				return nil
			},
			wantStatusCode: http.StatusOK,
		},
		{
			name: "directory with allowed name returns 400",
			path: "/downloads/runic-agent-amd64",
			setupFile: func(dir string) error {
				return os.Mkdir(filepath.Join(dir, "runic-agent-amd64"), 0755)
			},
			wantStatusCode: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup file if needed
			if tt.setupFile != nil {
				if err := tt.setupFile(tempDir); err != nil {
					t.Fatalf("failed to setup file: %v", err)
				}
			}

			req := httptest.NewRequest("GET", tt.path, nil)
			w := httptest.NewRecorder()

			handler(w, req)

			if w.Code != tt.wantStatusCode {
				t.Errorf("expected status %d, got %d: %s", tt.wantStatusCode, w.Code, w.Body.String())
			}

			// Cleanup files after each test
			files, err := os.ReadDir(tempDir)
			if err != nil {
				t.Logf("warning: failed to read temp dir: %v", err)
			}
			for _, f := range files {
				os.RemoveAll(filepath.Join(tempDir, f.Name()))
			}
		})
	}
}

// =============================================================================
// Test Handler with All Allowed Files
// =============================================================================

func TestHandlerAllAllowedFiles(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "downloads-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create all allowed files
	allowedFileNames := []string{
		"runic-agent-amd64",
		"runic-agent-arm",
		"runic-agent-arm64",
		"runic-agent-armv6",
		"runic-agent.service",
	}

	for _, name := range allowedFileNames {
		f, err := os.Create(filepath.Join(tempDir, name))
		if err != nil {
			t.Fatalf("failed to create file %s: %v", name, err)
		}
		f.WriteString("test content")
		f.Close()
	}

	handler := Handler(tempDir)

	for _, name := range allowedFileNames {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/downloads/"+name, nil)
			w := httptest.NewRecorder()

			handler(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("expected status %d, got %d: %s", http.StatusOK, w.Code, w.Body.String())
			}
		})
	}
}
