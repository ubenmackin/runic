package api

import (
	"io/fs"
	"net/http"
	"strings"
)

// InjectNonceIntoHTML reads an HTML file from the filesystem and injects the CSP nonce
// into all inline script tags. This is necessary for nonce-based CSP to work correctly.
func InjectNonceIntoHTML(subFS fs.FS, path string, nonce string) ([]byte, error) {
	// Read the HTML file
	content, err := fs.ReadFile(subFS, path)
	if err != nil {
		return nil, err
	}

	// Convert to string for manipulation
	html := string(content)

	// Inject nonce into inline script tags
	// Replace <script> with <script nonce="...">
	// We need to be careful not to modify external script tags
	html = strings.ReplaceAll(html, "<script>", `<script nonce="`+nonce+`">`)

	return []byte(html), nil
}

// ServeHTMLWithNonce serves an HTML file with the CSP nonce injected.
// This function should be used instead of directly serving HTML files when nonce-based CSP is enabled.
func ServeHTMLWithNonce(w http.ResponseWriter, r *http.Request, subFS fs.FS, path string, nonce string) error {
	content, err := InjectNonceIntoHTML(subFS, path, nonce)
	if err != nil {
		return err
	}

	// Set content type
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// Write the modified HTML
	_, err = w.Write(content)
	return err
}

// HTMLWithNonceHandler creates a handler that serves HTML files with nonce injection.
// This is used for serving the SPA with CSP nonce support.
func HTMLWithNonceHandler(subFS fs.FS, path string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get nonce from context
		nonce, ok := GetCSPNonce(r.Context())
		if !ok {
			// Fallback: serve without nonce (shouldn't happen if CSP middleware is applied)
			http.ServeFileFS(w, r, subFS, path)
			return
		}

		// Serve with nonce injection
		if err := ServeHTMLWithNonce(w, r, subFS, path, nonce); err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}
	}
}
