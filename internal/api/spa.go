package api

import (
	"bytes"
	"io/fs"
	"net/http"
	"path/filepath"
	"strings"

	"golang.org/x/net/html"
)

// isInlineScript returns true if the node is a <script> tag without a src attribute.
func isInlineScript(n *html.Node) bool {
	if n.Type != html.ElementNode || n.Data != "script" {
		return false
	}
	for _, a := range n.Attr {
		if a.Key == "src" {
			return false
		}
	}
	return true
}

// hasNonce returns true if the node already has a nonce attribute.
func hasNonce(n *html.Node) bool {
	for _, a := range n.Attr {
		if a.Key == "nonce" {
			return true
		}
	}
	return false
}

// InjectNonceIntoHTML injects a CSP nonce into all inline <script> tags (tags without a src attribute).
// It uses proper HTML parsing to handle all tag variants: <script>, <script async>, <script defer>,
// <SCRIPT>, <script type="module">, etc. External scripts (with src) are left untouched.
func InjectNonceIntoHTML(subFS fs.FS, path string, nonce string) ([]byte, error) {
	content, err := fs.ReadFile(subFS, path)
	if err != nil {
		return nil, err
	}

	doc, err := html.Parse(bytes.NewReader(content))
	if err != nil {
		return nil, err
	}

	injectNonce(doc, nonce)

	var buf bytes.Buffer
	if err := html.Render(&buf, doc); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// injectNonce recursively walks the HTML node tree and adds the nonce attribute
// to all inline <script> elements that don't already have one.
func injectNonce(n *html.Node, nonce string) {
	if isInlineScript(n) && !hasNonce(n) {
		n.Attr = append(n.Attr, html.Attribute{Key: "nonce", Val: nonce})
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		injectNonce(c, nonce)
	}
}

// ServeHTMLWithNonce serves an HTML file with a CSP nonce injected. This function should be used instead of directly serving HTML files when nonce-based CSP is enabled.
func ServeHTMLWithNonce(w http.ResponseWriter, r *http.Request, subFS fs.FS, path string, nonce string) error {
	content, err := InjectNonceIntoHTML(subFS, path, nonce)
	if err != nil {
		return err
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	_, err = w.Write(content)
	return err
}

// SetCacheHeaders sets appropriate Cache-Control headers based on file type.
//   - HTML files: no-cache (must revalidate to get latest version)
//   - Assets with content hashes (*.js, *.css in assets/): 1 year cache (immutable)
//   - Other static files: 1 hour cache
func SetCacheHeaders(w http.ResponseWriter, path string) {
	ext := filepath.Ext(path)
	fileName := filepath.Base(path)

	// HTML files should never be cached (always fetch latest)
	if ext == ".html" {
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")
		return
	}

	// Assets with content hashes (Vite generates files like index-Abc123.js)
	// These are immutable - the hash changes when content changes
	if strings.HasPrefix(path, "assets/") && (ext == ".js" || ext == ".css") {
		// Check if filename contains a hash pattern (hyphen followed by alphanumeric)
		// Vite pattern: name-hash.ext
		if strings.Contains(fileName, "-") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
			return
		}
	}

	w.Header().Set("Cache-Control", "public, max-age=3600")
}
