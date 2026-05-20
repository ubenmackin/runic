package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"runic/internal/api"
	"runic/internal/common/constants"
	runicdb "runic/internal/db"
	"runic/internal/store"
)

// TestValidateCertificate tests the validateCertificate function
func TestValidateCertificate(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		setupCert   func(certFile, keyFile *os.File) error
		wantErr     bool
		errContains string
	}{
		{
			name: "valid certificate and key",
			setupCert: func(certFile, keyFile *os.File) error {
				certPEM, keyPEM, err := generateTestCertAndKey()
				if err != nil {
					return err
				}
				if _, err := certFile.Write(certPEM); err != nil {
					return err
				}
				if _, err := keyFile.Write(keyPEM); err != nil {
					return err
				}
				return nil
			},
			wantErr: false,
		},
		{
			name: "missing certificate file",
			setupCert: func(certFile, keyFile *os.File) error {
				// Delete the cert file to simulate it not existing
				os.Remove(certFile.Name())
				// Write valid key
				_, keyPEM, err := generateTestCertAndKey()
				if err != nil {
					return err
				}
				if _, err := keyFile.Write(keyPEM); err != nil {
					return err
				}
				return nil
			},
			wantErr:     true,
			errContains: "certificate file not found",
		},
		{
			name: "missing key file",
			setupCert: func(certFile, keyFile *os.File) error {
				// Delete the key file to simulate it not existing
				os.Remove(keyFile.Name())
				// Write valid cert
				certPEM, _, err := generateTestCertAndKey()
				if err != nil {
					return err
				}
				if _, err := certFile.Write(certPEM); err != nil {
					return err
				}
				return nil
			},
			wantErr:     true,
			errContains: "key file not found",
		},
		{
			name: "invalid PEM certificate - not CERTIFICATE type",
			setupCert: func(certFile, keyFile *os.File) error {
				// Write invalid cert PEM (wrong type)
				invalidCert := pem.EncodeToMemory(&pem.Block{
					Type:  "INVALID TYPE",
					Bytes: []byte("invalid"),
				})
				if _, err := certFile.Write(invalidCert); err != nil {
					return err
				}
				// Write valid key
				_, keyPEM, err := generateTestCertAndKey()
				if err != nil {
					return err
				}
				if _, err := keyFile.Write(keyPEM); err != nil {
					return err
				}
				return nil
			},
			wantErr:     true,
			errContains: "invalid PEM block type",
		},
		{
			name: "invalid PEM key - not PRIVATE KEY type",
			setupCert: func(certFile, keyFile *os.File) error {
				// Write valid cert
				certPEM, _, err := generateTestCertAndKey()
				if err != nil {
					return err
				}
				if _, err := certFile.Write(certPEM); err != nil {
					return err
				}
				// Write invalid key PEM (wrong type)
				invalidKey := pem.EncodeToMemory(&pem.Block{
					Type:  "INVALID KEY TYPE",
					Bytes: []byte("invalid"),
				})
				if _, err := keyFile.Write(invalidKey); err != nil {
					return err
				}
				return nil
			},
			wantErr:     true,
			errContains: "invalid key PEM block type",
		},
		{
			name: "invalid PEM certificate - no PEM block",
			setupCert: func(certFile, keyFile *os.File) error {
				// Write non-PEM data for cert
				if _, err := certFile.WriteString("not a valid PEM block"); err != nil {
					return err
				}
				// Write valid key
				_, keyPEM, err := generateTestCertAndKey()
				if err != nil {
					return err
				}
				if _, err := keyFile.Write(keyPEM); err != nil {
					return err
				}
				return nil
			},
			wantErr:     true,
			errContains: "failed to decode certificate PEM block",
		},
		{
			name: "invalid PEM key - no PEM block",
			setupCert: func(certFile, keyFile *os.File) error {
				// Write valid cert
				certPEM, _, err := generateTestCertAndKey()
				if err != nil {
					return err
				}
				if _, err := certFile.Write(certPEM); err != nil {
					return err
				}
				// Write non-PEM data for key
				if _, err := keyFile.WriteString("not a valid PEM block"); err != nil {
					return err
				}
				return nil
			},
			wantErr:     true,
			errContains: "failed to decode key PEM block",
		},
		{
			name: "valid EC private key",
			setupCert: func(certFile, keyFile *os.File) error {
				certPEM, keyPEM, err := generateTestCertAndKeyEC()
				if err != nil {
					return err
				}
				if _, err := certFile.Write(certPEM); err != nil {
					return err
				}
				if _, err := keyFile.Write(keyPEM); err != nil {
					return err
				}
				return nil
			},
			wantErr: false,
		},
		{
			name: "valid RSA PRIVATE KEY type",
			setupCert: func(certFile, keyFile *os.File) error {
				certPEM, keyPEM, err := generateTestCertAndKey()
				if err != nil {
					return err
				}
				if _, err := certFile.Write(certPEM); err != nil {
					return err
				}
				if _, err := keyFile.Write(keyPEM); err != nil {
					return err
				}
				return nil
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := testValidateCertificate(t, tt.setupCert)

			if tt.wantErr {
				if err == nil {
					t.Errorf("validateCertificate() expected error, got nil")
					return
				}
				if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("validateCertificate() error = %v, want error containing %q", err, tt.errContains)
				}
			} else {
				if err != nil {
					t.Errorf("validateCertificate() unexpected error: %v", err)
				}
			}
		})
	}
}

// testValidateCertificate is a helper that creates temp cert/key files, runs the
// provided setup function to populate them, and calls validateCertificate.
func testValidateCertificate(t *testing.T, setupCert func(certFile, keyFile *os.File) error) error {
	t.Helper()
	certFile, keyFile, cleanup := testTempCertKeyFiles(t)
	defer cleanup()

	if err := setupCert(certFile, keyFile); err != nil {
		t.Fatalf("setupCert failed: %v", err)
	}
	certFile.Close()
	keyFile.Close()

	return validateCertificate(certFile.Name(), keyFile.Name())
}

// testTempCertKeyFiles creates temporary certificate and key files for testing.
// Returns the opened files (ready for writing) and a cleanup function.
// After writing to the files, callers must close them before calling validateCertificate.
func testTempCertKeyFiles(t *testing.T) (certFile, keyFile *os.File, cleanup func()) {
	t.Helper()

	f, err := os.CreateTemp("", "test-cert-*.pem")
	if err != nil {
		t.Fatalf("failed to create temp cert file: %v", err)
	}
	certName := f.Name()
	f.Close()

	f, err = os.CreateTemp("", "test-key-*.pem")
	if err != nil {
		os.Remove(certName)
		t.Fatalf("failed to create temp key file: %v", err)
	}
	keyName := f.Name()
	f.Close()

	// Reopen for writing
	certFile, err = os.OpenFile(certName, os.O_WRONLY, 0644)
	if err != nil {
		os.Remove(certName)
		os.Remove(keyName)
		t.Fatalf("failed to reopen cert file: %v", err)
	}
	keyFile, err = os.OpenFile(keyName, os.O_WRONLY, 0644)
	if err != nil {
		certFile.Close()
		os.Remove(certName)
		os.Remove(keyName)
		t.Fatalf("failed to reopen key file: %v", err)
	}

	cleanup = func() {
		os.Remove(certName)
		os.Remove(keyName)
	}

	return certFile, keyFile, cleanup
}

// TestSetCacheHeaders tests the api.SetCacheHeaders function
func TestSetCacheHeaders(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name          string
		path          string
		wantCacheCtrl string
		wantPragma    string
		wantExpires   string
		wantNoCache   bool
		wantImmutable bool
		wantOneHour   bool
	}{
		{
			name:          "HTML file - no cache",
			path:          "/index.html",
			wantNoCache:   true,
			wantCacheCtrl: "no-cache, no-store, must-revalidate",
			wantPragma:    "no-cache",
			wantExpires:   "0",
		},
		{
			name:          "HTML file in subdirectory - no cache",
			path:          "/pages/about.html",
			wantNoCache:   true,
			wantCacheCtrl: "no-cache, no-store, must-revalidate",
			wantPragma:    "no-cache",
			wantExpires:   "0",
		},
		{
			name:          "HTML file - exact extension match",
			path:          "test.html",
			wantNoCache:   true,
			wantCacheCtrl: "no-cache, no-store, must-revalidate",
			wantPragma:    "no-cache",
			wantExpires:   "0",
		},
		{
			name:          "JS asset with hash - immutable cache",
			path:          "assets/index-Abc123.js",
			wantImmutable: true,
			wantCacheCtrl: "public, max-age=31536000, immutable",
		},
		{
			name:          "CSS asset with hash - immutable cache",
			path:          "assets/styles-Xyz789.css",
			wantImmutable: true,
			wantCacheCtrl: "public, max-age=31536000, immutable",
		},
		{
			name:          "JS asset with complex hash - immutable cache",
			path:          "assets/vendor-b8a3c5d9e1f2.js",
			wantImmutable: true,
			wantCacheCtrl: "public, max-age=31536000, immutable",
		},
		{
			name:          "JS asset without hash - one hour cache",
			path:          "assets/index.js",
			wantOneHour:   true,
			wantCacheCtrl: "public, max-age=3600",
		},
		{
			name:          "CSS asset without hash - one hour cache",
			path:          "assets/styles.css",
			wantOneHour:   true,
			wantCacheCtrl: "public, max-age=3600",
		},
		{
			name:          "JS file outside assets - one hour cache",
			path:          "scripts/app.js",
			wantOneHour:   true,
			wantCacheCtrl: "public, max-age=3600",
		},
		{
			name:          "CSS file outside assets - one hour cache",
			path:          "styles/main.css",
			wantOneHour:   true,
			wantCacheCtrl: "public, max-age=3600",
		},
		{
			name:          "Image file - one hour cache",
			path:          "images/logo.png",
			wantOneHour:   true,
			wantCacheCtrl: "public, max-age=3600",
		},
		{
			name:          "JPEG image - one hour cache",
			path:          "photos/banner.jpg",
			wantOneHour:   true,
			wantCacheCtrl: "public, max-age=3600",
		},
		{
			name:          "SVG image - one hour cache",
			path:          "icons/arrow.svg",
			wantOneHour:   true,
			wantCacheCtrl: "public, max-age=3600",
		},
		{
			name:          "Font file - one hour cache",
			path:          "fonts/roboto.woff2",
			wantOneHour:   true,
			wantCacheCtrl: "public, max-age=3600",
		},
		{
			name:          "JSON file - one hour cache",
			path:          "data/config.json",
			wantOneHour:   true,
			wantCacheCtrl: "public, max-age=3600",
		},
		{
			name:          "Root path - one hour cache",
			path:          "/",
			wantOneHour:   true,
			wantCacheCtrl: "public, max-age=3600",
		},
		{
			name:          "File without extension - one hour cache",
			path:          "README",
			wantOneHour:   true,
			wantCacheCtrl: "public, max-age=3600",
		},
		{
			name:          "Asset JS with leading slash - one hour cache (path normalization needed)",
			path:          "/assets/main-a1b2c3.js",
			wantOneHour:   true,
			wantCacheCtrl: "public, max-age=3600",
		},
		{
			name:          "File with hash but wrong extension - one hour cache",
			path:          "assets/data-abc123.txt",
			wantOneHour:   true,
			wantCacheCtrl: "public, max-age=3600",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			w := httptest.NewRecorder()
			api.SetCacheHeaders(w, tt.path)

			headers := w.Header()

			// Check Cache-Control header
			gotCacheCtrl := headers.Get("Cache-Control")
			if gotCacheCtrl != tt.wantCacheCtrl {
				t.Errorf("Cache-Control = %q, want %q", gotCacheCtrl, tt.wantCacheCtrl)
			}

			// Check for no-cache specific headers
			if tt.wantNoCache {
				if gotPragma := headers.Get("Pragma"); gotPragma != tt.wantPragma {
					t.Errorf("Pragma = %q, want %q", gotPragma, tt.wantPragma)
				}
				if gotExpires := headers.Get("Expires"); gotExpires != tt.wantExpires {
					t.Errorf("Expires = %q, want %q", gotExpires, tt.wantExpires)
				}
			} else {
				// For non-no-cache responses, Pragma and Expires should not be set
				if gotPragma := headers.Get("Pragma"); gotPragma != "" {
					t.Errorf("Pragma should be empty for non-no-cache responses, got %q", gotPragma)
				}
				if gotExpires := headers.Get("Expires"); gotExpires != "" {
					t.Errorf("Expires should be empty for non-no-cache responses, got %q", gotExpires)
				}
			}

			// Verify immutable flag for assets with hash
			if tt.wantImmutable {
				if !strings.Contains(gotCacheCtrl, "immutable") {
					t.Errorf("Cache-Control should contain 'immutable' for hashed assets")
				}
				if !strings.Contains(gotCacheCtrl, "max-age=31536000") {
					t.Errorf("Cache-Control should contain 'max-age=31536000' for immutable assets")
				}
			}

			// Verify one-hour cache
			if tt.wantOneHour && !tt.wantImmutable {
				if !strings.Contains(gotCacheCtrl, "max-age=3600") {
					t.Errorf("Cache-Control should contain 'max-age=3600' for one-hour cache")
				}
			}
		})
	}
}

// TestSetCacheHeadersNoMutation verifies that api.SetCacheHeaders only sets headers
// and doesn't mutate other parts of the response
func TestSetCacheHeadersNoMutation(t *testing.T) {
	t.Parallel()
	w := httptest.NewRecorder()

	// Set some pre-existing headers
	w.Header().Set("Content-Type", "text/html")
	w.Header().Set("X-Custom-Header", "custom-value")

	// Verify pre-existing headers were set properly (avoid false-positive setup)
	if w.Header().Get("Content-Type") != "text/html" {
		t.Fatal("test setup: failed to set Content-Type header")
	}
	if w.Header().Get("X-Custom-Header") != "custom-value" {
		t.Fatal("test setup: failed to set X-Custom-Header header")
	}

	api.SetCacheHeaders(w, "index.html")

	// Use Result().Header for assertions after handler completes
	// (Header() is for mutation within a handler; Result().Header is for inspection)
	res := w.Result()

	// Verify pre-existing headers are preserved
	if res.Header.Get("Content-Type") != "text/html" {
		t.Errorf("Content-Type should be preserved")
	}
	if res.Header.Get("X-Custom-Header") != "custom-value" {
		t.Errorf("X-Custom-Header should be preserved")
	}

	// Verify cache headers are set
	if res.Header.Get("Cache-Control") != "no-cache, no-store, must-revalidate" {
		t.Errorf("Cache-Control should be set")
	}
}

// TestSetCacheHeadersMultipleCalls verifies that calling api.SetCacheHeaders
// multiple times updates the headers correctly
func TestSetCacheHeadersMultipleCalls(t *testing.T) {
	t.Parallel()
	w := httptest.NewRecorder()

	// First call for HTML
	api.SetCacheHeaders(w, "page.html")
	if !strings.Contains(w.Header().Get("Cache-Control"), "no-cache") {
		t.Error("First call should set no-cache for HTML")
	}

	// Second call for different file type - headers should be overwritten
	api.SetCacheHeaders(w, "assets/app-abc123.js")
	if !strings.Contains(w.Header().Get("Cache-Control"), "immutable") {
		t.Error("Second call should set immutable for hashed asset")
	}

	// Third call for another HTML - should override immutable headers
	api.SetCacheHeaders(w, "another.html")
	if !strings.Contains(w.Header().Get("Cache-Control"), "no-cache") {
		t.Error("Third call should set no-cache for HTML")
	}
}

// generateTestCertAndKey generates a test certificate and RSA private key
func generateTestCertAndKey() ([]byte, []byte, error) {
	// Generate RSA private key
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test-cert",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Self-sign the certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}

	// PEM encode certificate
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	// PEM encode private key (using RSA PRIVATE KEY type)
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	})

	return certPEM, keyPEM, nil
}

// generateTestCertAndKeyEC generates a test certificate and EC private key (P-256)
// Uses PKCS#8 PEM format for the key ("PRIVATE KEY" label).
func generateTestCertAndKeyEC() ([]byte, []byte, error) {
	// Generate ECDSA P-256 private key
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test-cert-ec",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Self-sign the certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}

	// PEM encode certificate
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	// PEM encode private key using PKCS#8 (produces "PRIVATE KEY" label)
	pkcs8Key, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pkcs8Key,
	})

	return certPEM, keyPEM, nil
}

func TestStartOfflineDetector_ContextCancellation(t *testing.T) {
	database, cleanup := setupTestMainDB(t)
	defer cleanup()
	ctx := context.Background()

	// Insert a peer with online status
	_, err := database.ExecContext(ctx,
		"INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, is_manual, status, last_heartbeat) VALUES (?, ?, ?, ?, 0, 'online', datetime('now'))",
		"online-peer", "10.0.0.1", "key", "hmac")
	if err != nil {
		t.Fatalf("insert peer: %v", err)
	}

	// Start detector with a context that we'll cancel quickly
	detectorCtx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		startOfflineDetector(detectorCtx, database)
		close(done)
	}()

	// Cancel after a brief moment
	cancel()

	// The goroutine should exit promptly
	select {
	case <-done:
		// Success: detector shut down
	case <-time.After(2 * time.Second):
		t.Error("startOfflineDetector did not shut down after context cancellation")
	}
}

func TestStartOfflineDetector_MarksStalePeersOffline(t *testing.T) {
	database, cleanup := setupTestMainDB(t)
	defer cleanup()
	ctx := context.Background()

	// Insert a peer with stale heartbeat (90+ seconds ago)
	_, err := database.ExecContext(ctx,
		"INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, is_manual, status, last_heartbeat) VALUES (?, ?, ?, ?, 0, 'online', datetime('now', '-120 seconds'))",
		"stale-peer", "10.0.0.2", "stale-agent-key", "stale-hmac-key")
	if err != nil {
		t.Fatalf("insert stale peer: %v", err)
	}

	// Insert a peer with recent heartbeat
	_, err = database.ExecContext(ctx,
		"INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, is_manual, status, last_heartbeat) VALUES (?, ?, ?, ?, 0, 'online', datetime('now'))",
		"fresh-peer", "10.0.0.3", "fresh-agent-key", "fresh-hmac-key")
	if err != nil {
		t.Fatalf("insert fresh peer: %v", err)
	}

	// Simulate what startOfflineDetector does on each tick
	_, err = database.ExecContext(ctx,
		fmt.Sprintf(`UPDATE peers SET status = 'offline'
		WHERE status = 'online'
		AND last_heartbeat < datetime('now', '-%d seconds')`, int(constants.OfflineThreshold.Seconds())),
	)
	if err != nil {
		t.Fatalf("offline update: %v", err)
	}

	// Stale peer should be offline
	var staleStatus string
	err = database.QueryRowContext(ctx, "SELECT status FROM peers WHERE hostname = ?", "stale-peer").Scan(&staleStatus)
	if err != nil {
		t.Fatalf("query stale peer: %v", err)
	}
	if staleStatus != "offline" {
		t.Errorf("expected stale peer status 'offline', got %q", staleStatus)
	}

	// Fresh peer should still be online
	var freshStatus string
	err = database.QueryRowContext(ctx, "SELECT status FROM peers WHERE hostname = ?", "fresh-peer").Scan(&freshStatus)
	if err != nil {
		t.Fatalf("query fresh peer: %v", err)
	}
	if freshStatus != "online" {
		t.Errorf("expected fresh peer status 'online', got %q", freshStatus)
	}
}

func TestStartTokenCleanup_ContextCancellation(t *testing.T) {
	database, cleanup := setupTestMainDB(t)
	defer cleanup()

	tokenStore := store.NewTokenStore(database)

	detectorCtx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		startTokenCleanup(detectorCtx, tokenStore)
		close(done)
	}()

	// Cancel after a brief moment
	cancel()

	// The goroutine should exit promptly
	select {
	case <-done:
		// Success: cleanup shut down
	case <-time.After(2 * time.Second):
		t.Error("startTokenCleanup did not shut down after context cancellation")
	}
}

func TestStartTokenCleanup_RemovesExpiredTokens(t *testing.T) {
	database, cleanup := setupTestMainDB(t)
	defer cleanup()
	ctx := context.Background()

	tokenStore := store.NewTokenStore(database)

	// Insert an expired token
	pastTime := time.Now().Add(-1 * time.Hour)
	err := tokenStore.RevokeToken(ctx, "expired-token-1", pastTime, "refresh")
	if err != nil {
		t.Fatalf("revoke expired token: %v", err)
	}

	// Insert a non-expired token
	futureTime := time.Now().Add(1 * time.Hour)
	err = tokenStore.RevokeToken(ctx, "valid-token-1", futureTime, "refresh")
	if err != nil {
		t.Fatalf("revoke valid token: %v", err)
	}

	// Run cleanup
	err = tokenStore.CleanupExpiredTokens(ctx)
	if err != nil {
		t.Fatalf("CleanupExpiredTokens: %v", err)
	}

	// Expired token should be gone
	revoked, err := tokenStore.IsTokenRevoked(ctx, "expired-token-1")
	if err != nil {
		t.Fatalf("check expired token: %v", err)
	}
	if revoked {
		t.Error("expected expired token to be cleaned up")
	}

	// Valid token should still be there
	revoked, err = tokenStore.IsTokenRevoked(ctx, "valid-token-1")
	if err != nil {
		t.Fatalf("check valid token: %v", err)
	}
	if !revoked {
		t.Error("expected valid token to still be revoked")
	}
}

// setupTestMainDB creates a temporary database for testing main.go functions.
func setupTestMainDB(t *testing.T) (*sql.DB, func()) {
	t.Helper()
	f, err := os.CreateTemp("", "runic-main-test-*.db")
	if err != nil {
		t.Fatal(err)
	}
	dbPath := f.Name()
	if cErr := f.Close(); cErr != nil {
		t.Logf("Failed to close temp file: %v", cErr)
	}

	database, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		os.Remove(dbPath)
		t.Fatal(err)
	}

	if _, err := database.Exec("PRAGMA foreign_keys=ON"); err != nil {
		database.Close()
		os.Remove(dbPath)
		t.Fatal(err)
	}

	if _, err := database.Exec(runicdb.Schema()); err != nil {
		database.Close()
		os.Remove(dbPath)
		t.Fatal(err)
	}

	cleanup := func() {
		database.Close()
		os.Remove(dbPath)
	}
	return database, cleanup
}
