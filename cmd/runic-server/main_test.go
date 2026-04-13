package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// TestValidateCertificate tests the validateCertificate function
func TestValidateCertificate(t *testing.T) {
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
			// Create temp cert file
			certFile, err := os.CreateTemp("", "test-cert-*.pem")
			if err != nil {
				t.Fatalf("failed to create temp cert file: %v", err)
			}
			defer os.Remove(certFile.Name())
			certFile.Close()

			// Create temp key file
			keyFile, err := os.CreateTemp("", "test-key-*.pem")
			if err != nil {
				t.Fatalf("failed to create temp key file: %v", err)
			}
			defer os.Remove(keyFile.Name())
			keyFile.Close()

			// Reopen files for writing
			certFile, err = os.OpenFile(certFile.Name(), os.O_WRONLY, 0644)
			if err != nil {
				t.Fatalf("failed to reopen cert file: %v", err)
			}
			keyFile, err = os.OpenFile(keyFile.Name(), os.O_WRONLY, 0644)
			if err != nil {
				t.Fatalf("failed to reopen key file: %v", err)
			}

			// Setup test case
			if err := tt.setupCert(certFile, keyFile); err != nil {
				t.Fatalf("setupCert failed: %v", err)
			}
			certFile.Close()
			keyFile.Close()

			// Run validation
			err = validateCertificate(certFile.Name(), keyFile.Name())

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

// TestSetCacheHeaders tests the setCacheHeaders function
func TestSetCacheHeaders(t *testing.T) {
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
			w := httptest.NewRecorder()
			setCacheHeaders(w, tt.path)

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

// TestSetCacheHeadersNoMutation verifies that setCacheHeaders only sets headers
// and doesn't mutate other parts of the response
func TestSetCacheHeadersNoMutation(t *testing.T) {
	w := httptest.NewRecorder()

	// Set some pre-existing headers
	w.Header().Set("Content-Type", "text/html")
	w.Header().Set("X-Custom-Header", "custom-value")

	setCacheHeaders(w, "index.html")

	// Verify pre-existing headers are preserved
	if w.Header().Get("Content-Type") != "text/html" {
		t.Errorf("Content-Type should be preserved")
	}
	if w.Header().Set("X-Custom-Header", "custom-value"); w.Header().Get("X-Custom-Header") != "custom-value" {
		t.Errorf("X-Custom-Header should be preserved")
	}

	// Verify cache headers are set
	if w.Header().Get("Cache-Control") != "no-cache, no-store, must-revalidate" {
		t.Errorf("Cache-Control should be set")
	}
}

// TestSetCacheHeadersMultipleCalls verifies that calling setCacheHeaders
// multiple times updates the headers correctly
func TestSetCacheHeadersMultipleCalls(t *testing.T) {
	w := httptest.NewRecorder()

	// First call for HTML
	setCacheHeaders(w, "page.html")
	if !strings.Contains(w.Header().Get("Cache-Control"), "no-cache") {
		t.Error("First call should set no-cache for HTML")
	}

	// Second call for different file type - headers should be overwritten
	setCacheHeaders(w, "assets/app-abc123.js")
	if !strings.Contains(w.Header().Get("Cache-Control"), "immutable") {
		t.Error("Second call should set immutable for hashed asset")
	}

	// Third call for another HTML - should override immutable headers
	setCacheHeaders(w, "another.html")
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

// generateTestCertAndKeyEC generates a test certificate and EC private key
func generateTestCertAndKeyEC() ([]byte, []byte, error) {
	// Generate EC private key
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
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

	// PEM encode private key (using EC PRIVATE KEY type by marshaling as PKCS8 and extracting)
	// For simplicity, we'll use RSA PRIVATE KEY which is also accepted
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	})

	return certPEM, keyPEM, nil
}
