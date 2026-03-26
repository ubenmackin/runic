package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gorilla/mux"

	"runic/internal/api"
	"runic/internal/auth"
	"runic/internal/db"
	"runic/internal/engine"
)

// validateCertificate reads and validates certificate and key files in PEM format
func validateCertificate(certFile, keyFile string) error {
	// Check if files exist
	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		return fmt.Errorf("certificate file not found: %s", certFile)
	}
	if _, err := os.Stat(keyFile); os.IsNotExist(err) {
		return fmt.Errorf("key file not found: %s", keyFile)
	}

	// Read certificate file
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return fmt.Errorf("failed to read certificate file: %w", err)
	}

	// Read key file
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return fmt.Errorf("failed to read key file: %w", err)
	}

	// Validate certificate PEM format
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return fmt.Errorf("failed to decode certificate PEM block from %s", certFile)
	}
	if certBlock.Type != "CERTIFICATE" {
		return fmt.Errorf("invalid PEM block type in certificate file: expected CERTIFICATE, got %s", certBlock.Type)
	}

	// Validate key PEM format
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return fmt.Errorf("failed to decode key PEM block from %s", keyFile)
	}
	if keyBlock.Type != "PRIVATE KEY" && !strings.HasPrefix(keyBlock.Type, "EC PRIVATE KEY") &&
		!strings.HasPrefix(keyBlock.Type, "RSA PRIVATE KEY") {
		return fmt.Errorf("invalid key PEM block type: expected PRIVATE key type, got %s", keyBlock.Type)
	}

	// Parse certificate to ensure it's valid
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	log.Printf("Certificate validated successfully (Subject: %s, Expires: %s)", cert.Subject.CommonName, cert.NotAfter.Format(time.RFC3339))

	return nil
}

func main() {
	// Get TLS certificate paths from environment variables
	certFile := os.Getenv("RUNIC_CERT_FILE")
	keyFile := os.Getenv("RUNIC_KEY_FILE")

	if certFile == "" || keyFile == "" {
		log.Fatal("RUNIC_CERT_FILE and RUNIC_KEY_FILE must be set for HTTPS mode")
	}

	// Validate certificates before starting server
	log.Printf("Validating TLS certificates (CERT: %s, KEY: %s)", certFile, keyFile)
	if err := validateCertificate(certFile, keyFile); err != nil {
		log.Fatalf("Certificate validation failed: %v", err)
	}

	// Get port from environment variable or use default
	port := os.Getenv("RUNIC_PORT")
	if port == "" {
		port = "60443"
	}
	addr := ":" + port

	dbPath := os.Getenv("RUNIC_DB_PATH")
	if dbPath == "" {
		dbPath = "./runic.db"
	}
	db.InitDB(dbPath)

	downloadsDir := os.Getenv("RUNIC_DOWNLOADS_DIR")
	if downloadsDir == "" {
		downloadsDir = "./downloads"
	}

	hmacKey := os.Getenv("RUNIC_HMAC_KEY")
	if hmacKey == "" {
		if os.Getenv("ENV") == "production" {
			log.Fatal("RUNIC_HMAC_KEY must be set in production")
		}
		hmacKey = "default-hmac-key-change-in-production"
		log.Println("WARNING: using default HMAC key in development mode")
	}

	compiler := engine.NewCompiler(db.DB.UnderlyingDB(), hmacKey)

	// Initialize auth with database for token revocation
	auth.SetDB(db.DB.UnderlyingDB())

	r := mux.NewRouter()

	// Public routes are now registered in internal/api/api.go

	// Health and Metrics endpoints (no authentication required)
	r.HandleFunc("/health", api.HealthHandler).Methods("GET")
	r.HandleFunc("/ready", api.ReadyHandler).Methods("GET")
	r.Handle("/metrics", api.MetricsHandler()).Methods("GET")

	// Register all API routes (public routes like setup and protected routes are all handled in api.go)
	apiInstance := api.NewAPI(compiler)
	api.RegisterRoutes(r, apiInstance, downloadsDir)

	// Serve embedded web frontend (SPA)
	// Strip the "web/dist" prefix so http.FS can find files in the embedded FS
	subFS, err := fs.Sub(api.WebDist, "web/dist")
	if err != nil {
		log.Fatalf("Failed to create sub filesystem: %v", err)
	}
	fileServer := http.FileServer(http.FS(subFS))

	// For any route not matched above, serve the SPA
	// If the file exists, serve it; otherwise serve index.html (for client-side routing)
	r.PathPrefix("/").HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// Try to open the requested file
		path := req.URL.Path
		if path == "/" {
			path = "/index.html"
		}
		// Remove leading slash for fs.FS lookup
		path = strings.TrimPrefix(path, "/")
		if _, err := subFS.Open(path); err == nil {
			fileServer.ServeHTTP(w, req)
		} else {
			// File not found — serve index.html for SPA client-side routing
			req.URL.Path = "/index.html"
			fileServer.ServeHTTP(w, req)
		}
	})

	// Start offline detector goroutine
	go startOfflineDetector()

	// Start token revocation cleanup goroutine (prunes expired entries hourly)
	go startTokenCleanup()

	// Configure TLS with modern cipher suites and minimum version TLS 1.2
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,       // TLS 1.3
			tls.TLS_CHACHA20_POLY1305_SHA256, // TLS 1.3
			tls.TLS_AES_128_GCM_SHA256,       // TLS 1.3
		},
		PreferServerCipherSuites: true,
	}

	srv := &http.Server{
		Addr:      addr,
		Handler:   r,
		TLSConfig: tlsConfig,
	}

	// Wait for SIGINT/SIGTERM to shut down
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	log.Printf("Starting Runic HTTPS server on %s (CERT: %s, KEY: %s)", addr, certFile, keyFile)
	go func() {
		if err := srv.ListenAndServeTLS(certFile, keyFile); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server failed: %v", err)
		}
	}()

	<-sigCh
	log.Println("Received shutdown signal...")
	os.Exit(0)
}

// startOfflineDetector marks servers as offline if they haven't sent a heartbeat in 90 seconds.
func startOfflineDetector() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			ctx := context.Background()
			_, err := db.DB.ExecContext(ctx,
				`UPDATE servers SET status = 'offline'
				 WHERE status = 'online'
				 AND last_heartbeat < datetime('now', '-90 seconds')`,
			)
			if err != nil {
				log.Printf("Offline detector error: %v", err)
			}
		}
	}
}

// startTokenCleanup periodically removes expired entries from the revoked_tokens table.
func startTokenCleanup() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			ctx := context.Background()
			if err := auth.CleanupExpiredTokens(ctx); err != nil {
				log.Printf("Token cleanup error: %v", err)
			}
		}
	}
}
