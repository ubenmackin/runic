package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/gorilla/mux"

	"runic/internal/alerts"
	"runic/internal/api"
	"runic/internal/auth"
	"runic/internal/common/constants"
	"runic/internal/common/version"
	"runic/internal/crypto"
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

// setCacheHeaders sets appropriate Cache-Control headers based on file type.
// - HTML files: no-cache (must revalidate to get latest version)
// - Assets with content hashes (*.js, *.css in assets/): 1 year cache (immutable)
// - Other static files: 1 hour cache
func setCacheHeaders(w http.ResponseWriter, path string) {
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

	// Other static assets (images, fonts, etc.) - cache for 1 hour
	w.Header().Set("Cache-Control", "public, max-age=3600")
}

func main() {
	// Command-line flags
	versionFlag := flag.Bool("version", false, "Print version and exit")
	flag.Parse()

	// Handle --version flag
	if *versionFlag {
		fmt.Printf("runic-server version %s\n", version.Version)
		os.Exit(0)
	}

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
	database, err := db.InitDB(dbPath)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}

	// Get logs database path from environment variable
	// Default to same directory as main DB with filename "logs.db"
	logsDBPath := os.Getenv("RUNIC_LOGS_DB_PATH")
	if logsDBPath == "" {
		// Default to logs.db in the same directory as the main database
		dbDir := filepath.Dir(dbPath)
		logsDBPath = filepath.Join(dbDir, "logs.db")
	}
	log.Printf("Logs database path: %s", logsDBPath)

	// Ensure control_plane_port is set in system_config for rule generation
	if err := db.SetSecret(context.Background(), database, "control_plane_port", port); err != nil {
		log.Fatalf("Failed to set control_plane_port in system_config: %v", err)
	}
	log.Printf("Control plane port set to %s in system_config", port)

	downloadsDir := os.Getenv("RUNIC_DOWNLOADS_DIR")
	if downloadsDir == "" {
		downloadsDir = "./downloads"
	}

	compiler := engine.NewCompiler(database)

	// Initialize encryptor for sensitive data (SMTP passwords, etc.)
	// The encryption_key is generated and stored in the database during migrations.
	// Security: The encryption key is kept in a narrow scope to minimize exposure
	// and is not retained in any variable after use.
	var encryptor *crypto.Encryptor
	// Use a function literal to create a narrow scope for the sensitive key
	func() {
		var encryptionKey string
		err := database.QueryRowContext(context.Background(),
			"SELECT value FROM system_config WHERE key = 'encryption_key'").Scan(&encryptionKey)
		if err == nil && encryptionKey != "" {
			enc, err := crypto.NewEncryptor(encryptionKey)
			if err == nil {
				encryptor = enc
				log.Printf("Encryptor initialized for sensitive data encryption")
			} else {
				log.Printf("Warning: failed to create encryptor: %v", err)
			}
		} else {
			log.Printf("Warning: encryption_key not found in database, SMTP password encryption disabled")
		}
		// encryptionKey goes out of scope here - no need to manually clear
	}()

	// Initialize alert service for notifications
	// Wrap *sql.DB in *db.Database for the alert service
	runicDB := db.New(database)
	alertService := alerts.NewService(runicDB)
	alertService.SetEncryptor(encryptor)

	// Initialize and start the alert service
	var peerMonitor *alerts.PeerMonitor
	var spikeDetector *alerts.SpikeDetector
	if err := alertService.Initialize(); err != nil {
		log.Printf("Warning: failed to initialize alert service: %v", err)
	} else {
		if err := alertService.Start(); err != nil {
			log.Printf("Warning: failed to start alert service: %v", err)
		} else {
			// Start peer monitor and spike detector workers
			peerMonitor = alerts.NewPeerMonitor(database, alertService)
			peerMonitor.Start()
			spikeDetector = alerts.NewSpikeDetector(database, alertService)
			spikeDetector.Start()
		}
	}

	// Initialize auth with database for token revocation
	auth.SetDB(database)

	r := mux.NewRouter()

	// Public routes are now registered in internal/api/api.go

	// Register all API routes (public routes like setup, protected routes, and system endpoints like /health)
	apiInstance := api.NewAPI(database, compiler, logsDBPath, alertService, encryptor)
	apiInstance.RegisterRoutes(r, downloadsDir)

	// Serve embedded web frontend (SPA)
	// Strip the "web/dist" prefix so http.FS can find files in the embedded FS
	subFS, err := fs.Sub(api.WebDist, "web/dist")
	if err != nil {
		log.Fatalf("Failed to create sub filesystem: %v", err)
	}
	fileServer := http.FileServer(http.FS(subFS))

	// For any route not matched above, serve the SPA with CSP nonce injection
	// If the file exists, serve it; otherwise serve index.html (for client-side routing)
	r.PathPrefix("/").Handler(api.CSP()(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// Get the nonce from context (set by CSP middleware)
		nonce, ok := api.GetCSPNonce(req.Context())

		// Try to open the requested file
		path := req.URL.Path
		if path == "/" {
			path = "/index.html"
		}
		// Remove leading slash for fs.FS lookup
		fsPath := strings.TrimPrefix(path, "/")

		if _, err := subFS.Open(fsPath); err == nil {
			// File exists
			// For HTML files, inject the nonce
			if strings.HasSuffix(path, ".html") {
				// index.html should never be cached
				w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
				w.Header().Set("Pragma", "no-cache")
				w.Header().Set("Expires", "0")

				if ok {
					// Serve HTML with nonce injection
					if err := api.ServeHTMLWithNonce(w, req, subFS, fsPath, nonce); err != nil {
						http.Error(w, "Internal Server Error", http.StatusInternalServerError)
					}
				} else {
					// Fallback: serve without nonce
					fileServer.ServeHTTP(w, req)
				}
			} else {
				// Set cache headers based on file type
				setCacheHeaders(w, path)
				fileServer.ServeHTTP(w, req)
			}
		} else {
			// File not found — serve index.html for SPA client-side routing
			// index.html should never be cached
			w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
			w.Header().Set("Pragma", "no-cache")
			w.Header().Set("Expires", "0")

			if ok {
				// Serve HTML with nonce injection
				if err := api.ServeHTMLWithNonce(w, req, subFS, "index.html", nonce); err != nil {
					http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				}
			} else {
				// Fallback: serve without nonce
				req.URL.Path = "/index.html"
				fileServer.ServeHTTP(w, req)
			}
		}
	})))

	// Create root context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start the ChangeWorker background goroutine
	apiInstance.ChangeWorker.Start(ctx)

	// Start offline detector goroutine
	go startOfflineDetector(ctx, database)

	// Start token revocation cleanup goroutine (prunes expired entries hourly)
	go startTokenCleanup(ctx)

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

	// Cancel context to signal background goroutines to stop
	cancel()

	// Create shutdown context with timeout
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer shutdownCancel()

	// Gracefully shutdown HTTP server
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("HTTP server shutdown error: %v", err)
	}

	// Stop rate limiter cleanup goroutines
	apiInstance.Stop()

	// Stop alert service and workers
	if peerMonitor != nil {
		peerMonitor.Stop()
	}
	if spikeDetector != nil {
		spikeDetector.Stop()
	}
	if alertService != nil {
		if err := alertService.Stop(); err != nil {
			log.Printf("Alert service shutdown error: %v", err)
		}
	}

	// Close database connection
	if database != nil {
		if err := database.Close(); err != nil {
			log.Printf("Database close error: %v", err)
		}
	}

	log.Println("Server shut down gracefully")
}

// startOfflineDetector marks peers as offline if they haven't sent a heartbeat in 90 seconds.
func startOfflineDetector(ctx context.Context, database *sql.DB) {
	ticker := time.NewTicker(constants.OfflineDetectorInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Println("Offline detector shutting down")
			return
		case <-ticker.C:
			ctx := context.Background()
			_, err := database.ExecContext(ctx,
				fmt.Sprintf(`UPDATE peers SET status = 'offline'
				WHERE status = 'online'
				AND last_heartbeat < datetime('now', '-%d seconds')`, constants.OfflineThresholdSeconds),
			)
			if err != nil {
				log.Printf("Offline detector error: %v", err)
			}
		}
	}
}

// startTokenCleanup periodically removes expired entries from the revoked_tokens table.
func startTokenCleanup(ctx context.Context) {
	ticker := time.NewTicker(constants.OfflineCleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Println("Token cleanup shutting down")
			return
		case <-ticker.C:
			ctx := context.Background()
			if err := auth.CleanupExpiredTokens(ctx); err != nil {
				log.Printf("Token cleanup error: %v", err)
			}
		}
	}
}
