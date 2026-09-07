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
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gorilla/mux"

	"runic/internal/alerts"
	"runic/internal/api"
	"runic/internal/auth"
	"runic/internal/common/constants"
	runiclog "runic/internal/common/log"
	"runic/internal/common/signal"
	"runic/internal/common/version"
	"runic/internal/crypto"
	"runic/internal/db"
	"runic/internal/engine"
	"runic/internal/metrics"
	"runic/internal/store"
)

func validateCertificate(certFile, keyFile string) error {
	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		return fmt.Errorf("certificate file not found: %s", certFile)
	}
	if _, err := os.Stat(keyFile); os.IsNotExist(err) {
		return fmt.Errorf("key file not found: %s", keyFile)
	}

	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return fmt.Errorf("failed to read certificate file: %w", err)
	}

	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return fmt.Errorf("failed to read key file: %w", err)
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return fmt.Errorf("failed to decode certificate PEM block from %s", certFile)
	}
	if certBlock.Type != "CERTIFICATE" {
		return fmt.Errorf("invalid PEM block type in certificate file: expected CERTIFICATE, got %s", certBlock.Type)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return fmt.Errorf("failed to decode key PEM block from %s", keyFile)
	}
	if keyBlock.Type != "PRIVATE KEY" && !strings.HasPrefix(keyBlock.Type, "EC PRIVATE KEY") &&
		!strings.HasPrefix(keyBlock.Type, "RSA PRIVATE KEY") {
		return fmt.Errorf("invalid key PEM block type: expected PRIVATE key type, got %s", keyBlock.Type)
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	runiclog.Info("Certificate validated successfully",
		"subject", cert.Subject.CommonName,
		"expires", cert.NotAfter.Format(time.RFC3339))

	return nil
}

func main() {
	versionFlag := flag.Bool("version", false, "Print version and exit")
	certFlag := flag.String("cert", "", "TLS certificate file path")
	keyFlag := flag.String("key", "", "TLS private key file path")
	flag.Parse()

	if *versionFlag {
		version.PrintVersion("runic-server", version.Version)
		return
	}

	logLevel := os.Getenv("LOG_LEVEL")
	if logLevel == "" {
		logLevel = "info"
	}
	runiclog.Init(logLevel, os.Stderr)

	// CLI flags take precedence, then env vars
	certFile := *certFlag
	if certFile == "" {
		certFile = os.Getenv("RUNIC_CERT_FILE")
	}
	keyFile := *keyFlag
	if keyFile == "" {
		keyFile = os.Getenv("RUNIC_KEY_FILE")
	}

	if certFile == "" || keyFile == "" {
		runiclog.Fatal("TLS certificate and key are required. Use -cert/-key flags or RUNIC_CERT_FILE/RUNIC_KEY_FILE env vars")
	}

	runiclog.Info("Validating TLS certificates")
	if err := validateCertificate(certFile, keyFile); err != nil {
		runiclog.Fatal("Certificate validation failed", "error", err)
	}

	port := os.Getenv("RUNIC_PORT")
	if port == "" {
		port = constants.DefaultControlPlanePort
	}
	portNum := 0
	if _, err := fmt.Sscanf(port, "%d", &portNum); err != nil || portNum < 1 || portNum > 65535 {
		runiclog.Fatal("Invalid port number", "port", port)
	}
	addr := ":" + port

	dbPath := os.Getenv("RUNIC_DB_PATH")
	if dbPath == "" {
		dbPath = "./runic.db"
	}
	database, err := db.InitDB(dbPath)
	if err != nil {
		runiclog.Fatal("Failed to initialize database", "error", err)
	}

	logsDBPath := os.Getenv("RUNIC_LOGS_DB_PATH")
	if logsDBPath == "" {
		dbDir := filepath.Dir(dbPath)
		logsDBPath = filepath.Join(dbDir, "logs.db")
	}
	runiclog.Info("Using logs database path", "path", logsDBPath)

	// Initialize logs database early (needed by alert service and spike detector)
	logsDB, err := db.InitLogsDB(logsDBPath)
	if err != nil {
		runiclog.Fatal("Failed to initialize logs database", "error", err)
	}
	runiclog.Info("Logs database initialized", "path", logsDBPath)

	// Ensure control_plane_port is set in system_config for rule generation
	settingsStore := store.NewSettingsStore(database, nil)
	if err := settingsStore.SetSystemConfig(context.TODO(), "control_plane_port", port); err != nil {
		runiclog.Fatal("Failed to set control_plane_port in system_config", "error", err)
	}
	runiclog.Debug("control_plane_port set in system_config", "port", port)

	downloadsDir := os.Getenv("RUNIC_DOWNLOADS_DIR")
	if downloadsDir == "" {
		downloadsDir = "./downloads"
	}

	peerStore := store.NewPeerStore(database)
	groupStore := store.NewGroupStore(database)
	alertStore := store.NewAlertStore(database)
	userStore := store.NewUserStore(database)
	compiler := engine.NewCompiler(database, peerStore.GetPeerHostname, groupStore.GetActiveGroupNameByID)
	compiler.SetBeginner(database)

	// Initialize encryptor for sensitive data (SMTP passwords, etc.)
	// The encryption_key is generated and stored in the database during migrations.
	// Security: The encryption key is kept in a narrow scope to minimize exposure
	// and is not retained in any variable after use.
	var encryptor *crypto.Encryptor
	// Use a function literal to create a narrow scope for the sensitive key
	func() {
		encryptionKey, err := settingsStore.GetSystemConfig(context.TODO(), "encryption_key")
		if err == nil && encryptionKey != "" {
			enc, err := crypto.NewEncryptor(encryptionKey)
			if err == nil {
				encryptor = enc
				runiclog.Info("Encryptor initialized for sensitive data encryption")
			} else {
				runiclog.Warn("Failed to create encryptor", "error", err)
			}
		} else {
			runiclog.Warn("Encryption key not found, SMTP password encryption disabled")
		}
		// encryptionKey goes out of scope here - no need to manually clear
	}()

	// Strip the "web/dist" prefix so http.FS can find files in the embedded FS.
	// Validated early (before ctx creation) so a fatal exit doesn't skip deferred cleanup.
	subFS, err := fs.Sub(api.WebDist, "web/dist")
	if err != nil {
		runiclog.Fatal("Failed to create sub filesystem", "error", err)
	}
	fileServer := http.FileServer(http.FS(subFS))

	// Create a lifecycle context for background tasks. Placed after all fatal-exit
	// checks so that os.Exit via runiclog.Fatal never skips defer cancel().
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Wrap *sql.DB in *db.Database for the alert service
	runicDB := db.New(database)
	alertService := alerts.NewService(runicDB, alertStore, userStore)
	alertService.SetEncryptor(encryptor)
	alertService.SetLogsDB(db.New(logsDB))
	alertService.SetHostnameLookup(peerStore.GetPeerHostname)

	var peerMonitor *alerts.PeerMonitor
	var spikeDetector *alerts.SpikeDetector
	if err := alertService.Initialize(); err != nil {
		runiclog.Warn("Failed to initialize alert service", "error", err)
	} else {
		if err := alertService.Start(); err != nil {
			runiclog.Warn("Failed to start alert service", "error", err)
		} else {
			peerMonitor = alerts.NewPeerMonitor(database, alertService)
			peerMonitor.Start()
			spikeDetector = alerts.NewSpikeDetector(logsDB, database, alertService, peerStore.GetPeerHostname)
			spikeDetector.Start()
		}
	}

	auth.SetTokenStore(store.NewTokenStore(database))
	metrics.RegisterMetrics()

	r := mux.NewRouter()

	// Public routes are now registered in internal/api/api.go

	apiInstance := api.NewAPI(database, compiler, logsDB, logsDBPath, alertService, encryptor)
	apiInstance.RegisterRoutes(r, downloadsDir)

	// Start background lifecycle goroutines (workers, log hub, cleanup)
	apiInstance.Start(ctx)

	srv := &http.Server{}

	// For any route not matched above, serve the SPA with CSP nonce injection
	// If the file exists, serve it; otherwise serve index.html (for client-side routing)
	r.PathPrefix("/").Handler(api.CSP()(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		nonce, ok := api.GetCSPNonce(req.Context())

		path := req.URL.Path
		if path == "/" {
			path = "/index.html"
		}
		fsPath := strings.TrimPrefix(path, "/")

		if _, err := subFS.Open(fsPath); err == nil {
			if strings.HasSuffix(path, ".html") {
				w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
				w.Header().Set("Pragma", "no-cache")
				w.Header().Set("Expires", "0")

				if ok {
					if err := api.ServeHTMLWithNonce(w, req, subFS, fsPath, nonce); err != nil {
						http.Error(w, "Internal Server Error", http.StatusInternalServerError)
					}
				} else {
					fileServer.ServeHTTP(w, req)
				}
			} else {
				api.SetCacheHeaders(w, path)
				fileServer.ServeHTTP(w, req)
			}
		} else {
			// File not found — serve index.html for SPA client-side routing
			w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
			w.Header().Set("Pragma", "no-cache")
			w.Header().Set("Expires", "0")

			if ok {
				if err := api.ServeHTMLWithNonce(w, req, subFS, "index.html", nonce); err != nil {
					http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				}
			} else {
				req.URL.Path = "/index.html"
				fileServer.ServeHTTP(w, req)
			}
		}
	})))

	// Configure TLS with modern cipher suites and minimum version TLS 1.2, P-256 and X25519 curves
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
		CurvePreferences: []tls.CurveID{
			tls.CurveP256,
			tls.X25519,
		},
	}

	srv.Addr = addr
	srv.Handler = r
	srv.TLSConfig = tlsConfig

	// Signal channel with buffer 2 to prevent lost signals during shutdown
	sigCh := signal.ShutdownSignal()

	// Channel to receive fatal server errors from the listener goroutine
	srvErrCh := make(chan error, 1)

	runiclog.Info("Starting Runic HTTPS server", "addr", addr)
	go func() {
		if err := srv.ListenAndServeTLS(certFile, keyFile); err != nil && err != http.ErrServerClosed {
			srvErrCh <- err
		}
	}()

	// Start background goroutines AFTER the server has started listening
	go startOfflineDetector(ctx, database)
	tokenStore := store.NewTokenStore(database)
	go startTokenCleanup(ctx, tokenStore)

	// Wait for shutdown signal OR server failure
	select {
	case <-sigCh:
		runiclog.Info("Received shutdown signal...")
	case err := <-srvErrCh:
		runiclog.Error("Server failed to start", "error", err)
	}

	// Reset signal handling to prevent double-kill during shutdown
	signal.ResetSignalHandling()

	cancel() // Signal all context-dependent goroutines to stop

	gracefulShutdown(srv, apiInstance, peerMonitor, spikeDetector, alertService, database, logsDB)
	runiclog.Info("Server shut down gracefully")
}

// gracefulShutdown runs the full shutdown sequence during normal server
// shutdown (signal or listener failure).
func gracefulShutdown(srv *http.Server, apiInstance *api.API, peerMonitor *alerts.PeerMonitor, spikeDetector *alerts.SpikeDetector, alertService *alerts.Service, database *sql.DB, logsDB *sql.DB) {
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer shutdownCancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		runiclog.Warn("HTTP server shutdown error", "error", err)
	}

	apiInstance.Stop()

	if peerMonitor != nil {
		peerMonitor.Stop()
	}
	if spikeDetector != nil {
		spikeDetector.Stop()
	}
	if alertService != nil {
		if err := alertService.Stop(); err != nil {
			runiclog.Warn("Alert service shutdown error", "error", err)
		}
	}

	if database != nil {
		if err := database.Close(); err != nil {
			runiclog.Warn("Database close error", "error", err)
		}
	}
	if logsDB != nil {
		if err := logsDB.Close(); err != nil {
			runiclog.Warn("Logs database close error", "error", err)
		}
	}
}

func startOfflineDetector(ctx context.Context, database *sql.DB) {
	ticker := time.NewTicker(constants.OfflineDetectorInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			runiclog.Debug("Offline detector shutting down")
			return
		case <-ticker.C:
			_, err := database.ExecContext(ctx,
				fmt.Sprintf(`UPDATE peers SET status = 'offline'
				WHERE status = 'online'
				AND last_heartbeat < datetime('now', '-%d seconds')`, int(constants.OfflineThreshold.Seconds())),
			)
			if err != nil {
				runiclog.Warn("Offline detector error", "error", err)
			}
		}
	}
}

func startTokenCleanup(ctx context.Context, ts *store.TokenStore) {
	ticker := time.NewTicker(constants.OfflineCleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			runiclog.Debug("Token cleanup shutting down")
			return
		case <-ticker.C:
			if err := ts.CleanupExpiredTokens(ctx); err != nil {
				runiclog.Warn("Token cleanup error", "error", err)
			}
		}
	}
}
