package main

import (
	"context"
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

func main() {
	dbPath := os.Getenv("RUNIC_DB_PATH")
	if dbPath == "" {
		dbPath = "./runic.db"
	}
	db.InitDB(dbPath)

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

	// Public routes
	r.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		token, err := auth.GenerateToken("admin")
		if err != nil {
			http.Error(w, "Error generating token", http.StatusInternalServerError)
			return
		}
		w.Write([]byte(token))
	}).Methods("POST")

	// Logout route (requires valid token)
	r.HandleFunc("/logout", auth.LogoutHandler).Methods("POST")

	// Health and Metrics endpoints (no authentication required)
	r.HandleFunc("/health", api.HealthHandler).Methods("GET")
	r.HandleFunc("/ready", api.ReadyHandler).Methods("GET")
	r.Handle("/metrics", api.MetricsHandler()).Methods("GET")

	// Protected routes
	protected := r.PathPrefix("/api").Subrouter()
	protected.Use(auth.Middleware)
	apiInstance := api.NewAPI(compiler)
	api.RegisterRoutes(protected, apiInstance)

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

	// Wait for SIGINT/SIGTERM to shut down
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	log.Println("Starting Runic server on :8080")
	go func() {
		if err := http.ListenAndServe(":8080", r); err != nil {
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
