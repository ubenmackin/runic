// Package api provides HTTP REST handlers.
package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"time"

	"github.com/gorilla/mux"

	"runic/internal/alerts"
	"runic/internal/api/agents"
	alerthandlers "runic/internal/api/alerts"
	authhandlers "runic/internal/api/auth"
	"runic/internal/api/common"
	"runic/internal/api/dashboard"
	"runic/internal/api/downloads"
	"runic/internal/api/events"
	"runic/internal/api/groups"
	"runic/internal/api/imports"
	"runic/internal/api/keys"
	"runic/internal/api/logs"
	"runic/internal/api/middleware"
	"runic/internal/api/peers"
	"runic/internal/api/pending"
	"runic/internal/api/policies"
	"runic/internal/api/services"
	"runic/internal/api/settings"
	"runic/internal/api/users"
	"runic/internal/auth"
	"runic/internal/common/log"
	"runic/internal/common/version"
	"runic/internal/crypto"
	dbpkg "runic/internal/db"
	"runic/internal/engine"
	"runic/internal/logcleanup"
	"runic/internal/metrics"
	"runic/internal/store"
)

// API holds dependencies for the API handlers.
type API struct {
	Compiler     *engine.Compiler
	DB           *sql.DB
	LogsDB       *sql.DB // Separate database for firewall logs
	AlertService *alerts.Service
	Encryptor    *crypto.Encryptor
	SSEHub       *events.SSEHub
	LogHub       *logs.Hub
	ChangeWorker *common.ChangeWorker
	PushWorker   *common.PushWorker

	Peers     *peers.Handler
	Agents    *agents.Handler
	Auth      *authhandlers.Handler
	Groups    *groups.Handler
	Policies  *policies.Handler
	Services  *services.Handler
	Imports   *imports.Handler
	Logs      *logs.Handler
	Users     *users.Handler
	Keys      *keys.Handler
	Pending   *pending.Handler
	Dashboard *dashboard.Handler
	Settings  *settings.Handler
	Alerts    *alerthandlers.Handler

	LoginRateLimiter    *middleware.RateLimiter
	RegisterRateLimiter *middleware.RateLimiter
	RefreshRateLimiter  *middleware.RateLimiter
	DownloadRateLimiter *middleware.RateLimiter
	LogoutRateLimiter   *middleware.RateLimiter
}

// NewAPI creates a new API instance with dependency injection.
// logsDBPath is the path to the logs database (separate from main DB).
func NewAPI(db *sql.DB, compiler *engine.Compiler, logsDBPath string, alertService *alerts.Service, encryptor *crypto.Encryptor) *API {
	logsDB, err := dbpkg.InitLogsDB(logsDBPath)
	if err != nil {
		log.Fatal("Failed to initialize logs database", "error", err)
	}

	// Migration: Copy existing firewall_logs to logs DB if needed
	if _, err := dbpkg.MigrateLogsFromMainDB(db, logsDB); err != nil {
		log.Warn("Log migration failed (existing logs will remain in main DB)", "error", err)
	}

	sseHub := events.NewSSEHub()
	changeWorker := common.NewChangeWorker(sseHub)
	pushWorker := common.NewPushWorker(db, compiler, alertService, sseHub)
	groupStore := store.NewGroupStore(db)
	policyStore := store.NewPolicyStore(db)
	return &API{
		Compiler:     compiler,
		DB:           db,
		LogsDB:       logsDB,
		AlertService: alertService,
		Encryptor:    encryptor,
		SSEHub:       sseHub,
		LogHub:       logs.NewHub(),
		ChangeWorker: changeWorker,
		PushWorker:   pushWorker,
		Peers:        peers.NewHandler(db, compiler, sseHub),
		Agents:       agents.NewHandler(db, logsDB, alertService),
		Auth:         authhandlers.NewHandler(db, db),
		Groups:       groups.NewHandler(db, compiler, changeWorker, groupStore),
		Policies:     policies.NewHandler(db, compiler, changeWorker, policyStore),
		Services:     services.NewHandler(db, compiler, changeWorker),
		Imports:      imports.NewHandler(db, sseHub, changeWorker),
		Logs:         logs.NewHandler(logsDB),
		Users:        users.NewHandler(db),
		Keys:         keys.NewHandler(db),
		Pending:      pending.NewHandler(db, compiler, sseHub, pushWorker),
		Dashboard:    dashboard.NewHandler(db, logsDB),
		Settings:     settings.NewHandler(db, logsDB, logsDBPath),
		Alerts:       alerthandlers.NewHandler(db, alertService, encryptor),
	}
}

type contextKey string

const apiContextKey contextKey = "api"

// apiMiddleware injects the API instance into request context for handlers.
func apiMiddleware(a *API) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), apiContextKey, a)
			ctx = agents.WithHubs(ctx, a.SSEHub, a.LogHub)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RegisterRoutes registers all API routes. Accepts an API instance for rule compilation endpoints.
func (a *API) RegisterRoutes(r *mux.Router, downloadsDir string) {

	ctx := context.Background()
	if a.PushWorker != nil {
		a.PushWorker.Start(ctx)
	}
	if a.ChangeWorker != nil {
		a.ChangeWorker.Start(ctx)
	}

	logCleanupWorker := logcleanup.NewWorker(a.DB, a.LogsDB)
	logCleanupWorker.Start(ctx)

	go a.LogHub.Run(ctx)

	// Apply SecurityHeaders as the outermost middleware to ensure ALL responses include security headers
	r.Use(SecurityHeaders)

	r.Use(RequestID())
	r.Use(RequestLogger())

	apiRouter := r.PathPrefix("/api/v1").Subrouter()
	apiRouter.Use(CORS()) // CORS must be first to handle preflight OPTIONS requests
	apiRouter.Use(apiMiddleware(a))
	apiRouter.Use(metricsMiddleware)
	// API routes have their own stricter CSP
	apiRouter.Use(CSPForAPI())

	// Health, Readiness, and Metrics endpoints (no authentication required)
	r.HandleFunc("/health", HealthHandler).Methods("GET")
	r.HandleFunc("/ready", ReadyHandler(a.DB)).Methods("GET")
	r.Handle("/metrics", MetricsHandler()).Methods("GET")

	// Per-endpoint rate limiters
	a.LoginRateLimiter = middleware.NewRateLimiter(5, time.Minute)
	a.RegisterRateLimiter = middleware.NewRateLimiter(10, time.Minute)
	a.RefreshRateLimiter = middleware.NewRateLimiter(10, time.Minute)
	a.LogoutRateLimiter = middleware.NewRateLimiter(10, time.Minute)

	apiRouter.HandleFunc("/setup", a.Auth.HandleSetup).Methods("GET")
	apiRouter.HandleFunc("/setup", a.Auth.HandleSetup).Methods("POST")

	apiRouter.Handle("/auth/login", a.LoginRateLimiter.Middleware(http.HandlerFunc(a.Auth.HandleLoginPOST))).Methods("POST")

	// Token refresh (public - uses refresh token, not access token)
	apiRouter.Handle("/auth/refresh", a.RefreshRateLimiter.Middleware(http.HandlerFunc(a.Auth.HandleRefreshPOST))).Methods("POST")

	apiRouter.Handle("/agent/register", a.RegisterRateLimiter.Middleware(http.HandlerFunc(a.Agents.RegisterAgent))).Methods("POST")

	// Protected routes (require JWT authentication)
	protected := apiRouter.NewRoute().Subrouter()
	protected.Use(auth.Middleware)

	protected.Handle("/auth/logout", a.LogoutRateLimiter.Middleware(http.HandlerFunc(a.Auth.HandleLogoutPOST))).Methods("POST")

	authViewer := protected.PathPrefix("/auth").Subrouter()
	a.Auth.RegisterRoutes(authViewer)

	dashboardViewer := protected.PathPrefix("/dashboard").Subrouter()
	a.Dashboard.RegisterRoutes(dashboardViewer)

	protected.HandleFunc("/logs", a.Logs.GetLogs).Methods("GET")
	protected.HandleFunc("/logs/stream", logs.MakeLogsStreamHandler(a.LogHub)).Methods("GET")

	peersViewer := protected.PathPrefix("/peers").Subrouter()
	a.Peers.RegisterRoutes(peersViewer)

	groupsViewer := protected.PathPrefix("/groups").Subrouter()
	a.Groups.RegisterRoutes(groupsViewer)

	servicesViewer := protected.PathPrefix("/services").Subrouter()
	a.Services.RegisterRoutes(servicesViewer)

	policiesViewer := protected.PathPrefix("/policies").Subrouter()
	a.Policies.RegisterRoutes(policiesViewer)

	protected.HandleFunc("/pending-changes", a.Pending.ListPendingChanges).Methods("GET")
	protected.HandleFunc("/pending-changes/{peerId:[0-9]+}", a.Pending.GetPeerPendingChanges).Methods("GET")

	protected.HandleFunc("/info", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]interface{}{
			"version":              version.Version,
			"commit":               version.Commit,
			"built_at":             version.BuiltAt,
			"latest_agent_version": version.AgentVersion,
		}); err != nil {
			log.Warn("Failed to encode version info", "error", err)
		}
	}).Methods("GET")

	admin := protected.PathPrefix("").Subrouter()
	admin.Use(middleware.RequireRole("admin"))

	admin.HandleFunc("/users", a.Users.ListUsers).Methods("GET")
	admin.HandleFunc("/users", a.Users.CreateUser).Methods("POST")
	admin.HandleFunc("/users/{id:[0-9]+}", a.Users.UpdateUser).Methods("PUT")
	admin.HandleFunc("/users/{id:[0-9]+}", a.Users.DeleteUser).Methods("DELETE")

	admin.HandleFunc("/setup-keys", a.Keys.ListKeys).Methods("GET")
	admin.HandleFunc("/setup-keys/{type}", a.Keys.CreateKey).Methods("POST")
	admin.HandleFunc("/setup-keys/{type}", a.Keys.DeleteKey).Methods("DELETE")

	admin.HandleFunc("/registration-tokens", a.Agents.ListRegistrationTokens).Methods("GET")
	admin.HandleFunc("/registration-tokens", a.Agents.GenerateRegistrationToken).Methods("POST")
	admin.HandleFunc("/registration-tokens/{id:[0-9]+}", a.Agents.RevokeRegistrationToken).Methods("DELETE")

	settingsAdmin := admin.PathPrefix("/settings").Subrouter()
	a.Settings.RegisterRoutes(settingsAdmin)

	admin.HandleFunc("/logs", a.Settings.ClearAllLogs).Methods("DELETE")

	if a.Alerts != nil {
		alertsAdmin := admin.PathPrefix("").Subrouter()
		a.Alerts.RegisterRoutes(alertsAdmin)
	}

	if a.Alerts != nil {
		userPrefs := protected.PathPrefix("").Subrouter()
		a.Alerts.RegisterUserRoutes(userPrefs)
	}

	editor := protected.PathPrefix("").Subrouter()
	editor.Use(middleware.RequireRole("admin", "editor"))

	peersEditor := editor.PathPrefix("/peers").Subrouter()
	a.Peers.RegisterRoutes(peersEditor)
	editor.HandleFunc("/peers/{id:[0-9]+}/update-agent", a.Peers.UpdateAgent).Methods("POST")

	groupsEditor := editor.PathPrefix("/groups").Subrouter()
	a.Groups.RegisterRoutes(groupsEditor)

	servicesEditor := editor.PathPrefix("/services").Subrouter()
	a.Services.RegisterRoutes(servicesEditor)

	policiesEditor := editor.PathPrefix("/policies").Subrouter()
	a.Policies.RegisterRoutes(policiesEditor)

	importsEditor := editor.PathPrefix("").Subrouter()
	a.Imports.RegisterRoutes(importsEditor)

	editor.HandleFunc("/pending-changes/{peerId:[0-9]+}/preview", a.Pending.PreviewPeerPendingBundle).Methods("POST")
	editor.HandleFunc("/pending-changes/{peerId:[0-9]+}/apply", a.Pending.ApplyPeerPendingBundle).Methods("POST")
	editor.HandleFunc("/pending-changes/{peerId:[0-9]+}/apply-entity", a.Pending.ApplyEntityPendingChanges).Methods("POST")
	editor.HandleFunc("/pending-changes/rollback", a.Pending.RollbackPendingChanges).Methods("POST")
	editor.HandleFunc("/pending-changes/apply-all", a.Pending.ApplyAllPendingBundles).Methods("POST")
	editor.HandleFunc("/pending-changes/push-all", a.Pending.PushAllRules).Methods("POST")
	editor.HandleFunc("/pending-changes/push/{peerId:[0-9]+}", a.Pending.PushCurrentRules).Methods("POST")
	editor.HandleFunc("/push-jobs/{job_id}/events", a.Pending.HandlePushJobSSE).Methods("GET")

	protected.HandleFunc("/events", a.Pending.HandleFrontendSSE).Methods("GET")

	// Agent routes (require agent auth via JWT)
	apiRouter.HandleFunc("/agent/bundle/{host_id}", a.Agents.AgentAuthMiddleware(a.Agents.GetBundle)).Methods("GET")
	apiRouter.HandleFunc("/agent/heartbeat", a.Agents.AgentAuthMiddleware(a.Agents.Heartbeat)).Methods("GET", "POST")
	apiRouter.HandleFunc("/agent/logs", a.Agents.AgentAuthMiddleware(a.Agents.SubmitLogs)).Methods("POST")
	apiRouter.HandleFunc("/agent/backup/{host_id}", a.Agents.AgentAuthMiddleware(a.Agents.SubmitBackup)).Methods("POST")
	apiRouter.HandleFunc("/agent/bundle/{host_id}/applied", a.Agents.AgentAuthMiddleware(a.Agents.ConfirmBundleApplied)).Methods("POST")
	apiRouter.HandleFunc("/agent/events/{host_id}", a.Agents.AgentAuthMiddleware(a.Agents.MakeHandleSSEventsHandler(a.SSEHub))).Methods("GET")
	apiRouter.HandleFunc("/agent/test-key", a.Agents.AgentAuthMiddleware(a.Agents.AgentTestKey)).Methods("POST")

	// Agent key rotation (public - authenticated via rotation token)
	apiRouter.HandleFunc("/agent/check-rotation", a.Agents.AgentAuthMiddleware(a.Agents.AgentCheckRotation)).Methods("GET")
	apiRouter.HandleFunc("/agent/rotate-key", a.Peers.AgentRotateKey).Methods("POST")
	apiRouter.HandleFunc("/agent/confirm-rotation", a.Peers.AgentConfirmRotation).Methods("POST")

	// Catch-all for unmatched API routes - returns 404 instead of falling through to SPA
	// This must be registered last so it only catches truly unmatched routes
	apiRouter.PathPrefix("/").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		if err := json.NewEncoder(w).Encode(map[string]string{"error": "API endpoint not found"}); err != nil {
			log.Warn("Failed to encode error", "err", err)
		}
	})

	// Downloads route (public - for agent binary downloads)
	// Must be registered before SPA catch-all handler (in main.go)
	// Rate limited to 10 requests per minute to prevent abuse
	a.DownloadRateLimiter = middleware.NewRateLimiter(10, time.Minute)
	downloadsHandler := a.DownloadRateLimiter.Middleware(downloads.Handler(downloadsDir))
	r.Handle("/downloads/{filename}", downloadsHandler).Methods("GET")

	// Handle /api/v1 root path (not matched by PathPrefix subrouter)
	// Returns API info instead of falling through to SPA
	r.HandleFunc("/api/v1", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]string{
			"status":  "ok",
			"version": "v1",
			"message": "Runic API",
		}); err != nil {
			log.Warn("Failed to encode api info", "err", err)
		}
	}).Methods("GET")
}

// Stop stops all rate limiter cleanup goroutines.
func (a *API) Stop() {
	if a.ChangeWorker != nil {
		a.ChangeWorker.Stop()
	}
	if a.PushWorker != nil {
		a.PushWorker.Stop()
	}
	if a.LoginRateLimiter != nil {
		a.LoginRateLimiter.Stop()
	}
	if a.RegisterRateLimiter != nil {
		a.RegisterRateLimiter.Stop()
	}
	if a.RefreshRateLimiter != nil {
		a.RefreshRateLimiter.Stop()
	}
	if a.DownloadRateLimiter != nil {
		a.DownloadRateLimiter.Stop()
	}
	if a.LogoutRateLimiter != nil {
		a.LogoutRateLimiter.Stop()
	}
	authhandlers.StopCleanup()
}

// HealthHandler returns the health status of the service
func HealthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]string{"status": "healthy"}); err != nil {
		log.Warn("Failed to encode health", "err", err)
	}
}

// ReadyHandler returns the readiness status of the service
func ReadyHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()

		if err := db.PingContext(ctx); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			if encErr := json.NewEncoder(w).Encode(map[string]string{"status": "not_ready", "error": "database unavailable"}); encErr != nil {
				log.Warn("Failed to encode not_ready", "error", encErr)
			}
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]string{"status": "ready"}); err != nil {
			log.Warn("Failed to encode ready", "error", err)
		}
	}
}

// MetricsHandler returns the Prometheus metrics HTTP handler
func MetricsHandler() http.Handler {
	return metrics.Handler()
}

// metricsMiddleware collects metrics for all requests
func metricsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Use ResponseRecorder to capture status code
		rw := common.NewResponseRecorder(w)

		next.ServeHTTP(rw, r)

		var endpoint string
		if vars := mux.Vars(r); len(vars) > 0 {
			endpoint = r.URL.Path
			for key := range vars {
				newLen := len(endpoint) - len(key) - 3
				if newLen > 0 {
					endpoint = endpoint[:newLen]
				}
				break
			}
		} else {
			endpoint = r.URL.Path
		}

		duration := time.Since(start)

		metrics.RecordRequest(endpoint, r.Method, rw.StatusCode(), duration)

		if rw.StatusCode() >= 500 {
			metrics.RecordError(endpoint, "server_error", rw.StatusCode())
		}
	})
}
