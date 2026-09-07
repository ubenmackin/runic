// Package api provides HTTP REST handlers.
package api

import (
	"context"
	"database/sql"
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
	"runic/internal/common/constants"
	"runic/internal/common/log"
	"runic/internal/common/version"
	"runic/internal/crypto"
	dbpkg "runic/internal/db"
	"runic/internal/engine"
	"runic/internal/logcleanup"
	"runic/internal/metrics"
	"runic/internal/store"
)

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

	Peers      *peers.Handler
	Agents     *agents.Handler
	Auth       *authhandlers.Handler
	Groups     *groups.Handler
	Policies   *policies.Handler
	Services   *services.Handler
	Imports    *imports.Handler
	Logs       *logs.Handler
	Users      *users.Handler
	UserTokens *users.TokenHandler
	Keys       *keys.Handler
	Pending    *pending.Handler
	Dashboard  *dashboard.Handler
	Settings   *settings.Handler
	Alerts     *alerthandlers.Handler

	LoginRateLimiter    *middleware.RateLimiter
	RegisterRateLimiter *middleware.RateLimiter
	RefreshRateLimiter  *middleware.RateLimiter
	DownloadRateLimiter *middleware.RateLimiter
	LogoutRateLimiter   *middleware.RateLimiter
	TokenRateLimiter    *middleware.RateLimiter

	logCleanupWorker *logcleanup.Worker
	logCleanupCancel context.CancelFunc
	logHubCtx        context.Context
	logHubCancel     context.CancelFunc
}

// NewAPI creates a new API instance. logsDB is the already-initialized logs database connection.
// logsDBPath is the path to the logs database (for settings/clear-logs).
func NewAPI(db *sql.DB, compiler *engine.Compiler, logsDB *sql.DB, logsDBPath string, alertService *alerts.Service, encryptor *crypto.Encryptor) *API {
	// Migration: Copy existing firewall_logs to logs DB if needed
	if _, err := dbpkg.MigrateLogsFromMainDB(context.Background(), db, logsDB); err != nil {
		log.Warn("Log migration failed (existing logs will remain in main DB)", "error", err)
	}

	sseHub := events.NewSSEHub()
	changeWorker := common.NewChangeWorker(sseHub, db)
	pushWorker := common.NewPushWorker(db, compiler, alertService, sseHub)
	groupStore := store.NewGroupStore(db)
	policyStore := store.NewPolicyStore(db)
	peerStore := store.NewPeerStore(db)
	serviceStore := store.NewServiceStore(db)
	userStore := store.NewUserStore(db)
	settingsStore := store.NewSettingsStore(db, logsDB)
	importStore := store.NewImportStore(db, peerStore, groupStore, serviceStore)
	dashboardStore := store.NewDashboardStore(db, logsDB)
	alertStore := store.NewAlertStore(db)
	keyStore, err := store.NewKeyStore(db)
	if err != nil {
		// db is guaranteed non-nil when NewAPI is called; this should never happen.
		log.Error("Failed to create key store", "error", err)
		return nil
	}
	logsStore := store.NewLogsStore(logsDB)
	pendingStore := store.NewPendingStore(db)
	peersHandler := peers.NewHandler(peerStore, db, compiler, sseHub, settingsStore)
	peersHandler.DashboardStore = dashboardStore
	peersHandler.PendingStore = pendingStore
	peersHandler.AlertService = alertService
	if _, err := dashboardStore.PurgeAgentUpdateLogs(context.Background()); err != nil {
		log.Warn("Failed to purge legacy agent update logs (firewall_logs will retain agent_update rows)", "error", err)
	}
	userTokenStore := store.NewUserTokenStore(db)
	// Wire PAT authentication so `Bearer runic_pat_*` credentials issued below
	// authenticate through the shared auth middleware with live role lookup.
	auth.SetPATStore(userTokenStore)
	auth.SetPATUserStore(userStore)
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
		Peers:        peersHandler,
		Agents:       agents.NewHandler(peerStore, dashboardStore, alertService, importStore, store.NewTokenStore(db), db),
		Auth:         authhandlers.NewHandler(userStore, store.NewTokenStore(db), db),
		Groups:       groups.NewHandler(db, compiler, changeWorker, groupStore, peerStore),
		Policies:     policies.NewHandler(db, compiler, changeWorker, policyStore),
		Services:     services.NewHandler(db, serviceStore, compiler, changeWorker),
		Imports:      imports.NewHandler(importStore, sseHub, changeWorker),
		Logs:         logs.NewHandler(logsStore, store.NewTokenStore(db)),
		Users:        users.NewHandler(userStore),
		UserTokens:   users.NewTokenHandler(userTokenStore, userStore),
		Keys:         keys.NewHandler(keyStore),
		Pending:      pending.NewHandler(peerStore, groupStore, policyStore, serviceStore, pendingStore, db, compiler, sseHub, pushWorker),
		Dashboard:    dashboard.NewHandler(dashboardStore),
		Settings:     settings.NewHandler(settingsStore, logsDBPath),
		Alerts:       alerthandlers.NewHandler(alertStore, alertService, encryptor, userStore),
	}
}

func apiMiddleware(a *API) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := agents.WithHubs(r.Context(), a.SSEHub, a.LogHub)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// stripSpoofableProxyHeaders removes attacker-controlled proxy headers before
// security-sensitive auth rate limiters run, so downstream handlers that still
// call common.GetClientIP for logging observe the true TCP peer instead of a
// spoofed X-Forwarded-For value. The StrictMiddleware limiters paired with
// this wrapper key on common.RemoteAddrIP (ignoring those headers entirely),
// so X-Forwarded-For/X-Real-IP rotation cannot yield a fresh bucket per guess
// and bypass the login sliding window or the per-username+per-IP account
// lockout. Sharing one bucket per egress IP behind a legitimate proxy is
// acceptable for rare auth operations (5-10/min). See common.RemoteAddrIP
// and the trust warning on common.GetClientIP.
func stripSpoofableProxyHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Header.Del("X-Forwarded-For")
		r.Header.Del("X-Real-IP")
		next.ServeHTTP(w, r)
	})
}

// stripSpoofableProxyHeadersForRegister removes attacker-controlled proxy
// headers before the register rate limiter runs, so the limiter keys on
// RemoteAddr (via common.GetClientIP fallback) instead of a spoofable
// X-Forwarded-For value. Without this, a direct-exposure attacker could rotate
// the header per request to bypass the 10/min per-IP limit and brute-force
// hostnames or burn single-use tokens. Registration is rare, so sharing one
// bucket per egress IP behind a legitimate proxy is acceptable. See
// common.RemoteAddrIP and the trust warning on common.GetClientIP.
//
// Deprecated: prefer stripSpoofableProxyHeaders (identical behavior) for new
// auth routes; kept as a thin alias so existing call sites keep compiling.
func stripSpoofableProxyHeadersForRegister(next http.Handler) http.Handler {
	return stripSpoofableProxyHeaders(next)
}

// Start launches background lifecycle goroutines (workers, log hub, cleanup).
// This is separated from RegisterRoutes so that route registration remains pure.
func (a *API) Start(ctx context.Context) {
	if a.PushWorker != nil {
		a.PushWorker.Start(ctx)
	}
	if a.ChangeWorker != nil {
		a.ChangeWorker.Start(ctx)
	}

	var logCleanupCtx context.Context
	logCleanupCtx, a.logCleanupCancel = context.WithCancel(ctx)
	a.logCleanupWorker = logcleanup.NewWorker(a.DB, a.LogsDB)
	a.logCleanupWorker.Start(logCleanupCtx)

	a.logHubCtx, a.logHubCancel = context.WithCancel(ctx)
	go a.LogHub.Run(a.logHubCtx)
}

func (a *API) RegisterRoutes(r *mux.Router, downloadsDir string) {
	r.Use(PanicRecovery()) // outermost — catches panics from all downstream middlewares and handlers
	r.Use(SecurityHeaders)

	r.Use(RequestID())
	r.Use(RequestLogger())

	apiRouter := r.PathPrefix("/api/v1").Subrouter()
	apiRouter.Use(CORS()) // CORS applied to /api/v1 routes; handles preflight OPTIONS
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
	// Agent binary downloads burst to fleet width on Update All (21-way in
	// production) plus agent-side 429/5xx retries with backoff. A 10/min
	// limiter turns that burst into 429s that retries must then absorb, so
	// downloads get headroom while login/token minting stay tight. The
	// bulk fan-out additionally staggers SSE notifications (see
	// peers.Handler.UpdateAllAgents) and skips up-to-date peers so the
	// burst rarely reaches this ceiling.
	a.DownloadRateLimiter = middleware.NewRateLimiter(60, time.Minute)
	// PAT creation is rate-limited like login to bound credential minting.
	a.TokenRateLimiter = middleware.NewRateLimiter(5, time.Minute)

	apiRouter.Handle("/setup", stripSpoofableProxyHeaders(http.HandlerFunc(a.Auth.HandleSetupGET))).Methods("GET")
	apiRouter.Handle("/setup", stripSpoofableProxyHeaders(http.HandlerFunc(a.Auth.HandleSetupPOST))).Methods("POST")

	// Login is brute-force sensitive: the 5/min sliding-window limiter and the
	// 5-attempt/15-minute per-username+per-IP lockout (see
	// auth.CheckAndRecordFailure) both key on common.RemoteAddrIP, and
	// spoofable proxy headers are stripped first so rotating X-Forwarded-For
	// per guess cannot yield a fresh bucket. The StrictMiddleware limiter
	// ignores those headers even without stripping (defense in depth); the
	// strip additionally keeps request logs truthful.
	apiRouter.Handle("/auth/login", stripSpoofableProxyHeaders(a.LoginRateLimiter.StrictMiddleware(http.HandlerFunc(a.Auth.HandleLoginPOST)))).Methods("POST")

	// Token refresh (public - uses refresh token, not access token)
	// Protected by cookie presence check + IP rate limiting keyed on
	// RemoteAddrIP so header rotation cannot bypass the 10/min limit.
	apiRouter.Handle("/auth/refresh", RequireRefreshCookie()(stripSpoofableProxyHeaders(a.RefreshRateLimiter.StrictMiddleware(http.HandlerFunc(a.Auth.HandleRefreshPOST))))).Methods("POST")

	// Agent registration stays public (new peers hold no JWT yet) but the
	// handler requires a fresh single-use token or proof of possession for
	// existing hosts, and the limiter is keyed on RemoteAddrIP (spoofable
	// proxy headers stripped above) so X-Forwarded-For rotation cannot
	// bypass it.
	apiRouter.Handle("/agent/register", stripSpoofableProxyHeadersForRegister(a.RegisterRateLimiter.StrictMiddleware(http.HandlerFunc(a.Agents.RegisterAgent)))).Methods("POST")

	// Protected routes (require JWT authentication)
	protected := apiRouter.NewRoute().Subrouter()
	protected.Use(auth.Middleware)

	// Logout is authenticated so brute force is out of scope, but it stays
	// rate-limited on RemoteAddrIP for abuse bounding with the same
	// header-stripping hardening as the other auth endpoints.
	protected.Handle("/auth/logout", stripSpoofableProxyHeaders(a.LogoutRateLimiter.StrictMiddleware(http.HandlerFunc(a.Auth.HandleLogoutPOST)))).Methods("POST")

	authViewer := protected.PathPrefix("/auth").Subrouter()
	a.Auth.RegisterRoutes(authViewer)

	dashboardViewer := protected.PathPrefix("/dashboard").Subrouter()
	a.Dashboard.RegisterRoutes(dashboardViewer)

	protected.HandleFunc("/logs", a.Logs.GetLogs).Methods("GET")
	protected.HandleFunc("/logs/stream", logs.MakeLogsStreamHandler(a.LogHub, store.NewTokenStore(a.DB))).Methods("GET")

	peersViewer := protected.PathPrefix("/peers").Subrouter()
	a.Peers.RegisterReadRoutes(peersViewer)

	groupsViewer := protected.PathPrefix("/groups").Subrouter()
	a.Groups.RegisterReadRoutes(groupsViewer)

	servicesViewer := protected.PathPrefix("/services").Subrouter()
	a.Services.RegisterReadRoutes(servicesViewer)

	policiesViewer := protected.PathPrefix("/policies").Subrouter()
	a.Policies.RegisterReadRoutes(policiesViewer)

	protected.HandleFunc("/pending-changes", a.Pending.ListPendingChanges).Methods("GET")
	protected.HandleFunc("/pending-changes/{peerId:[0-9]+}", a.Pending.GetPeerPendingChanges).Methods("GET")

	protected.HandleFunc("/info", func(w http.ResponseWriter, r *http.Request) {
		common.RespondJSON(w, http.StatusOK, map[string]interface{}{
			"version":              version.Version,
			"commit":               version.Commit,
			"built_at":             version.BuiltAt,
			"latest_agent_version": version.AgentVersion,
		})
	}).Methods("GET")

	// User API tokens (PATs), self-service on the protected subrouter so any
	// role may manage its own tokens. Creation is rate-limited like login and
	// request bodies are capped at 1MB inside the handler.
	if a.UserTokens != nil {
		protected.HandleFunc("/users/me/tokens", a.UserTokens.ListTokens).Methods("GET")
		protected.Handle("/users/me/tokens", a.TokenRateLimiter.Middleware(http.HandlerFunc(a.UserTokens.CreateToken))).Methods("POST")
		protected.HandleFunc("/users/me/tokens/{id:[0-9]+}", a.UserTokens.RevokeToken).Methods("DELETE")
		// Legacy aliases without the /me/ segment (same self semantics).
		protected.HandleFunc("/users/tokens", a.UserTokens.ListTokens).Methods("GET")
		protected.Handle("/users/tokens", a.TokenRateLimiter.Middleware(http.HandlerFunc(a.UserTokens.CreateToken))).Methods("POST")
		protected.HandleFunc("/users/tokens/{token_id:[0-9]+}", a.UserTokens.RevokeToken).Methods("DELETE")
	}

	admin := protected.PathPrefix("").Subrouter()
	admin.Use(middleware.RequireRole("admin"))

	admin.HandleFunc("/users", a.Users.CreateUser).Methods("POST")
	admin.HandleFunc("/users/{id:[0-9]+}", a.Users.UpdateUser).Methods("PUT")
	admin.HandleFunc("/users/{id:[0-9]+}", a.Users.DeleteUser).Methods("DELETE")

	// Admin equivalents for managing another user's tokens (e.g. llm_agent).
	if a.UserTokens != nil {
		admin.HandleFunc("/users/{id:[0-9]+}/tokens", a.UserTokens.ListTokens).Methods("GET")
		admin.Handle("/users/{id:[0-9]+}/tokens", a.TokenRateLimiter.Middleware(http.HandlerFunc(a.UserTokens.CreateToken))).Methods("POST")
		admin.HandleFunc("/users/{id:[0-9]+}/tokens/{token_id:[0-9]+}", a.UserTokens.RevokeToken).Methods("DELETE")
	}

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

	editor.HandleFunc("/users", a.Users.ListUsers).Methods("GET")

	peersEditor := editor.PathPrefix("/peers").Subrouter()
	a.Peers.RegisterRoutes(peersEditor)
	editor.HandleFunc("/peers/{id:[0-9]+}/update-agent", a.Peers.UpdateAgent).Methods("POST")
	editor.HandleFunc("/peers/update-agents", a.Peers.UpdateAllAgents).Methods("POST")

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

	// Agent key rotation (rotate-key/confirm-rotation are public - authenticated via rotation token; check-rotation above stays JWT-authenticated). The
	// handlers enforce per-IP sliding windows keyed on common.RemoteAddrIP
	// (10/min rotate-key, 20/min confirm-rotation), ignoring
	// X-Forwarded-For/X-Real-IP so header rotation cannot yield a fresh
	// bucket per guess and brute-force rotation tokens on direct exposure
	// (same keying principle as middleware.StrictMiddleware). Spoofable
	// proxy headers are stripped first so downstream logging via
	// common.GetClientIP observes the true TCP peer.
	apiRouter.HandleFunc("/agent/check-rotation", a.Agents.AgentAuthMiddleware(a.Agents.AgentCheckRotation)).Methods("GET")
	apiRouter.Handle("/agent/rotate-key", stripSpoofableProxyHeaders(http.HandlerFunc(a.Peers.AgentRotateKey))).Methods("POST")
	apiRouter.Handle("/agent/confirm-rotation", stripSpoofableProxyHeaders(http.HandlerFunc(a.Peers.AgentConfirmRotation))).Methods("POST")

	// Catch-all for unmatched API routes - returns 404 instead of falling through to SPA
	// This must be registered last so it only catches truly unmatched routes
	apiRouter.PathPrefix("/").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		common.RespondError(w, http.StatusNotFound, "API endpoint not found")
	})

	// Downloads route (public - for agent binary downloads)
	// Must be registered before SPA catch-all handler (in main.go)
	// Rate limited to 60 requests per minute per IP: wide enough for a
	// staggered 21-way Update All burst plus backoff retries, tight enough
	// to bound abuse. The 429 path returns Retry-After, which the agent
	// download path honors with retry/backoff. The limiter uses
	// StrictMiddleware keyed on common.RemoteAddrIP with spoofable proxy
	// headers stripped first, so rotating X-Forwarded-For per request
	// cannot yield a fresh bucket and defeat the 60/min burst protection.
	downloadsHandler := stripSpoofableProxyHeaders(a.DownloadRateLimiter.StrictMiddleware(downloads.Handler(downloadsDir)))
	r.Handle("/downloads/{filename}", downloadsHandler).Methods("GET")

	// Share the staged-binary directory with the peers handler so bulk
	// agent updates can refuse to report sent when the deploy left the
	// downloads dir stale (missing arch binaries).
	if a.Peers != nil {
		a.Peers.DownloadsDir = downloadsDir
	}

	// Handle /api/v1 root path (not matched by PathPrefix subrouter)
	// Returns API info instead of falling through to SPA
	r.HandleFunc("/api/v1", func(w http.ResponseWriter, r *http.Request) {
		common.RespondJSON(w, http.StatusOK, map[string]string{
			"status":  "ok",
			"version": "v1",
			"message": "Runic API",
		})
	}).Methods("GET")
}

func (a *API) Stop() {
	if a.ChangeWorker != nil {
		a.ChangeWorker.Stop()
	}
	if a.PushWorker != nil {
		a.PushWorker.Stop()
	}
	if a.logCleanupCancel != nil {
		a.logCleanupCancel()
	}
	if a.logHubCancel != nil {
		a.logHubCancel()
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
	if a.TokenRateLimiter != nil {
		a.TokenRateLimiter.Stop()
	}
	authhandlers.StopCleanup()
	authhandlers.StopSetupRateLimit()
	peers.StopRotationRateLimiters()
}

func HealthHandler(w http.ResponseWriter, r *http.Request) {
	common.RespondJSON(w, http.StatusOK, map[string]string{"status": "healthy"})
}

func ReadyHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), constants.ReadyHandlerTimeout)
		defer cancel()

		if err := db.PingContext(ctx); err != nil {
			common.RespondJSON(w, http.StatusServiceUnavailable, map[string]string{
				"status": "not_ready",
				"error":  "database unavailable",
			})
			return
		}

		common.RespondJSON(w, http.StatusOK, map[string]string{"status": "ready"})
	}
}

func MetricsHandler() http.Handler {
	return metrics.Handler()
}

func metricsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Reuse existing ResponseRecorder if one is already in the chain (e.g. from RequestLogger)
		// to avoid double-wrapping the ResponseWriter.
		rw, ok := w.(*common.ResponseRecorder)
		if !ok {
			rw = common.NewResponseRecorder(w)
		}
		next.ServeHTTP(rw, r)

		endpoint := r.URL.Path
		if route := mux.CurrentRoute(r); route != nil {
			if tmpl, err := route.GetPathTemplate(); err == nil {
				endpoint = tmpl
			}
		}

		duration := time.Since(start)
		metrics.RecordRequest(endpoint, r.Method, rw.StatusCode(), duration)

		if rw.StatusCode() >= 500 {
			metrics.RecordError(endpoint, "server_error", rw.StatusCode())
		}
	})
}
