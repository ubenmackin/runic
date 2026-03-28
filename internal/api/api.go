package api

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/gorilla/mux"

	"runic/internal/api/agents"
	authhandlers "runic/internal/api/auth"
	"runic/internal/api/dashboard"
	"runic/internal/api/downloads"
	"runic/internal/api/events"
	"runic/internal/api/groups"
	"runic/internal/api/keys"
	"runic/internal/api/logs"
	"runic/internal/api/middleware"
	"runic/internal/api/peers"
	"runic/internal/api/policies"
	"runic/internal/api/services"
	"runic/internal/api/users"
	"runic/internal/auth"
	"runic/internal/db"
	"runic/internal/engine"
	"runic/internal/metrics"
)

// API holds dependencies for the API handlers.
type API struct {
	Compiler *engine.Compiler
	SSEHub   *events.SSEHub
	LogHub   *logs.Hub
}

// NewAPI creates a new API instance with the given compiler.
func NewAPI(compiler *engine.Compiler) *API {
	return &API{
		Compiler: compiler,
		SSEHub:   events.NewSSEHub(),
		LogHub:   logs.NewHub(),
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

// GetAPI retrieves the API instance from request context.
func GetAPI(ctx context.Context) *API {
	if a, ok := ctx.Value(apiContextKey).(*API); ok {
		return a
	}
	return nil
}

// RegisterRoutes registers all API routes. Accepts an API instance for rule compilation endpoints.
func RegisterRoutes(r *mux.Router, a *API, downloadsDir string) {

	// Apply RequestID middleware to all routes
	r.Use(RequestID())

	// Apply RequestLogger middleware for tracing requests
	r.Use(RequestLogger())

	// Apply CSP middleware for frontend routes (not API routes)
	// API routes have their own stricter CSP
	r.Use(CSP())

	// Create /api/v1 subrouter with common middleware
	apiRouter := r.PathPrefix("/api/v1").Subrouter()
	apiRouter.Use(CORS()) // CORS must be first to handle preflight OPTIONS requests
	apiRouter.Use(apiMiddleware(a))
	apiRouter.Use(metricsMiddleware)
	// API routes get stricter CSP (overwrites the general CSP)
	apiRouter.Use(CSPForAPI())

	// Public routes (no authentication required)
	// Setup
	apiRouter.HandleFunc("/setup", authhandlers.HandleSetup).Methods("GET")
	apiRouter.HandleFunc("/setup", authhandlers.HandleSetup).Methods("POST")

	// Login
	apiRouter.HandleFunc("/auth/login", authhandlers.HandleLoginPOST).Methods("POST")

	// Token refresh (public - uses refresh token, not access token)
	apiRouter.HandleFunc("/auth/refresh", authhandlers.HandleRefreshPOST).Methods("POST")

	// Agent registration (no auth needed)
	apiRouter.HandleFunc("/agent/register", agents.RegisterAgent).Methods("POST")

	// Protected routes (require JWT authentication)
	protected := apiRouter.NewRoute().Subrouter()
	protected.Use(auth.Middleware)

	// Logout
	protected.HandleFunc("/auth/logout", authhandlers.HandleLogoutPOST).Methods("POST")

	// Peers
	protected.HandleFunc("/peers", peers.GetPeers).Methods("GET")
	protected.HandleFunc("/peers", peers.CreatePeer).Methods("POST")
	protected.HandleFunc("/peers/{id:[0-9]+}", peers.DeletePeer).Methods("DELETE")
	protected.HandleFunc("/peers/{id:[0-9]+}/compile", peers.MakeCompilePeerHandler(a.Compiler)).Methods("POST")

	// Groups
	protected.HandleFunc("/groups", groups.ListGroups).Methods("GET")
	protected.HandleFunc("/groups", groups.CreateGroup).Methods("POST")
	protected.HandleFunc("/groups/{id:[0-9]+}", groups.GetGroup).Methods("GET")
	protected.HandleFunc("/groups/{id:[0-9]+}", groups.UpdateGroup).Methods("PUT")
	protected.HandleFunc("/groups/{id:[0-9]+}", groups.DeleteGroup).Methods("DELETE")

	// Group members
	protected.HandleFunc("/groups/{id:[0-9]+}/members", groups.ListGroupMembers).Methods("GET")
	protected.HandleFunc("/groups/{id:[0-9]+}/members", groups.MakeAddGroupMemberHandler(a.Compiler)).Methods("POST")
	protected.HandleFunc("/groups/{groupId:[0-9]+}/members/{peerId:[0-9]+}", groups.MakeDeleteGroupMemberHandler(a.Compiler)).Methods("DELETE")

	// Services
	protected.HandleFunc("/services", services.ListServices).Methods("GET")
	protected.HandleFunc("/services", services.CreateService).Methods("POST")
	protected.HandleFunc("/services/{id:[0-9]+}", services.GetService).Methods("GET")
	protected.HandleFunc("/services/{id:[0-9]+}", services.UpdateService).Methods("PUT")
	protected.HandleFunc("/services/{id:[0-9]+}", services.DeleteService).Methods("DELETE")

	// Policies
	protected.HandleFunc("/policies", policies.ListPolicies).Methods("GET")
	protected.HandleFunc("/policies", policies.MakeCreatePolicyHandler(a.Compiler)).Methods("POST")
	protected.HandleFunc("/policies/preview", policies.MakePolicyPreviewHandler(a.Compiler)).Methods("POST")
	protected.HandleFunc("/policies/{id:[0-9]+}", policies.GetPolicy).Methods("GET")
	protected.HandleFunc("/policies/{id:[0-9]+}", policies.MakeUpdatePolicyHandler(a.Compiler)).Methods("PUT")
	protected.HandleFunc("/policies/{id:[0-9]+}", policies.MakeDeletePolicyHandler(a.Compiler)).Methods("DELETE")

	// Dashboard
	protected.HandleFunc("/dashboard", dashboard.HandleDashboard).Methods("GET")

	// Setup Keys
	protected.HandleFunc("/setup-keys", keys.ListKeys).Methods("GET")
	protected.HandleFunc("/setup-keys/{type}", keys.CreateKey).Methods("POST")
	protected.HandleFunc("/setup-keys/{type}", keys.DeleteKey).Methods("DELETE")

	// Users
	protected.HandleFunc("/users", users.ListUsers).Methods("GET")
	protected.HandleFunc("/users", users.CreateUser).Methods("POST")
	protected.HandleFunc("/users/{id:[0-9]+}", users.DeleteUser).Methods("DELETE")

	// Logs (Phase 5)
	protected.HandleFunc("/logs", logs.GetLogs).Methods("GET")
	protected.HandleFunc("/logs/stream", logs.MakeLogsStreamHandler(a.LogHub)).Methods("GET")

	// Agent routes (require agent auth via JWT)
	apiRouter.HandleFunc("/agent/bundle/{host_id}", agents.AgentAuthMiddleware(agents.GetBundle)).Methods("GET")
	apiRouter.HandleFunc("/agent/heartbeat", agents.AgentAuthMiddleware(agents.Heartbeat)).Methods("GET", "POST")
	apiRouter.HandleFunc("/agent/logs", agents.AgentAuthMiddleware(agents.SubmitLogs)).Methods("POST")
	apiRouter.HandleFunc("/agent/bundle/{host_id}/applied", agents.AgentAuthMiddleware(agents.ConfirmBundleApplied)).Methods("POST")
	apiRouter.HandleFunc("/agent/events/{host_id}", agents.AgentAuthMiddleware(agents.MakeHandleSSEventsHandler(a.SSEHub))).Methods("GET")

	// Catch-all for unmatched API routes - returns 404 instead of falling through to SPA
	// This must be registered last so it only catches truly unmatched routes
	apiRouter.PathPrefix("/").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "API endpoint not found"})
	})

	// Downloads route (public - for agent binary downloads)
	// Must be registered before SPA catch-all handler (in main.go)
	// Rate limited to 10 requests per minute to prevent abuse
	downloadRateLimiter := middleware.NewRateLimiter(10, time.Minute)
	downloadsHandler := downloadRateLimiter.Middleware(http.HandlerFunc(downloads.Handler(downloadsDir)))
	r.Handle("/downloads/{filename}", downloadsHandler).Methods("GET")

	// Handle /api/v1 root path (not matched by PathPrefix subrouter)
	// Returns API info instead of falling through to SPA
	r.HandleFunc("/api/v1", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status":  "ok",
			"version": "v1",
			"message": "Runic API",
		})
	}).Methods("GET")
}

// HealthHandler returns the health status of the service
func HealthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "healthy"})
}

// ReadyHandler returns the readiness status of the service
func ReadyHandler(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	// Check database connectivity
	if err := db.DB.PingContext(ctx); err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]string{"status": "not_ready", "error": "database unavailable"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ready"})
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
		rw := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		next.ServeHTTP(rw, r)

		// Extract endpoint name from route
		var endpoint string
		if vars := mux.Vars(r); len(vars) > 0 {
			// Extract endpoint pattern without IDs
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

		// Record metrics
		metrics.RecordRequest(endpoint, r.Method, rw.statusCode, duration)

		// Record errors if status code is 5xx
		if rw.statusCode >= 500 {
			metrics.RecordError(endpoint, "server_error", rw.statusCode)
		}
	})
}

// responseWriter wraps http.ResponseWriter to capture status code
type responseWriter struct {
	http.ResponseWriter
	statusCode    int
	written       bool
	contentLength int
}

func (rw *responseWriter) WriteHeader(code int) {
	if !rw.written {
		rw.statusCode = code
		rw.ResponseWriter.WriteHeader(code)
		rw.written = true
	}
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	if !rw.written {
		rw.WriteHeader(http.StatusOK) // Default to 200 if WriteHeader not called
	}
	n, err := rw.ResponseWriter.Write(b)
	rw.contentLength += n
	return n, err
}
