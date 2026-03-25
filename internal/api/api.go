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
	"runic/internal/api/events"
	"runic/internal/api/groups"
	"runic/internal/api/logs"
	"runic/internal/api/policies"
	"runic/internal/api/servers"
	"runic/internal/api/services"
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
func RegisterRoutes(r *mux.Router, a *API) {

	// Apply RequestID middleware to all routes
	r.Use(RequestID())

	// Create /api/v1 subrouter with common middleware
	apiRouter := r.PathPrefix("/api/v1").Subrouter()
	apiRouter.Use(apiMiddleware(a))
	apiRouter.Use(metricsMiddleware)

	// Public routes (no authentication required)
	// Setup
	apiRouter.HandleFunc("/setup", authhandlers.HandleSetup).Methods("GET")
	apiRouter.HandleFunc("/setup", authhandlers.HandleSetup).Methods("POST")

	// Login
	apiRouter.HandleFunc("/auth/login", authhandlers.HandleLoginPOST).Methods("POST")

	// Agent registration (no auth needed)
	apiRouter.HandleFunc("/agent/register", agents.RegisterAgent).Methods("POST")

	// Protected routes (require JWT authentication)
	protected := apiRouter.PathPrefix("/").Subrouter()
	protected.Use(auth.Middleware)

	// Logout
	protected.HandleFunc("/auth/logout", authhandlers.HandleLogoutPOST).Methods("POST")

	// Servers
	protected.HandleFunc("/servers", servers.GetServers).Methods("GET")
	protected.HandleFunc("/servers", servers.CreateServer).Methods("POST")
	protected.HandleFunc("/servers/{id:[0-9]+}/compile", servers.MakeCompileServerHandler(a.Compiler)).Methods("POST")

	// Groups
	protected.HandleFunc("/groups", groups.ListGroups).Methods("GET")
	protected.HandleFunc("/groups", groups.CreateGroup).Methods("POST")
	protected.HandleFunc("/groups/{id:[0-9]+}", groups.GetGroup).Methods("GET")
	protected.HandleFunc("/groups/{id:[0-9]+}", groups.UpdateGroup).Methods("PUT")
	protected.HandleFunc("/groups/{id:[0-9]+}", groups.DeleteGroup).Methods("DELETE")

	// Group members
	protected.HandleFunc("/groups/{id:[0-9]+}/members", groups.ListGroupMembers).Methods("GET")
	protected.HandleFunc("/groups/{id:[0-9]+}/members", groups.MakeAddGroupMemberHandler(a.Compiler)).Methods("POST")
	protected.HandleFunc("/groups/{groupId:[0-9]+}/members/{memberId:[0-9]+}", groups.MakeDeleteGroupMemberHandler(a.Compiler)).Methods("DELETE")

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

	// Logs (Phase 5)
	protected.HandleFunc("/logs", logs.GetLogs).Methods("GET")
	protected.HandleFunc("/logs/stream", logs.MakeLogsStreamHandler(a.LogHub)).Methods("GET")

	// Agent routes (require agent auth via JWT)
	apiRouter.HandleFunc("/agent/bundle/{host_id}", agents.AgentAuthMiddleware(agents.GetBundle)).Methods("GET")
	apiRouter.HandleFunc("/agent/heartbeat", agents.AgentAuthMiddleware(agents.Heartbeat)).Methods("GET", "POST")
	apiRouter.HandleFunc("/agent/logs", agents.AgentAuthMiddleware(agents.SubmitLogs)).Methods("POST")
	apiRouter.HandleFunc("/agent/bundle/{host_id}/applied", agents.AgentAuthMiddleware(agents.ConfirmBundleApplied)).Methods("POST")
	apiRouter.HandleFunc("/agent/events/{host_id}", agents.AgentAuthMiddleware(agents.HandleSSEvents)).Methods("GET")
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
