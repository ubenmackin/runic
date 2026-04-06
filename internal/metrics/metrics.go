// Package metrics provides instrumentation and telemetry tools.
package metrics

import (
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics holds all metric objects for the application.
type Metrics struct {
	// httpRequestsTotal tracks total HTTP requests by endpoint, method, and status
	httpRequestsTotal *prometheus.CounterVec

	// httpRequestDurationSeconds tracks HTTP request latency
	httpRequestDurationSeconds *prometheus.HistogramVec

	// httpErrorsTotal tracks HTTP errors by endpoint and error type
	httpErrorsTotal *prometheus.CounterVec

	// agentsConnected tracks the number of connected agents
	agentsConnected prometheus.Gauge

	// agentsDisconnected tracks the number of disconnected agents
	agentsDisconnected prometheus.Gauge

	// runicPeersTotal tracks the total number of peers
	runicPeersTotal prometheus.Gauge

	// runicPoliciesTotal tracks the total number of policies
	runicPoliciesTotal prometheus.Gauge

	// runicBundleCompilationDurationSeconds tracks bundle compilation duration
	runicBundleCompilationDurationSeconds prometheus.Histogram

	// runicActiveConnections tracks the number of active SSE/WebSocket connections
	runicActiveConnections prometheus.Gauge

	// registry is the prometheus registry used by this Metrics instance
	registry prometheus.Registerer
}

// defaultMetrics is the default Metrics instance that uses the default Prometheus registry.
var defaultMetrics *Metrics

func init() {
	// Initialize default metrics with the default Prometheus registry
	defaultMetrics = NewMetrics(prometheus.DefaultRegisterer)
}

// NewMetrics creates a new Metrics instance with the given registerer.
// If registerer is nil, it uses prometheus.DefaultRegisterer.
func NewMetrics(registerer prometheus.Registerer) *Metrics {
	if registerer == nil {
		registerer = prometheus.DefaultRegisterer
	}

	m := &Metrics{
		registry: registerer,
		httpRequestsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "http_requests_total",
				Help: "Total HTTP requests processed",
			},
			[]string{"endpoint", "method", "status"},
		),
		httpRequestDurationSeconds: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "http_request_duration_seconds",
				Help:    "HTTP request latency in seconds",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"endpoint", "method"},
		),
		httpErrorsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "http_errors_total",
				Help: "Total HTTP errors encountered",
			},
			[]string{"endpoint", "error_type", "status"},
		),
		agentsConnected: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "agents_connected",
			Help: "Number of currently connected agents",
		}),
		agentsDisconnected: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "agents_disconnected",
			Help: "Number of currently disconnected agents",
		}),
		runicPeersTotal: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "runic_peers_total",
			Help: "Total number of peers in the system",
		}),
		runicPoliciesTotal: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "runic_policies_total",
			Help: "Total number of policies in the system",
		}),
		runicBundleCompilationDurationSeconds: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "runic_bundle_compilation_duration_seconds",
			Help:    "Bundle compilation duration in seconds",
			Buckets: prometheus.DefBuckets,
		}),
		runicActiveConnections: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "runic_active_connections",
			Help: "Number of active SSE/WebSocket connections",
		}),
	}

	// Register all metrics with the registerer
	registerer.MustRegister(
		m.httpRequestsTotal,
		m.httpRequestDurationSeconds,
		m.httpErrorsTotal,
		m.agentsConnected,
		m.agentsDisconnected,
		m.runicPeersTotal,
		m.runicPoliciesTotal,
		m.runicBundleCompilationDurationSeconds,
		m.runicActiveConnections,
	)

	return m
}

// RecordRequest increments the request counter and records request duration.
// This function uses the default Metrics instance.
func RecordRequest(endpoint, method string, statusCode int, duration time.Duration) {
	defaultMetrics.RecordRequest(endpoint, method, statusCode, duration)
}

// RecordRequest increments the request counter and records request duration.
func (m *Metrics) RecordRequest(endpoint, method string, statusCode int, duration time.Duration) {
	status := strconv.Itoa(statusCode)
	m.httpRequestsTotal.WithLabelValues(endpoint, method, status).Inc()
	m.httpRequestDurationSeconds.WithLabelValues(endpoint, method).Observe(duration.Seconds())
}

// RecordError increments the error counter.
// This function uses the default Metrics instance.
func RecordError(endpoint string, errorType string, statusCode int) {
	defaultMetrics.RecordError(endpoint, errorType, statusCode)
}

// RecordError increments the error counter.
func (m *Metrics) RecordError(endpoint string, errorType string, statusCode int) {
	status := strconv.Itoa(statusCode)
	m.httpErrorsTotal.WithLabelValues(endpoint, errorType, status).Inc()
}

// SetAgentCounters sets the agent connection counts.
// This function uses the default Metrics instance.
func SetAgentCounters(connected, disconnected float64) {
	defaultMetrics.SetAgentCounters(connected, disconnected)
}

// SetAgentCounters sets the agent connection counts.
func (m *Metrics) SetAgentCounters(connected, disconnected float64) {
	m.agentsConnected.Set(connected)
	m.agentsDisconnected.Set(disconnected)
}

// SetPeersTotal sets the total number of peers.
// This function uses the default Metrics instance.
func SetPeersTotal(count float64) {
	defaultMetrics.SetPeersTotal(count)
}

// SetPeersTotal sets the total number of peers.
func (m *Metrics) SetPeersTotal(count float64) {
	m.runicPeersTotal.Set(count)
}

// SetPoliciesTotal sets the total number of policies.
// This function uses the default Metrics instance.
func SetPoliciesTotal(count float64) {
	defaultMetrics.SetPoliciesTotal(count)
}

// SetPoliciesTotal sets the total number of policies.
func (m *Metrics) SetPoliciesTotal(count float64) {
	m.runicPoliciesTotal.Set(count)
}

// RecordBundleCompilationDuration records the duration of bundle compilation.
// This function uses the default Metrics instance.
func RecordBundleCompilationDuration(duration time.Duration) {
	defaultMetrics.RecordBundleCompilationDuration(duration)
}

// RecordBundleCompilationDuration records the duration of bundle compilation.
func (m *Metrics) RecordBundleCompilationDuration(duration time.Duration) {
	m.runicBundleCompilationDurationSeconds.Observe(duration.Seconds())
}

// SetActiveConnections sets the number of active SSE/WebSocket connections.
// This function uses the default Metrics instance.
func SetActiveConnections(count float64) {
	defaultMetrics.SetActiveConnections(count)
}

// SetActiveConnections sets the number of active SSE/WebSocket connections.
func (m *Metrics) SetActiveConnections(count float64) {
	m.runicActiveConnections.Set(count)
}

// Handler returns the Prometheus metrics HTTP handler.
// This uses the default Prometheus registry.
func Handler() http.Handler {
	return promhttp.Handler()
}

// HandlerFor returns an HTTP handler for a specific Metrics instance's registry.
func (m *Metrics) HandlerFor() http.Handler {
	gatherer, ok := m.registry.(prometheus.Gatherer)
	if !ok {
		// Return a handler that returns an error
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "metrics registry does not implement Gatherer", http.StatusInternalServerError)
		})
	}
	return promhttp.HandlerFor(gatherer, promhttp.HandlerOpts{})
}
