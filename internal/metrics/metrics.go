// Package metrics provides instrumentation and telemetry tools.
package metrics

import (
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"runic/internal/common/log"
)

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

var defaultMetrics *Metrics

// RegisterMetrics initializes default metrics with the default Prometheus registry.
// Must be called explicitly at application startup before any metrics are recorded.
func RegisterMetrics() {
	defaultMetrics = NewMetrics(prometheus.DefaultRegisterer)
}

// NewMetrics uses prometheus.DefaultRegisterer if registerer is nil.
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
				Name: "http_request_duration_seconds",
				Help: "HTTP request latency in seconds",
				// NOTE: prometheus.DefBuckets (default: .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10)
				// provides poor resolution for very fast endpoints like health checks which complete in
				// sub-millisecond range. If more granularity is required for fast endpoints, consider
				// defining custom buckets such as prometheus.LinearBuckets(0.0001, 0.0002, 10).
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

	// Register all metrics with the registerer, skipping already-registered metrics to avoid panics
	for _, c := range []prometheus.Collector{
		m.httpRequestsTotal,
		m.httpRequestDurationSeconds,
		m.httpErrorsTotal,
		m.agentsConnected,
		m.agentsDisconnected,
		m.runicPeersTotal,
		m.runicPoliciesTotal,
		m.runicBundleCompilationDurationSeconds,
		m.runicActiveConnections,
	} {
		if err := registerer.Register(c); err != nil {
			if _, ok := err.(prometheus.AlreadyRegisteredError); !ok {
				log.Warn("Failed to register metric", "error", err)
			}
		}
	}

	return m
}

// RecordRequest uses the default Metrics instance.
func RecordRequest(endpoint, method string, statusCode int, duration time.Duration) {
	if defaultMetrics == nil {
		return
	}
	defaultMetrics.RecordRequest(endpoint, method, statusCode, duration)
}

func (m *Metrics) RecordRequest(endpoint, method string, statusCode int, duration time.Duration) {
	status := strconv.Itoa(statusCode)
	m.httpRequestsTotal.WithLabelValues(endpoint, method, status).Inc()
	m.httpRequestDurationSeconds.WithLabelValues(endpoint, method).Observe(duration.Seconds())
}

// RecordError uses the default Metrics instance.
func RecordError(endpoint string, errorType string, statusCode int) {
	if defaultMetrics == nil {
		return
	}
	defaultMetrics.RecordError(endpoint, errorType, statusCode)
}

func (m *Metrics) RecordError(endpoint string, errorType string, statusCode int) {
	status := strconv.Itoa(statusCode)
	m.httpErrorsTotal.WithLabelValues(endpoint, errorType, status).Inc()
}

// Handler uses the default Prometheus registry.
func Handler() http.Handler {
	return promhttp.Handler()
}
