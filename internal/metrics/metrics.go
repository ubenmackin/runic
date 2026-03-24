package metrics

import (
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	// httpRequestsTotal tracks total HTTP requests by endpoint, method, and status
	httpRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "Total HTTP requests processed",
		},
		[]string{"endpoint", "method", "status"},
	)

	// httpRequestDurationSeconds tracks HTTP request latency
	httpRequestDurationSeconds = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "http_request_duration_seconds",
			Help:    "HTTP request latency in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"endpoint", "method"},
	)

	// httpErrorsTotal tracks HTTP errors by endpoint and error type
	httpErrorsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_errors_total",
			Help: "Total HTTP errors encountered",
		},
		[]string{"endpoint", "error_type", "status"},
	)

	// agentsConnected tracks the number of connected agents
	agentsConnected = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "agents_connected",
		Help: "Number of currently connected agents",
	})

	// agentsDisconnected tracks the number of disconnected agents
	agentsDisconnected = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "agents_disconnected",
		Help: "Number of currently disconnected agents",
	})
)

// RecordRequest increments the request counter and records request duration
func RecordRequest(endpoint, method string, statusCode int, duration time.Duration) {
	status := strconv.Itoa(statusCode)
	httpRequestsTotal.WithLabelValues(endpoint, method, status).Inc()
	httpRequestDurationSeconds.WithLabelValues(endpoint, method).Observe(duration.Seconds())
}

// RecordError increments the error counter
func RecordError(endpoint string, errorType string, statusCode int) {
	status := strconv.Itoa(statusCode)
	httpErrorsTotal.WithLabelValues(endpoint, errorType, status).Inc()
}

// SetAgentCounters sets the agent connection counts
func SetAgentCounters(connected, disconnected float64) {
	agentsConnected.Set(connected)
	agentsDisconnected.Set(disconnected)
}

// Handler returns the Prometheus metrics HTTP handler
func Handler() http.Handler {
	return promhttp.Handler()
}
