package metrics

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// gatherMetric collects all metric families and returns the one matching the given name.
func gatherMetric(g prometheus.Gatherer, name string) (*dto.MetricFamily, error) {
	families, err := g.Gather()
	if err != nil {
		return nil, err
	}
	for _, f := range families {
		if f.GetName() == name {
			return f, nil
		}
	}
	return nil, nil
}

// findMetricWithLabels finds a metric with matching label values.
func findMetricWithLabels(family *dto.MetricFamily, labels map[string]string) *dto.Metric {
	if family == nil {
		return nil
	}
	for _, m := range family.GetMetric() {
		match := true
		metricLabels := m.GetLabel()
		for k, v := range labels {
			found := false
			for _, l := range metricLabels {
				if l.GetName() == k && l.GetValue() == v {
					found = true
					break
				}
			}
			if !found {
				match = false
				break
			}
		}
		if match {
			return m
		}
	}
	return nil
}

// requireMetricGauge asserts that a gauge metric exists and returns its value.
func requireMetricGauge(t *testing.T, g prometheus.Gatherer, name string) float64 {
	t.Helper()
	family, err := gatherMetric(g, name)
	if err != nil {
		t.Fatalf("failed to gather metrics: %v", err)
	}
	if family == nil {
		t.Fatalf("%s metric family not found", name)
	}
	if len(family.GetMetric()) < 1 {
		t.Fatalf("%s metric not found", name)
	}
	return family.GetMetric()[0].GetGauge().GetValue()
}

// TestRecordRequest_IncrementsCounter tests that RecordRequest increments the http_requests_total counter.
func TestRecordRequest_IncrementsCounter(t *testing.T) {
	registry := prometheus.NewRegistry()
	m := NewMetrics(registry)
	endpoint := "/api/test"
	method := "GET"
	statusCode := 200
	duration := 100 * time.Millisecond

	m.RecordRequest(endpoint, method, statusCode, duration)

	family, err := gatherMetric(registry, "http_requests_total")
	if err != nil {
		t.Fatalf("failed to gather metrics: %v", err)
	}
	if family == nil {
		t.Fatal("http_requests_total metric family not found")
	}

	metric := findMetricWithLabels(family, map[string]string{
		"endpoint": endpoint,
		"method":   method,
		"status":   "200",
	})
	if metric == nil {
		t.Fatal("metric with expected labels not found")
	}

	if metric.GetCounter().GetValue() < 1 {
		t.Errorf("expected counter >= 1, got %f", metric.GetCounter().GetValue())
	}
}

// TestRecordRequest_RecordsDuration tests that RecordRequest observes the duration histogram.
func TestRecordRequest_RecordsDuration(t *testing.T) {
	registry := prometheus.NewRegistry()
	m := NewMetrics(registry)
	endpoint := "/api/duration"
	method := "POST"
	duration := 250 * time.Millisecond

	m.RecordRequest(endpoint, method, 201, duration)

	family, err := gatherMetric(registry, "http_request_duration_seconds")
	if err != nil {
		t.Fatalf("failed to gather metrics: %v", err)
	}
	if family == nil {
		t.Fatal("http_request_duration_seconds metric family not found")
	}

	metric := findMetricWithLabels(family, map[string]string{
		"endpoint": endpoint,
		"method":   method,
	})
	if metric == nil {
		t.Fatal("metric with expected labels not found")
	}

	if metric.GetHistogram().GetSampleCount() < 1 {
		t.Errorf("expected histogram sample count >= 1, got %d", metric.GetHistogram().GetSampleCount())
	}
}

// TestRecordRequest_DifferentStatusCodes tests that different status codes produce separate counters.
func TestRecordRequest_DifferentStatusCodes(t *testing.T) {
	registry := prometheus.NewRegistry()
	m := NewMetrics(registry)
	endpoint := "/api/status"
	method := "GET"

	m.RecordRequest(endpoint, method, 200, 10*time.Millisecond)
	m.RecordRequest(endpoint, method, 404, 10*time.Millisecond)
	m.RecordRequest(endpoint, method, 500, 10*time.Millisecond)

	family, err := gatherMetric(registry, "http_requests_total")
	if err != nil {
		t.Fatalf("failed to gather metrics: %v", err)
	}
	if family == nil {
		t.Fatal("http_requests_total metric family not found")
	}

	for _, code := range []string{"200", "404", "500"} {
		metric := findMetricWithLabels(family, map[string]string{
			"endpoint": endpoint,
			"method":   method,
			"status":   code,
		})
		if metric == nil {
			t.Errorf("metric for status code %s not found", code)
			continue
		}
		if metric.GetCounter().GetValue() < 1 {
			t.Errorf("expected counter >= 1 for status %s, got %f", code, metric.GetCounter().GetValue())
		}
	}
}

// TestRecordError_IncrementsCounter tests that RecordError increments the http_errors_total counter.
func TestRecordError_IncrementsCounter(t *testing.T) {
	registry := prometheus.NewRegistry()
	m := NewMetrics(registry)
	endpoint := "/api/error"
	errorType := "not_found"
	statusCode := 404

	m.RecordError(endpoint, errorType, statusCode)

	family, err := gatherMetric(registry, "http_errors_total")
	if err != nil {
		t.Fatalf("failed to gather metrics: %v", err)
	}
	if family == nil {
		t.Fatal("http_errors_total metric family not found")
	}

	metric := findMetricWithLabels(family, map[string]string{
		"endpoint":   endpoint,
		"error_type": errorType,
		"status":     "404",
	})
	if metric == nil {
		t.Fatal("metric with expected labels not found")
	}

	if metric.GetCounter().GetValue() < 1 {
		t.Errorf("expected counter >= 1, got %f", metric.GetCounter().GetValue())
	}
}

// TestRecordError_MultipleErrors tests that multiple error types are tracked separately.
func TestRecordError_MultipleErrors(t *testing.T) {
	registry := prometheus.NewRegistry()
	m := NewMetrics(registry)
	endpoint := "/api/errors"

	m.RecordError(endpoint, "not_found", 404)
	m.RecordError(endpoint, "internal_error", 500)
	m.RecordError(endpoint, "unauthorized", 401)

	family, err := gatherMetric(registry, "http_errors_total")
	if err != nil {
		t.Fatalf("failed to gather metrics: %v", err)
	}
	if family == nil {
		t.Fatal("http_errors_total metric family not found")
	}

	errorTypes := map[string]string{
		"not_found":      "404",
		"internal_error": "500",
		"unauthorized":   "401",
	}

	for errorType, status := range errorTypes {
		metric := findMetricWithLabels(family, map[string]string{
			"endpoint":   endpoint,
			"error_type": errorType,
			"status":     status,
		})
		if metric == nil {
			t.Errorf("metric for error_type=%s status=%s not found", errorType, status)
			continue
		}
		if metric.GetCounter().GetValue() < 1 {
			t.Errorf("expected counter >= 1 for error_type=%s, got %f", errorType, metric.GetCounter().GetValue())
		}
	}
}

// TestRecordError_SameErrorTwice tests that calling RecordError twice increments the counter.
func TestRecordError_SameErrorTwice(t *testing.T) {
	registry := prometheus.NewRegistry()
	m := NewMetrics(registry)
	endpoint := "/api/double-error"
	errorType := "timeout"

	m.RecordError(endpoint, errorType, 504)
	m.RecordError(endpoint, errorType, 504)

	family, err := gatherMetric(registry, "http_errors_total")
	if err != nil {
		t.Fatalf("failed to gather metrics: %v", err)
	}
	if family == nil {
		t.Fatal("http_errors_total metric family not found")
	}

	metric := findMetricWithLabels(family, map[string]string{
		"endpoint":   endpoint,
		"error_type": errorType,
		"status":     "504",
	})
	if metric == nil {
		t.Fatal("metric with expected labels not found")
	}

	if metric.GetCounter().GetValue() < 2 {
		t.Errorf("expected counter >= 2, got %f", metric.GetCounter().GetValue())
	}
}

// TestSetAgentCounters_SetsGauges tests that SetAgentCounters sets both connected and disconnected gauges.
func TestSetAgentCounters_SetsGauges(t *testing.T) {
	registry := prometheus.NewRegistry()
	m := NewMetrics(registry)
	m.SetAgentCounters(5, 2)

	gotConnected := requireMetricGauge(t, registry, "agents_connected")
	if gotConnected != 5 {
		t.Errorf("agents_connected = %f, want 5", gotConnected)
	}

	gotDisconnected := requireMetricGauge(t, registry, "agents_disconnected")
	if gotDisconnected != 2 {
		t.Errorf("agents_disconnected = %f, want 2", gotDisconnected)
	}
}

// TestSetAgentCounters_ZeroValues tests that SetAgentCounters handles zero values.
func TestSetAgentCounters_ZeroValues(t *testing.T) {
	registry := prometheus.NewRegistry()
	m := NewMetrics(registry)
	m.SetAgentCounters(0, 0)

	gotConnected := requireMetricGauge(t, registry, "agents_connected")
	if gotConnected != 0 {
		t.Errorf("agents_connected = %f, want 0", gotConnected)
	}
}

// TestSetPeersTotal_SetsGauge tests that SetPeersTotal sets the peer count gauge.
func TestSetPeersTotal_SetsGauge(t *testing.T) {
	registry := prometheus.NewRegistry()
	m := NewMetrics(registry)
	m.SetPeersTotal(10)

	got := requireMetricGauge(t, registry, "runic_peers_total")
	if got != 10 {
		t.Errorf("runic_peers_total = %f, want 10", got)
	}
}

// TestSetPoliciesTotal_SetsGauge tests that SetPoliciesTotal sets the policy count gauge.
func TestSetPoliciesTotal_SetsGauge(t *testing.T) {
	registry := prometheus.NewRegistry()
	m := NewMetrics(registry)
	m.SetPoliciesTotal(25)

	got := requireMetricGauge(t, registry, "runic_policies_total")
	if got != 25 {
		t.Errorf("runic_policies_total = %f, want 25", got)
	}
}

// TestRecordBundleCompilationDuration tests bundle compilation duration histogram observations.
func TestRecordBundleCompilationDuration(t *testing.T) {
	tests := []struct {
		name      string
		durations []time.Duration
		wantCount uint64
	}{
		{
			name:      "records histogram",
			durations: []time.Duration{500 * time.Millisecond},
			wantCount: 1,
		},
		{
			name:      "multiple observations",
			durations: []time.Duration{100 * time.Millisecond, 200 * time.Millisecond, 300 * time.Millisecond},
			wantCount: 3,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			registry := prometheus.NewRegistry()
			m := NewMetrics(registry)
			for _, d := range tt.durations {
				m.RecordBundleCompilationDuration(d)
			}
			family, err := gatherMetric(registry, "runic_bundle_compilation_duration_seconds")
			if err != nil {
				t.Fatalf("failed to gather metrics: %v", err)
			}
			if family == nil {
				t.Fatal("runic_bundle_compilation_duration_seconds metric family not found")
			}
			if len(family.GetMetric()) < 1 {
				t.Fatal("runic_bundle_compilation_duration_seconds metric not found")
			}
			h := family.GetMetric()[0].GetHistogram()
			if h.GetSampleCount() < tt.wantCount {
				t.Errorf("expected histogram sample count >= %d, got %d", tt.wantCount, h.GetSampleCount())
			}
		})
	}
}

// TestSetActiveConnections_SetsGauge tests that SetActiveConnections sets the connection count gauge.
func TestSetActiveConnections_SetsGauge(t *testing.T) {
	registry := prometheus.NewRegistry()
	m := NewMetrics(registry)
	m.SetActiveConnections(15)

	got := requireMetricGauge(t, registry, "runic_active_connections")
	if got != 15 {
		t.Errorf("runic_active_connections = %f, want 15", got)
	}
}

// TestSetActiveConnections_UpdateValue tests that SetActiveConnections can update an existing value.
func TestSetActiveConnections_UpdateValue(t *testing.T) {
	registry := prometheus.NewRegistry()
	m := NewMetrics(registry)
	m.SetActiveConnections(10)
	m.SetActiveConnections(20)

	got := requireMetricGauge(t, registry, "runic_active_connections")
	if got != 20 {
		t.Errorf("runic_active_connections = %f, want 20", got)
	}
}

// TestHandler_ReturnsHTTPHandler tests that Handler returns a valid HTTP handler.
func TestHandler_ReturnsHTTPHandler(t *testing.T) {
	h := Handler()
	if h == nil {
		t.Fatal("Handler() returned nil")
	}

	// Verify it's a valid http.Handler by making a test request
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, rec.Code)
	}
}

// TestRecordRequest_MultipleMethods tests that different HTTP methods produce separate counters.
func TestRecordRequest_MultipleMethods(t *testing.T) {
	registry := prometheus.NewRegistry()
	m := NewMetrics(registry)
	endpoint := "/api/methods"

	m.RecordRequest(endpoint, "GET", 200, 10*time.Millisecond)
	m.RecordRequest(endpoint, "POST", 201, 10*time.Millisecond)
	m.RecordRequest(endpoint, "DELETE", 204, 10*time.Millisecond)

	family, err := gatherMetric(registry, "http_requests_total")
	if err != nil {
		t.Fatalf("failed to gather metrics: %v", err)
	}
	if family == nil {
		t.Fatal("http_requests_total metric family not found")
	}

	methods := []string{"GET", "POST", "DELETE"}
	statuses := []string{"200", "201", "204"}

	for i, method := range methods {
		metric := findMetricWithLabels(family, map[string]string{
			"endpoint": endpoint,
			"method":   method,
			"status":   statuses[i],
		})
		if metric == nil {
			t.Errorf("metric for method=%s status=%s not found", method, statuses[i])
			continue
		}
		if metric.GetCounter().GetValue() < 1 {
			t.Errorf("expected counter >= 1 for method=%s, got %f", method, metric.GetCounter().GetValue())
		}
	}
}

// TestDefaultMetricsFunctions tests that package-level functions work with the default metrics.
func TestDefaultMetricsFunctions(t *testing.T) {
	// This test verifies that the default Metrics instance works correctly.
	// We can't test isolation here since it uses the global registry,
	// but we can verify the functions don't panic.
	RecordRequest("/api/default", "GET", 200, 10*time.Millisecond)
	RecordError("/api/default", "test_error", 500)
	SetAgentCounters(1, 0)
	SetPeersTotal(5)
	SetPoliciesTotal(10)
	RecordBundleCompilationDuration(100 * time.Millisecond)
	SetActiveConnections(3)
}
