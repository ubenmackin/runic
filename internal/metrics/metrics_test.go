package metrics

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

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

func TestGauge_AgentsConnected(t *testing.T) {
	registry := prometheus.NewRegistry()
	m := NewMetrics(registry)

	family, err := gatherMetric(registry, "agents_connected")
	if err != nil {
		t.Fatalf("failed to gather metrics: %v", err)
	}
	if family == nil {
		t.Fatal("agents_connected metric family not found")
	}

	// Gauge should start at 0
	if family.GetMetric()[0].GetGauge().GetValue() != 0 {
		t.Errorf("expected initial gauge value 0, got %f", family.GetMetric()[0].GetGauge().GetValue())
	}

	// Set gauge and verify
	m.agentsConnected.Set(5)
	family, err = gatherMetric(registry, "agents_connected")
	if err != nil {
		t.Fatalf("failed to gather metrics after set: %v", err)
	}
	if family.GetMetric()[0].GetGauge().GetValue() != 5 {
		t.Errorf("expected gauge value 5, got %f", family.GetMetric()[0].GetGauge().GetValue())
	}

	// Increment and verify
	m.agentsConnected.Inc()
	family, err = gatherMetric(registry, "agents_connected")
	if err != nil {
		t.Fatalf("failed to gather metrics after inc: %v", err)
	}
	if family.GetMetric()[0].GetGauge().GetValue() != 6 {
		t.Errorf("expected gauge value 6, got %f", family.GetMetric()[0].GetGauge().GetValue())
	}

	// Decrement and verify
	m.agentsConnected.Dec()
	family, err = gatherMetric(registry, "agents_connected")
	if err != nil {
		t.Fatalf("failed to gather metrics after dec: %v", err)
	}
	if family.GetMetric()[0].GetGauge().GetValue() != 5 {
		t.Errorf("expected gauge value 5, got %f", family.GetMetric()[0].GetGauge().GetValue())
	}
}

func TestGauge_RunicPeersTotal(t *testing.T) {
	registry := prometheus.NewRegistry()
	m := NewMetrics(registry)

	family, err := gatherMetric(registry, "runic_peers_total")
	if err != nil {
		t.Fatalf("failed to gather metrics: %v", err)
	}
	if family == nil {
		t.Fatal("runic_peers_total metric family not found")
	}

	// Gauge should start at 0
	if family.GetMetric()[0].GetGauge().GetValue() != 0 {
		t.Errorf("expected initial gauge value 0, got %f", family.GetMetric()[0].GetGauge().GetValue())
	}

	// Set gauge via Add
	m.runicPeersTotal.Add(10)
	family, err = gatherMetric(registry, "runic_peers_total")
	if err != nil {
		t.Fatalf("failed to gather metrics after add: %v", err)
	}
	if family.GetMetric()[0].GetGauge().GetValue() != 10 {
		t.Errorf("expected gauge value 10, got %f", family.GetMetric()[0].GetGauge().GetValue())
	}

	// Sub via Sub
	m.runicPeersTotal.Sub(3)
	family, err = gatherMetric(registry, "runic_peers_total")
	if err != nil {
		t.Fatalf("failed to gather metrics after sub: %v", err)
	}
	if family.GetMetric()[0].GetGauge().GetValue() != 7 {
		t.Errorf("expected gauge value 7, got %f", family.GetMetric()[0].GetGauge().GetValue())
	}
}

func TestGauge_RunicPoliciesTotal(t *testing.T) {
	registry := prometheus.NewRegistry()
	m := NewMetrics(registry)

	family, err := gatherMetric(registry, "runic_policies_total")
	if err != nil {
		t.Fatalf("failed to gather metrics: %v", err)
	}
	if family == nil {
		t.Fatal("runic_policies_total metric family not found")
	}

	// Set gauge and verify
	m.runicPoliciesTotal.Set(42)
	family, err = gatherMetric(registry, "runic_policies_total")
	if err != nil {
		t.Fatalf("failed to gather metrics: %v", err)
	}
	if family.GetMetric()[0].GetGauge().GetValue() != 42 {
		t.Errorf("expected gauge value 42, got %f", family.GetMetric()[0].GetGauge().GetValue())
	}
}

func TestGauge_ActiveConnections(t *testing.T) {
	registry := prometheus.NewRegistry()
	m := NewMetrics(registry)

	family, err := gatherMetric(registry, "runic_active_connections")
	if err != nil {
		t.Fatalf("failed to gather metrics: %v", err)
	}
	if family == nil {
		t.Fatal("runic_active_connections metric family not found")
	}

	// Set and verify
	m.runicActiveConnections.Set(3)
	family, err = gatherMetric(registry, "runic_active_connections")
	if err != nil {
		t.Fatalf("failed to gather metrics: %v", err)
	}
	if family.GetMetric()[0].GetGauge().GetValue() != 3 {
		t.Errorf("expected gauge value 3, got %f", family.GetMetric()[0].GetGauge().GetValue())
	}
}

func TestHistogram_BundleCompilationDuration(t *testing.T) {
	registry := prometheus.NewRegistry()
	m := NewMetrics(registry)

	// Observe some durations
	m.runicBundleCompilationDurationSeconds.Observe(0.5)
	m.runicBundleCompilationDurationSeconds.Observe(1.0)
	m.runicBundleCompilationDurationSeconds.Observe(2.5)

	family, err := gatherMetric(registry, "runic_bundle_compilation_duration_seconds")
	if err != nil {
		t.Fatalf("failed to gather metrics: %v", err)
	}
	if family == nil {
		t.Fatal("runic_bundle_compilation_duration_seconds metric family not found")
	}

	metric := family.GetMetric()[0]
	histogram := metric.GetHistogram()

	if histogram.GetSampleCount() != 3 {
		t.Errorf("expected sample count 3, got %d", histogram.GetSampleCount())
	}

	// Total of observed values: 0.5 + 1.0 + 2.5 = 4.0
	if histogram.GetSampleSum() != 4.0 {
		t.Errorf("expected sample sum 4.0, got %f", histogram.GetSampleSum())
	}
}

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
