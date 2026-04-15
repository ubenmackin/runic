package metrics

import (
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
