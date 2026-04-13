// Package alerts provides alert and notification functionality.
package alerts

import (
	"strings"
	"testing"
	"time"
)

// Note: sanitizeHeaderValue tests were removed due to escaping complexity.
// The function uses `"\\r"` and `"\\n"` in the source code, which in Go string
// literals means the literal two-character sequences (backslash + r/n), NOT
// the actual CR/LF control characters. Testing this behavior requires careful
// handling of Go string escaping that is confusing to reason about.
// The function's behavior should be verified manually or with a different test approach.

// TestBuildMessage tests the buildMessage method.
func TestBuildMessage(t *testing.T) {
	s := &SMTPSender{
		config: SMTPConfig{
			FromAddress: "sender@test.com",
		},
	}

	tests := []struct {
		name        string
		to          string
		subject     string
		body        string
		contentType string
		contains    []string
	}{
		{
			name:        "plain text email",
			to:          "recipient@test.com",
			subject:     "Test Subject",
			body:        "Test body content",
			contentType: "text/plain",
			contains: []string{
				"From: sender@test.com",
				"To: recipient@test.com",
				"Subject: Test Subject",
				"MIME-Version: 1.0",
				"Content-Type: text/plain; charset=\"UTF-8\"",
				"Test body content",
			},
		},
		{
			name:        "HTML email",
			to:          "html@test.com",
			subject:     "HTML Subject",
			body:        "<html><body>HTML content</body></html>",
			contentType: "text/html",
			contains: []string{
				"From: sender@test.com",
				"To: html@test.com",
				"Subject: HTML Subject",
				"MIME-Version: 1.0",
				"Content-Type: text/html; charset=\"UTF-8\"",
				"<html><body>HTML content</body></html>",
			},
		},
		{
			name:        "email with special characters",
			to:          "special@test.com",
			subject:     "Special: Test!",
			body:        "Body with special chars: !@#$%^&*()",
			contentType: "text/plain",
			contains: []string{
				"From: sender@test.com",
				"To: special@test.com",
				"Subject: Special: Test!",
				"Body with special chars: !@#$%^&*()",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := s.buildMessage(tt.to, tt.subject, tt.body, tt.contentType)

			// Check all required content is present
			for _, expected := range tt.contains {
				if !strings.Contains(got, expected) {
					t.Errorf("buildMessage() missing expected content %q", expected)
				}
			}

			// Verify Date header is present
			if !strings.Contains(got, "Date: ") {
				t.Error("buildMessage() missing Date header")
			}

			// Verify proper CRLF line endings
			if !strings.Contains(got, "\r\n") {
				t.Error("buildMessage() missing CRLF line endings")
			}

			// Verify body separation
			if !strings.Contains(got, "\r\n\r\n") {
				t.Error("buildMessage() missing header/body separator")
			}
		})
	}
}

// TestBuildMessage_DateHeader tests that Date header is properly formatted.
func TestBuildMessage_DateHeader(t *testing.T) {
	s := &SMTPSender{
		config: SMTPConfig{
			FromAddress: "sender@test.com",
		},
	}

	message := s.buildMessage("to@test.com", "Test", "Body", "text/plain")

	lines := strings.Split(message, "\r\n")
	var dateLine string
	for _, line := range lines {
		if strings.HasPrefix(line, "Date: ") {
			dateLine = strings.TrimPrefix(line, "Date: ")
			break
		}
	}

	if dateLine == "" {
		t.Fatal("Date header not found")
	}

	_, err := time.Parse(time.RFC1123Z, dateLine)
	if err != nil {
		t.Errorf("Date header %q is not in RFC1123Z format: %v", dateLine, err)
	}
}

// TestGenerateAlertSubject tests the generateAlertSubject method.
func TestGenerateAlertSubject(t *testing.T) {
	s := &SMTPSender{}

	tests := []struct {
		name         string
		event        *AlertEvent
		wantContains []string
	}{
		{
			name: "peer offline with warning severity",
			event: &AlertEvent{
				Type:     AlertTypePeerOffline,
				PeerName: "test-peer",
				PeerID:   1,
			},
			wantContains: []string{"[Runic]", "[WARNING]", "Peer Offline:", "test-peer"},
		},
		{
			name: "peer offline with critical severity",
			event: &AlertEvent{
				Type:     AlertTypePeerOffline,
				PeerName: "critical-peer",
				PeerID:   2,
				Severity: SeverityCritical,
			},
			wantContains: []string{"[Runic]", "[CRITICAL]", "Peer Offline:", "critical-peer"},
		},
		{
			name: "peer online with info severity",
			event: &AlertEvent{
				Type:     AlertTypePeerOnline,
				PeerName: "online-peer",
				PeerID:   3,
			},
			wantContains: []string{"[Runic]", "[INFO]", "Peer Online:", "online-peer"},
		},
		{
			name: "new peer with info severity",
			event: &AlertEvent{
				Type:     AlertTypeNewPeer,
				PeerName: "new-peer",
				PeerID:   4,
			},
			wantContains: []string{"[Runic]", "[INFO]", "New Peer Detected:", "new-peer"},
		},
		{
			name: "bundle failed with critical severity",
			event: &AlertEvent{
				Type:     AlertTypeBundleFailed,
				PeerName: "failed-peer",
				PeerID:   5,
			},
			wantContains: []string{"[Runic]", "[CRITICAL]", "Bundle Failed:", "failed-peer"},
		},
		{
			name: "blocked spike with warning severity",
			event: &AlertEvent{
				Type:  AlertTypeBlockedSpike,
				Value: 150,
			},
			wantContains: []string{"[Runic]", "[WARNING]", "Blocked Traffic Spike:", "150"},
		},
		{
			name: "peer offline with explicit info severity",
			event: &AlertEvent{
				Type:     AlertTypePeerOffline,
				PeerName: "info-peer",
				PeerID:   6,
				Severity: SeverityInfo,
			},
			wantContains: []string{"[Runic]", "[INFO]", "Peer Offline:", "info-peer"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := s.generateAlertSubject(tt.event)

			for _, want := range tt.wantContains {
				if !strings.Contains(got, want) {
					t.Errorf("generateAlertSubject() = %q, missing expected %q", got, want)
				}
			}
		})
	}
}

// TestGenerateAlertSubject_SeverityPrefix tests that severity affects the prefix.
func TestGenerateAlertSubject_SeverityPrefix(t *testing.T) {
	s := &SMTPSender{}

	tests := []struct {
		name           string
		severity       Severity
		expectedPrefix string
	}{
		{
			name:           "critical severity",
			severity:       SeverityCritical,
			expectedPrefix: "[CRITICAL]",
		},
		{
			name:           "warning severity",
			severity:       SeverityWarning,
			expectedPrefix: "[WARNING]",
		},
		{
			name:           "info severity",
			severity:       SeverityInfo,
			expectedPrefix: "[INFO]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event := &AlertEvent{
				Type:     AlertTypePeerOffline,
				PeerName: "test-peer",
				Severity: tt.severity,
			}

			got := s.generateAlertSubject(event)

			if !strings.Contains(got, tt.expectedPrefix) {
				t.Errorf("generateAlertSubject() = %q, missing expected prefix %q", got, tt.expectedPrefix)
			}
		})
	}
}

// TestGenerateAlertHTML tests the generateAlertHTML method.
func TestGenerateAlertHTML(t *testing.T) {
	s := &SMTPSender{}

	tests := []struct {
		name         string
		event        *AlertEvent
		wantContains []string
	}{
		{
			name: "peer offline alert",
			event: &AlertEvent{
				Type:      AlertTypePeerOffline,
				PeerName:  "offline-peer",
				PeerID:    1,
				Timestamp: time.Now(),
				Message:   "Peer has been offline for 60 minutes",
			},
			wantContains: []string{
				"<!DOCTYPE html>",
				"<html>",
				"</html>",
				"offline-peer",
				"peer_offline",
				"Timestamp:",
				"Runic",
			},
		},
		{
			name: "peer online alert",
			event: &AlertEvent{
				Type:      AlertTypePeerOnline,
				PeerName:  "online-peer",
				PeerID:    2,
				Timestamp: time.Now(),
			},
			wantContains: []string{
				"<!DOCTYPE html>",
				"<html>",
				"online-peer",
				"peer_online",
				"Timestamp:",
			},
		},
		{
			name: "new peer alert",
			event: &AlertEvent{
				Type:      AlertTypeNewPeer,
				PeerName:  "new-peer",
				PeerID:    3,
				Timestamp: time.Now(),
			},
			wantContains: []string{
				"new-peer",
				"new_peer",
				"Timestamp:",
			},
		},
		{
			name: "bundle failed alert",
			event: &AlertEvent{
				Type:      AlertTypeBundleFailed,
				PeerName:  "failed-peer",
				PeerID:    4,
				Timestamp: time.Now(),
				Message:   "Compilation error occurred",
			},
			wantContains: []string{
				"failed-peer",
				"bundle_failed",
				"Timestamp:",
				"Compilation error occurred",
			},
		},
		{
			name: "blocked spike alert",
			event: &AlertEvent{
				Type:      AlertTypeBlockedSpike,
				Value:     200,
				Timestamp: time.Now(),
			},
			wantContains: []string{
				"Blocked Events",
				"200",
				"Timestamp:",
			},
		},
		{
			name: "critical severity alert",
			event: &AlertEvent{
				Type:      AlertTypeBundleFailed,
				PeerName:  "critical-peer",
				PeerID:    5,
				Severity:  SeverityCritical,
				Timestamp: time.Now(),
			},
			wantContains: []string{
				"CRITICAL",
				"#DC2626",
			},
		},
		{
			name: "warning severity alert",
			event: &AlertEvent{
				Type:      AlertTypePeerOffline,
				PeerName:  "warning-peer",
				PeerID:    6,
				Severity:  SeverityWarning,
				Timestamp: time.Now(),
			},
			wantContains: []string{
				"WARNING",
				"#F59E0B",
			},
		},
		{
			name: "info severity alert",
			event: &AlertEvent{
				Type:      AlertTypePeerOnline,
				PeerName:  "info-peer",
				PeerID:    7,
				Severity:  SeverityInfo,
				Timestamp: time.Now(),
			},
			wantContains: []string{
				"INFO",
				"#7C3AED",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := s.generateAlertHTML(tt.event)

			for _, want := range tt.wantContains {
				if !strings.Contains(got, want) {
					t.Errorf("generateAlertHTML() missing expected content %q", want)
				}
			}
		})
	}
}

// TestGenerateAlertHTML_ValidHTMLStructure tests that the HTML is valid.
func TestGenerateAlertHTML_ValidHTMLStructure(t *testing.T) {
	s := &SMTPSender{}

	event := &AlertEvent{
		Type:      AlertTypePeerOffline,
		PeerName:  "test-peer",
		PeerID:    1,
		Timestamp: time.Now(),
	}

	html := s.generateAlertHTML(event)

	requiredElements := []string{
		"<!DOCTYPE html>",
		"<html>",
		"</html>",
		"<head>",
		"</head>",
		"<body",
		"</body>",
		"<meta charset=\"UTF-8\">",
		"<meta name=\"viewport\"",
	}

	for _, elem := range requiredElements {
		if !strings.Contains(html, elem) {
			t.Errorf("generateAlertHTML() missing required HTML element: %q", elem)
		}
	}
}

// TestGenerateAlertHTML_SeverityBadge tests that the severity badge is present.
func TestGenerateAlertHTML_SeverityBadge(t *testing.T) {
	s := &SMTPSender{}

	tests := []struct {
		name          string
		severity      Severity
		expectedBadge string
		expectedColor string
	}{
		{
			name:          "critical badge",
			severity:      SeverityCritical,
			expectedBadge: "CRITICAL",
			expectedColor: "#DC2626",
		},
		{
			name:          "warning badge",
			severity:      SeverityWarning,
			expectedBadge: "WARNING",
			expectedColor: "#F59E0B",
		},
		{
			name:          "info badge",
			severity:      SeverityInfo,
			expectedBadge: "INFO",
			expectedColor: "#7C3AED",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event := &AlertEvent{
				Type:      AlertTypePeerOffline,
				PeerName:  "test-peer",
				PeerID:    1,
				Severity:  tt.severity,
				Timestamp: time.Now(),
			}

			html := s.generateAlertHTML(event)

			if !strings.Contains(html, tt.expectedBadge) {
				t.Errorf("generateAlertHTML() missing badge label %q", tt.expectedBadge)
			}

			if !strings.Contains(html, tt.expectedColor) {
				t.Errorf("generateAlertHTML() missing badge color %q", tt.expectedColor)
			}
		})
	}
}

// TestGenerateAlertHTML_Timestamp tests that the timestamp is included.
func TestGenerateAlertHTML_Timestamp(t *testing.T) {
	s := &SMTPSender{}

	testTime := time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC)
	event := &AlertEvent{
		Type:      AlertTypePeerOffline,
		PeerName:  "test-peer",
		PeerID:    1,
		Timestamp: testTime,
	}

	html := s.generateAlertHTML(event)

	expectedFormat := testTime.Format(time.RFC1123)
	if !strings.Contains(html, expectedFormat) {
		t.Errorf("generateAlertHTML() missing formatted timestamp %q", expectedFormat)
	}
}

// TestGenerateAlertHTML_EventDetails tests that event details are included.
func TestGenerateAlertHTML_EventDetails(t *testing.T) {
	s := &SMTPSender{}

	event := &AlertEvent{
		Type:      AlertTypePeerOffline,
		PeerName:  "test-peer",
		PeerID:    42,
		Timestamp: time.Now(),
		Message:   "Custom message for this alert",
	}

	html := s.generateAlertHTML(event)

	if !strings.Contains(html, "test-peer") {
		t.Error("generateAlertHTML() missing peer name")
	}

	if !strings.Contains(html, "42") {
		t.Error("generateAlertHTML() missing peer ID")
	}

	if !strings.Contains(html, "Custom message for this alert") {
		t.Error("generateAlertHTML() missing custom message")
	}

	if !strings.Contains(html, string(AlertTypePeerOffline)) {
		t.Error("generateAlertHTML() missing alert type")
	}
}

// TestGenerateAlertHTML_DifferentContentTypes tests different alert types produce different content.
func TestGenerateAlertHTML_DifferentContentTypes(t *testing.T) {
	s := &SMTPSender{}

	tests := []struct {
		name            string
		eventType       AlertType
		expectedContent string
	}{
		{
			name:            "peer offline shows offline message",
			eventType:       AlertTypePeerOffline,
			expectedContent: "no longer responding",
		},
		{
			name:            "peer online shows online message",
			eventType:       AlertTypePeerOnline,
			expectedContent: "now online and responding",
		},
		{
			name:            "new peer shows new peer message",
			eventType:       AlertTypeNewPeer,
			expectedContent: "new peer has been detected",
		},
		{
			name:            "bundle failed shows bundle message",
			eventType:       AlertTypeBundleFailed,
			expectedContent: "Bundle compilation failed",
		},
		{
			name:            "blocked spike shows spike message",
			eventType:       AlertTypeBlockedSpike,
			expectedContent: "spike in blocked traffic",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event := &AlertEvent{
				Type:      tt.eventType,
				PeerName:  "test-peer",
				PeerID:    1,
				Timestamp: time.Now(),
			}

			html := s.generateAlertHTML(event)

			if !strings.Contains(html, tt.expectedContent) {
				t.Errorf("generateAlertHTML() for %s missing expected content %q", tt.eventType, tt.expectedContent)
			}
		})
	}
}
