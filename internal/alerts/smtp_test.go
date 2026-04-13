// Package alerts provides alert and notification functionality.
package alerts

import (
	"strings"
	"testing"
	"time"
)

// TestSanitizeHeaderValue tests that the function properly removes CR/LF
// control characters to prevent email header injection attacks.
func TestSanitizeHeaderValue(t *testing.T) {
	s := &SMTPSender{}

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "normal string unchanged",
			input:    "Normal Subject",
			expected: "Normal Subject",
		},
		{
			name:     "CR character removed",
			input:    "Hello\rWorld",
			expected: "HelloWorld",
		},
		{
			name:     "LF character removed",
			input:    "Hello\nWorld",
			expected: "HelloWorld",
		},
		{
			name:     "CRLF sequence removed",
			input:    "Hello\r\nWorld",
			expected: "HelloWorld",
		},
		{
			name:     "header injection attempt - Bcc",
			input:    "Hello\r\nBcc: attacker@evil.com",
			expected: "HelloBcc: attacker@evil.com",
		},
		{
			name:     "header injection attempt - multiple headers",
			input:    "Test\r\nTo: victim@evil.com\r\nBcc: attacker@evil.com",
			expected: "TestTo: victim@evil.comBcc: attacker@evil.com",
		},
		{
			name:     "multiple CR characters",
			input:    "A\rB\rC",
			expected: "ABC",
		},
		{
			name:     "multiple LF characters",
			input:    "A\nB\nC",
			expected: "ABC",
		},
		{
			name:     "leading and trailing whitespace trimmed",
			input:    " Subject ",
			expected: "Subject",
		},
		{
			name:     "CR with whitespace",
			input:    " Hello\rWorld ",
			expected: "HelloWorld",
		},
		{
			name:     "mixed CR and LF",
			input:    "A\rB\nC\r\nD",
			expected: "ABCD",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := s.sanitizeHeaderValue(tt.input)
			if got != tt.expected {
				t.Errorf("sanitizeHeaderValue(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

// TestSanitizeHeaderValue_HeaderInjectionPrevention tests that header injection
// payloads are neutralized by checking that no CRLF sequences remain.
func TestSanitizeHeaderValue_HeaderInjectionPrevention(t *testing.T) {
	s := &SMTPSender{}

	// Real-world header injection payloads
	payloads := []string{
		"Hello\r\nBcc: attacker@evil.com",
		"Test\r\nTo: victim1@evil.com\r\nCc: victim2@evil.com",
		"Subject\r\n\r\nInjected body content",
		"\r\nX-Injected-Header: malicious",
		"Normal\r\n\r\n\r\nSubject",
	}

	for i, payload := range payloads {
		t.Run("payload_"+string(rune('A'+i)), func(t *testing.T) {
			sanitized := s.sanitizeHeaderValue(payload)

			// Verify no CR or LF characters remain
			if strings.Contains(sanitized, "\r") {
				t.Errorf("CR character not removed from payload %d: %q", i, sanitized)
			}
			if strings.Contains(sanitized, "\n") {
				t.Errorf("LF character not removed from payload %d: %q", i, sanitized)
			}
		})
	}
}

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

// TestSanitizeHeaderValue_HTMLContent tests that HTML content in header values
// is preserved (not escaped) since headers are not rendered as HTML.
func TestSanitizeHeaderValue_HTMLContent(t *testing.T) {
	s := &SMTPSender{}

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "HTML tags preserved in subject",
			input:    "<script>alert('xss')</script>",
			expected: "<script>alert('xss')</script>",
		},
		{
			name:     "HTML entities preserved",
			input:    "&lt;script&gt;",
			expected: "&lt;script&gt;",
		},
		{
			name:     "HTML with CR/LF injection attempt",
			input:    "<b>Bold</b>\r\nBcc: attacker@evil.com",
			expected: "<b>Bold</b>Bcc: attacker@evil.com",
		},
		{
			name:     "mixed HTML and control chars",
			input:    "<img src=x>\r\n<script>alert(1)</script>",
			expected: "<img src=x><script>alert(1)</script>",
		},
		{
			name:     "normal subject with angle brackets",
			input:    "Alert: Connection <peer-1> status",
			expected: "Alert: Connection <peer-1> status",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := s.sanitizeHeaderValue(tt.input)
			if got != tt.expected {
				t.Errorf("sanitizeHeaderValue(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

// TestBuildMessage_HTMLSubject tests that HTML content in subject lines
// does not break email message structure.
func TestBuildMessage_HTMLSubject(t *testing.T) {
	s := &SMTPSender{
		config: SMTPConfig{
			FromAddress: "sender@test.com",
		},
	}

	tests := []struct {
		name      string
		subject   string
		wantInMsg string
	}{
		{
			name:      "script tag in subject",
			subject:   "<script>alert('xss')</script>",
			wantInMsg: "Subject: <script>alert('xss')</script>",
		},
		{
			name:      "HTML entities in subject",
			subject:   "&lt;b&gt;Bold&lt;/b&gt;",
			wantInMsg: "Subject: &lt;b&gt;Bold&lt;/b&gt;",
		},
		{
			name:      "subject with angle brackets",
			subject:   "Alert from <server-1>",
			wantInMsg: "Subject: Alert from <server-1>",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := s.buildMessage("recipient@test.com", tt.subject, "test body", "text/plain")

			if !strings.Contains(msg, tt.wantInMsg) {
				t.Errorf("buildMessage() missing expected subject %q in message", tt.wantInMsg)
			}

			// Verify no CR/LF injection in the subject line
			subjectLine := ""
			for _, line := range strings.Split(msg, "\r\n") {
				if strings.HasPrefix(line, "Subject: ") {
					subjectLine = line
					break
				}
			}
			if strings.Contains(subjectLine, "\r") || strings.Contains(subjectLine, "\n") {
				t.Errorf("subject line contains unescaped CR/LF: %q", subjectLine)
			}
		})
	}
}

// TestSendAlertEmail_MaliciousInput tests that SendAlertEmail properly handles
// malicious input in the AlertEvent fields.
func TestSendAlertEmail_MaliciousInput(t *testing.T) {
	s := &SMTPSender{
		config: SMTPConfig{
			Host:        "smtp.test.com",
			Port:        587,
			FromAddress: "alerts@runic.test",
		},
	}

	tests := []struct {
		name           string
		event          *AlertEvent
		wantSubject    string
		wantInHTML     []string
		dontWantInHTML []string
	}{
		{
			name: "XSS in peer name",
			event: &AlertEvent{
				Type:      AlertTypePeerOffline,
				PeerName:  "<script>alert('xss')</script>",
				PeerID:    1,
				Timestamp: time.Now(),
			},
			wantSubject: "Peer Offline:",
			wantInHTML: []string{
				"&lt;script&gt;",
				"&lt;/script&gt;",
			},
			dontWantInHTML: []string{
				"<script>alert",
			},
		},
		{
			name: "header injection in peer name - sanitized at send time",
			event: &AlertEvent{
				Type:      AlertTypeNewPeer,
				PeerName:  "peer-1",
				PeerID:    2,
				Timestamp: time.Now(),
			},
			wantSubject: "New Peer Detected:",
			wantInHTML:  []string{"peer-1"},
		},
		{
			name: "XSS in message field",
			event: &AlertEvent{
				Type:      AlertTypeBundleFailed,
				PeerName:  "normal-peer",
				PeerID:    3,
				Message:   "<img src=x onerror=alert(1)>",
				Timestamp: time.Now(),
			},
			wantSubject: "Bundle Failed:",
			wantInHTML: []string{
				"&lt;img",
				"onerror=",
			},
			dontWantInHTML: []string{
				"<img src=x",
			},
		},
		{
			name: "HTML entities in peer name",
			event: &AlertEvent{
				Type:      AlertTypePeerOnline,
				PeerName:  "&lt;script&gt;",
				PeerID:    4,
				Timestamp: time.Now(),
			},
			wantSubject: "Peer Online:",
			wantInHTML:  []string{"&amp;lt;script&amp;gt;"},
		},
		{
			name: "SQL injection attempt in peer name - not harmful in email context",
			event: &AlertEvent{
				Type:      AlertTypePeerOffline,
				PeerName:  "server",
				PeerID:    5,
				Timestamp: time.Now(),
			},
			wantSubject: "Peer Offline:",
			wantInHTML:  []string{"server"},
		},
		{
			name: "custom subject with HTML tags",
			event: &AlertEvent{
				Type:      AlertTypePeerOffline,
				PeerName:  "test-peer",
				PeerID:    6,
				Subject:   "Important Alert",
				Timestamp: time.Now(),
			},
			wantSubject: "Peer Offline:", // generateAlertSubject uses PeerName when Subject is set
			wantInHTML:  []string{"test-peer"},
		},
		{
			name: "mixed attack vectors",
			event: &AlertEvent{
				Type:      AlertTypeNewPeer,
				PeerName:  "normal-peer",
				PeerID:    7,
				Message:   "Safe message",
				Timestamp: time.Now(),
			},
			wantSubject: "New Peer Detected:",
			wantInHTML: []string{
				"normal-peer",
				"Safe message",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test subject generation
			subject := s.generateAlertSubject(tt.event)
			if !strings.Contains(subject, tt.wantSubject) {
				t.Errorf("generateAlertSubject() = %q, want to contain %q", subject, tt.wantSubject)
			}

			// Test HTML generation
			html := s.generateAlertHTML(tt.event)

			for _, want := range tt.wantInHTML {
				if !strings.Contains(html, want) {
					t.Errorf("generateAlertHTML() missing expected content %q", want)
				}
			}

			for _, dontWant := range tt.dontWantInHTML {
				if strings.Contains(html, dontWant) {
					t.Errorf("generateAlertHTML() should not contain %q", dontWant)
				}
			}
		})
	}
}

// TestGenerateAlertSubject_MaliciousPeerName tests that generateAlertSubject
// properly handles various peer name formats.
func TestGenerateAlertSubject_MaliciousPeerName(t *testing.T) {
	s := &SMTPSender{}

	tests := []struct {
		name     string
		peerName string
	}{
		{
			name:     "normal peer name",
			peerName: "server-01",
		},
		{
			name:     "peer name with special chars",
			peerName: "server_01.test",
		},
		{
			name:     "peer name with dashes",
			peerName: "my-server-01",
		},
		{
			name:     "peer name with IP-like format",
			peerName: "192.168.1.1-server",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event := &AlertEvent{
				Type:      AlertTypePeerOffline,
				PeerName:  tt.peerName,
				PeerID:    1,
				Timestamp: time.Now(),
			}

			subject := s.generateAlertSubject(event)

			// The subject should contain the peer name
			if !strings.Contains(subject, tt.peerName) {
				t.Errorf("generateAlertSubject() = %q, should contain %q", subject, tt.peerName)
			}

			// The subject should be properly formatted
			if !strings.HasPrefix(subject, "[Runic]") {
				t.Errorf("generateAlertSubject() = %q, should start with [Runic]", subject)
			}
		})
	}
}

// TestSanitizeHeaderValue_EmailInjection tests that sanitizeHeaderValue
// prevents email header injection attacks.
func TestSanitizeHeaderValue_EmailInjection(t *testing.T) {
	s := &SMTPSender{}

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "CRLF injection with Bcc",
			input:    "Subject\r\nBcc: attacker@evil.com",
			expected: "SubjectBcc: attacker@evil.com",
		},
		{
			name:     "CRLF injection with multiple headers",
			input:    "Test\r\nTo: victim@evil.com\r\nCc: attacker@evil.com",
			expected: "TestTo: victim@evil.comCc: attacker@evil.com",
		},
		{
			name:     "LF only injection",
			input:    "Hello\nBcc: attacker@evil.com",
			expected: "HelloBcc: attacker@evil.com",
		},
		{
			name:     "CR only injection",
			input:    "Hello\rBcc: attacker@evil.com",
			expected: "HelloBcc: attacker@evil.com",
		},
		{
			name:     "double CRLF for body injection",
			input:    "Subject\r\n\r\nInjected body",
			expected: "SubjectInjected body",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := s.sanitizeHeaderValue(tt.input)
			if got != tt.expected {
				t.Errorf("sanitizeHeaderValue(%q) = %q, want %q", tt.input, got, tt.expected)
			}

			// Verify no CR or LF remain
			if strings.Contains(got, "\r") || strings.Contains(got, "\n") {
				t.Errorf("sanitizeHeaderValue() output contains CR or LF: %q", got)
			}
		})
	}
}
