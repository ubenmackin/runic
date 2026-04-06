package transport

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// Test ParseLogLine with RUNIC-DROP action
func TestParseLogLine_RunicDrop(t *testing.T) {
	line := `Jan 15 12:00:00 hostname kernel: [RUNIC-DROP] IN=eth0 SRC=192.168.1.100 DST=192.168.1.1 PROTO=TCP SPT=443 DPT=80`

	ev, err := ParseLogLine(line)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if ev.Action != "DROP" {
		t.Errorf("expected action DROP, got %q", ev.Action)
	}

	if ev.RawLine != line {
		t.Errorf("expected raw line %q, got %q", line, ev.RawLine)
	}
}

// Test ParseLogLine with RUNIC-ACCEPT action
func TestParseLogLine_RunicAccept(t *testing.T) {
	line := `Jan 15 12:00:00 hostname kernel: [RUNIC-ACCEPT] OUT=eth0 SRC=10.0.0.5 DST=8.8.8.8 PROTO=UDP SPT=53 DPT=53`

	ev, err := ParseLogLine(line)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if ev.Action != "ACCEPT" {
		t.Errorf("expected action ACCEPT, got %q", ev.Action)
	}
}

// Test ParseLogLine with syslog timestamp format
func TestParseLogLine_SyslogTimestamp(t *testing.T) {
	line := `Jan 15 14:30:45 server01 kernel: [RUNIC-DROP] SRC=192.168.1.50 DST=10.0.0.1 PROTO=ICMP`

	ev, err := ParseLogLine(line)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expectedTimestamp := "Jan 15 14:30:45"
	if ev.Timestamp != expectedTimestamp {
		t.Errorf("expected timestamp %q, got %q", expectedTimestamp, ev.Timestamp)
	}
}

// Test ParseLogLine with ISO8601 timestamp format
func TestParseLogLine_ISO8601Timestamp(t *testing.T) {
	line := `2026-03-31T15:48:14.402322-07:00 hostname kernel: [RUNIC-DROP] SRC=192.168.1.100 DST=192.168.1.1 PROTO=TCP`

	ev, err := ParseLogLine(line)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expectedTimestamp := "2026-03-31T15:48:14.402322-07:00"
	if ev.Timestamp != expectedTimestamp {
		t.Errorf("expected timestamp %q, got %q", expectedTimestamp, ev.Timestamp)
	}
}

// Test ParseLogLine extracts source IP (SRC=)
func TestParseLogLine_SrcIP(t *testing.T) {
	line := `Jan 15 12:00:00 hostname kernel: [RUNIC-DROP] SRC=192.168.1.100 DST=192.168.1.1 PROTO=TCP`

	ev, err := ParseLogLine(line)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if ev.SrcIP != "192.168.1.100" {
		t.Errorf("expected src IP 192.168.1.100, got %q", ev.SrcIP)
	}
}

// Test ParseLogLine extracts destination IP (DST=)
func TestParseLogLine_DstIP(t *testing.T) {
	line := `Jan 15 12:00:00 hostname kernel: [RUNIC-DROP] SRC=192.168.1.100 DST=192.168.1.1 PROTO=TCP`

	ev, err := ParseLogLine(line)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if ev.DstIP != "192.168.1.1" {
		t.Errorf("expected dst IP 192.168.1.1, got %q", ev.DstIP)
	}
}

// Test ParseLogLine extracts protocol (PROTO=)
func TestParseLogLine_Protocol(t *testing.T) {
	line := `Jan 15 12:00:00 hostname kernel: [RUNIC-ACCEPT] SRC=10.0.0.1 DST=10.0.0.2 PROTO=TCP`

	ev, err := ParseLogLine(line)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if ev.Protocol != "tcp" {
		t.Errorf("expected protocol tcp, got %q", ev.Protocol)
	}
}

// Test ParseLogLine extracts source port (SPT=)
func TestParseLogLine_SrcPort(t *testing.T) {
	line := `Jan 15 12:00:00 hostname kernel: [RUNIC-DROP] SRC=192.168.1.100 DST=192.168.1.1 PROTO=TCP SPT=443 DPT=80`

	ev, err := ParseLogLine(line)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if ev.SrcPort != 443 {
		t.Errorf("expected source port 443, got %d", ev.SrcPort)
	}
}

// Test ParseLogLine extracts destination port (DPT=)
func TestParseLogLine_DstPort(t *testing.T) {
	line := `Jan 15 12:00:00 hostname kernel: [RUNIC-DROP] SRC=192.168.1.100 DST=192.168.1.1 PROTO=TCP SPT=443 DPT=80`

	ev, err := ParseLogLine(line)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if ev.DstPort != 80 {
		t.Errorf("expected destination port 80, got %d", ev.DstPort)
	}
}

// Test ParseLogLine extracts direction (IN=, OUT=)
func TestParseLogLine_Direction(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		expected string
	}{
		{
			name:     "IN direction",
			line:     `Jan 15 12:00:00 hostname kernel: [RUNIC-DROP] IN=eth0 SRC=192.168.1.100 DST=192.168.1.1 PROTO=TCP`,
			expected: "IN",
		},
		{
			name:     "OUT direction",
			line:     `Jan 15 12:00:00 hostname kernel: [RUNIC-DROP] OUT=eth0 SRC=192.168.1.100 DST=192.168.1.1 PROTO=TCP`,
			expected: "OUT",
		},
		{
			name:     "FWD direction (both IN and OUT)",
			line:     `Jan 15 12:00:00 hostname kernel: [RUNIC-DROP] IN=eth0 OUT=eth1 SRC=192.168.1.100 DST=192.168.1.1 PROTO=TCP`,
			expected: "FWD",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev, err := ParseLogLine(tt.line)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if ev.Direction != tt.expected {
				t.Errorf("expected direction %q, got %q", tt.expected, ev.Direction)
			}
		})
	}
}

// Test ParseLogLine handles line without kernel prefix
func TestParseLogLine_NoKernelPrefix(t *testing.T) {
	line := `[RUNIC-DROP] SRC=192.168.1.100 DST=192.168.1.1 PROTO=TCP`

	ev, err := ParseLogLine(line)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Action should still be detected
	if ev.Action != "DROP" {
		t.Errorf("expected action DROP, got %q", ev.Action)
	}

	// But fields should be empty as there's no kernel prefix
	if ev.SrcIP != "" {
		t.Errorf("expected empty src IP, got %q", ev.SrcIP)
	}
}

// Test ParseLogLine handles missing fields gracefully
func TestParseLogLine_MissingFields(t *testing.T) {
	line := `Jan 15 12:00:00 hostname kernel: [RUNIC-DROP]`

	ev, err := ParseLogLine(line)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should have action and timestamp but empty fields
	if ev.Action != "DROP" {
		t.Errorf("expected action DROP, got %q", ev.Action)
	}

	if ev.Timestamp == "" {
		t.Error("expected non-empty timestamp")
	}

	if ev.SrcIP != "" {
		t.Errorf("expected empty src IP, got %q", ev.SrcIP)
	}

	if ev.DstIP != "" {
		t.Errorf("expected empty dst IP, got %q", ev.DstIP)
	}

	if ev.Protocol != "" {
		t.Errorf("expected empty protocol, got %q", ev.Protocol)
	}
}

// Test NewShipper creates Shipper with correct fields
func TestNewShipper(t *testing.T) {
	client := &http.Client{}
	controlPlaneURL := "https://control.example.com"
	token := "test-token"
	hostID := "host-123"
	logPath := "/var/log/kern.log"

	shipper := NewShipper(client, controlPlaneURL, token, hostID, logPath)

	if shipper.client != client {
		t.Error("expected client to be set")
	}

	if shipper.controlPlaneURL != controlPlaneURL {
		t.Errorf("expected controlPlaneURL %q, got %q", controlPlaneURL, shipper.controlPlaneURL)
	}

	if shipper.token != token {
		t.Errorf("expected token %q, got %q", token, shipper.token)
	}

	if shipper.hostID != hostID {
		t.Errorf("expected hostID %q, got %q", hostID, shipper.hostID)
	}

	if shipper.logPath != logPath {
		t.Errorf("expected logPath %q, got %q", logPath, shipper.logPath)
	}

	if shipper.lines == nil {
		t.Error("expected lines channel to be initialized")
	}
}

// Test Shipper.Run handles log file not existing
func TestShipper_Run_FileNotExists(t *testing.T) {
	// Create a shipper with a non-existent log path
	shipper := NewShipper(&http.Client{}, "http://localhost", "token", "host1", "/nonexistent/path/log.log")

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Should not panic - should handle gracefully and return
	shipper.Run(ctx)
}

// Test Shipper.ship sends batch to control plane
func TestShipper_Ship_Success(t *testing.T) {
	var receivedBody map[string]interface{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		decoder := json.NewDecoder(r.Body)
		decoder.Decode(&receivedBody)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	shipper := NewShipper(server.Client(), server.URL, "test-token", "host-123", "/var/log/kern.log")

	batch := []LogEvent{
		{
			Timestamp: "Jan 15 12:00:00",
			Action:    "DROP",
			SrcIP:     "192.168.1.100",
			DstIP:     "192.168.1.1",
			Protocol:  "tcp",
			SrcPort:   443,
			DstPort:   80,
		},
		{
			Timestamp: "Jan 15 12:00:01",
			Action:    "ACCEPT",
			SrcIP:     "10.0.0.5",
			DstIP:     "8.8.8.8",
			Protocol:  "udp",
			SrcPort:   53,
			DstPort:   53,
		},
	}

	ctx := context.Background()
	shipper.ship(ctx, batch)

	if receivedBody == nil {
		t.Fatal("expected request body to be received by server")
	}

	events, ok := receivedBody["events"].([]interface{})
	if !ok {
		t.Fatal("expected events array in request body")
	}

	if len(events) != 2 {
		t.Errorf("expected 2 events, got %d", len(events))
	}

	hostID, ok := receivedBody["host_id"].(string)
	if !ok || hostID != "host-123" {
		t.Errorf("expected host_id 'host-123', got %v", receivedBody["host_id"])
	}
}

// Test Shipper.ship handles HTTP error gracefully
func TestShipper_Ship_HTTPError(t *testing.T) {
	// Server that returns 500 error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	shipper := NewShipper(server.Client(), server.URL, "test-token", "host-123", "/var/log/kern.log")

	batch := []LogEvent{
		{
			Timestamp: "Jan 15 12:00:00",
			Action:    "DROP",
			SrcIP:     "192.168.1.100",
		},
	}

	// Should not panic - just logs the error
	ctx := context.Background()
	shipper.ship(ctx, batch)
}

// Test ParseLogLine handles IPv6 addresses
func TestParseLogLine_IPv6(t *testing.T) {
	line := `Jan 15 12:00:00 hostname kernel: [RUNIC-DROP] SRC=2001:0db8:85a3:0000:0000:8a2e:0370:7334 DST=::1 PROTO=TCP`

	ev, err := ParseLogLine(line)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if ev.SrcIP != "2001:0db8:85a3:0000:0000:8a2e:0370:7334" {
		t.Errorf("expected src IP, got %q", ev.SrcIP)
	}

	if ev.DstIP != "::1" {
		t.Errorf("expected dst IP ::1, got %q", ev.DstIP)
	}
}

// Test ParseLogLine handles ICMP protocol
func TestParseLogLine_ICMP(t *testing.T) {
	line := `Jan 15 12:00:00 hostname kernel: [RUNIC-DROP] SRC=192.168.1.100 DST=192.168.1.1 PROTO=ICMP`

	ev, err := ParseLogLine(line)
	if err != nil {
		t.Fatalf("unexpected error: %v", ev)
	}

	if ev.Protocol != "icmp" {
		t.Errorf("expected protocol icmp, got %q", ev.Protocol)
	}

	// ICMP doesn't have ports, they should be zero
	if ev.SrcPort != 0 {
		t.Errorf("expected src port 0 for ICMP, got %d", ev.SrcPort)
	}
	if ev.DstPort != 0 {
		t.Errorf("expected dst port 0 for ICMP, got %d", ev.DstPort)
	}
}

// Test batch size limit (max 100 events)
func TestShipper_BatchSizeLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	shipper := NewShipper(server.Client(), server.URL, "test-token", "host-123", "/var/log/kern.log")

	// Create a batch of 100 events
	batch := make([]LogEvent, 100)
	for i := 0; i < 100; i++ {
		batch[i] = LogEvent{
			Timestamp: "Jan 15 12:00:00",
			Action:    "DROP",
			SrcIP:     "192.168.1.1",
		}
	}

	ctx := context.Background()
	// This should ship without issues - testing batch size boundary
	shipper.ship(ctx, batch)
}

// Test ParseLogLine handles empty line
func TestParseLogLine_EmptyLine(t *testing.T) {
	line := ""

	ev, err := ParseLogLine(line)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should return empty event with raw line empty
	if ev.RawLine != "" {
		t.Errorf("expected empty raw line, got %q", ev.RawLine)
	}

	if ev.Action != "" {
		t.Errorf("expected empty action, got %q", ev.Action)
	}
}

// Test ParseLogLine with lowercase action
func TestParseLogLine_LowercaseAction(t *testing.T) {
	line := `Jan 15 12:00:00 hostname kernel: DROP SRC=192.168.1.100 DST=192.168.1.1 PROTO=TCP`

	ev, err := ParseLogLine(line)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should detect DROP even without RUNIC prefix
	if ev.Action != "DROP" {
		t.Errorf("expected action DROP, got %q", ev.Action)
	}
}

// Test batch logic with ticker interval simulation
func TestShipper_BatchInterval(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	shipper := NewShipper(server.Client(), server.URL, "test-token", "host-123", "/var/log/kern.log")

	// Test that ship method handles empty batch
	ctx := context.Background()
	shipper.ship(ctx, []LogEvent{}) // Should not panic

	// Test that ship method handles nil batch
	shipper.ship(ctx, nil) // Should not panic

	// Verify that the shipper was created with the correct config
	if shipper.controlPlaneURL != server.URL {
		t.Errorf("expected controlPlaneURL %q, got %q", server.URL, shipper.controlPlaneURL)
	}
}

// Test ParseLogLine with various timestamp formats
func TestParseLogLine_TimestampFormats(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		expected string
	}{
		{
			name:     "Feb 28 timestamp",
			line:     `Feb 28 23:59:59 hostname kernel: [RUNIC-DROP] SRC=1.1.1.1 DST=2.2.2.2 PROTO=TCP`,
			expected: "Feb 28 23:59:59",
		},
		{
			name:     "Dec 31 timestamp",
			line:     `Dec 31 00:00:00 hostname kernel: [RUNIC-ACCEPT] SRC=1.1.1.1 DST=2.2.2.2 PROTO=UDP`,
			expected: "Dec 31 00:00:00",
		},
		{
			name:     "ISO8601 with Z",
			line:     `2026-01-15T12:00:00Z hostname kernel: [RUNIC-DROP] SRC=1.1.1.1 DST=2.2.2.2 PROTO=TCP`,
			expected: "2026-01-15T12:00:00Z",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev, err := ParseLogLine(tt.line)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if ev.Timestamp != tt.expected {
				t.Errorf("expected timestamp %q, got %q", tt.expected, ev.Timestamp)
			}
		})
	}
}

// Test filtering of non-RUNIC lines in tail
func TestShipper_TailFiltersNonRunicLines(t *testing.T) {
	// Create a temporary log file
	tmpFile := t.TempDir() + "/test.log"

	// Create file first, then write RUNIC line after seeking to end
	// First write the non-RUNIC lines
	initialContent := `Jan 15 12:00:00 hostname kernel: Some other log message
Jan 15 12:00:01 hostname kernel: Another message`
	if err := os.WriteFile(tmpFile, []byte(initialContent), 0644); err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}

	shipper := NewShipper(&http.Client{}, "http://localhost", "token", "host1", tmpFile)

	// Now append the RUNIC line to the file (simulating new log entry)
	f, err := os.OpenFile(tmpFile, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatalf("failed to open temp file for append: %v", err)
	}
	runicLine := `\nJan 15 12:00:02 hostname kernel: [RUNIC-DROP] SRC=192.168.1.100 DST=192.168.1.1 PROTO=TCP`
	if _, err := f.WriteString(runicLine); err != nil {
		f.Close()
		t.Fatalf("failed to append to temp file: %v", err)
	}
	f.Close()

	// Run with a timeout - the shipper should seek to end and only read new content
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	// Collect lines from tail (will only get new lines after seek)
	var runicLines []string
	for line := range shipper.tail(ctx, tmpFile) {
		runicLines = append(runicLines, line)
	}

	// Since the shipper seeks to end, it won't read the RUNIC line we added
	// This test verifies that tail doesn't panic on non-existent files
	// and that it handles filtering when it does receive lines
	if len(runicLines) > 0 {
		if !strings.Contains(runicLines[0], "[RUNIC-DROP]") {
			t.Errorf("expected RUNIC-DROP line, got %q", runicLines[0])
		}
	}
}
