package transport

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"runic/internal/common/constants"
	"runic/internal/common/log"
)

// LogEvent represents a parsed firewall log event.
type LogEvent struct {
	Timestamp string `json:"timestamp"`
	Direction string `json:"direction"`
	SrcIP     string `json:"src_ip"`
	DstIP     string `json:"dst_ip"`
	Protocol  string `json:"protocol"`
	SrcPort   int    `json:"src_port,omitempty"`
	DstPort   int    `json:"dst_port,omitempty"`
	Action    string `json:"action"`
	RawLine   string `json:"raw_line"`
}

// Shipper handles log tailing and shipping to the control plane.
type Shipper struct {
	client          *http.Client
	controlPlaneURL string
	token           string
	hostID          string
	logPath         string
	lines           chan string
}

// NewShipper creates a new Shipper.
func NewShipper(client *http.Client, controlPlaneURL, token, hostID, logPath string) *Shipper {
	return &Shipper{
		client:          client,
		controlPlaneURL: controlPlaneURL,
		token:           token,
		hostID:          hostID,
		logPath:         logPath,
		lines:           make(chan string, 100),
	}
}

// Run starts the shipper's tail and batch loops.
func (s *Shipper) Run(ctx context.Context) {
	// Start tailing
	tailedLines := s.tail(ctx, s.logPath)

	// Process lines and batch ship
	var batch []LogEvent
	ticker := time.NewTicker(constants.LogShipperBatchInterval)
	defer ticker.Stop()

	for {
		select {
		case line, ok := <-tailedLines:
			if !ok {
				// Tail ended, flush remaining
				if len(batch) > 0 {
					s.ship(context.Background(), batch)
				}
				return
			}
			if ev, err := ParseLogLine(line); err == nil {
				batch = append(batch, ev)
				if len(batch) >= 100 {
					s.ship(ctx, batch)
					batch = nil
				}
			}

		case <-ticker.C:
			if len(batch) > 0 {
				s.ship(ctx, batch)
				batch = nil
			}

		case <-ctx.Done():
			// Best-effort flush on shutdown
			if len(batch) > 0 {
				s.ship(context.Background(), batch)
			}
			return
		}
	}
}

// tail watches a log file and sends new lines to a channel.
func (s *Shipper) tail(ctx context.Context, path string) <-chan string {
	lines := make(chan string, 100)

	go func() {
		defer close(lines)

		f, err := os.Open(path)
		if err != nil {
			log.Error("Cannot open log file", "path", path, "error", err)
			return
		}
		defer f.Close()

		// Seek to end of file to only read new lines
		if _, err := f.Seek(0, io.SeekEnd); err != nil {
			log.Error("Seek failed", "error", err)
			return
		}

		scanner := bufio.NewScanner(f)
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			// Check for new data with a small sleep
			if !scanner.Scan() {
				if err := scanner.Err(); err != nil {
					log.Error("Scan error", "error", err)
				}
				// Handle log rotation: if file shrunk, reopen
				if stat, statErr := os.Stat(path); statErr == nil {
					pos, _ := f.Seek(0, io.SeekCurrent)
					if stat.Size() < pos {
						f.Close()
						newFile, err := os.Open(path)
						if err != nil {
							log.Error("Cannot reopen log file", "path", path, "error", err)
							return
						}
						f = newFile
						if _, err := f.Seek(0, io.SeekEnd); err != nil {
							log.Error("Seek failed after reopen", "error", err)
							f.Close()
							return
						}
						scanner = bufio.NewScanner(f)
					}
				}
				time.Sleep(constants.LogTailSleepInterval)
				continue
			}

			line := scanner.Text()
			if strings.Contains(line, "[RUNIC-DROP]") || strings.Contains(line, "[RUNIC-ACCEPT]") {
				select {
				case lines <- line:
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	return lines
}

// ParseLogLine parses an iptables kernel log line into a LogEvent.
func ParseLogLine(line string) (LogEvent, error) {
	ev := LogEvent{
		RawLine: line,
	}

	// Detect action
	if strings.Contains(line, "[RUNIC-DROP]") {
		ev.Action = "DROP"
	} else if strings.Contains(line, "[RUNIC-ACCEPT]") {
		ev.Action = "ACCEPT"
	} else {
		// Try to detect from log anyway
		if strings.Contains(line, "DROP") {
			ev.Action = "DROP"
		} else if strings.Contains(line, "ACCEPT") {
			ev.Action = "ACCEPT"
		}
	}

	// Parse syslog timestamp: "Jan 1 12:00:00"
	// Format: "Jan 1 12:00:00 hostname kernel: [RUNIC-DROP] ..."
	parts := strings.SplitN(line, " ", 5)
	if len(parts) >= 4 {
		// First 3 parts are timestamp (month, day, time)
		ev.Timestamp = fmt.Sprintf("%s %s %s", parts[0], parts[1], parts[2])
	}

	// Parse key=value fields after the kernel prefix
	// Find the part after "kernel:"
	kernelIdx := strings.Index(line, "kernel:")
	if kernelIdx == -1 {
		return ev, nil
	}

	fieldsStr := line[kernelIdx+7:]
	fieldParts := strings.Fields(fieldsStr)

	for _, field := range fieldParts {
		kv := strings.SplitN(field, "=", 2)
		if len(kv) != 2 {
			continue
		}

		key := kv[0]
		value := kv[1]

		switch key {
		case "IN":
			if value != "" {
				ev.Direction = "IN"
			}
		case "OUT":
			if value != "" {
				if ev.Direction == "IN" {
					ev.Direction = "FWD"
				} else {
					ev.Direction = "OUT"
				}
			}
		case "SRC":
			ev.SrcIP = value
		case "DST":
			ev.DstIP = value
		case "PROTO":
			ev.Protocol = strings.ToLower(value)
		case "SPT":
			fmt.Sscanf(value, "%d", &ev.SrcPort)
		case "DPT":
			fmt.Sscanf(value, "%d", &ev.DstPort)
		}
	}

	return ev, nil
}

// ship sends a batch of log events to the control plane.
func (s *Shipper) ship(ctx context.Context, batch []LogEvent) {
	if len(batch) == 0 {
		return
	}

	url := s.controlPlaneURL + "/api/v1/agent/logs"

	body, err := json.Marshal(map[string]interface{}{
		"host_id": s.hostID,
		"events":  batch,
	})
	if err != nil {
		log.Error("Failed to marshal batch", "error", err)
		return
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(string(body)))
	if err != nil {
		log.Error("Failed to create request", "error", err)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "runic-agent")
	if s.token != "" {
		req.Header.Set("Authorization", "Bearer "+s.token)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		log.Error("Failed to ship events", "count", len(batch), "error", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		log.Warn("Server returned error status", "status_code", resp.StatusCode, "count", len(batch))
	} else {
		log.Info("Shipped log events", "count", len(batch))
	}
}
