package metrics

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"runic/internal/common"
	"runic/internal/models"
)

// SendHeartbeat sends a heartbeat to the control plane.
func SendHeartbeat(ctx context.Context, client common.HTTPClient, controlPlaneURL, hostID, bundleVersion, token, version string) error {
	uptime := getUptime()
	load := getLoad1m()

	body := models.HeartbeatRequest{
		HostID:               hostID,
		BundleVersionApplied: bundleVersion,
		UptimeSeconds:        uptime,
		Load1m:               load,
		AgentVersion:         version,
	}

	data, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal heartbeat: %w", err)
	}

	url := controlPlaneURL + "/api/v1/agent/heartbeat"
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "runic-agent/"+version)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("heartbeat failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("heartbeat returned status %d", resp.StatusCode)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		// Non-JSON response is fine for heartbeat
		return nil
	}

	return nil
}

// getUptime reads /proc/uptime and returns uptime in seconds.
func getUptime() float64 {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}

	var uptime float64
	if _, err := fmt.Sscanf(string(data), "%f", &uptime); err != nil {
		return 0
	}
	return uptime
}

// getLoad1m reads /proc/loadavg and returns the 1-minute load average.
func getLoad1m() float64 {
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0
	}

	var load1, load5, load15 float64
	if _, err := fmt.Sscanf(string(data), "%f %f %f", &load1, &load5, &load15); err != nil {
		return 0
	}
	return load1
}
