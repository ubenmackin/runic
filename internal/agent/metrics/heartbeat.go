// Package metrics handles agent telemetry.
package metrics

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"

	"runic/internal/common"
	"runic/internal/models"
)

// SendHeartbeat sends a heartbeat to the control plane.
func SendHeartbeat(ctx context.Context, client common.HTTPClient, controlPlaneURL, hostID, bundleVersion, token, version string, allIPs []string) error {
	uptime := getUptime()
	load := getLoad1m()

	body := models.HeartbeatRequest{
		HostID:               hostID,
		BundleVersionApplied: bundleVersion,
		UptimeSeconds:        uptime,
		Load1m:               load,
		AgentVersion:         version,
		HasIPSet:             boolPtr(common.DetectIPSet()),
		AllIPs:               allIPs,
	}

	resp, err := common.DoJSONRequest(ctx, client, "POST", controlPlaneURL+"/api/v1/agent/heartbeat", body, token, "runic-agent/"+version)
	if err != nil {
		return fmt.Errorf("heartbeat failed: %w", err)
	}
	defer func() {
		if cErr := resp.Body.Close(); cErr != nil {
			slog.Warn("failed to close body", "error", cErr)
		}
	}()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
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

// boolPtr returns a pointer to the given bool value.
func boolPtr(b bool) *bool {
	return &b
}
