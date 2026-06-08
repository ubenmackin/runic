package identity

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"

	"runic/internal/common"
	"runic/internal/common/log"
	"runic/internal/models"
)

// Register registers the agent with the control plane. It returns the updated config with credentials.
func Register(ctx context.Context, client common.HTTPClient, cfg *Config, version string, saveFunc func() error, allIPs []string) error {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	osID, _ := DetectOS()
	osType := NormalizeOS(osID)
	if osID == "" {
		osType = "linux"
	}
	kernel := detectKernelVersion()
	hasDocker := detectDocker()
	ip := detectLocalIP()

	hasIPSet := common.DetectIPSet()

	body := models.AgentRegisterRequest{
		Hostname:     hostname,
		IP:           ip,
		OSType:       osType,
		Arch:         runtime.GOARCH,
		Kernel:       kernel,
		AgentVersion: version,
		HasDocker:    hasDocker,
		HasIPSet:     &hasIPSet,
		AllIPs:       allIPs,
	}

	if cfg.RegistrationToken != "" {
		body.RegistrationToken = cfg.RegistrationToken
	}

	url := cfg.ControlPlaneURL + "/api/v1/agent/register"
	resp, err := common.DoJSONRequest(ctx, client, "POST", url, body, cfg.Token, "runic-agent")
	if err != nil {
		return fmt.Errorf("registration request failed: %w", err)
	}
	defer func() {
		if cErr := resp.Body.Close(); cErr != nil {
			log.Warn("Failed to close response body", "error", cErr)
		}
	}()

	if resp.StatusCode != 200 && resp.StatusCode != 201 {
		return fmt.Errorf("registration returned status %d", resp.StatusCode)
	}

	var regResp models.AgentRegisterResponse
	if err := json.NewDecoder(resp.Body).Decode(&regResp); err != nil {
		return fmt.Errorf("decode registration response: %w", err)
	}

	cfg.HostID = regResp.HostID
	cfg.Token = regResp.Token
	cfg.PullIntervalSec = regResp.PullInterval
	cfg.CurrentBundleVer = regResp.CurrentBundleVer
	cfg.HMACKey = regResp.HMACKey

	cfg.RegistrationToken = ""

	if err := saveFunc(); err != nil {
		return fmt.Errorf("save config after registration: %w", err)
	}

	log.Info("Registered with Runic control plane", "hostname", hostname, "host_id", regResp.HostID)
	return nil
}

func detectKernelVersion() string {
	data, err := os.ReadFile("/proc/version")
	if err != nil {
		return ""
	}

	parts := strings.Split(string(data), " ")
	if len(parts) >= 3 {
		return parts[2]
	}

	return strings.TrimSpace(string(data))
}

// detectDocker checks for the Docker socket.
// NOTE: This duplicates detectDocker in internal/agent/apply/applier.go.
// Both are kept separate to avoid a cross-package dependency on a shared
// utility; the duplication is small and acceptable.
func detectDocker() bool {
	fi, err := os.Stat("/var/run/docker.sock")
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeSocket != 0
}

func detectLocalIP() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}

	var bestIP string

	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			default:
				continue
			}

			if ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}

			if ip4 := ip.To4(); ip4 != nil {
				if bestIP == "" {
					bestIP = ip4.String()
				}
			}
		}
	}

	return bestIP
}
