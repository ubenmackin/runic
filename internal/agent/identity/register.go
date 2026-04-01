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

// Register performs initial registration with the control plane.
// It returns the updated config with credentials.
func Register(ctx context.Context, client common.HTTPClient, cfg *Config, version string, saveFunc func() error) error {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	osType := detectOSType()
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
	}

	url := cfg.ControlPlaneURL + "/api/v1/agent/register"
	resp, err := common.DoJSONRequest(ctx, client, "POST", url, body, cfg.Token, "runic-agent")
	if err != nil {
		return fmt.Errorf("registration request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 && resp.StatusCode != 201 {
		return fmt.Errorf("registration returned status %d", resp.StatusCode)
	}

	var regResp models.AgentRegisterResponse
	if err := json.NewDecoder(resp.Body).Decode(&regResp); err != nil {
		return fmt.Errorf("decode registration response: %w", err)
	}

	// Save credentials to config
	cfg.HostID = regResp.HostID
	cfg.Token = regResp.Token
	cfg.PullIntervalSec = regResp.PullInterval
	cfg.CurrentBundleVer = regResp.CurrentBundleVer
	cfg.HMACKey = regResp.HMACKey

	if err := saveFunc(); err != nil {
		return fmt.Errorf("save config after registration: %w", err)
	}

	log.Info("Registered with Runic control plane", "hostname", hostname, "host_id", regResp.HostID)
	return nil
}

// detectOSType reads /etc/os-release to determine the OS type.
func detectOSType() string {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return "linux"
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "ID=") {
			id := strings.TrimPrefix(line, "ID=")
			id = strings.Trim(id, `"`)
			id = strings.ToLower(id)

			// Map known values
			switch {
			case strings.HasPrefix(id, "opensuse"):
				return "opensuse"
			case id == "raspbian":
				return "raspbian"
			case id == "debian":
				return "debian"
			case id == "ubuntu":
				return "ubuntu"
			case strings.HasPrefix(id, "fedora"), strings.HasPrefix(id, "rhel"), strings.HasPrefix(id, "centos"):
				return "rhel"
			case strings.HasPrefix(id, "arch"):
				return "arch"
			default:
				return id
			}
		}
	}

	return "linux"
}

// detectKernelVersion returns the kernel version from /proc/version.
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

// detectDocker returns true if /var/run/docker.sock exists and is a socket.
func detectDocker() bool {
	fi, err := os.Stat("/var/run/docker.sock")
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeSocket != 0
}

// detectLocalIP returns the primary non-loopback IPv4 address.
func detectLocalIP() string {
	// Get all network interfaces
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}

	var bestIP string

	for _, iface := range ifaces {
		// Skip loopback and down interfaces
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
			case *net.TCPAddr:
				ip = v.IP
			case *net.UDPAddr:
				ip = v.IP
			case *net.IPNet:
				ip = v.IP
			default:
				continue
			}

			// Skip loopback and link-local
			if ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}

			// Prefer IPv4
			if ip4 := ip.To4(); ip4 != nil {
				// First valid IPv4 wins as fallback
				if bestIP == "" {
					bestIP = ip4.String()
				}
			}
		}
	}

	return bestIP
}
