package identity

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strings"
	"time"

	"runic/internal/common"
	"runic/internal/common/log"
	"runic/internal/models"
)

// ErrPersistAfterRegister marks a failure to persist config after a
// successful registration. Credentials are already mutated on cfg when this
// error is returned, so callers may retain them in-memory.
var ErrPersistAfterRegister = errors.New("save config after registration")

// BuildHMACProof builds a re-registration proof of possession for the stored
// HMAC key without disclosing the key itself. The message is built by the
// shared models.ReRegistrationHMACProofMessage so proofs verify with the
// server's verifyHMACReRegistrationProof. The timestamp is Unix seconds and
// the signature is hex(HMAC-SHA256(hmacKey, message)).
// The server rejects proofs outside a 5 minute skew window, so the host
// clock must be NTP-synced or re-registration via HMAC proof fails.
// Hostname must already be sanitized with models.SanitizeReRegistrationHostname
// to match the server's sanitization (control-character strip, TrimSpace, 255
// truncate) before lookup and verification, or verification fails. An empty
// hmacKey returns zero values so callers can skip the proof (first boot or
// new peer).
func BuildHMACProof(hostname, hmacKey string) (int64, string) {
	if hmacKey == "" {
		return 0, ""
	}
	ts := time.Now().Unix()
	msg := models.ReRegistrationHMACProofMessage(hostname, ts)
	mac := hmac.New(sha256.New, []byte(hmacKey))
	mac.Write([]byte(msg))
	return ts, hex.EncodeToString(mac.Sum(nil))
}

// Register registers the agent with the control plane. It returns the updated config with credentials.
func Register(ctx context.Context, client common.HTTPClient, cfg *Config, version string, saveFunc func() error, allIPs []string) error {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}
	// Sanitize identically to the server before lookup and proof verification
	// so proofs over hostnames with spaces, control characters, or over-long
	// values verify. The sanitized value is sent in the request body and used
	// for the HMAC proof.
	sanitizedHostname, _ := models.SanitizeReRegistrationHostname(hostname)
	hostname = sanitizedHostname

	osID, _ := DetectOS()
	osType := NormalizeOS(osID)
	if osID == "" {
		osType = "linux"
	}
	kernel := detectKernelVersion()
	hasDocker := common.DetectDockerSocket()
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

	if cfg.AgentKey != "" {
		body.AgentKey = cfg.AgentKey
	}

	if cfg.HMACKey != "" {
		if ts, sig := BuildHMACProof(hostname, cfg.HMACKey); ts != 0 && sig != "" {
			body.HMACProofTimestamp = ts
			body.HMACProofSignature = sig
		}
	}

	url := cfg.ControlPlaneURL + "/api/v1/agent/register"
	resp, err := common.DoJSONRequest(ctx, client, "POST", url, body, cfg.Token, "runic-agent")
	if err != nil {
		return fmt.Errorf("registration request failed: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
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
	if regResp.HMACKey != "" {
		cfg.HMACKey = regResp.HMACKey
	}
	if regResp.AgentKey != "" {
		cfg.AgentKey = regResp.AgentKey
	}

	cfg.RegistrationToken = ""

	if err := saveFunc(); err != nil {
		return fmt.Errorf("%w: %w", ErrPersistAfterRegister, err)
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
