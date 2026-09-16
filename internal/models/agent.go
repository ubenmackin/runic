package models

import (
	"fmt"
	"strings"

	"runic/internal/common"
)

// ReRegistrationHostnameMaxLen bounds hostnames used in re-registration
// proofs. It matches the 255 limit applied by the server before lookup and
// verification so over-long hostnames cannot drift between paths.
const ReRegistrationHostnameMaxLen = 255

// ReRegistrationHMACProofMessage builds the exact message the agent HMACs
// with its stored HMAC key to prove possession without disclosing the key.
// It is the single canonical helper shared by the agent client, the server
// verifier, and both test suites so the "runic-re-register:<hostname>:<timestamp>"
// format cannot drift between paths.
func ReRegistrationHMACProofMessage(hostname string, timestamp int64) string {
	return fmt.Sprintf("runic-re-register:%s:%d", hostname, timestamp)
}

// SanitizeReRegistrationHostname sanitizes a hostname identically to the
// server's entry-point sanitization before lookup and proof verification:
// it strips ASCII control characters (<0x20 and 0x7F), trims surrounding
// spaces, and truncates to ReRegistrationHostnameMaxLen with rune-safe
// truncation. It returns the sanitized hostname and whether any modification
// was made. It is the single canonical helper shared by the agent client and
// the server so proofs over hostnames with leading/trailing spaces, control
// characters, or over-long values verify identically on both sides.
func SanitizeReRegistrationHostname(input string) (string, bool) {
	if input == "" {
		return "", false
	}
	modified := false
	var result strings.Builder
	for _, r := range input {
		if r < 0x20 || r == 0x7F {
			modified = true
			continue
		}
		result.WriteRune(r)
	}
	sanitized := result.String()
	trimmed := strings.TrimSpace(sanitized)
	if trimmed != sanitized {
		modified = true
		sanitized = trimmed
	}
	if len(sanitized) > ReRegistrationHostnameMaxLen {
		modified = true
		sanitized = common.TruncateString(sanitized, ReRegistrationHostnameMaxLen)
	}
	return sanitized, modified
}

type AgentRegisterRequest struct {
	Hostname          string   `json:"hostname" validate:"required,hostname"`
	IP                string   `json:"ip" validate:"required,ip"`
	OSType            string   `json:"os_type" validate:"required"`
	Arch              string   `json:"arch"`
	Kernel            string   `json:"kernel"`
	AgentVersion      string   `json:"agent_version"`
	HasDocker         bool     `json:"has_docker"`
	HasIPSet          *bool    `json:"has_ipset"`
	RegistrationToken string   `json:"registration_token"`
	AllIPs            []string `json:"all_ips"`
	// AgentKey proves possession of the stored per-peer agent key when
	// re-registering an existing host. Optional; compared in constant time.
	AgentKey string `json:"agent_key,omitempty"`
	// HMACProofTimestamp and HMACProofSignature prove possession of the
	// stored HMAC key without disclosing it. Signature is hex(HMAC-SHA256(
	// hmac_key, "runic-re-register:<hostname>:<timestamp>")) with timestamp
	// as Unix seconds. The server rejects proofs outside a small skew window.
	HMACProofTimestamp int64  `json:"hmac_proof_timestamp,omitempty"`
	HMACProofSignature string `json:"hmac_proof_signature,omitempty"`
}

type AgentRegisterResponse struct {
	HostID           string `json:"host_id"`
	Token            string `json:"token"`
	PullInterval     int    `json:"pull_interval_seconds"`
	CurrentBundleVer string `json:"current_bundle_version"`
	HMACKey          string `json:"hmac_key"`
	AgentKey         string `json:"agent_key,omitempty"`
}

type HeartbeatRequest struct {
	HostID               string   `json:"host_id" validate:"required"`
	BundleVersionApplied string   `json:"bundle_version_applied"`
	UptimeSeconds        float64  `json:"uptime_seconds"`
	Load1m               float64  `json:"load_1m"`
	AgentVersion         string   `json:"agent_version"`
	HasIPSet             *bool    `json:"has_ipset"`
	AllIPs               []string `json:"all_ips"`
	LastUpdateError      string   `json:"last_update_error,omitempty"`
}

type BundleResponse struct {
	Version       string `json:"version"`
	VersionNumber int    `json:"version_number"`
	Rules         string `json:"rules"`
	HMAC          string `json:"hmac"`
}
