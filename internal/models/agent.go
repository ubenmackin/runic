package models

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
