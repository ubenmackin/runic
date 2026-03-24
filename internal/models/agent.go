package models

// AgentRegisterRequest is the payload sent during agent registration.
type AgentRegisterRequest struct {
	Hostname     string `json:"hostname"`
	IP           string `json:"ip"`
	OSType       string `json:"os_type"`
	Arch         string `json:"arch"`
	Kernel       string `json:"kernel"`
	AgentVersion string `json:"agent_version"`
	HasDocker    bool   `json:"has_docker"`
}

// AgentRegisterResponse is the payload returned after successful agent registration.
type AgentRegisterResponse struct {
	HostID           string `json:"host_id"`
	Token            string `json:"token"`
	PullInterval     int    `json:"pull_interval_seconds"`
	CurrentBundleVer string `json:"current_bundle_version"`
	HMACKey          string `json:"hmac_key"`
}

// HeartbeatRequest is the payload sent in agent heartbeats.
type HeartbeatRequest struct {
	HostID               string  `json:"host_id"`
	BundleVersionApplied string  `json:"bundle_version_applied"`
	UptimeSeconds        float64 `json:"uptime_seconds"`
	Load1m               float64 `json:"load_1m"`
	AgentVersion         string  `json:"agent_version"`
}

// BundleResponse is the response from the bundle endpoint.
type BundleResponse struct {
	Version string `json:"version"`
	Rules   string `json:"rules"`
	HMAC    string `json:"hmac"`
}
