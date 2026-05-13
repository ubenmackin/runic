package models

type ActivityItem struct {
	Timestamp string `json:"timestamp"`
	SrcIP     string `json:"src_ip"`
	DstIP     string `json:"dst_ip"`
	Protocol  string `json:"protocol"`
	Action    string `json:"action"`
	Hostname  string `json:"hostname,omitempty"`
}

type PeerHealth struct {
	Hostname      string `json:"hostname"`
	IP            string `json:"ip_address"`
	AgentVersion  string `json:"agent_version"`
	LastHeartbeat string `json:"last_heartbeat"`
	IsOnline      bool   `json:"is_online"`
	IsManual      bool   `json:"is_manual"`
}

type BlockedIP struct {
	SrcIP string `json:"src_ip"`
	Count int    `json:"count"`
}

type DashboardStats struct {
	TotalPeers       int            `json:"total_peers"`
	OnlinePeers      int            `json:"online_peers"`
	OfflinePeers     int            `json:"offline_peers"`
	ManualPeers      int            `json:"manual_peers"`
	TotalPolicies    int            `json:"total_policies"`
	BlockedLastHour  int            `json:"blocked_last_hour"`
	BlockedLast24h   int            `json:"blocked_last_24h"`
	RecentActivity   []ActivityItem `json:"recent_activity"`
	PeerHealth       []PeerHealth   `json:"peer_health"`
	TopBlockedSource []BlockedIP    `json:"top_blocked_sources"`
	Degraded         bool           `json:"degraded,omitempty"`
}
