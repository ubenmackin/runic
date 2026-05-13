package models

import "time"

// LogEvent represents a single firewall log entry.
// This model is used with manual positional SQL scanning in logs_store.go.
// Only json tags are needed — no db: or gorm: tags.
type LogEvent struct {
	ID              int       `json:"id"`
	PeerID          int       `json:"peer_id"`
	PeerHostname    string    `json:"peer_hostname"`
	Timestamp       time.Time `json:"timestamp"`
	Direction       string    `json:"direction,omitempty"`
	Action          string    `json:"action"`
	SrcIP           string    `json:"src_ip"`
	SrcPort         int       `json:"src_port,omitempty"`
	DstIP           string    `json:"dst_ip"`
	DstPort         int       `json:"dst_port"`
	Protocol        string    `json:"protocol"`
	RawLine         string    `json:"raw_line,omitempty"`
	MatchedPolicyID *string   `json:"matched_policy_id,omitempty"`
	PolicyName      string    `json:"policy_name,omitempty"`
}
