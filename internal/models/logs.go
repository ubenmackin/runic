package models

import "time"

type LogEvent struct {
	ID              int       `json:"id"`
	PeerID          string    `json:"peer_id"`
	Hostname        string    `json:"hostname,omitempty"`
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
