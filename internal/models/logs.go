package models

import "time"

type LogEvent struct {
	ID              int       `json:"id" db:"id"`
	PeerID          string    `json:"peer_id" db:"peer_id"`
	PeerHostname    string    `json:"peer_hostname" db:"peer_hostname"`
	Timestamp       time.Time `json:"timestamp" db:"timestamp"`
	Direction       string    `json:"direction,omitempty" db:"direction"`
	Action          string    `json:"action" db:"action"`
	SrcIP           string    `json:"src_ip" db:"src_ip"`
	SrcPort         int       `json:"src_port,omitempty" db:"src_port"`
	DstIP           string    `json:"dst_ip" db:"dst_ip"`
	DstPort         int       `json:"dst_port" db:"dst_port"`
	Protocol        string    `json:"protocol" db:"protocol"`
	RawLine         string    `json:"raw_line,omitempty" db:"raw_line"`
	MatchedPolicyID *string   `json:"matched_policy_id,omitempty" db:"matched_policy_id"`
	PolicyName      string    `json:"policy_name,omitempty" db:"policy_name"`
}
