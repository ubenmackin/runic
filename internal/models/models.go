// Package models provides database models.
package models

import (
	"database/sql"
	"time"
)

type PeerRow struct {
	ID            int
	Hostname      string
	IPAddress     string
	OSType        string
	Arch          string
	HasDocker     bool
	AgentKey      string
	AgentToken    sql.NullString
	AgentVersion  sql.NullString
	IsManual      bool
	BundleVersion sql.NullString
	LastHeartbeat sql.NullTime
	Status        string
	CreatedAt     time.Time
}

type GroupRow struct {
	ID          int
	Name        string
	Description string
	IsSystem    bool
}

type GroupMemberRow struct {
	ID      int
	GroupID int
	PeerID  int
	AddedAt sql.NullTime
}

type ServiceRow struct {
	ID            int
	Name          string
	Ports         string
	SourcePorts   string
	Protocol      string
	Description   string
	DirectionHint string
	IsSystem      bool
}

type PolicyRow struct {
	ID          int
	Name        string
	Description string
	SourceID    int
	SourceType  string
	ServiceID   int
	TargetID    int
	TargetType  string
	Action      string
	Priority    int
	Enabled     bool
	TargetScope string
	Direction   string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type RuleBundleRow struct {
	ID            int
	PeerID        int
	Version       string
	VersionNumber int
	RulesContent  string
	HMAC          string
	CreatedAt     time.Time
	AppliedAt     sql.NullTime
}

type CreateBundleParams struct {
	PeerID        int
	Version       string
	VersionNumber int
	RulesContent  string
	HMAC          string
}

type SpecialTargetRow struct {
	ID          int
	Name        string // internal name like "__subnet_broadcast__"
	DisplayName string // user-friendly name like "Subnet Broadcast"
	Description string // optional description
	Address     string // IP address or "computed" for subnet_broadcast
}

// PendingChange represents a queued change that affects a peer's firewall rules.
type PendingChange struct {
	ID            int    `json:"id"`
	PeerID        int    `json:"peer_id"`
	ChangeType    string `json:"change_type"` // policy, group, service
	ChangeID      int    `json:"change_id"`
	ChangeAction  string `json:"change_action"` // create, update, delete
	ChangeSummary string `json:"change_summary"`
	CreatedAt     string `json:"created_at"`
}

// PendingBundlePreview represents a compiled bundle preview awaiting review.
type PendingBundlePreview struct {
	ID           int    `json:"id"`
	PeerID       int    `json:"peer_id"`
	RulesContent string `json:"rules_content"`
	DiffContent  string `json:"diff_content"`
	VersionHash  string `json:"version_hash"`
	CreatedAt    string `json:"created_at"`
}
