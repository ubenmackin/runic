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
	ID              int
	Name            string
	Description     string
	IsSystem        bool
	IsPendingDelete bool
}

type GroupMemberRow struct {
	ID      int
	GroupID int
	PeerID  int
	AddedAt sql.NullTime
}

type ServiceRow struct {
	ID              int    `json:"id"`
	Name            string `json:"name"`
	Ports           string `json:"ports"`
	SourcePorts     string `json:"source_ports"`
	Protocol        string `json:"protocol"`
	Description     string `json:"description"`
	DirectionHint   string `json:"direction_hint"`
	IsSystem        bool   `json:"is_system"`
	NoConntrack     bool   `json:"no_conntrack"`
	IsPendingDelete bool   `json:"is_pending_delete"`
}

type PolicyRow struct {
	ID              int
	Name            string
	Description     string
	SourceID        int
	SourceType      string
	SourceIP        *string
	ServiceID       int
	TargetID        int
	TargetType      string
	TargetIP        *string
	Action          string
	Priority        int
	Enabled         bool
	TargetScope     string
	Direction       string
	IsPendingDelete bool
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

type RuleBundleRow struct {
	ID             int
	PeerID         int
	Version        string
	VersionNumber  int
	RulesContent   string
	HMAC           string
	CreatedAt      time.Time
	AppliedAt      sql.NullTime
	FirstAppliedAt sql.NullTime `json:"first_applied_at" db:"first_applied_at"`
}

// UserRow intentionally omits the password_hash field from JSON serialization.
type UserRow struct {
	ID        int       `json:"id"`
	Username  string    `json:"username"`
	Email     string    `json:"email"`
	Role      string    `json:"role"`
	CreatedAt time.Time `json:"created_at"`
}

// UserCredentials is returned only by UserStore.GetCredentials and must never be serialized to JSON.
type UserCredentials struct {
	ID           int
	Username     string
	PasswordHash string
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

type PendingChange struct {
	ID            int    `json:"id"`
	PeerID        int    `json:"peer_id"`
	ChangeType    string `json:"change_type"` // policy, group, service
	ChangeID      int    `json:"change_id"`
	ChangeAction  string `json:"change_action"` // create, update, delete
	ChangeSummary string `json:"change_summary"`
	CreatedAt     string `json:"created_at"`
}

type PendingBundlePreview struct {
	ID           int    `json:"id"`
	PeerID       int    `json:"peer_id"`
	RulesContent string `json:"rules_content"`
	DiffContent  string `json:"diff_content"`
	VersionHash  string `json:"version_hash"`
	CreatedAt    string `json:"created_at"`
}

type ChangeSnapshot struct {
	ID           int    `json:"id"`
	EntityType   string `json:"entity_type"`
	EntityID     int    `json:"entity_id"`
	Action       string `json:"action"`
	SnapshotData string `json:"snapshot_data"`
	CreatedAt    string `json:"created_at"`
}
