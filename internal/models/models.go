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
	DockerOnly  bool
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type RuleBundleRow struct {
	ID           int
	PeerID       int
	Version      string
	RulesContent string
	HMAC         string
	CreatedAt    time.Time
	AppliedAt    sql.NullTime
}

type CreateBundleParams struct {
	PeerID       int
	Version      string
	RulesContent string
	HMAC         string
}
