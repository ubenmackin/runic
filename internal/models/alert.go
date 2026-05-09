// Package models provides database models.
package models

import (
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"time"
)

const DropActionFilter = "(action = 'DROP' OR action = 'LOG_DROP')"

type AlertType string

const (
	AlertTypePeerOffline    AlertType = "peer_offline"
	AlertTypeBundleFailed   AlertType = "bundle_failed"
	AlertTypeBlockedSpike   AlertType = "blocked_spike"
	AlertTypePeerOnline     AlertType = "peer_online"
	AlertTypeNewPeer        AlertType = "new_peer"
	AlertTypeBundleDeployed AlertType = "bundle_deployed"
)

type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityWarning  Severity = "warning"
	SeverityCritical Severity = "critical"
)

type AlertStatus string

const (
	AlertStatusPending   AlertStatus = "pending"
	AlertStatusSent      AlertStatus = "sent"
	AlertStatusFailed    AlertStatus = "failed"
	AlertStatusThrottled AlertStatus = "throttled"
)

// NullTime marshals to null when invalid, and to the RFC3339 formatted time string when valid.
type NullTime struct {
	sql.NullTime
}

// MarshalJSON returns "null" for invalid times, or the RFC3339 formatted time for valid times.
func (nt NullTime) MarshalJSON() ([]byte, error) {
	if !nt.Valid {
		return []byte("null"), nil
	}
	return json.Marshal(nt.Time)
}

func (nt *NullTime) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		nt.Valid = false
		return nil
	}
	if err := json.Unmarshal(data, &nt.Time); err != nil {
		return err
	}
	nt.Valid = true
	return nil
}

func (nt *NullTime) Scan(value interface{}) error {
	return nt.NullTime.Scan(value)
}

func (nt NullTime) Value() (driver.Value, error) {
	if !nt.Valid {
		return nil, nil
	}
	return nt.Time, nil
}

func (at AlertType) String() string {
	return string(at)
}

func (at AlertType) IsValid() bool {
	switch at {
	case AlertTypePeerOffline, AlertTypeBundleFailed, AlertTypeBlockedSpike, AlertTypePeerOnline, AlertTypeNewPeer, AlertTypeBundleDeployed:
		return true
	default:
		return false
	}
}

func (s Severity) String() string {
	return string(s)
}

func (s Severity) IsValid() bool {
	switch s {
	case SeverityInfo, SeverityWarning, SeverityCritical:
		return true
	default:
		return false
	}
}

func (at AlertType) DefaultSeverity() Severity {
	switch at {
	case AlertTypePeerOffline:
		return SeverityWarning
	case AlertTypeBundleFailed:
		return SeverityCritical
	case AlertTypeBlockedSpike:
		return SeverityWarning
	case AlertTypePeerOnline:
		return SeverityInfo
	case AlertTypeNewPeer:
		return SeverityInfo
	case AlertTypeBundleDeployed:
		return SeverityInfo
	default:
		return SeverityInfo
	}
}

type AlertRule struct {
	ID                     uint      `json:"id" gorm:"primaryKey;autoIncrement"`
	Name                   string    `json:"name" gorm:"size:255;not null" validate:"required,min=1,max=255"`
	AlertType              AlertType `json:"alert_type" gorm:"size:50;not null;index" validate:"required"`
	Enabled                bool      `json:"enabled" gorm:"default:true"`
	ThresholdValue         int       `json:"threshold_value" gorm:"default:0"`
	ThresholdWindowMinutes int       `json:"threshold_window_minutes" gorm:"default:5"`
	PeerID                 *int      `json:"peer_id,omitempty" gorm:"index"`
	// minimum time between alerts for this rule
	ThrottleMinutes int       `json:"throttle_minutes" gorm:"default:15"`
	CreatedAt       time.Time `json:"created_at" gorm:"autoCreateTime"`
	UpdatedAt       time.Time `json:"updated_at" gorm:"autoUpdateTime"`
}

func (AlertRule) TableName() string {
	return "alert_rules"
}

func (ar *AlertRule) IsEnabled() bool {
	return ar.Enabled
}

func (ar *AlertRule) GetType() AlertType {
	return ar.AlertType
}

func (ar *AlertRule) GetThresholdDuration() time.Duration {
	return time.Duration(ar.ThresholdWindowMinutes) * time.Minute
}

func (ar *AlertRule) GetThrottleDuration() time.Duration {
	return time.Duration(ar.ThrottleMinutes) * time.Minute
}

// AppliesToPeer returns true if the rule applies to the given peer. If PeerID is nil, the rule applies to all peers.
func (ar *AlertRule) AppliesToPeer(peerID int) bool {
	if ar.PeerID == nil {
		return true
	}
	return *ar.PeerID == peerID
}

type AlertHistory struct {
	ID           uint           `json:"id" gorm:"primaryKey;autoIncrement"`
	RuleID       uint           `json:"rule_id" gorm:"not null;index"`
	AlertType    AlertType      `json:"alert_type" gorm:"size:50;not null;index"`
	PeerID       *int           `json:"peer_id,omitempty" gorm:"index"`
	PeerHostname string         `json:"peer_hostname,omitempty" gorm:"-"` // Populated from JOIN, not a DB column
	Severity     Severity       `json:"severity" gorm:"size:20;not null"`
	Subject      string         `json:"subject" gorm:"size:500;not null"`
	Message      string         `json:"message" gorm:"type:text;not null"`
	Metadata     string         `json:"metadata,omitempty" gorm:"type:text"` // JSON string for additional context
	Status       AlertStatus    `json:"status" gorm:"size:20;not null;index"`
	SentAt       NullTime       `json:"sent_at" gorm:"index"`
	ErrorMessage sql.NullString `json:"error_message,omitempty" gorm:"type:text"`
	CreatedAt    time.Time      `json:"created_at" gorm:"autoCreateTime;index"`
}

func (AlertHistory) TableName() string {
	return "alert_history"
}

func (ah *AlertHistory) IsSent() bool {
	return ah.Status == AlertStatusSent
}

func (ah *AlertHistory) IsFailed() bool {
	return ah.Status == AlertStatusFailed
}

type UserNotificationPreferences struct {
	ID                 uint      `json:"id" gorm:"primaryKey;autoIncrement"`
	UserID             uint      `json:"user_id" gorm:"not null;uniqueIndex"`
	QuietHoursEnabled  bool      `json:"quiet_hours_enabled" gorm:"default:false"`
	QuietHoursStart    string    `json:"quiet_hours_start" gorm:"size:5"`
	QuietHoursEnd      string    `json:"quiet_hours_end" gorm:"size:5"`
	QuietHoursTimezone string    `json:"quiet_hours_timezone" gorm:"size:50"`
	DigestEnabled      bool      `json:"digest_enabled" gorm:"default:false"`
	DigestFrequency    string    `json:"digest_frequency" gorm:"size:20;default:'daily'"`
	DigestTime         string    `json:"digest_time" gorm:"size:5;default:'09:00'"`
	DigestTimezone     string    `json:"digest_timezone" gorm:"size:50"`
	CreatedAt          time.Time `json:"created_at" gorm:"autoCreateTime"`
	UpdatedAt          time.Time `json:"updated_at" gorm:"autoUpdateTime"`
}

func (UserNotificationPreferences) TableName() string {
	return "user_notification_preferences"
}

type AlertDigest struct {
	ID         uint      `json:"id" gorm:"primaryKey;autoIncrement"`
	UserID     uint      `json:"user_id" gorm:"not null;index"`
	DigestDate string    `json:"digest_date" gorm:"size:10;not null;index"`
	AlertCount int       `json:"alert_count" gorm:"default:0"`
	Summary    string    `json:"summary" gorm:"type:text"`
	SentAt     time.Time `json:"sent_at"`
	CreatedAt  time.Time `json:"created_at" gorm:"autoCreateTime"`
}

func (AlertDigest) TableName() string {
	return "alert_digests"
}

func (d *AlertDigest) HasAlerts() bool {
	return d.AlertCount > 0
}

type SMTPConfig struct {
	Host        string `json:"host" gorm:"size:255;not null" validate:"required"`
	Port        int    `json:"port" gorm:"not null" validate:"required,min=1,max=65535"`
	Username    string `json:"username" gorm:"size:255"`
	Password    string `json:"-" gorm:"size:500"` // stored encrypted, excluded from JSON responses
	UseTLS      bool   `json:"use_tls" gorm:"default:true"`
	FromAddress string `json:"from_address" gorm:"size:255" validate:"required,email"`
	Enabled     bool   `json:"enabled" gorm:"default:false"`
}

func (c *SMTPConfig) IsEnabled() bool {
	return c.Enabled && c.Host != "" && c.Port > 0 && c.FromAddress != ""
}

func (c *SMTPConfig) GetAddress() string {
	return c.Host
}

// AlertEvent represents a triggered alert event. Security Note: String fields (PeerName, Subject, Message) may contain
// untrusted input from external sources. The system employs a layered
// defense approach:
// - Entry point: SanitizeAlertInput/SanitizeAlertInputStrict when creating
// - Email generation: htmlEscape() for HTML content escaping
//
// Callers should ensure proper sanitization at the entry point when creating
type AlertEvent struct {
	Type   AlertType `json:"type"`
	PeerID int       `json:"peer_id,omitempty"`
	// PeerName may contain untrusted input from external sources.
	// Sanitization happens at entry point (SanitizeAlertInput) and
	// HTML escaping at email generation (htmlEscape).
	PeerName  string                 `json:"peer_name,omitempty"`
	Value     int                    `json:"value,omitempty"` // e.g., blocked count for spike
	Timestamp time.Time              `json:"timestamp"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
	Severity  Severity               `json:"severity,omitempty"`
	Subject   string                 `json:"subject,omitempty"`
	Message   string                 `json:"message,omitempty"`
}

func (e *AlertEvent) GetType() AlertType {
	return e.Type
}

func (e *AlertEvent) GetSeverity() Severity {
	if e.Severity == "" {
		return e.Type.DefaultSeverity()
	}
	return e.Severity
}

func (e *AlertEvent) IsCritical() bool {
	return e.GetSeverity() == SeverityCritical
}

func (e *AlertEvent) CreateAlertHistory(ruleID uint) AlertHistory {
	peerID := &e.PeerID
	if e.PeerID == 0 {
		peerID = nil
	}

	metadataJSON := ""
	if len(e.Metadata) > 0 {
		metadataBytes, err := json.Marshal(e.Metadata)
		if err != nil {
			metadataJSON = "{}"
		} else {
			metadataJSON = string(metadataBytes)
		}
	}

	return AlertHistory{
		RuleID:    ruleID,
		AlertType: e.Type,
		PeerID:    peerID,
		Severity:  e.GetSeverity(),
		Subject:   e.Subject,
		Message:   e.Message,
		Metadata:  metadataJSON,
		Status:    AlertStatusPending,
		CreatedAt: time.Now(),
	}
}

type CreateAlertRuleRequest struct {
	Name                   string    `json:"name" validate:"required,min=1,max=255"`
	AlertType              AlertType `json:"alert_type" validate:"required"`
	Enabled                bool      `json:"enabled"`
	ThresholdValue         int       `json:"threshold_value"`
	ThresholdWindowMinutes int       `json:"threshold_window_minutes" validate:"min=1"`
	PeerID                 *int      `json:"peer_id,omitempty"`
	ThrottleMinutes        int       `json:"throttle_minutes" validate:"min=0"`
}

type UpdateAlertRuleRequest struct {
	Name                   string    `json:"name,omitempty" validate:"omitempty,min=1,max=255"`
	AlertType              AlertType `json:"alert_type,omitempty" validate:"omitempty"`
	Enabled                *bool     `json:"enabled,omitempty"`
	ThresholdValue         *int      `json:"threshold_value,omitempty" validate:"omitempty,min=0"`
	ThresholdWindowMinutes *int      `json:"threshold_window_minutes,omitempty" validate:"omitempty,min=1"`
	PeerID                 *int      `json:"peer_id,omitempty"`
	ThrottleMinutes        *int      `json:"throttle_minutes,omitempty" validate:"omitempty,min=0"`
}

type UpdateNotificationPreferencesRequest struct {
	QuietHoursEnabled  *bool   `json:"quiet_hours_enabled,omitempty"`
	QuietHoursStart    *string `json:"quiet_hours_start,omitempty" validate:"omitempty,len=5"`
	QuietHoursEnd      *string `json:"quiet_hours_end,omitempty" validate:"omitempty,len=5"`
	QuietHoursTimezone *string `json:"quiet_hours_timezone,omitempty"`
	DigestEnabled      *bool   `json:"digest_enabled,omitempty"`
	DigestFrequency    *string `json:"digest_frequency,omitempty"`
	DigestTime         *string `json:"digest_time,omitempty" validate:"omitempty,len=5"`
	DigestTimezone     *string `json:"digest_timezone,omitempty"`
}

type TestEmailRequest struct {
	Recipient string `json:"recipient" validate:"required,email"`
}

type TestEmailResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

type AlertHistoryFilter struct {
	Search    string `json:"search,omitempty"`
	AlertType string `json:"alert_type,omitempty"`
	Severity  string `json:"severity,omitempty"`
	Status    string `json:"status,omitempty"`
	StartDate string `json:"start_date,omitempty"`
	EndDate   string `json:"end_date,omitempty"`
	SortBy    string `json:"sort_by,omitempty"`
	SortDir   string `json:"sort_dir,omitempty"`
	Limit     int    `json:"limit,omitempty"`
	Offset    int    `json:"offset,omitempty"`
}

type AlertHistoryListResult struct {
	Alerts []AlertHistory `json:"alerts"`
	Total  int            `json:"total"`
	Limit  int            `json:"limit"`
	Offset int            `json:"offset"`
}

type SMTPConfigView struct {
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Username    string `json:"username"`
	PasswordSet bool   `json:"password_set"`
	UseTLS      bool   `json:"use_tls"`
	FromAddress string `json:"from_address"`
	Enabled     bool   `json:"enabled"`
}

// Sentinel errors for alert rules and history.
var (
	ErrAlertRuleNotFound    = errors.New("alert rule not found")
	ErrAlertHistoryNotFound = errors.New("alert history not found")
)
