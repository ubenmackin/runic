// Package alerts provides alert and notification functionality.
package alerts

import (
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"time"
)

// AlertType defines the type of alert.
type AlertType string

const (
	AlertTypePeerOffline    AlertType = "peer_offline"
	AlertTypeBundleFailed   AlertType = "bundle_failed"
	AlertTypeBlockedSpike   AlertType = "blocked_spike"
	AlertTypePeerOnline     AlertType = "peer_online"
	AlertTypeNewPeer        AlertType = "new_peer"
	AlertTypeBundleDeployed AlertType = "bundle_deployed"
)

// Severity defines the severity level of an alert.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityWarning  Severity = "warning"
	SeverityCritical Severity = "critical"
)

// AlertStatus defines the status of an alert history entry.
type AlertStatus string

const (
	AlertStatusPending   AlertStatus = "pending"
	AlertStatusSent      AlertStatus = "sent"
	AlertStatusFailed    AlertStatus = "failed"
	AlertStatusThrottled AlertStatus = "throttled"
)

// NullTime is a custom type that wraps sql.NullTime with proper JSON marshaling.
// It marshals to null when invalid, and to the RFC3339 formatted time string when valid.
type NullTime struct {
	sql.NullTime
}

// MarshalJSON implements the json.Marshaler interface for NullTime.
// Returns "null" for invalid times, or the RFC3339 formatted time for valid times.
func (nt NullTime) MarshalJSON() ([]byte, error) {
	if !nt.Valid {
		return []byte("null"), nil
	}
	return json.Marshal(nt.Time)
}

// UnmarshalJSON implements the json.Unmarshaler interface for NullTime.
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

// Scan implements the sql.Scanner interface for NullTime.
func (nt *NullTime) Scan(value interface{}) error {
	return nt.NullTime.Scan(value)
}

// Value implements the driver.Valuer interface for NullTime.
func (nt NullTime) Value() (driver.Value, error) {
	if !nt.Valid {
		return nil, nil
	}
	return nt.Time, nil
}

// String returns the string representation of the AlertType.
func (at AlertType) String() string {
	return string(at)
}

// IsValid checks if the AlertType is a valid alert type.
func (at AlertType) IsValid() bool {
	switch at {
	case AlertTypePeerOffline, AlertTypeBundleFailed, AlertTypeBlockedSpike, AlertTypePeerOnline, AlertTypeNewPeer, AlertTypeBundleDeployed:
		return true
	default:
		return false
	}
}

// String returns the string representation of the Severity.
func (s Severity) String() string {
	return string(s)
}

// IsValid checks if the Severity is a valid severity level.
func (s Severity) IsValid() bool {
	switch s {
	case SeverityInfo, SeverityWarning, SeverityCritical:
		return true
	default:
		return false
	}
}

// DefaultSeverity returns the default severity for an alert type.
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

// AlertRule represents an alert rule configuration.
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

// TableName specifies the table name for AlertRule.
func (AlertRule) TableName() string {
	return "alert_rules"
}

// IsEnabled returns true if the alert rule is enabled.
func (ar *AlertRule) IsEnabled() bool {
	return ar.Enabled
}

// GetType returns the alert type of the rule.
func (ar *AlertRule) GetType() AlertType {
	return ar.AlertType
}

// GetThresholdDuration returns the threshold window as a duration.
func (ar *AlertRule) GetThresholdDuration() time.Duration {
	return time.Duration(ar.ThresholdWindowMinutes) * time.Minute
}

// GetThrottleDuration returns the throttle duration.
func (ar *AlertRule) GetThrottleDuration() time.Duration {
	return time.Duration(ar.ThrottleMinutes) * time.Minute
}

// AppliesToPeer checks if the rule applies to a specific peer.
// If PeerID is nil, the rule applies to all peers.
func (ar *AlertRule) AppliesToPeer(peerID int) bool {
	if ar.PeerID == nil {
		return true
	}
	return *ar.PeerID == peerID
}

// AlertHistory represents a record of an alert that was triggered.
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

// TableName specifies the table name for AlertHistory.
func (AlertHistory) TableName() string {
	return "alert_history"
}

// IsSent returns true if the alert was successfully sent.
func (ah *AlertHistory) IsSent() bool {
	return ah.Status == AlertStatusSent
}

// IsFailed returns true if the alert failed to send.
func (ah *AlertHistory) IsFailed() bool {
	return ah.Status == AlertStatusFailed
}

// UserNotificationPreferences represents a user's notification settings.
type UserNotificationPreferences struct {
	ID                 uint      `json:"id" gorm:"primaryKey;autoIncrement"`
	UserID             uint      `json:"user_id" gorm:"not null;uniqueIndex"`
	EnabledAlerts      string    `json:"enabled_alerts" gorm:"type:text"` // JSON array of alert types, empty means all enabled
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

// TableName specifies the table name for UserNotificationPreferences.
func (UserNotificationPreferences) TableName() string {
	return "user_notification_preferences"
}

// IsAlertEnabled checks if a specific alert type is enabled for the user.
// If EnabledAlerts is empty, all alerts are considered enabled.
func (u *UserNotificationPreferences) IsAlertEnabled(alertType AlertType) bool {
	if u.EnabledAlerts == "" {
		return true
	}
	var enabledTypes []string
	if err := json.Unmarshal([]byte(u.EnabledAlerts), &enabledTypes); err != nil {
		// If parsing fails, assume all are enabled
		return true
	}
	for _, t := range enabledTypes {
		if t == string(alertType) {
			return true
		}
	}
	return false
}

// AlertDigest represents a daily/weekly digest sent to a user.
type AlertDigest struct {
	ID         uint      `json:"id" gorm:"primaryKey;autoIncrement"`
	UserID     uint      `json:"user_id" gorm:"not null;index"`
	DigestDate string    `json:"digest_date" gorm:"size:10;not null;index"`
	AlertCount int       `json:"alert_count" gorm:"default:0"`
	Summary    string    `json:"summary" gorm:"type:text"`
	SentAt     time.Time `json:"sent_at"`
	CreatedAt  time.Time `json:"created_at" gorm:"autoCreateTime"`
}

// TableName specifies the table name for AlertDigest.
func (AlertDigest) TableName() string {
	return "alert_digests"
}

// HasAlerts returns true if the digest contains any alerts.
func (d *AlertDigest) HasAlerts() bool {
	return d.AlertCount > 0
}

// SMTPConfig represents SMTP settings for email sending.
type SMTPConfig struct {
	Host        string `json:"host" gorm:"size:255;not null" validate:"required"`
	Port        int    `json:"port" gorm:"not null" validate:"required,min=1,max=65535"`
	Username    string `json:"username" gorm:"size:255"`
	Password    string `json:"-" gorm:"size:500"` // stored encrypted, excluded from JSON responses
	UseTLS      bool   `json:"use_tls" gorm:"default:true"`
	FromAddress string `json:"from_address" gorm:"size:255" validate:"required,email"`
	Enabled     bool   `json:"enabled" gorm:"default:false"`
}

// IsEnabled returns true if SMTP is enabled and configured.
func (c *SMTPConfig) IsEnabled() bool {
	return c.Enabled && c.Host != "" && c.Port > 0 && c.FromAddress != ""
}

// GetAddress returns the full SMTP server address (host:port).
func (c *SMTPConfig) GetAddress() string {
	return c.Host
}

// AlertEvent represents an event that can trigger an alert.
//
// Security Note: String fields (PeerName, Subject, Message) may contain
// untrusted input from external sources. The system employs a layered
// defense approach:
//   - Entry point: SanitizeAlertInput/SanitizeAlertInputStrict when creating
//     AlertEvent instances from external sources
//   - Email generation: htmlEscape() for HTML content escaping
//
// Callers should ensure proper sanitization at the entry point when creating
// AlertEvent instances from external sources.
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

// GetType returns the alert type of the event.
func (e *AlertEvent) GetType() AlertType {
	return e.Type
}

// GetSeverity returns the severity of the event.
func (e *AlertEvent) GetSeverity() Severity {
	if e.Severity == "" {
		return e.Type.DefaultSeverity()
	}
	return e.Severity
}

// IsCritical returns true if the event severity is critical.
func (e *AlertEvent) IsCritical() bool {
	return e.GetSeverity() == SeverityCritical
}

// CreateAlertHistory creates an AlertHistory record from the event.
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

// CreateAlertRuleRequest represents the request payload for creating an alert rule.
type CreateAlertRuleRequest struct {
	Name                   string    `json:"name" validate:"required,min=1,max=255"`
	AlertType              AlertType `json:"alert_type" validate:"required"`
	Enabled                bool      `json:"enabled"`
	ThresholdValue         int       `json:"threshold_value"`
	ThresholdWindowMinutes int       `json:"threshold_window_minutes" validate:"min=1"`
	PeerID                 *int      `json:"peer_id,omitempty"`
	ThrottleMinutes        int       `json:"throttle_minutes" validate:"min=0"`
}

// UpdateAlertRuleRequest represents the request payload for updating an alert rule.
type UpdateAlertRuleRequest struct {
	Name                   string    `json:"name,omitempty" validate:"omitempty,min=1,max=255"`
	AlertType              AlertType `json:"alert_type,omitempty" validate:"omitempty"`
	Enabled                *bool     `json:"enabled,omitempty"`
	ThresholdValue         *int      `json:"threshold_value,omitempty" validate:"omitempty,min=0"`
	ThresholdWindowMinutes *int      `json:"threshold_window_minutes,omitempty" validate:"omitempty,min=1"`
	PeerID                 *int      `json:"peer_id,omitempty"`
	ThrottleMinutes        *int      `json:"throttle_minutes,omitempty" validate:"omitempty,min=0"`
}

// UpdateNotificationPreferencesRequest represents the request payload for updating notification preferences.
type UpdateNotificationPreferencesRequest struct {
	EnabledAlerts      *string `json:"enabled_alerts,omitempty"` // JSON array of alert types
	QuietHoursEnabled  *bool   `json:"quiet_hours_enabled,omitempty"`
	QuietHoursStart    *string `json:"quiet_hours_start,omitempty" validate:"omitempty,len=5"`
	QuietHoursEnd      *string `json:"quiet_hours_end,omitempty" validate:"omitempty,len=5"`
	QuietHoursTimezone *string `json:"quiet_hours_timezone,omitempty"`
	DigestEnabled      *bool   `json:"digest_enabled,omitempty"`
	DigestFrequency    *string `json:"digest_frequency,omitempty"`
	DigestTime         *string `json:"digest_time,omitempty" validate:"omitempty,len=5"`
	DigestTimezone     *string `json:"digest_timezone,omitempty"`
}

// TestEmailRequest represents the request payload for sending a test email.
type TestEmailRequest struct {
	Recipient string `json:"recipient" validate:"required,email"`
}

// TestEmailResponse represents the response from a test email request.
type TestEmailResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}
