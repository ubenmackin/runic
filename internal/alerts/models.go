// Package alerts provides alert and notification functionality.
package alerts

import (
	"runic/internal/common"
	"runic/internal/models"
)

// PeerHostnameLookup is the shared type for hostname resolution by peer ID.
type PeerHostnameLookup = common.PeerHostnameLookup

// Type aliases for backward compatibility.
// The canonical definitions live in runic/internal/models.
type (
	AlertType                            = models.AlertType
	Severity                             = models.Severity
	AlertStatus                          = models.AlertStatus
	NullTime                             = models.NullTime
	AlertRule                            = models.AlertRule
	AlertHistory                         = models.AlertHistory
	UserNotificationPreferences          = models.UserNotificationPreferences
	AlertDigest                          = models.AlertDigest
	SMTPConfig                           = models.SMTPConfig
	AlertEvent                           = models.AlertEvent
	CreateAlertRuleRequest               = models.CreateAlertRuleRequest
	UpdateAlertRuleRequest               = models.UpdateAlertRuleRequest
	UpdateNotificationPreferencesRequest = models.UpdateNotificationPreferencesRequest
	TestEmailRequest                     = models.TestEmailRequest
	TestEmailResponse                    = models.TestEmailResponse
	AlertHistoryFilter                   = models.AlertHistoryFilter
	AlertHistoryListResult               = models.AlertHistoryListResult
	SMTPConfigView                       = models.SMTPConfigView
)

// Constant aliases for backward compatibility.
const (
	DropActionFilter        = models.DropActionFilter
	AlertTypePeerOffline    = models.AlertTypePeerOffline
	AlertTypeBundleFailed   = models.AlertTypeBundleFailed
	AlertTypeBlockedSpike   = models.AlertTypeBlockedSpike
	AlertTypePeerOnline     = models.AlertTypePeerOnline
	AlertTypeNewPeer        = models.AlertTypeNewPeer
	AlertTypeBundleDeployed = models.AlertTypeBundleDeployed
	SeverityInfo            = models.SeverityInfo
	SeverityWarning         = models.SeverityWarning
	SeverityCritical        = models.SeverityCritical
	AlertStatusPending      = models.AlertStatusPending
	AlertStatusSent         = models.AlertStatusSent
	AlertStatusFailed       = models.AlertStatusFailed
	AlertStatusThrottled    = models.AlertStatusThrottled
)

// Error variable aliases for backward compatibility.
var (
	ErrAlertRuleNotFound    = models.ErrAlertRuleNotFound
	ErrAlertHistoryNotFound = models.ErrAlertHistoryNotFound
)
