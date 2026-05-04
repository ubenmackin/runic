// Package alerts provides API handlers for the alert system.
package alerts

import (
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"

	"runic/internal/alerts"
	"runic/internal/api/common"
	"runic/internal/auth"
	"runic/internal/common/log"
	"runic/internal/crypto"
	"runic/internal/db"
)

// Handler handles alert API requests.
type Handler struct {
	DB           db.Querier
	AlertService *alerts.Service
	Encryptor    *crypto.Encryptor
}

// NewHandler creates a new alert handler.
func NewHandler(database db.Querier, alertService *alerts.Service, encryptor *crypto.Encryptor) *Handler {
	return &Handler{
		DB:           database,
		AlertService: alertService,
		Encryptor:    encryptor,
	}
}

// ListAlerts returns paginated alert history with filtering support.
func (h *Handler) ListAlerts(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 50
	}

	// If both page and offset are provided, page takes precedence
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	var offset int
	if page > 0 {
		offset = (page - 1) * limit
	} else {
		offset, _ = strconv.Atoi(r.URL.Query().Get("offset"))
		if offset < 0 {
			offset = 0
		}
	}

	filter := alerts.AlertHistoryFilter{
		Search:    r.URL.Query().Get("search"),
		AlertType: r.URL.Query().Get("alert_type"),
		Severity:  r.URL.Query().Get("severity"),
		Status:    r.URL.Query().Get("status"),
		StartDate: r.URL.Query().Get("start_date"),
		EndDate:   r.URL.Query().Get("end_date"),
		SortBy:    r.URL.Query().Get("sort_key"),
		SortDir:   r.URL.Query().Get("sort_direction"),
		Limit:     limit,
		Offset:    offset,
	}

	result, err := alerts.ListAlertHistory(ctx, h.DB, &filter)
	if err != nil {
		log.ErrorContext(ctx, "Failed to list alert history", "error", err)
		common.RespondError(w, http.StatusInternalServerError, "failed to list alerts")
		return
	}

	common.RespondJSON(w, http.StatusOK, result)
}

// GetAlert returns a single alert by ID.
func (h *Handler) GetAlert(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)

	id, err := common.ParseUintSafe(vars["id"])
	if err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid alert id")
		return
	}

	if id > math.MaxInt {
		common.RespondError(w, http.StatusBadRequest, "invalid alert id")
		return
	}
	alert, err := alerts.GetAlertHistory(ctx, h.DB, int(id))
	if err != nil {
		if errors.Is(err, alerts.ErrAlertHistoryNotFound) {
			common.RespondError(w, http.StatusNotFound, "alert not found")
			return
		}
		log.ErrorContext(ctx, "Failed to get alert", "error", err)
		common.RespondError(w, http.StatusInternalServerError, "failed to get alert")
		return
	}

	common.RespondJSON(w, http.StatusOK, alert)
}

// ListAlertRules returns all alert rules.
func (h *Handler) ListAlertRules(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	rules, err := alerts.ListAlertRules(ctx, h.DB)
	if err != nil {
		log.ErrorContext(ctx, "Failed to list alert rules", "error", err)
		common.RespondError(w, http.StatusInternalServerError, "failed to list alert rules")
		return
	}

	common.RespondJSON(w, http.StatusOK, rules)
}

// UpdateAlertRule updates an alert rule.
func (h *Handler) UpdateAlertRule(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)

	id, err := common.ParseUintSafe(vars["id"])
	if err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid rule id")
		return
	}

	var req alerts.UpdateAlertRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	rule, err := alerts.GetAlertRule(ctx, h.DB, id)
	if err != nil {
		common.RespondError(w, http.StatusNotFound, "alert rule not found")
		return
	}

	if req.Name != "" {
		rule.Name = req.Name
	}
	if req.AlertType != "" {
		rule.AlertType = req.AlertType
	}
	if req.Enabled != nil {
		rule.Enabled = *req.Enabled
	}
	if req.ThresholdValue != nil {
		rule.ThresholdValue = *req.ThresholdValue
	}
	if req.ThresholdWindowMinutes != nil {
		rule.ThresholdWindowMinutes = *req.ThresholdWindowMinutes
	}
	if req.PeerID != nil {
		rule.PeerID = req.PeerID
	}
	if req.ThrottleMinutes != nil {
		rule.ThrottleMinutes = *req.ThrottleMinutes
	}

	if err := alerts.UpdateAlertRule(ctx, h.DB, rule); err != nil {
		log.ErrorContext(ctx, "Failed to update alert rule", "error", err)
		common.RespondError(w, http.StatusInternalServerError, "failed to update alert rule")
		return
	}

	common.RespondJSON(w, http.StatusOK, rule)
}

// GetSMTPConfig returns SMTP configuration (password masked).
func (h *Handler) GetSMTPConfig(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	config, err := alerts.GetSMTPConfig(ctx, h.DB)
	if err != nil {
		log.ErrorContext(ctx, "Failed to get SMTP config", "error", err)
		common.RespondError(w, http.StatusInternalServerError, "failed to get SMTP config")
		return
	}

	common.RespondJSON(w, http.StatusOK, config)
}

// UpdateSMTPConfig updates SMTP configuration.
func (h *Handler) UpdateSMTPConfig(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req struct {
		Host        string `json:"host"`
		Port        int    `json:"port"`
		Username    string `json:"username"`
		Password    string `json:"password,omitempty"`
		UseTLS      bool   `json:"use_tls"`
		FromAddress string `json:"from_address"`
		Enabled     bool   `json:"enabled"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	settings := map[string]string{
		"smtp_host":         req.Host,
		"smtp_port":         strconv.Itoa(req.Port),
		"smtp_username":     req.Username,
		"smtp_use_tls":      strconv.Itoa(boolToInt(req.UseTLS)),
		"smtp_from_address": req.FromAddress,
		"smtp_enabled":      strconv.Itoa(boolToInt(req.Enabled)),
	}

	if req.Password != "" {
		passwordToStore := req.Password
		if h.Encryptor != nil {
			encrypted, err := h.Encryptor.Encrypt(req.Password)
			if err != nil {
				log.ErrorContext(ctx, "Failed to encrypt smtp_password", "error", err)
				common.RespondError(w, http.StatusInternalServerError, "failed to encrypt SMTP password")
				return
			}
			passwordToStore = encrypted
		}
		settings["smtp_password"] = passwordToStore
	}

	if err := alerts.UpsertSMTPSettings(ctx, h.DB, settings); err != nil {
		log.ErrorContext(ctx, "Failed to update SMTP config", "error", err)
		common.RespondError(w, http.StatusInternalServerError, "failed to update SMTP config")
		return
	}

	common.RespondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// TestSMTP sends a test email to the current user.
func (h *Handler) TestSMTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get username from context
	username := auth.UsernameFromContext(ctx)
	if username == "" {
		common.RespondError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	// Look up user ID from username
	var userID int
	var email string
	err := h.DB.QueryRowContext(ctx, "SELECT id, email FROM users WHERE username = ?", username).Scan(&userID, &email)
	if err != nil {
		log.ErrorContext(ctx, "Failed to get user", "error", err)
		common.RespondError(w, http.StatusInternalServerError, "failed to get user")
		return
	}

	// Get SMTP sender from alert service
	if h.AlertService == nil {
		common.RespondError(w, http.StatusInternalServerError, "alert service not available")
		return
	}

	smtpSender := h.AlertService.GetSMTPSender()
	if smtpSender == nil {
		common.RespondError(w, http.StatusInternalServerError, "SMTP not configured")
		return
	}

	testEvent := &alerts.AlertEvent{
		Type:      "test",
		Subject:   "Runic SMTP Test",
		Message:   "This is a test email from Runic. If you received this, your SMTP configuration is working correctly.",
		Timestamp: time.Now(),
	}

	if err := smtpSender.SendAlertEmail(email, testEvent); err != nil {
		log.ErrorContext(ctx, "Failed to send test email", "error", err)
		common.RespondJSON(w, http.StatusOK, map[string]interface{}{
			"success": false,
			"message": err.Error(),
		})
		return
	}

	common.RespondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Test email sent to " + email,
	})
}

// GetNotificationPrefs returns the current user's notification preferences.
func (h *Handler) GetNotificationPrefs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get username from context
	username := auth.UsernameFromContext(ctx)
	if username == "" {
		common.RespondError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	// Look up user ID from username
	var userID int
	err := h.DB.QueryRowContext(ctx, "SELECT id FROM users WHERE username = ?", username).Scan(&userID)
	if err != nil {
		log.ErrorContext(ctx, "Failed to get user", "error", err)
		common.RespondError(w, http.StatusInternalServerError, "failed to get user")
		return
	}
	if userID < 0 {
		common.RespondError(w, http.StatusBadRequest, "invalid user id")
		return
	}

	prefs, err := alerts.GetUserNotificationPreferences(ctx, h.DB, uint(userID))
	if err != nil {
		// Return default preferences if not found
		defaultPrefs := &alerts.UserNotificationPreferences{
			UserID:             uint(userID),
			QuietHoursEnabled:  false,
			QuietHoursStart:    "22:00",
			QuietHoursEnd:      "07:00",
			QuietHoursTimezone: "UTC",
			DigestEnabled:      false,
			DigestFrequency:    "daily",
			DigestTime:         "08:00",
			DigestTimezone:     "UTC",
		}
		common.RespondJSON(w, http.StatusOK, defaultPrefs)
		return
	}

	common.RespondJSON(w, http.StatusOK, prefs)
}

// UpdateNotificationPrefs updates the current user's notification preferences.
func (h *Handler) UpdateNotificationPrefs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get username from context
	username := auth.UsernameFromContext(ctx)
	if username == "" {
		common.RespondError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	// Look up user ID from username
	var userID int
	err := h.DB.QueryRowContext(ctx, "SELECT id FROM users WHERE username = ?", username).Scan(&userID)
	if err != nil {
		log.ErrorContext(ctx, "Failed to get user", "error", err)
		common.RespondError(w, http.StatusInternalServerError, "failed to get user")
		return
	}
	if userID < 0 {
		common.RespondError(w, http.StatusBadRequest, "invalid user id")
		return
	}

	var req alerts.UpdateNotificationPreferencesRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	// Get existing prefs or create new
	prefs, err := alerts.GetUserNotificationPreferences(ctx, h.DB, uint(userID))
	if err != nil {
		prefs = &alerts.UserNotificationPreferences{
			UserID:             uint(userID),
			QuietHoursStart:    "22:00",
			QuietHoursEnd:      "07:00",
			QuietHoursTimezone: "UTC",
			DigestFrequency:    "daily",
			DigestTime:         "08:00",
			DigestTimezone:     "UTC",
		}
	}

	// Validate and sync timezone fields
	// Both timezone fields should always have the same value
	var timezoneToSet string
	switch {
	case req.QuietHoursTimezone != nil && req.DigestTimezone != nil:
		// Both provided - validate they match
		if *req.QuietHoursTimezone != *req.DigestTimezone {
			common.RespondError(w, http.StatusBadRequest, "quiet_hours_timezone and digest_timezone must be the same")
			return
		}
		timezoneToSet = *req.QuietHoursTimezone
	case req.QuietHoursTimezone != nil:
		timezoneToSet = *req.QuietHoursTimezone
	case req.DigestTimezone != nil:
		timezoneToSet = *req.DigestTimezone
	}

	// Validate timezone if provided
	if timezoneToSet != "" {
		if _, err := time.LoadLocation(timezoneToSet); err != nil {
			common.RespondError(w, http.StatusBadRequest, "Invalid timezone: must be valid IANA timezone identifier")
			return
		}
	}

	if req.QuietHoursEnabled != nil {
		prefs.QuietHoursEnabled = *req.QuietHoursEnabled
	}
	if req.QuietHoursStart != nil {
		prefs.QuietHoursStart = *req.QuietHoursStart
	}
	if req.QuietHoursEnd != nil {
		prefs.QuietHoursEnd = *req.QuietHoursEnd
	}
	// Sync both timezone fields
	if timezoneToSet != "" {
		prefs.QuietHoursTimezone = timezoneToSet
		prefs.DigestTimezone = timezoneToSet
	}
	if req.DigestEnabled != nil {
		prefs.DigestEnabled = *req.DigestEnabled
	}
	if req.DigestFrequency != nil {
		prefs.DigestFrequency = *req.DigestFrequency
	}
	if req.DigestTime != nil {
		prefs.DigestTime = *req.DigestTime
	}

	if err := alerts.UpsertUserNotificationPreferences(ctx, h.DB, prefs); err != nil {
		log.ErrorContext(ctx, "Failed to update notification preferences", "error", err)
		common.RespondError(w, http.StatusInternalServerError, "failed to update preferences")
		return
	}

	common.RespondJSON(w, http.StatusOK, prefs)
}

// DeleteAlert deletes a single alert by ID.
func (h *Handler) DeleteAlert(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)

	id, err := common.ParseUintSafe(vars["id"])
	if err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid alert id")
		return
	}

	if err := alerts.DeleteAlertHistory(ctx, h.DB, id); err != nil {
		if errors.Is(err, alerts.ErrAlertHistoryNotFound) {
			common.RespondError(w, http.StatusNotFound, "alert not found")
			return
		}
		log.ErrorContext(ctx, "Failed to delete alert", "error", err)
		common.RespondError(w, http.StatusInternalServerError, "failed to delete alert")
		return
	}

	common.RespondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// ClearAllAlerts deletes all alert history entries.
func (h *Handler) ClearAllAlerts(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if err := alerts.ClearAllAlertHistory(ctx, h.DB); err != nil {
		log.ErrorContext(ctx, "Failed to clear all alerts", "error", err)
		common.RespondError(w, http.StatusInternalServerError, "failed to clear alerts")
		return
	}

	common.RespondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// RegisterRoutes adds alert routes to the given router.
func (h *Handler) RegisterRoutes(r *mux.Router) {
	// Alert history routes (admin only)
	r.HandleFunc("/alerts", h.ListAlerts).Methods("GET")
	r.HandleFunc("/alerts", h.ClearAllAlerts).Methods("DELETE")
	r.HandleFunc("/alerts/{id:[0-9]+}", h.GetAlert).Methods("GET")
	r.HandleFunc("/alerts/{id:[0-9]+}", h.DeleteAlert).Methods("DELETE")

	// Alert rules routes (admin only)
	r.HandleFunc("/alert-rules", h.ListAlertRules).Methods("GET")
	r.HandleFunc("/alert-rules/{id:[0-9]+}", h.UpdateAlertRule).Methods("PUT")

	// SMTP config routes (admin only)
	r.HandleFunc("/settings/smtp", h.GetSMTPConfig).Methods("GET")
	r.HandleFunc("/settings/smtp", h.UpdateSMTPConfig).Methods("PUT")
	r.HandleFunc("/settings/smtp/test", h.TestSMTP).Methods("POST")
}

// RegisterUserRoutes adds user-specific alert routes (authenticated users).
func (h *Handler) RegisterUserRoutes(r *mux.Router) {
	r.HandleFunc("/users/me/notification-preferences", h.GetNotificationPrefs).Methods("GET")
	r.HandleFunc("/users/me/notification-preferences", h.UpdateNotificationPrefs).Methods("PUT")
}

// boolToInt converts a boolean to an integer (1 for true, 0 for false).
// Used for storing boolean values in system_config as "1" or "0" strings.
func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
