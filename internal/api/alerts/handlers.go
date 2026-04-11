// Package alerts provides API handlers for the alert system.
package alerts

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"

	"runic/internal/alerts"
	"runic/internal/api/common"
	"runic/internal/common/log"
	"runic/internal/crypto"
)

// Handler handles alert API requests.
type Handler struct {
	DB           *sql.DB
	AlertService *alerts.Service
	Encryptor    *crypto.Encryptor
}

// NewHandler creates a new alert handler.
func NewHandler(db *sql.DB, alertService *alerts.Service, encryptor *crypto.Encryptor) *Handler {
	return &Handler{
		DB:           db,
		AlertService: alertService,
		Encryptor:    encryptor,
	}
}

// ListAlerts returns paginated alert history.
func (h *Handler) ListAlerts(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse pagination params
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 50
	}
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if offset < 0 {
		offset = 0
	}

	history, err := alerts.ListAlertHistory(ctx, h.DB, limit, offset)
	if err != nil {
		log.ErrorContext(ctx, "Failed to list alert history", "error", err)
		common.RespondError(w, http.StatusInternalServerError, "failed to list alerts")
		return
	}

	common.RespondJSON(w, http.StatusOK, map[string]interface{}{
		"alerts": history,
		"limit":  limit,
		"offset": offset,
	})
}

// GetAlert returns a single alert by ID.
func (h *Handler) GetAlert(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)

	id, err := strconv.ParseUint(vars["id"], 10, 64)
	if err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid alert id")
		return
	}

	var alert alerts.AlertHistory
	err = h.DB.QueryRowContext(ctx, `
		SELECT id, rule_id, alert_type, peer_id, severity, subject, message, metadata, status, sent_at, error_message, created_at
		FROM alert_history WHERE id = ?
	`, id).Scan(&alert.ID, &alert.RuleID, &alert.AlertType, &alert.PeerID, &alert.Severity,
		&alert.Subject, &alert.Message, &alert.Metadata, &alert.Status, &alert.SentAt, &alert.ErrorMessage, &alert.CreatedAt)

	if err == sql.ErrNoRows {
		common.RespondError(w, http.StatusNotFound, "alert not found")
		return
	}
	if err != nil {
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

	id, err := strconv.ParseUint(vars["id"], 10, 64)
	if err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid rule id")
		return
	}

	var req alerts.UpdateAlertRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	// Get existing rule
	rule, err := alerts.GetAlertRule(ctx, h.DB, uint(id))
	if err != nil {
		common.RespondError(w, http.StatusNotFound, "alert rule not found")
		return
	}

	// Apply updates
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

	config := struct {
		Host        string `json:"host"`
		Port        int    `json:"port"`
		Username    string `json:"username"`
		PasswordSet bool   `json:"password_set"`
		UseTLS      bool   `json:"use_tls"`
		FromAddress string `json:"from_address"`
		Enabled     bool   `json:"enabled"`
	}{}

	// Get individual settings
	err := h.DB.QueryRowContext(ctx, "SELECT value FROM system_config WHERE key = 'smtp_host'").Scan(&config.Host)
	if err != nil && err != sql.ErrNoRows {
		log.ErrorContext(ctx, "Failed to get smtp_host", "error", err)
		common.RespondError(w, http.StatusInternalServerError, "failed to get SMTP config")
		return
	}

	var portStr string
	err = h.DB.QueryRowContext(ctx, "SELECT value FROM system_config WHERE key = 'smtp_port'").Scan(&portStr)
	if err == nil {
		config.Port, _ = strconv.Atoi(portStr)
	}

	err = h.DB.QueryRowContext(ctx, "SELECT value FROM system_config WHERE key = 'smtp_username'").Scan(&config.Username)
	if err != nil && err != sql.ErrNoRows {
		log.ErrorContext(ctx, "Failed to get smtp_username", "error", err)
	}

	var hasPassword bool
	err = h.DB.QueryRowContext(ctx, "SELECT COUNT(*) > 0 FROM system_config WHERE key = 'smtp_password' AND value IS NOT NULL AND value != ''").Scan(&hasPassword)
	config.PasswordSet = err == nil && hasPassword

	var useTLS int
	err = h.DB.QueryRowContext(ctx, "SELECT CAST(value AS INTEGER) FROM system_config WHERE key = 'smtp_use_tls'").Scan(&useTLS)
	if err == nil {
		config.UseTLS = useTLS == 1
	}

	err = h.DB.QueryRowContext(ctx, "SELECT value FROM system_config WHERE key = 'smtp_from_address'").Scan(&config.FromAddress)
	if err != nil && err != sql.ErrNoRows {
		log.ErrorContext(ctx, "Failed to get smtp_from_address", "error", err)
	}

	var enabled int
	err = h.DB.QueryRowContext(ctx, "SELECT CAST(value AS INTEGER) FROM system_config WHERE key = 'smtp_enabled'").Scan(&enabled)
	if err == nil {
		config.Enabled = enabled == 1
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

	// Upsert each setting
	settings := map[string]string{
		"smtp_host":         req.Host,
		"smtp_port":         strconv.Itoa(req.Port),
		"smtp_username":     req.Username,
		"smtp_use_tls":      strconv.FormatBool(req.UseTLS),
		"smtp_from_address": req.FromAddress,
		"smtp_enabled":      strconv.FormatBool(req.Enabled),
	}

	for key, value := range settings {
		_, err := h.DB.ExecContext(ctx,
			"INSERT OR REPLACE INTO system_config (key, value, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)",
			key, value,
		)
		if err != nil {
			log.ErrorContext(ctx, "Failed to update SMTP setting", "key", key, "error", err)
			common.RespondError(w, http.StatusInternalServerError, "failed to update SMTP config")
			return
		}
	}

	// Only update password if provided (non-empty)
	if req.Password != "" {
		// Encrypt the password before storing
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

		_, err := h.DB.ExecContext(ctx,
			"INSERT OR REPLACE INTO system_config (key, value, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)",
			"smtp_password", passwordToStore,
		)
		if err != nil {
			log.ErrorContext(ctx, "Failed to update smtp_password", "error", err)
			common.RespondError(w, http.StatusInternalServerError, "failed to update SMTP config")
			return
		}
	}

	common.RespondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// TestSMTP sends a test email to the current user.
func (h *Handler) TestSMTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get current user's email
	userID, ok := ctx.Value("user_id").(int)
	if !ok {
		common.RespondError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	var email string
	err := h.DB.QueryRowContext(ctx, "SELECT email FROM users WHERE id = ?", userID).Scan(&email)
	if err != nil {
		log.ErrorContext(ctx, "Failed to get user email", "error", err)
		common.RespondError(w, http.StatusInternalServerError, "failed to get user email")
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

	// Send test email
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

	userID, ok := ctx.Value("user_id").(int)
	if !ok {
		common.RespondError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	prefs, err := alerts.GetUserNotificationPreferences(ctx, h.DB, uint(userID))
	if err != nil {
		// Return default preferences if not found
		defaultPrefs := &alerts.UserNotificationPreferences{
			UserID:             uint(userID),
			EnabledAlerts:      "[]",
			QuietHoursEnabled:  false,
			QuietHoursStart:    "22:00",
			QuietHoursEnd:      "07:00",
			QuietHoursTimezone: "UTC",
			DigestEnabled:      false,
			DigestFrequency:    "daily",
			DigestTime:         "08:00",
		}
		common.RespondJSON(w, http.StatusOK, defaultPrefs)
		return
	}

	common.RespondJSON(w, http.StatusOK, prefs)
}

// UpdateNotificationPrefs updates the current user's notification preferences.
func (h *Handler) UpdateNotificationPrefs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	userID, ok := ctx.Value("user_id").(int)
	if !ok {
		common.RespondError(w, http.StatusUnauthorized, "not authenticated")
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
			EnabledAlerts:      "[]",
			QuietHoursStart:    "22:00",
			QuietHoursEnd:      "07:00",
			QuietHoursTimezone: "UTC",
			DigestFrequency:    "daily",
			DigestTime:         "08:00",
		}
	}

	// Apply updates
	if req.EnabledAlerts != nil {
		prefs.EnabledAlerts = *req.EnabledAlerts
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
	if req.QuietHoursTimezone != nil {
		prefs.QuietHoursTimezone = *req.QuietHoursTimezone
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

// RegisterRoutes adds alert routes to the given router.
func (h *Handler) RegisterRoutes(r *mux.Router) {
	// Alert history routes (admin only)
	r.HandleFunc("/alerts", h.ListAlerts).Methods("GET")
	r.HandleFunc("/alerts/{id:[0-9]+}", h.GetAlert).Methods("GET")

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
