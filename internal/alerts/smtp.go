// Package alerts provides alert and notification functionality.
package alerts

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"html"
	"log/slog"
	"net/smtp"
	"os"
	"regexp"
	"strings"
	"time"

	"runic/internal/common/log"
	"runic/internal/crypto"
	"runic/internal/db"
)

// Package-level compiled regexes for HTML sanitization (compile once).
// These regexes are used to sanitize HTML email content to prevent XSS attacks.
var (
	// Matches script tags and their contents (case-insensitive, multiline)
	scriptRegex = regexp.MustCompile(`(?is)<script[^>]*>.*?</script>`)
	// Matches style tags and their contents (CSS injection vector)
	styleTagRegex = regexp.MustCompile(`(?is)<style[^>]*>.*?</style>`)
	// Matches event handler attributes (onclick, onerror, onload, etc.)
	// Handles both quoted and unquoted attribute values
	eventHandlerRegex = regexp.MustCompile(`(?i)\s+on\w+\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+)`)
	// dangerousURLRegex matches dangerous URL protocols (javascript:, data:, vbscript:) in
	// href, src, and style attributes.
	//
	// SECURITY NOTE: This regex does NOT handle HTML entity-encoded protocols
	// (e.g., &#106;avascript: or &#x6A;avascript:). This is acceptable because:
	// 1. User-controlled content (PeerName, Message, Type) is ALWAYS htmlEscaped
	//    before reaching this function, converting & to &amp;
	// 2. Entity-encoded content becomes double-encoded (&#106; → &amp;#106;)
	// 3. Browsers display literal text, preventing protocol execution
	//
	// If unescaped user content ever reaches this function, the entity bypass would work.
	// This sanitizer is defense-in-depth for trusted/system-generated content.
	dangerousURLRegex = regexp.MustCompile(`(?i)(href|src|style)\s*=\s*(?:"[^"]*(?:javascript|data|vbscript)[^"]*"|'[^']*(?:javascript|data|vbscript)[^']*')`)
	// Matches dangerous tags that can carry XSS payloads or cause content injection
	dangerousTagRegex = regexp.MustCompile(`(?i)</?(?:iframe|object|embed|form|svg|math|style|link|base)[^>]*>`)
	// Matches dangerous meta refresh tags (but preserves legitimate meta tags like charset, viewport)
	dangerousMetaRegex = regexp.MustCompile(`(?i)<meta[^>]+http-equiv\s*=\s*["']?refresh["']?[^>]*>`)
)

// Default SMTP retry constants.
const (
	smtpMaxRetries  = 3
	smtpBaseBackoff = 1 * time.Second
	smtpMaxBackoff  = 8 * time.Second // 1s, 2s, 4s, 8s cap
)

type SMTPSender struct {
	config    SMTPConfig
	encryptor *crypto.Encryptor
	logger    *slog.Logger
	database  db.Querier
}

// NewSMTPSender creates a new SMTP sender. The encryptor is used to decrypt the SMTP password if it's encrypted.
// The database is used to query instance_url for email footer links.
func NewSMTPSender(config *SMTPConfig, encryptor *crypto.Encryptor, database db.Querier) *SMTPSender {
	return &SMTPSender{
		config:    *config,
		encryptor: encryptor,
		logger:    log.L().With("component", "smtp_sender"),
		database:  database,
	}
}

func (s *SMTPSender) SetLogger(logger *slog.Logger) {
	s.logger = logger.With("component", "smtp_sender")
}

func (s *SMTPSender) Send(to, subject, body string) error {
	return s.sendEmail(to, subject, body, "text/plain")
}

func (s *SMTPSender) SendHTML(to, subject, htmlBody string) error {
	return s.sendEmail(to, subject, htmlBody, "text/html")
}

// SendAlertEmail sends an alert email. It creates a sanitized copy of the event to prevent email content injection
// from untrusted input in Subject, PeerName, Message, and Metadata string values.
// The sanitization removes control characters that could be used for header injection.
// Existing HTML escaping and header sanitization remain as defense-in-depth layers.
func (s *SMTPSender) SendAlertEmail(to string, event *AlertEvent) error {
	sanitizedEvent := *event

	sanitizedSubject, _ := SanitizeAlertInput(event.Subject, 0)
	sanitizedEvent.Subject = sanitizedSubject

	// Metadata string values are sanitized via SanitizeAlertInput before use
	if event.Metadata != nil {
		sanitizedEvent.Metadata = make(map[string]interface{}, len(event.Metadata))
		for k, v := range event.Metadata {
			if strVal, ok := v.(string); ok {
				safeVal, _ := SanitizeAlertInput(strVal, 0)
				sanitizedEvent.Metadata[k] = safeVal
				continue
			}
			sanitizedEvent.Metadata[k] = v
		}
	}

	sanitizedPeerName, _ := SanitizeAlertInput(event.PeerName, 0)
	sanitizedEvent.PeerName = sanitizedPeerName

	sanitizedMessage, _ := SanitizeAlertInput(event.Message, 0)
	sanitizedEvent.Message = sanitizedMessage

	subject := fmt.Sprintf("[Runic] %s", sanitizedEvent.Subject)
	if subject == "[Runic] " {
		subject = s.generateAlertSubject(&sanitizedEvent)
	}

	instanceCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	instanceURL := GetInstanceURL(instanceCtx, s.database)

	htmlBody := s.generateAlertHTML(&sanitizedEvent, instanceURL)
	return s.SendHTML(to, subject, htmlBody)
}

func (s *SMTPSender) sendEmail(to, subject, body, contentType string) error {
	if !s.config.IsEnabled() {
		return fmt.Errorf("SMTP is not enabled or not configured")
	}

	if to == "" {
		return fmt.Errorf("recipient email address is required")
	}

	password := s.config.Password
	if s.encryptor != nil && s.config.Password != "" {
		decrypted, err := s.encryptor.Decrypt(s.config.Password)
		if err != nil {
			s.logger.Error("failed to decrypt SMTP password", "error", err)
			return fmt.Errorf("failed to decrypt SMTP password: %w", err)
		}
		password = decrypted
	}

	// Sanitize header values to prevent email header injection.
	subject = s.sanitizeHeaderValue(subject)

	safeBody := body
	if strings.EqualFold(contentType, "text/html") {
		safeBody = s.sanitizeHTMLBody(body)
	}

	message := s.buildMessage(to, subject, safeBody, contentType)

	addr := fmt.Sprintf("%s:%d", s.config.Host, s.config.Port)

	s.logger.Debug("sending email",
		"to", to,
		"subject", subject,
		"smtp_host", s.config.Host,
		"smtp_port", s.config.Port,
	)

	var auth smtp.Auth
	if s.config.Username != "" && password != "" {
		auth = smtp.PlainAuth("", s.config.Username, password, s.config.Host)
	}

	// Retry with exponential backoff on transient SMTP failures.
	var lastErr error
	for attempt := 0; attempt <= smtpMaxRetries; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(1<<(attempt-1)) * smtpBaseBackoff
			if backoff > smtpMaxBackoff {
				backoff = smtpMaxBackoff
			}
			s.logger.Info("retrying SMTP send",
				"attempt", attempt,
				"max_retries", smtpMaxRetries,
				"backoff", backoff,
				"last_error", lastErr,
			)
			time.Sleep(backoff)
		}

		err := s.sendWithTLS(addr, auth, s.config.FromAddress, []string{to}, []byte(message))
		if err == nil {
			s.logger.Info("email sent successfully",
				"to", to,
				"subject", subject,
			)
			return nil
		}
		lastErr = err
		s.logger.Error("failed to send email",
			"to", to,
			"subject", subject,
			"attempt", attempt+1,
			"error", err,
		)
	}

	return fmt.Errorf("failed to send email after %d attempts: %w", smtpMaxRetries+1, lastErr)
}

func (s *SMTPSender) sendWithTLS(addr string, auth smtp.Auth, from string, to []string, msg []byte) error {
	var smtpConn *smtp.Client

	// SMTPS (direct TLS, typically port 465): connect with TLS from the start.
	if s.config.UseSMTPS {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: false,
			ServerName:         s.config.Host,
		}
		conn, err := tls.Dial("tcp", addr, tlsConfig)
		if err != nil {
			return fmt.Errorf("failed to connect to SMTPS server: %w", err)
		}
		defer func() {
			if err := conn.Close(); err != nil {
				s.logger.Debug("failed to close SMTPS connection", "error", err)
			}
		}()

		smtpConn, err = smtp.NewClient(conn, s.config.Host)
		if err != nil {
			return fmt.Errorf("failed to create SMTP client over TLS: %w", err)
		}
	} else {
		// Standard SMTP with optional STARTTLS (ports 25, 587, etc.)
		// NOTE: smtpConn.Close() (deferred below) is the sole owner of the
		// underlying connection — no separate conn.Close() defer is needed.
		var err error
		conn, err := smtp.Dial(addr)
		if err != nil {
			return fmt.Errorf("failed to connect to SMTP server: %w", err)
		}

		smtpConn = conn

		if s.config.UseTLS {
			if ok, _ := conn.Extension("STARTTLS"); ok {
				tlsConfig := &tls.Config{
					InsecureSkipVerify: false,
					ServerName:         s.config.Host,
				}
				if err := conn.StartTLS(tlsConfig); err != nil {
					return fmt.Errorf("STARTTLS failed: %w", err)
				}
				s.logger.Debug("STARTTLS enabled for SMTP connection")
			}
		}
	}

	defer func() {
		if err := smtpConn.Close(); err != nil {
			s.logger.Debug("failed to close SMTP client", "error", err)
		}
	}()

	return s.smtpConversation(smtpConn, auth, from, to, msg)
}

// smtpConversation performs the standard SMTP conversation (Hello, Auth, Mail, Rcpt, Data, Write)
// on an already-connected *smtp.Client. This eliminates the 100-line code duplication between
// the SMTPS and STARTTLS branches of sendWithTLS.
func (s *SMTPSender) smtpConversation(client *smtp.Client, auth smtp.Auth, from string, to []string, msg []byte) error {
	heloHostname := s.getHeloHostname()
	if err := client.Hello(heloHostname); err != nil {
		return fmt.Errorf("SMTP Hello (HELO) failed: %w", err)
	}

	if auth != nil {
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("SMTP authentication failed: %w", err)
		}
		s.logger.Debug("SMTP authentication successful")
	}

	if err := client.Mail(from); err != nil {
		return fmt.Errorf("failed to set sender: %w", err)
	}
	for _, recipient := range to {
		if err := client.Rcpt(recipient); err != nil {
			return fmt.Errorf("failed to set recipient %s: %w", recipient, err)
		}
	}

	wc, err := client.Data()
	if err != nil {
		return fmt.Errorf("failed to get data writer: %w", err)
	}
	defer func() {
		if err := wc.Close(); err != nil {
			s.logger.Debug("failed to close data writer", "error", err)
		}
	}()

	_, err = wc.Write(msg)
	if err != nil {
		return fmt.Errorf("failed to write message: %w", err)
	}

	return nil
}

// getHeloHostname returns the HELO/EHLO hostname to use in the SMTP conversation.
// If config.HeloHostname is set, it is used. Otherwise, the system hostname is used.
// If os.Hostname() also fails, "localhost" is returned as a safe default.
func (s *SMTPSender) getHeloHostname() string {
	if s.config.HeloHostname != "" {
		return s.config.HeloHostname
	}
	hostname, err := os.Hostname()
	if err != nil {
		s.logger.Warn("failed to get system hostname for HELO, falling back to localhost", "error", err)
		return "localhost"
	}
	return hostname
}

func (s *SMTPSender) sanitizeHeaderValue(value string) string {
	sanitized, _ := SanitizeAlertInput(value, 0) // no length limit for headers
	return sanitized
}

func (s *SMTPSender) htmlEscape(text string) string {
	return html.EscapeString(text)
}

// It removes dangerous HTML elements and attributes that could be used for XSS attacks.
//
// DEFENSE-IN-DEPTH ARCHITECTURE:
// This function is NOT the primary XSS prevention mechanism. The primary defense is:
//   - htmlEscape(): All user-controlled content (PeerName, Message, Type) is
//     HTML-entity escaped before insertion into templates
//   - SanitizeAlertInput(): Control characters removed to prevent header injection
//
// This function serves as a safety net to catch any missed untrusted interpolation
// in the system-generated email content.
//
// KNOWN LIMITATIONS:
//   - HTML entity-encoded protocols (&#106;avascript:) are NOT detected
//     (mitigated by htmlEscape upstream)
//   - CSS expression() in style attributes is NOT removed
//     (IE-specific attack, mitigated by htmlEscape upstream)
//   - This uses regex-based sanitization which is NOT a full HTML parser
//     (acceptable for our controlled email templates)
//
// Patterns removed:
// - <script>...</script> tags and contents
// - <style>...</style> tags and contents (CSS injection)
// - Event handler attributes (onclick, onerror, onload, etc.)
// - Dangerous URL protocols (javascript:, data:, vbscript:) in href/src/style
// - Dangerous tags (iframe, object, embed, form, svg, math, link, base)
// - Dangerous meta refresh tags with javascript: URLs
func (s *SMTPSender) sanitizeHTMLBody(body string) string {
	body = scriptRegex.ReplaceAllString(body, "")
	body = styleTagRegex.ReplaceAllString(body, "")
	body = eventHandlerRegex.ReplaceAllString(body, "")
	body = dangerousURLRegex.ReplaceAllString(body, "")
	body = dangerousTagRegex.ReplaceAllString(body, "")
	body = dangerousMetaRegex.ReplaceAllString(body, "")

	return body
}

func (s *SMTPSender) buildMessage(to, subject, body, contentType string) string {
	var msg bytes.Buffer

	// Sanitize ALL header values at the sink to prevent header injection
	// This ensures protection regardless of whether caller sanitized values
	safeFrom := s.sanitizeHeaderValue(s.config.FromAddress)
	safeTo := s.sanitizeHeaderValue(to)
	safeSubject := s.sanitizeHeaderValue(subject)

	fmt.Fprintf(&msg, "From: %s\r\n", safeFrom)
	fmt.Fprintf(&msg, "To: %s\r\n", safeTo)
	fmt.Fprintf(&msg, "Subject: %s\r\n", safeSubject)
	fmt.Fprintf(&msg, "Date: %s\r\n", time.Now().Format(time.RFC1123Z))
	msg.WriteString("MIME-Version: 1.0\r\n")
	safeContentType := s.sanitizeHeaderValue(contentType)
	fmt.Fprintf(&msg, "Content-Type: %s; charset=\"UTF-8\"\r\n", safeContentType)

	// Sanitize HTML body to prevent script injection
	safeBody := body
	if strings.HasPrefix(strings.ToLower(contentType), "text/html") {
		safeBody = s.sanitizeHTMLBody(body)
	}

	msg.WriteString("\r\n")
	msg.WriteString(safeBody)

	return msg.String()
}

func (s *SMTPSender) generateAlertSubject(event *AlertEvent) string {
	var prefix string
	switch event.GetSeverity() {
	case SeverityCritical:
		prefix = "[CRITICAL]"
	case SeverityWarning:
		prefix = "[WARNING]"
	default:
		prefix = "[INFO]"
	}

	var detail string
	switch event.Type {
	case AlertTypePeerOffline:
		detail = fmt.Sprintf("Peer Offline: %s", event.PeerName)
	case AlertTypePeerOnline:
		detail = fmt.Sprintf("Peer Online: %s", event.PeerName)
	case AlertTypeNewPeer:
		detail = fmt.Sprintf("New Peer Detected: %s", event.PeerName)
	case AlertTypeBundleFailed:
		detail = fmt.Sprintf("Bundle Failed: %s", event.PeerName)
	case AlertTypeBlockedSpike:
		detail = fmt.Sprintf("Blocked Traffic Spike: %d events", event.Value)
	default:
		detail = fmt.Sprintf("Alert: %s", event.Type)
	}

	return fmt.Sprintf("[Runic] %s %s", prefix, detail)
}

// Uses terminal aesthetic with dark mode colors and monospace font.
func (s *SMTPSender) generateAlertHTML(event *AlertEvent, instanceURL string) string {
	bodyBg := "#0a0a0a"
	containerBg := "#121212"
	borderColor := "#2d2d2d"
	tableBg := "#0d0d0d"
	textPrimary := "#d1d5db"
	textSecondary := "#e5e7eb"
	textMuted := "#6b7280"
	textDim := "#9ca3af"
	purple := "#a855f7"

	var badgeColor, badgeBg string
	var severityLabel string
	switch event.GetSeverity() {
	case SeverityCritical:
		badgeColor = "#ef4444"
		badgeBg = "#ef4444"
		severityLabel = "CRITICAL"
	case SeverityWarning:
		badgeColor = "#d97706"
		badgeBg = "#d97706"
		severityLabel = "WARNING"
	default:
		badgeColor = "#a855f7"
		badgeBg = "#a855f7"
		severityLabel = "INFO"
	}

	getMetaString := func(key string) string {
		if v, ok := event.Metadata[key]; ok {
			if s, ok := v.(string); ok {
				return s
			}
		}
		return ""
	}

	// renderTDRow builds a single table row with label and value columns.
	// This eliminates repeated HTML-in-Go template code across alert types.
	renderTDRow := func(label, value, valueColor string) string {
		if valueColor == "" {
			valueColor = textSecondary
		}
		return fmt.Sprintf(`<tr>
<td style="padding: 12px 15px; border-bottom: 1px solid %s; color: %s; width: 140px; font-weight: bold; text-transform: uppercase; letter-spacing: 1px;">%s</td>
<td style="padding: 12px 15px; border-bottom: 1px solid %s; color: %s;">%s</td>
</tr>`, borderColor, textMuted, s.htmlEscape(label), borderColor, valueColor, value)
	}

	var detailsTable strings.Builder

	switch event.Type {
	case AlertTypePeerOffline:
		detailsTable.WriteString(renderTDRow("Peer", fmt.Sprintf("%s (ID: %d)", s.htmlEscape(event.PeerName), event.PeerID), ""))
		if ip := getMetaString("ip_address"); ip != "" {
			detailsTable.WriteString(renderTDRow("IP Address", s.htmlEscape(ip), ""))
		}
		if offlineDuration := getMetaString("offline_duration"); offlineDuration != "" {
			detailsTable.WriteString(renderTDRow("Offline Duration", s.htmlEscape(offlineDuration), ""))
		}

	case AlertTypePeerOnline:
		detailsTable.WriteString(renderTDRow("Peer", fmt.Sprintf("%s (ID: %d)", s.htmlEscape(event.PeerName), event.PeerID), ""))
		if ip := getMetaString("ip_address"); ip != "" {
			detailsTable.WriteString(renderTDRow("IP Address", s.htmlEscape(ip), ""))
		}

	case AlertTypeNewPeer:
		detailsTable.WriteString(renderTDRow("Peer", fmt.Sprintf("%s (ID: %d)", s.htmlEscape(event.PeerName), event.PeerID), ""))
		if ip := getMetaString("ip_address"); ip != "" {
			detailsTable.WriteString(renderTDRow("IP Address", s.htmlEscape(ip), ""))
		}

	case AlertTypeBundleFailed:
		detailsTable.WriteString(renderTDRow("Peer", fmt.Sprintf("%s (ID: %d)", s.htmlEscape(event.PeerName), event.PeerID), ""))
		if errorMsg := getMetaString("error_message"); errorMsg != "" {
			detailsTable.WriteString(renderTDRow("Error", s.htmlEscape(errorMsg), "#ef4444"))
		}

	case AlertTypeBlockedSpike:
		detailsTable.WriteString(renderTDRow("Blocked Events", fmt.Sprintf("%d", event.Value), ""))
		if threshold := getMetaString("threshold"); threshold != "" {
			detailsTable.WriteString(renderTDRow("Threshold", s.htmlEscape(threshold), ""))
		}
		detailsTable.WriteString(renderTDRow("Alert Type", s.htmlEscape(string(event.Type)), ""))
	}

	detailsTable.WriteString(renderTDRow("Timestamp", event.Timestamp.Format(time.RFC1123), textDim))

	var messageContent string
	if event.Message != "" {
		detailsTable.WriteString(renderTDRow("Details", s.htmlEscape(event.Message), ""))
		messageContent = fmt.Sprintf(`<p style="font-size: 13px; color: %s; margin: 0 0 20px 0;">Details: %s</p>`, textDim, s.htmlEscape(event.Message))
	}

	settingsLink := instanceURL + "/settings"

	alertTitle := string(event.Type)
	if event.Subject != "" {
		alertTitle = event.Subject
	}

	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="color-scheme" content="dark">
<meta name="supported-color-schemes" content="dark">
<style type="text/css">
/* Force dark mode in email clients */
:root { color-scheme: dark; }
body { background-color: %s !important; }
</style>
</head>
<body style="background-color: %s; padding: 40px 20px; margin: 0; font-family: 'JetBrains Mono', Consolas, 'Courier New', monospace;">

<!-- Main Container -->
<div style="max-width: 600px; margin: 0 auto; background-color: %s; border: 1px solid %s; color: %s; line-height: 1.6;">

  <!-- Header -->
  <div style="padding: 20px;">
    <div style="border-bottom: 1px dashed #4b5563; padding-bottom: 15px; color: %s; font-size: 12px; font-weight: bold; letter-spacing: 2px;">
      [ RUNIC // SYSTEM ALERT ]
    </div>
  </div>

  <!-- Alert Summary -->
  <div style="padding: 0 20px;">
    <div style="margin-bottom: 15px;">
      <span style="color: %s; border: 1px solid %s; padding: 2px 8px; font-size: 11px; font-weight: bold; margin-right: 10px; display: inline-block;">[ %s ]</span>
      <span style="font-size: 16px; font-weight: bold; color: #f3f4f6;">%s</span>
    </div>
    <!-- Content -->
    <div style="font-size: 13px; color: %s; margin-bottom: 20px;">
      %s
    </div>
  </div>

  <!-- Details Table -->
  <div style="padding: 0 20px 20px 20px;">
    <table width="100%%" cellpadding="0" cellspacing="0" style="border-collapse: collapse; font-size: 12px; background-color: %s; border: 1px solid %s;">
      %s
    </table>
  </div>

  <!-- Footer -->
  <div style="background-color: %s; border-top: 1px solid %s; padding: 20px; text-align: center;">
    <div style="font-size: 11px; color: %s;">
      This is an automated alert from <span style="color: %s; font-weight: bold;">Runic</span>.
      <br><br>
      <a href="%s" style="color: #d97706; text-decoration: none; border-bottom: 1px dashed #d97706; padding-bottom: 2px;">Manage notification preferences</a>
    </div>
  </div>

</div>
</body>
</html>
`,
		bodyBg,
		bodyBg,
		containerBg,
		borderColor,
		textPrimary,
		purple,
		badgeColor,
		badgeBg,
		severityLabel,
		s.htmlEscape(alertTitle),
		textSecondary,
		messageContent,
		tableBg,
		borderColor,
		detailsTable.String(),
		tableBg,
		borderColor,
		textMuted,
		purple,
		settingsLink,
	)

	return html
}
