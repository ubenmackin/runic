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

// SMTPSender handles sending emails via SMTP.
type SMTPSender struct {
	config    SMTPConfig
	encryptor *crypto.Encryptor
	logger    *slog.Logger
	database  db.Querier
}

// NewSMTPSender creates a new SMTP sender with the given configuration.
// The encryptor is used to decrypt the SMTP password if it's encrypted.
// The database is used to query instance_url for email footer links.
func NewSMTPSender(config *SMTPConfig, encryptor *crypto.Encryptor, database db.Querier) *SMTPSender {
	return &SMTPSender{
		config:    *config,
		encryptor: encryptor,
		logger:    log.L().With("component", "smtp_sender"),
		database:  database,
	}
}

// SetLogger sets a custom logger for the SMTP sender.
func (s *SMTPSender) SetLogger(logger *slog.Logger) {
	s.logger = logger.With("component", "smtp_sender")
}

// Send sends a plain text email to the specified recipient.
func (s *SMTPSender) Send(to, subject, body string) error {
	return s.sendEmail(to, subject, body, "text/plain")
}

// SendHTML sends an HTML email to the specified recipient.
func (s *SMTPSender) SendHTML(to, subject, htmlBody string) error {
	return s.sendEmail(to, subject, htmlBody, "text/html")
}

// SendAlertEmail sends an alert notification email using the Runic branding.
func (s *SMTPSender) SendAlertEmail(to string, event *AlertEvent) error {
	subject := fmt.Sprintf("[Runic] %s", event.Subject)
	if subject == "[Runic] " {
		subject = s.generateAlertSubject(event)
	}

	// Get instance URL for footer links
	instanceURL := GetInstanceURL(context.Background(), s.database)

	htmlBody := s.generateAlertHTML(event, instanceURL)
	return s.SendHTML(to, subject, htmlBody)
}

// sendEmail is the internal method that handles the actual email sending.
func (s *SMTPSender) sendEmail(to, subject, body, contentType string) error {
	if !s.config.IsEnabled() {
		return fmt.Errorf("SMTP is not enabled or not configured")
	}

	if to == "" {
		return fmt.Errorf("recipient email address is required")
	}

	// Decrypt password if encryptor is provided and password exists
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

	// Build the email message
	message := s.buildMessage(to, subject, body, contentType)

	// Create SMTP client
	addr := fmt.Sprintf("%s:%d", s.config.Host, s.config.Port)

	s.logger.Debug("sending email",
		"to", to,
		"subject", subject,
		"smtp_host", s.config.Host,
		"smtp_port", s.config.Port,
	)

	// Get authentication
	var auth smtp.Auth
	if s.config.Username != "" && password != "" {
		auth = smtp.PlainAuth("", s.config.Username, password, s.config.Host)
	}

	// Send the email
	err := s.sendWithTLS(addr, auth, s.config.FromAddress, []string{to}, []byte(message))
	if err != nil {
		s.logger.Error("failed to send email",
			"to", to,
			"subject", subject,
			"error", err,
		)
		return fmt.Errorf("failed to send email: %w", err)
	}

	s.logger.Info("email sent successfully",
		"to", to,
		"subject", subject,
	)

	return nil
}

// sendWithTLS sends an email with TLS/STARTTLS support.
func (s *SMTPSender) sendWithTLS(addr string, auth smtp.Auth, from string, to []string, msg []byte) error {
	// Connect to the SMTP server
	conn, err := smtp.Dial(addr)
	if err != nil {
		return fmt.Errorf("failed to connect to SMTP server: %w", err)
	}
	defer func() {
		if err := conn.Close(); err != nil {
			s.logger.Debug("failed to close SMTP connection", "error", err)
		}
	}()

	// Get server hostname for Hello
	if err := conn.Hello("localhost"); err != nil {
		return fmt.Errorf("SMTP Hello failed: %w", err)
	}

	// Check if STARTTLS is supported and use it if enabled
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

	// Authenticate if credentials are provided
	if auth != nil {
		if err := conn.Auth(auth); err != nil {
			return fmt.Errorf("SMTP authentication failed: %w", err)
		}
		s.logger.Debug("SMTP authentication successful")
	}

	// Set the sender
	if err := conn.Mail(from); err != nil {
		return fmt.Errorf("failed to set sender: %w", err)
	}

	// Set the recipients
	for _, recipient := range to {
		if err := conn.Rcpt(recipient); err != nil {
			return fmt.Errorf("failed to set recipient %s: %w", recipient, err)
		}
	}

	// Send the email body
	wc, err := conn.Data()
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

// sanitizeHeaderValue sanitizes header values using the shared SanitizeAlertInput function.
func (s *SMTPSender) sanitizeHeaderValue(value string) string {
	sanitized, _ := SanitizeAlertInput(value, 0) // no length limit for headers
	return sanitized
}

// htmlEscape escapes special HTML characters to prevent XSS/injection in email content.
func (s *SMTPSender) htmlEscape(text string) string {
	return html.EscapeString(text)
}

// sanitizeHTMLBody sanitizes HTML email content to prevent script/content injection.
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
	// Remove script tags and their contents
	body = scriptRegex.ReplaceAllString(body, "")

	// Remove style tags and their contents (CSS injection)
	body = styleTagRegex.ReplaceAllString(body, "")

	// Remove event handler attributes (onclick, onerror, onload, etc.)
	// Handles both quoted and unquoted attribute values
	body = eventHandlerRegex.ReplaceAllString(body, "")

	// Remove javascript:, data:, vbscript: URLs in href/src/style attributes
	body = dangerousURLRegex.ReplaceAllString(body, "")

	// Remove dangerous tags (iframe, object, embed, form, svg, math, style, link, base)
	body = dangerousTagRegex.ReplaceAllString(body, "")

	// Remove dangerous meta refresh tags (but preserve legitimate meta tags)
	body = dangerousMetaRegex.ReplaceAllString(body, "")

	return body
}

// buildMessage constructs the email message with headers.
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

// generateAlertSubject creates a subject line for an alert event.
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

// generateAlertHTML creates an HTML email body for an alert event.
// Uses terminal aesthetic with dark mode colors and monospace font.
func (s *SMTPSender) generateAlertHTML(event *AlertEvent, instanceURL string) string {
	// Terminal aesthetic colors
	bodyBg := "#0a0a0a"
	containerBg := "#121212"
	borderColor := "#2d2d2d"
	tableBg := "#0d0d0d"
	textPrimary := "#d1d5db"
	textSecondary := "#e5e7eb"
	textMuted := "#6b7280"
	textDim := "#9ca3af"
	purple := "#a855f7"

	// Severity colors for badges
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

	// Helper to get metadata string value
	getMetaString := func(key string) string {
		if v, ok := event.Metadata[key]; ok {
			if s, ok := v.(string); ok {
				return s
			}
		}
		return ""
	}

	// Build details table rows based on alert type
	var detailsTable strings.Builder

	switch event.Type {
	case AlertTypePeerOffline:
		offlineDuration := getMetaString("offline_duration")
		fmt.Fprintf(&detailsTable, `<tr>
<td style="padding: 12px 15px; border-bottom: 1px solid %s; color: %s; width: 140px; font-weight: bold; text-transform: uppercase; letter-spacing: 1px;">Peer</td>
<td style="padding: 12px 15px; border-bottom: 1px solid %s; color: %s; font-weight: bold;">%s (ID: %d)</td>
</tr>`, borderColor, textMuted, borderColor, textSecondary, s.htmlEscape(event.PeerName), event.PeerID)

		if ip := getMetaString("ip_address"); ip != "" {
			fmt.Fprintf(&detailsTable, `
<tr>
<td style="padding: 12px 15px; border-bottom: 1px solid %s; color: %s; font-weight: bold; text-transform: uppercase; letter-spacing: 1px;">IP Address</td>
<td style="padding: 12px 15px; border-bottom: 1px solid %s; color: %s;">%s</td>
</tr>`, borderColor, textMuted, borderColor, textSecondary, s.htmlEscape(ip))
		}

		if offlineDuration != "" {
			fmt.Fprintf(&detailsTable, `
<tr>
<td style="padding: 12px 15px; border-bottom: 1px solid %s; color: %s; font-weight: bold; text-transform: uppercase; letter-spacing: 1px;">Offline Duration</td>
<td style="padding: 12px 15px; border-bottom: 1px solid %s; color: %s;">%s</td>
</tr>`, borderColor, textMuted, borderColor, textSecondary, s.htmlEscape(offlineDuration))
		}

	case AlertTypePeerOnline:
		fmt.Fprintf(&detailsTable, `<tr>
<td style="padding: 12px 15px; border-bottom: 1px solid %s; color: %s; width: 140px; font-weight: bold; text-transform: uppercase; letter-spacing: 1px;">Peer</td>
<td style="padding: 12px 15px; border-bottom: 1px solid %s; color: %s; font-weight: bold;">%s (ID: %d)</td>
</tr>`, borderColor, textMuted, borderColor, textSecondary, s.htmlEscape(event.PeerName), event.PeerID)

		if ip := getMetaString("ip_address"); ip != "" {
			fmt.Fprintf(&detailsTable, `
<tr>
<td style="padding: 12px 15px; border-bottom: 1px solid %s; color: %s; font-weight: bold; text-transform: uppercase; letter-spacing: 1px;">IP Address</td>
<td style="padding: 12px 15px; border-bottom: 1px solid %s; color: %s;">%s</td>
</tr>`, borderColor, textMuted, borderColor, textSecondary, s.htmlEscape(ip))
		}

	case AlertTypeNewPeer:
		fmt.Fprintf(&detailsTable, `<tr>
<td style="padding: 12px 15px; border-bottom: 1px solid %s; color: %s; width: 140px; font-weight: bold; text-transform: uppercase; letter-spacing: 1px;">Peer</td>
<td style="padding: 12px 15px; border-bottom: 1px solid %s; color: %s; font-weight: bold;">%s (ID: %d)</td>
</tr>`, borderColor, textMuted, borderColor, textSecondary, s.htmlEscape(event.PeerName), event.PeerID)

		if ip := getMetaString("ip_address"); ip != "" {
			fmt.Fprintf(&detailsTable, `
<tr>
<td style="padding: 12px 15px; border-bottom: 1px solid %s; color: %s; font-weight: bold; text-transform: uppercase; letter-spacing: 1px;">IP Address</td>
<td style="padding: 12px 15px; border-bottom: 1px solid %s; color: %s;">%s</td>
</tr>`, borderColor, textMuted, borderColor, textSecondary, s.htmlEscape(ip))
		}

	case AlertTypeBundleFailed:
		fmt.Fprintf(&detailsTable, `<tr>
<td style="padding: 12px 15px; border-bottom: 1px solid %s; color: %s; width: 140px; font-weight: bold; text-transform: uppercase; letter-spacing: 1px;">Peer</td>
<td style="padding: 12px 15px; border-bottom: 1px solid %s; color: %s; font-weight: bold;">%s (ID: %d)</td>
</tr>`, borderColor, textMuted, borderColor, textSecondary, s.htmlEscape(event.PeerName), event.PeerID)

		errorMsg := getMetaString("error_message")
		if errorMsg != "" {
			fmt.Fprintf(&detailsTable, `
<tr>
<td style="padding: 12px 15px; border-bottom: 1px solid %s; color: %s; font-weight: bold; text-transform: uppercase; letter-spacing: 1px;">Error</td>
<td style="padding: 12px 15px; border-bottom: 1px solid %s; color: #ef4444;">%s</td>
</tr>`, borderColor, textMuted, borderColor, s.htmlEscape(errorMsg))
		}

	case AlertTypeBlockedSpike:
		fmt.Fprintf(&detailsTable, `<tr>
<td style="padding: 12px 15px; border-bottom: 1px solid %s; color: %s; width: 140px; font-weight: bold; text-transform: uppercase; letter-spacing: 1px;">Blocked Events</td>
<td style="padding: 12px 15px; border-bottom: 1px solid %s; color: %s; font-weight: bold;">%d</td>
</tr>`, borderColor, textMuted, borderColor, textSecondary, event.Value)

		threshold := getMetaString("threshold")
		if threshold != "" {
			fmt.Fprintf(&detailsTable, `
<tr>
<td style="padding: 12px 15px; border-bottom: 1px solid %s; color: %s; font-weight: bold; text-transform: uppercase; letter-spacing: 1px;">Threshold</td>
<td style="padding: 12px 15px; border-bottom: 1px solid %s; color: %s;">%s</td>
</tr>`, borderColor, textMuted, borderColor, textSecondary, s.htmlEscape(threshold))
		}

	default:
		fmt.Fprintf(&detailsTable, `<tr>
<td style="padding: 12px 15px; border-bottom: 1px solid %s; color: %s; width: 140px; font-weight: bold; text-transform: uppercase; letter-spacing: 1px;">Alert Type</td>
<td style="padding: 12px 15px; border-bottom: 1px solid %s; color: %s;">%s</td>
</tr>`, borderColor, textMuted, borderColor, textSecondary, s.htmlEscape(string(event.Type)))
	}

	// Always add timestamp row
	fmt.Fprintf(&detailsTable, `
<tr>
<td style="padding: 12px 15px; border-bottom: 1px solid %s; color: %s; font-weight: bold; text-transform: uppercase; letter-spacing: 1px;">Timestamp</td>
<td style="padding: 12px 15px; border-bottom: 1px solid %s; color: %s;">%s</td>
</tr>`, borderColor, textMuted, borderColor, textDim, event.Timestamp.Format(time.RFC1123))

	// Add custom message if provided
	var messageContent string
	if event.Message != "" {
		fmt.Fprintf(&detailsTable, `
<tr>
<td style="padding: 12px 15px; color: %s; font-weight: bold; text-transform: uppercase; letter-spacing: 1px;">Details</td>
<td style="padding: 12px 15px; color: %s;">%s</td>
</tr>`, textMuted, textSecondary, s.htmlEscape(event.Message))
		messageContent = fmt.Sprintf(`<p style="font-size: 13px; color: %s; margin: 0 0 20px 0;">Details: %s</p>`, textDim, s.htmlEscape(event.Message))
	}

	// Build footer URLs
	settingsLink := instanceURL + "/settings"

	// Build alert title from subject or type
	alertTitle := string(event.Type)
	if event.Subject != "" {
		alertTitle = event.Subject
	}

	// Build full HTML email with terminal aesthetic
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
		bodyBg, // style background-color
		bodyBg, // body background-color
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
