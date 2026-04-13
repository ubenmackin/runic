// Package alerts provides alert and notification functionality.
package alerts

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/smtp"
	"strings"
	"time"

	"runic/internal/crypto"

	"runic/internal/common/log"
)

// SMTPSender handles sending emails via SMTP.
type SMTPSender struct {
	config    SMTPConfig
	encryptor *crypto.Encryptor
	logger    *slog.Logger
}

// NewSMTPSender creates a new SMTP sender with the given configuration.
// The encryptor is used to decrypt the SMTP password if it's encrypted.
func NewSMTPSender(config *SMTPConfig, encryptor *crypto.Encryptor) *SMTPSender {
	return &SMTPSender{
		config:    *config,
		encryptor: encryptor,
		logger:    log.L().With("component", "smtp_sender"),
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

	htmlBody := s.generateAlertHTML(event)
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

// sanitizeHeaderValue removes CR/LF from header values to prevent header injection.
func (s *SMTPSender) sanitizeHeaderValue(value string) string {
	value = strings.ReplaceAll(value, "\r", "")
	value = strings.ReplaceAll(value, "\n", "")
	return strings.TrimSpace(value)
}

// buildMessage constructs the email message with headers.
func (s *SMTPSender) buildMessage(to, subject, body, contentType string) string {
	var msg bytes.Buffer

	fmt.Fprintf(&msg, "From: %s\r\n", s.config.FromAddress)
	fmt.Fprintf(&msg, "To: %s\r\n", to)
	fmt.Fprintf(&msg, "Subject: %s\r\n", subject)
	fmt.Fprintf(&msg, "Date: %s\r\n", time.Now().Format(time.RFC1123Z))
	msg.WriteString("MIME-Version: 1.0\r\n")
	fmt.Fprintf(&msg, "Content-Type: %s; charset=\"UTF-8\"\r\n", contentType)
	msg.WriteString("\r\n")
	msg.WriteString(body)

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
func (s *SMTPSender) generateAlertHTML(event *AlertEvent) string {
	// Runic branding colors
	purple := "#7C3AED"
	amber := "#F59E0B"

	var severityColor, severityLabel string
	switch event.GetSeverity() {
	case SeverityCritical:
		severityColor = "#DC2626" // red
		severityLabel = "CRITICAL"
	case SeverityWarning:
		severityColor = amber
		severityLabel = "WARNING"
	default:
		severityColor = purple
		severityLabel = "INFO"
	}

	// Build alert type specific content
	var alertContent strings.Builder
	switch event.Type {
	case AlertTypePeerOffline:
		fmt.Fprintf(&alertContent, `
			<p><strong>Peer:</strong> %s (ID: %d)</p>
			<p>The peer has gone offline and is no longer responding.</p>
		`, event.PeerName, event.PeerID)
	case AlertTypePeerOnline:
		fmt.Fprintf(&alertContent, `
			<p><strong>Peer:</strong> %s (ID: %d)</p>
			<p>The peer is now online and responding.</p>
		`, event.PeerName, event.PeerID)
	case AlertTypeNewPeer:
		fmt.Fprintf(&alertContent, `
			<p><strong>Peer:</strong> %s (ID: %d)</p>
			<p>A new peer has been detected in the network.</p>
		`, event.PeerName, event.PeerID)
	case AlertTypeBundleFailed:
		fmt.Fprintf(&alertContent, `
			<p><strong>Peer:</strong> %s (ID: %d)</p>
			<p>Bundle compilation failed for this peer.</p>
		`, event.PeerName, event.PeerID)
	case AlertTypeBlockedSpike:
		fmt.Fprintf(&alertContent, `
			<p><strong>Blocked Events:</strong> %d</p>
			<p>A spike in blocked traffic has been detected.</p>
		`, event.Value)
	default:
		fmt.Fprintf(&alertContent, `
			<p><strong>Alert Type:</strong> %s</p>
		`, event.Type)
	}

	// Add custom message if provided
	if event.Message != "" {
		fmt.Fprintf(&alertContent, `<p><strong>Details:</strong> %s</p>`, event.Message)
	}

	// Build full HTML email
	html := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="margin: 0; padding: 0; background-color: #f3f4f6; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;">
	<table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%%" style="background-color: #f3f4f6; padding: 40px 20px;">
		<tr>
			<td align="center">
				<table role="presentation" cellspacing="0" cellpadding="0" border="0" width="600" style="background-color: #ffffff; border-radius: 8px; overflow: hidden; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);">
					<!-- Header -->
					<tr>
						<td style="background-color: %s; padding: 30px 40px; text-align: center;">
							<h1 style="margin: 0; color: #ffffff; font-size: 28px; font-weight: 700;">Runic</h1>
							<p style="margin: 10px 0 0 0; color: #ffffff; opacity: 0.9; font-size: 14px;">Network Policy Management</p>
						</td>
					</tr>
					<!-- Alert Badge -->
					<tr>
						<td style="padding: 30px 40px 10px 40px; text-align: center;">
							<span style="display: inline-block; background-color: %s; color: #ffffff; padding: 8px 20px; border-radius: 20px; font-size: 12px; font-weight: 600; text-transform: uppercase; letter-spacing: 1px;">%s</span>
						</td>
					</tr>
					<!-- Content -->
					<tr>
						<td style="padding: 20px 40px 30px 40px;">
							<h2 style="margin: 0 0 20px 0; color: #1f2937; font-size: 20px; font-weight: 600;">%s</h2>
							<div style="color: #4b5563; font-size: 16px; line-height: 1.6;">
								%s
							</div>
						</td>
					</tr>
					<!-- Timestamp -->
					<tr>
						<td style="padding: 0 40px 30px 40px;">
							<p style="margin: 0; color: #9ca3af; font-size: 14px;">
								<strong>Timestamp:</strong> %s
							</p>
						</td>
					</tr>
					<!-- Footer -->
					<tr>
						<td style="background-color: #f9fafb; padding: 20px 40px; border-top: 1px solid #e5e7eb;">
							<p style="margin: 0; color: #6b7280; font-size: 12px; text-align: center;">
								This is an automated alert from <a href="#" style="color: %s; text-decoration: none; font-weight: 600;">Runic</a>.
								<br>
								<a href="#" style="color: %s; text-decoration: none;">Manage notification preferences</a>
							</p>
						</td>
					</tr>
				</table>
			</td>
		</tr>
	</table>
</body>
</html>
`,
		purple,                       // header background
		severityColor, severityLabel, // badge
		event.Type,                           // h2 title
		alertContent.String(),                // content
		event.Timestamp.Format(time.RFC1123), // timestamp
		purple,                               // footer link color
		amber,                                // preferences link color
	)

	return html
}
