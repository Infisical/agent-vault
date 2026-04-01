// Package notify provides SMTP email notification support for Agent Vault.
package notify

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/mail"
	"net/smtp"
	"os"
	"strconv"
	"strings"
	"time"
)

// SMTPConfig holds the SMTP server configuration loaded from environment variables.
type SMTPConfig struct {
	Host          string
	Port          int
	Username      string
	Password      string
	From          string
	FromName      string // Display name for From header (default "Agent Vault")
	TLSMode       string // "opportunistic" (default), "required", "none"
	TLSSkipVerify bool   // Skip TLS certificate verification
}

// LoadSMTPConfig reads SMTP configuration from AGENT_VAULT_SMTP_* environment variables.
// Returns nil if AGENT_VAULT_SMTP_HOST is not set (SMTP disabled).
func LoadSMTPConfig() *SMTPConfig {
	host := os.Getenv("AGENT_VAULT_SMTP_HOST")
	if host == "" {
		return nil
	}

	port := 587
	if p := os.Getenv("AGENT_VAULT_SMTP_PORT"); p != "" {
		if v, err := strconv.Atoi(p); err == nil && v > 0 {
			port = v
		}
	}

	from := os.Getenv("AGENT_VAULT_SMTP_FROM")
	if from == "" {
		return nil
	}

	fromName := os.Getenv("AGENT_VAULT_SMTP_FROM_NAME")
	if fromName == "" {
		fromName = "Agent Vault"
	}

	tlsMode := strings.ToLower(os.Getenv("AGENT_VAULT_SMTP_TLS_MODE"))
	switch tlsMode {
	case "opportunistic", "required", "none":
		// valid
	default:
		tlsMode = "opportunistic"
	}

	tlsSkipVerify := os.Getenv("AGENT_VAULT_SMTP_TLS_SKIP_VERIFY")
	skipVerify := tlsSkipVerify == "true" || tlsSkipVerify == "1"

	return &SMTPConfig{
		Host:          host,
		Port:          port,
		Username:      os.Getenv("AGENT_VAULT_SMTP_USERNAME"),
		Password:      os.Getenv("AGENT_VAULT_SMTP_PASSWORD"),
		From:          from,
		FromName:      fromName,
		TLSMode:       tlsMode,
		TLSSkipVerify: skipVerify,
	}
}

// Notifier sends email notifications via SMTP.
// If created with a nil config, all operations are silent no-ops.
type Notifier struct {
	config *SMTPConfig
}

// New creates a Notifier. Pass nil config to create a no-op notifier.
func New(config *SMTPConfig) *Notifier {
	return &Notifier{config: config}
}

// Enabled reports whether SMTP is configured.
func (n *Notifier) Enabled() bool {
	return n != nil && n.config != nil
}

// SendMail sends an email to the given recipients. Returns an error if the
// send fails. Callers that want fire-and-forget semantics should invoke this
// in a goroutine.
func (n *Notifier) SendMail(to []string, subject, body string) error {
	if !n.Enabled() || len(to) == 0 {
		return nil
	}

	cfg := n.config
	addr := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))

	msg := buildMessage(cfg.FromName, cfg.From, to, subject, body)

	if cfg.Port == 465 {
		return sendImplicitTLS(cfg, addr, to, msg)
	}
	return sendSTARTTLS(cfg, addr, to, msg)
}

// sendSTARTTLS connects on a plain TCP socket and upgrades via STARTTLS.
func sendSTARTTLS(cfg *SMTPConfig, addr string, to []string, msg []byte) error {
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return fmt.Errorf("smtp dial: %w", err)
	}

	c, err := smtp.NewClient(conn, cfg.Host)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("smtp client: %w", err)
	}
	defer func() { _ = c.Close() }()

	tlsEstablished := false
	if cfg.TLSMode != "none" {
		tlsCfg := &tls.Config{ServerName: cfg.Host, InsecureSkipVerify: cfg.TLSSkipVerify} //nolint:gosec // user-configurable TLS skip verify for SMTP
		if ok, _ := c.Extension("STARTTLS"); ok {
			if err := c.StartTLS(tlsCfg); err != nil {
				return fmt.Errorf("starttls: %w", err)
			}
			tlsEstablished = true
		} else if cfg.TLSMode == "required" {
			return fmt.Errorf("smtp: server does not support STARTTLS (tls_mode=required)")
		}
		// Opportunistic mode: STARTTLS not available, skip authentication
		// to prevent sending credentials over a plaintext connection.
	}

	return finishSend(c, cfg, to, msg, tlsEstablished)
}

// sendImplicitTLS connects over TLS directly (port 465).
func sendImplicitTLS(cfg *SMTPConfig, addr string, to []string, msg []byte) error {
	tlsCfg := &tls.Config{ServerName: cfg.Host, InsecureSkipVerify: cfg.TLSSkipVerify} //nolint:gosec // user-configurable TLS skip verify for SMTP
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", addr, tlsCfg)
	if err != nil {
		return fmt.Errorf("smtp tls dial: %w", err)
	}

	c, err := smtp.NewClient(conn, cfg.Host)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("smtp client: %w", err)
	}
	defer func() { _ = c.Close() }()

	return finishSend(c, cfg, to, msg, true) // implicit TLS = always encrypted
}

// finishSend authenticates (if credentials are set and TLS is active), then sends the message.
func finishSend(c *smtp.Client, cfg *SMTPConfig, to []string, msg []byte, tlsEstablished bool) error {
	if cfg.Username != "" && cfg.Password != "" {
		if !tlsEstablished {
			return fmt.Errorf("smtp: refusing to send credentials over unencrypted connection")
		}
		auth := smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Host)
		if err := c.Auth(auth); err != nil {
			return fmt.Errorf("smtp auth: %w", err)
		}
	}

	if err := c.Mail(cfg.From); err != nil {
		return fmt.Errorf("smtp mail: %w", err)
	}
	for _, addr := range to {
		if err := c.Rcpt(addr); err != nil {
			return fmt.Errorf("smtp rcpt %s: %w", addr, err)
		}
	}

	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("smtp data: %w", err)
	}
	if _, err := w.Write(msg); err != nil {
		return fmt.Errorf("smtp write: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("smtp close data: %w", err)
	}

	return c.Quit()
}

// SendHTMLMail sends an HTML email to the given recipients.
func (n *Notifier) SendHTMLMail(to []string, subject, htmlBody string) error {
	if !n.Enabled() || len(to) == 0 {
		return nil
	}

	cfg := n.config
	addr := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))

	msg := buildHTMLMessage(cfg.FromName, cfg.From, to, subject, htmlBody)

	if cfg.Port == 465 {
		return sendImplicitTLS(cfg, addr, to, msg)
	}
	return sendSTARTTLS(cfg, addr, to, msg)
}

// sanitizeHeader strips \r and \n characters to prevent email header injection.
func sanitizeHeader(s string) string {
	return strings.NewReplacer("\r", "", "\n", "").Replace(s)
}

// buildRFC2822 constructs an RFC 2822 email with the given content type.
func buildRFC2822(fromName, from string, to []string, subject, contentType, body string) []byte {
	from = sanitizeHeader(from)
	fromName = sanitizeHeader(fromName)
	subject = sanitizeHeader(subject)
	sanitizedTo := make([]string, len(to))
	for i, t := range to {
		sanitizedTo[i] = sanitizeHeader(t)
	}
	addr := mail.Address{Name: fromName, Address: from}
	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\n", addr.String())
	fmt.Fprintf(&b, "To: %s\r\n", strings.Join(sanitizedTo, ", "))
	fmt.Fprintf(&b, "Subject: %s\r\n", subject)
	b.WriteString("MIME-Version: 1.0\r\n")
	fmt.Fprintf(&b, "Content-Type: %s\r\n", contentType)
	b.WriteString("\r\n")
	b.WriteString(body)
	return []byte(b.String())
}

// buildMessage constructs a basic RFC 2822 plain text email message.
func buildMessage(fromName, from string, to []string, subject, body string) []byte {
	return buildRFC2822(fromName, from, to, subject, "text/plain; charset=UTF-8", body)
}

// buildHTMLMessage constructs an RFC 2822 HTML email message.
func buildHTMLMessage(fromName, from string, to []string, subject, htmlBody string) []byte {
	return buildRFC2822(fromName, from, to, subject, "text/html; charset=UTF-8", htmlBody)
}
