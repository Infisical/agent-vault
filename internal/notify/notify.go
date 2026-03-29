// Package notify provides SMTP email notification support for Agent Vault.
package notify

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"os"
	"strconv"
	"strings"
	"time"
)

// SMTPConfig holds the SMTP server configuration loaded from environment variables.
type SMTPConfig struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
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

	return &SMTPConfig{
		Host:     host,
		Port:     port,
		Username: os.Getenv("AGENT_VAULT_SMTP_USERNAME"),
		Password: os.Getenv("AGENT_VAULT_SMTP_PASSWORD"),
		From:     from,
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

	msg := buildMessage(cfg.From, to, subject, body)

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

	if ok, _ := c.Extension("STARTTLS"); ok {
		tlsCfg := &tls.Config{ServerName: cfg.Host}
		if err := c.StartTLS(tlsCfg); err != nil {
			return fmt.Errorf("starttls: %w", err)
		}
	}

	return finishSend(c, cfg, to, msg)
}

// sendImplicitTLS connects over TLS directly (port 465).
func sendImplicitTLS(cfg *SMTPConfig, addr string, to []string, msg []byte) error {
	tlsCfg := &tls.Config{ServerName: cfg.Host}
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

	return finishSend(c, cfg, to, msg)
}

// finishSend authenticates (if credentials are set), then sends the message.
func finishSend(c *smtp.Client, cfg *SMTPConfig, to []string, msg []byte) error {
	if cfg.Username != "" && cfg.Password != "" {
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

	msg := buildHTMLMessage(cfg.From, to, subject, htmlBody)

	if cfg.Port == 465 {
		return sendImplicitTLS(cfg, addr, to, msg)
	}
	return sendSTARTTLS(cfg, addr, to, msg)
}

// sanitizeHeader strips \r and \n characters to prevent email header injection.
func sanitizeHeader(s string) string {
	return strings.NewReplacer("\r", "", "\n", "").Replace(s)
}

// buildMessage constructs a basic RFC 2822 plain text email message.
func buildMessage(from string, to []string, subject, body string) []byte {
	from = sanitizeHeader(from)
	subject = sanitizeHeader(subject)
	sanitizedTo := make([]string, len(to))
	for i, t := range to {
		sanitizedTo[i] = sanitizeHeader(t)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "From: Agent Vault <%s>\r\n", from)
	fmt.Fprintf(&b, "To: %s\r\n", strings.Join(sanitizedTo, ", "))
	fmt.Fprintf(&b, "Subject: %s\r\n", subject)
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	b.WriteString("\r\n")
	b.WriteString(body)
	return []byte(b.String())
}

// buildHTMLMessage constructs an RFC 2822 HTML email message.
func buildHTMLMessage(from string, to []string, subject, htmlBody string) []byte {
	from = sanitizeHeader(from)
	subject = sanitizeHeader(subject)
	sanitizedTo := make([]string, len(to))
	for i, t := range to {
		sanitizedTo[i] = sanitizeHeader(t)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "From: Agent Vault <%s>\r\n", from)
	fmt.Fprintf(&b, "To: %s\r\n", strings.Join(sanitizedTo, ", "))
	fmt.Fprintf(&b, "Subject: %s\r\n", subject)
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/html; charset=UTF-8\r\n")
	b.WriteString("\r\n")
	b.WriteString(htmlBody)
	return []byte(b.String())
}
