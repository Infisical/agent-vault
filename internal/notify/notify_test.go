package notify

import (
	"bufio"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
)

func TestLoadSMTPConfig_Disabled(t *testing.T) {
	t.Setenv("AGENT_VAULT_SMTP_HOST", "")
	t.Setenv("AGENT_VAULT_SMTP_FROM", "")

	cfg := LoadSMTPConfig()
	if cfg != nil {
		t.Fatal("expected nil config when AGENT_VAULT_SMTP_HOST is empty")
	}
}

func TestLoadSMTPConfig_MissingFrom(t *testing.T) {
	t.Setenv("AGENT_VAULT_SMTP_HOST", "smtp.example.com")
	t.Setenv("AGENT_VAULT_SMTP_FROM", "")

	cfg := LoadSMTPConfig()
	if cfg != nil {
		t.Fatal("expected nil config when AGENT_VAULT_SMTP_FROM is empty")
	}
}

func TestLoadSMTPConfig_Defaults(t *testing.T) {
	t.Setenv("AGENT_VAULT_SMTP_HOST", "smtp.example.com")
	t.Setenv("AGENT_VAULT_SMTP_PORT", "")
	t.Setenv("AGENT_VAULT_SMTP_USERNAME", "")
	t.Setenv("AGENT_VAULT_SMTP_PASSWORD", "")
	t.Setenv("AGENT_VAULT_SMTP_FROM", "test@example.com")

	cfg := LoadSMTPConfig()
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
	if cfg.Host != "smtp.example.com" {
		t.Fatalf("expected host smtp.example.com, got %s", cfg.Host)
	}
	if cfg.Port != 587 {
		t.Fatalf("expected default port 587, got %d", cfg.Port)
	}
	if cfg.Username != "" {
		t.Fatalf("expected empty username, got %s", cfg.Username)
	}
	if cfg.From != "test@example.com" {
		t.Fatalf("expected from test@example.com, got %s", cfg.From)
	}
}

func TestLoadSMTPConfig_CustomPort(t *testing.T) {
	t.Setenv("AGENT_VAULT_SMTP_HOST", "smtp.example.com")
	t.Setenv("AGENT_VAULT_SMTP_PORT", "465")
	t.Setenv("AGENT_VAULT_SMTP_FROM", "test@example.com")

	cfg := LoadSMTPConfig()
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
	if cfg.Port != 465 {
		t.Fatalf("expected port 465, got %d", cfg.Port)
	}
}

func TestLoadSMTPConfig_InvalidPort(t *testing.T) {
	t.Setenv("AGENT_VAULT_SMTP_HOST", "smtp.example.com")
	t.Setenv("AGENT_VAULT_SMTP_PORT", "abc")
	t.Setenv("AGENT_VAULT_SMTP_FROM", "test@example.com")

	cfg := LoadSMTPConfig()
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
	if cfg.Port != 587 {
		t.Fatalf("expected fallback port 587, got %d", cfg.Port)
	}
}

func TestLoadSMTPConfig_Full(t *testing.T) {
	t.Setenv("AGENT_VAULT_SMTP_HOST", "mail.corp.com")
	t.Setenv("AGENT_VAULT_SMTP_PORT", "2525")
	t.Setenv("AGENT_VAULT_SMTP_USERNAME", "user")
	t.Setenv("AGENT_VAULT_SMTP_PASSWORD", "pass")
	t.Setenv("AGENT_VAULT_SMTP_FROM", "sb@corp.com")

	cfg := LoadSMTPConfig()
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
	if cfg.Host != "mail.corp.com" || cfg.Port != 2525 {
		t.Fatalf("unexpected host/port: %s:%d", cfg.Host, cfg.Port)
	}
	if cfg.Username != "user" || cfg.Password != "pass" {
		t.Fatal("unexpected credentials")
	}
	if cfg.From != "sb@corp.com" {
		t.Fatalf("unexpected from: %s", cfg.From)
	}
}

func TestLoadSMTPConfig_FromNameDefault(t *testing.T) {
	t.Setenv("AGENT_VAULT_SMTP_HOST", "smtp.example.com")
	t.Setenv("AGENT_VAULT_SMTP_FROM", "test@example.com")
	t.Setenv("AGENT_VAULT_SMTP_FROM_NAME", "")

	cfg := LoadSMTPConfig()
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
	if cfg.FromName != "Agent Vault" {
		t.Fatalf("expected default FromName 'Agent Vault', got %q", cfg.FromName)
	}
}

func TestLoadSMTPConfig_FromNameCustom(t *testing.T) {
	t.Setenv("AGENT_VAULT_SMTP_HOST", "smtp.example.com")
	t.Setenv("AGENT_VAULT_SMTP_FROM", "test@example.com")
	t.Setenv("AGENT_VAULT_SMTP_FROM_NAME", "My App")

	cfg := LoadSMTPConfig()
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
	if cfg.FromName != "My App" {
		t.Fatalf("expected FromName 'My App', got %q", cfg.FromName)
	}
}

func TestLoadSMTPConfig_TLSModeDefaults(t *testing.T) {
	t.Setenv("AGENT_VAULT_SMTP_HOST", "smtp.example.com")
	t.Setenv("AGENT_VAULT_SMTP_FROM", "test@example.com")
	t.Setenv("AGENT_VAULT_SMTP_TLS_MODE", "")

	cfg := LoadSMTPConfig()
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
	if cfg.TLSMode != "opportunistic" {
		t.Fatalf("expected default TLSMode 'opportunistic', got %q", cfg.TLSMode)
	}
}

func TestLoadSMTPConfig_TLSModeValid(t *testing.T) {
	for _, mode := range []string{"opportunistic", "required", "none"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("AGENT_VAULT_SMTP_HOST", "smtp.example.com")
			t.Setenv("AGENT_VAULT_SMTP_FROM", "test@example.com")
			t.Setenv("AGENT_VAULT_SMTP_TLS_MODE", mode)

			cfg := LoadSMTPConfig()
			if cfg == nil {
				t.Fatal("expected non-nil config")
			}
			if cfg.TLSMode != mode {
				t.Fatalf("expected TLSMode %q, got %q", mode, cfg.TLSMode)
			}
		})
	}
}

func TestLoadSMTPConfig_TLSModeInvalidFallback(t *testing.T) {
	t.Setenv("AGENT_VAULT_SMTP_HOST", "smtp.example.com")
	t.Setenv("AGENT_VAULT_SMTP_FROM", "test@example.com")
	t.Setenv("AGENT_VAULT_SMTP_TLS_MODE", "bogus")

	cfg := LoadSMTPConfig()
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
	if cfg.TLSMode != "opportunistic" {
		t.Fatalf("expected fallback TLSMode 'opportunistic', got %q", cfg.TLSMode)
	}
}

func TestLoadSMTPConfig_TLSSkipVerify(t *testing.T) {
	tests := []struct {
		env  string
		want bool
	}{
		{"", false},
		{"false", false},
		{"yes", false},
		{"true", true},
		{"1", true},
	}
	for _, tt := range tests {
		t.Run("val="+tt.env, func(t *testing.T) {
			t.Setenv("AGENT_VAULT_SMTP_HOST", "smtp.example.com")
			t.Setenv("AGENT_VAULT_SMTP_FROM", "test@example.com")
			t.Setenv("AGENT_VAULT_SMTP_TLS_SKIP_VERIFY", tt.env)

			cfg := LoadSMTPConfig()
			if cfg == nil {
				t.Fatal("expected non-nil config")
			}
			if cfg.TLSSkipVerify != tt.want {
				t.Fatalf("TLSSkipVerify for %q: expected %v, got %v", tt.env, tt.want, cfg.TLSSkipVerify)
			}
		})
	}
}

func TestSendSTARTTLS_RequiredMode_NoSTARTTLS(t *testing.T) {
	// Mock SMTP server that does NOT advertise STARTTLS.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	addr := ln.Addr().(*net.TCPAddr)
	done := make(chan struct{})

	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		write := func(s string) { conn.Write([]byte(s + "\r\n")) }
		reader := bufio.NewReader(conn)
		readLine := func() string {
			line, _ := reader.ReadString('\n')
			return strings.TrimSpace(line)
		}

		write("220 localhost ESMTP")
		cmd := readLine() // EHLO
		if !strings.HasPrefix(cmd, "EHLO") {
			write("500 expected EHLO")
			return
		}
		// No STARTTLS advertised
		write("250-localhost")
		write("250 OK")

		// The client should disconnect after the STARTTLS error.
		readLine() // QUIT or EOF
		write("221 Bye")
	}()

	cfg := &SMTPConfig{
		Host:     "127.0.0.1",
		Port:     addr.Port,
		From:     "test@example.com",
		FromName: "Agent Vault",
		TLSMode:  "required",
	}
	smtpAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(addr.Port))
	msg := buildMessage(cfg.FromName, cfg.From, []string{"to@example.com"}, "Test", "body")

	err = sendSTARTTLS(cfg, smtpAddr, []string{"to@example.com"}, msg)
	if err == nil {
		t.Fatal("expected error when STARTTLS required but not available")
	}
	if !strings.Contains(err.Error(), "tls_mode=required") {
		t.Fatalf("expected error to mention tls_mode=required, got: %v", err)
	}

	<-done
}

func TestNotifier_Enabled(t *testing.T) {
	var nilNotifier *Notifier
	if nilNotifier.Enabled() {
		t.Fatal("nil notifier should not be enabled")
	}

	noop := New(nil)
	if noop.Enabled() {
		t.Fatal("notifier with nil config should not be enabled")
	}

	active := New(&SMTPConfig{Host: "smtp.example.com", Port: 587, From: "test@example.com"})
	if !active.Enabled() {
		t.Fatal("notifier with config should be enabled")
	}
}

func TestNotifier_SendMail_NoOp(t *testing.T) {
	noop := New(nil)
	if err := noop.SendMail([]string{"a@b.com"}, "test", "body"); err != nil {
		t.Fatalf("no-op SendMail should not error: %v", err)
	}
}

func TestNotifier_SendMail_EmptyRecipients(t *testing.T) {
	n := New(&SMTPConfig{Host: "smtp.example.com", Port: 587, From: "test@example.com"})
	if err := n.SendMail(nil, "test", "body"); err != nil {
		t.Fatalf("SendMail with no recipients should not error: %v", err)
	}
}

func TestBuildMessage(t *testing.T) {
	msg := string(buildMessage("Agent Vault", "from@example.com", []string{"to@example.com"}, "Test Subject", "Hello world"))

	if !strings.Contains(msg, "From: \"Agent Vault\" <from@example.com>") {
		t.Errorf("missing or malformed From header, got: %s", msg)
	}
	if !strings.Contains(msg, "To: to@example.com") {
		t.Error("missing To header")
	}
	if !strings.Contains(msg, "Subject: Test Subject") {
		t.Error("missing Subject header")
	}
	if !strings.Contains(msg, "Content-Type: text/plain; charset=UTF-8") {
		t.Error("missing Content-Type header")
	}
	if !strings.Contains(msg, "\r\n\r\nHello world") {
		t.Error("missing body separator or body")
	}
}

func TestBuildMessage_CustomFromName(t *testing.T) {
	msg := string(buildMessage("My Company", "noreply@co.com", []string{"to@example.com"}, "Hi", "body"))
	if !strings.Contains(msg, "From: \"My Company\" <noreply@co.com>") {
		t.Errorf("expected custom from name in From header, got: %s", msg)
	}
}

func TestBuildHTMLMessage_FromName(t *testing.T) {
	msg := string(buildHTMLMessage("Custom Name", "from@example.com", []string{"to@example.com"}, "Sub", "<p>hi</p>"))
	if !strings.Contains(msg, "From: \"Custom Name\" <from@example.com>") {
		t.Errorf("expected custom from name in HTML From header, got: %s", msg)
	}
}

// TestSendMail_MockServer tests SendMail against a minimal mock SMTP server.
func TestSendMail_MockServer(t *testing.T) {
	// Start a minimal SMTP server on a random port.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	addr := ln.Addr().(*net.TCPAddr)
	received := make(chan string, 1)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Minimal SMTP conversation.
		write := func(s string) { conn.Write([]byte(s + "\r\n")) }
		reader := bufio.NewReader(conn)
		readLine := func() string {
			line, _ := reader.ReadString('\n')
			return strings.TrimSpace(line)
		}

		write("220 localhost ESMTP")
		cmd := readLine() // EHLO
		if !strings.HasPrefix(cmd, "EHLO") {
			write("500 expected EHLO")
			return
		}
		write("250-localhost")
		write("250 OK")

		readLine() // MAIL FROM
		write("250 OK")

		readLine() // RCPT TO
		write("250 OK")

		readLine() // DATA
		write("354 Go ahead")

		// Read until lone dot.
		var data strings.Builder
		for {
			line := readLine()
			if line == "." {
				break
			}
			data.WriteString(line + "\n")
		}
		write("250 OK")
		received <- data.String()

		readLine() // QUIT
		write("221 Bye")
	}()

	// Temporarily override env for this test.
	origHost := os.Getenv("AGENT_VAULT_SMTP_HOST")
	defer os.Setenv("AGENT_VAULT_SMTP_HOST", origHost)

	n := New(&SMTPConfig{
		Host: "127.0.0.1",
		Port: addr.Port,
		From: "sb@test.com",
	})

	err = n.SendMail([]string{"admin@test.com"}, "Test", "Hello from Agent Vault")
	if err != nil {
		t.Fatalf("SendMail failed: %v", err)
	}

	data := <-received
	if !strings.Contains(data, "Subject: Test") {
		t.Error("email missing subject")
	}
	if !strings.Contains(data, "Hello from Agent Vault") {
		t.Error("email missing body")
	}
}
