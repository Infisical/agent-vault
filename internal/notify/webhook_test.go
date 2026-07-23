package notify

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLoadWebhookConfig_Disabled(t *testing.T) {
	t.Setenv("AGENT_VAULT_NOTIFY_WEBHOOK_URL", "")

	cfg := LoadWebhookConfig()
	if cfg != nil {
		t.Fatal("expected nil config when AGENT_VAULT_NOTIFY_WEBHOOK_URL is empty")
	}
}

func TestLoadWebhookConfig_DefaultsToGeneric(t *testing.T) {
	t.Setenv("AGENT_VAULT_NOTIFY_WEBHOOK_URL", "https://example.com/hook")
	t.Setenv("AGENT_VAULT_NOTIFY_FORMAT", "")

	cfg := LoadWebhookConfig()
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
	if cfg.URL != "https://example.com/hook" {
		t.Fatalf("expected URL to match, got %s", cfg.URL)
	}
	if cfg.Format != "generic" {
		t.Fatalf("expected default format generic, got %s", cfg.Format)
	}
}

func TestLoadWebhookConfig_SlackFormat(t *testing.T) {
	t.Setenv("AGENT_VAULT_NOTIFY_WEBHOOK_URL", "https://hooks.slack.com/services/x")
	t.Setenv("AGENT_VAULT_NOTIFY_FORMAT", "Slack")

	cfg := LoadWebhookConfig()
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
	if cfg.Format != "slack" {
		t.Fatalf("expected format to be normalized to slack, got %s", cfg.Format)
	}
}

func TestLoadWebhookConfig_InvalidFormatFallsBackToGeneric(t *testing.T) {
	t.Setenv("AGENT_VAULT_NOTIFY_WEBHOOK_URL", "https://example.com/hook")
	t.Setenv("AGENT_VAULT_NOTIFY_FORMAT", "bogus")

	cfg := LoadWebhookConfig()
	if cfg.Format != "generic" {
		t.Fatalf("expected invalid format to fall back to generic, got %s", cfg.Format)
	}
}

func TestNotifier_WebhookEnabled(t *testing.T) {
	var nilNotifier *Notifier
	if nilNotifier.WebhookEnabled() {
		t.Fatal("nil notifier should not be webhook-enabled")
	}

	noop := New(nil, nil)
	if noop.WebhookEnabled() {
		t.Fatal("notifier with nil webhook config should not be webhook-enabled")
	}

	active := New(nil, &WebhookConfig{URL: "https://example.com/hook", Format: "generic"})
	if !active.WebhookEnabled() {
		t.Fatal("notifier with webhook config should be webhook-enabled")
	}
}

func TestSendProposalWebhook_NoOp(t *testing.T) {
	n := New(nil, nil)
	if err := n.SendProposalWebhook(ProposalWebhookEvent{Event: "proposal.created"}); err != nil {
		t.Fatalf("no-op SendProposalWebhook should not error: %v", err)
	}
}

func TestSendProposalWebhook_Generic(t *testing.T) {
	var received ProposalWebhookEvent
	var gotContentType string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotContentType = r.Header.Get("Content-Type")
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Errorf("failed to decode webhook body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n := New(nil, &WebhookConfig{URL: srv.URL, Format: "generic"})
	evt := ProposalWebhookEvent{
		Event:       "proposal.created",
		Vault:       "my-vault",
		ProposalID:  42,
		AgentName:   "codegen-bot",
		Message:     "needs access to stripe",
		ApprovalURL: "https://vault.example.com/approve/42?token=abc",
	}
	if err := n.SendProposalWebhook(evt); err != nil {
		t.Fatalf("SendProposalWebhook failed: %v", err)
	}

	if gotContentType != "application/json" {
		t.Fatalf("expected application/json content type, got %s", gotContentType)
	}
	if received != evt {
		t.Fatalf("expected received payload %+v to match sent event %+v", received, evt)
	}
}

func TestSendProposalWebhook_SlackFormat(t *testing.T) {
	var body map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n := New(nil, &WebhookConfig{URL: srv.URL, Format: "slack"})
	evt := ProposalWebhookEvent{
		Event:       "proposal.created",
		Vault:       "my-vault",
		ProposalID:  7,
		AgentName:   "codegen-bot",
		Message:     "needs access to stripe",
		ApprovalURL: "https://vault.example.com/approve/7?token=abc",
	}
	if err := n.SendProposalWebhook(evt); err != nil {
		t.Fatalf("SendProposalWebhook failed: %v", err)
	}

	text, ok := body["text"]
	if !ok {
		t.Fatalf("expected slack payload to have a text field, got %+v", body)
	}
	if !strings.Contains(text, "#7") || !strings.Contains(text, "my-vault") || !strings.Contains(text, evt.ApprovalURL) {
		t.Fatalf("expected slack text to reference proposal id, vault, and approval URL, got: %s", text)
	}
}

func TestSendProposalWebhook_NonSuccessStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	n := New(nil, &WebhookConfig{URL: srv.URL, Format: "generic"})
	err := n.SendProposalWebhook(ProposalWebhookEvent{Event: "proposal.created"})
	if err == nil {
		t.Fatal("expected error for non-2xx/3xx webhook response")
	}
}

func TestSendProposalWebhook_UnreachableURL(t *testing.T) {
	n := New(nil, &WebhookConfig{URL: "http://127.0.0.1:1/hook", Format: "generic"})
	err := n.SendProposalWebhook(ProposalWebhookEvent{Event: "proposal.created"})
	if err == nil {
		t.Fatal("expected error for unreachable webhook URL")
	}
}
