package notify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

// WebhookConfig holds outbound webhook notification configuration loaded
// from AGENT_VAULT_NOTIFY_* environment variables.
type WebhookConfig struct {
	URL    string
	Format string // "generic" (default) or "slack" — Discord's Incoming Webhook API also accepts the slack {"text": ...} shape
}

// LoadWebhookConfig reads webhook configuration from AGENT_VAULT_NOTIFY_WEBHOOK_URL
// and AGENT_VAULT_NOTIFY_FORMAT. Returns nil if the URL is not set (webhooks disabled).
func LoadWebhookConfig() *WebhookConfig {
	url := os.Getenv("AGENT_VAULT_NOTIFY_WEBHOOK_URL")
	if url == "" {
		return nil
	}

	format := strings.ToLower(os.Getenv("AGENT_VAULT_NOTIFY_FORMAT"))
	switch format {
	case "slack", "generic":
		// valid
	default:
		format = "generic"
	}

	return &WebhookConfig{URL: url, Format: format}
}

// ProposalWebhookEvent describes a proposal lifecycle event delivered to the
// configured webhook URL as a JSON payload (generic format).
type ProposalWebhookEvent struct {
	Event       string `json:"event"` // e.g. "proposal.created"
	Vault       string `json:"vault"`
	ProposalID  int    `json:"proposal_id"`
	AgentName   string `json:"agent_name,omitempty"`
	Message     string `json:"message,omitempty"`
	ApprovalURL string `json:"approval_url"`
}

// webhookHTTPClient is shared across sends; short timeout since this is a
// fire-and-forget best-effort notification, not on the request's critical path.
var webhookHTTPClient = &http.Client{Timeout: 10 * time.Second}

// WebhookEnabled reports whether outbound webhook notifications are configured.
func (n *Notifier) WebhookEnabled() bool {
	return n != nil && n.webhookConfig != nil
}

// SendProposalWebhook posts a proposal lifecycle event to the configured
// webhook URL. No-op if webhooks are not configured. Callers that want
// fire-and-forget semantics should invoke this in a goroutine.
func (n *Notifier) SendProposalWebhook(evt ProposalWebhookEvent) error {
	if !n.WebhookEnabled() {
		return nil
	}

	var payload interface{}
	if n.webhookConfig.Format == "slack" {
		payload = map[string]string{"text": slackProposalText(evt)}
	} else {
		payload = evt
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal webhook payload: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, n.webhookConfig.URL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build webhook request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := webhookHTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("webhook post: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook post: unexpected status %d", resp.StatusCode)
	}
	return nil
}

// slackProposalText renders a proposal event as Slack (mrkdwn) formatted text.
// Discord's webhook API also accepts a plain {"content": ...} field, but tolerates
// the Slack {"text": ...} shape closely enough for a single format to cover both;
// operators who need Discord-native embeds can front the webhook with a small relay.
func slackProposalText(evt ProposalWebhookEvent) string {
	var b strings.Builder
	fmt.Fprintf(&b, "*New proposal (#%d)* in vault `%s`", evt.ProposalID, evt.Vault)
	if evt.AgentName != "" {
		fmt.Fprintf(&b, " from agent `%s`", evt.AgentName)
	}
	if evt.Message != "" {
		fmt.Fprintf(&b, "\n> %s", evt.Message)
	}
	fmt.Fprintf(&b, "\n<%s|Review and approve>", evt.ApprovalURL)
	return b.String()
}
