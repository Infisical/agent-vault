package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Infisical/agent-vault/internal/notify"
)

func TestNotifyWebhookTestRequiresOwner(t *testing.T) {
	ms, agentToken := setupMockStoreWithScopedSession(t, "default", "root-ns-id")
	notifier := notify.New(nil, &notify.WebhookConfig{URL: "http://example.invalid", Format: "generic"})
	srv := newTestServer(withStore(ms), withNotifier(notifier))

	req := httptest.NewRequest(http.MethodPost, "/v1/admin/notify/webhook/test", nil)
	req.Header.Set("Authorization", "Bearer "+agentToken)
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestNotifyWebhookTestNotConfigured(t *testing.T) {
	ms, ownerToken := setupMockStoreWithSession(t)
	// nil notifier = webhook not configured
	srv := newTestServer(withStore(ms))

	req := httptest.NewRequest(http.MethodPost, "/v1/admin/notify/webhook/test", nil)
	req.Header.Set("Authorization", "Bearer "+ownerToken)
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]string
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	if resp["error"] != "Webhook notifications are not configured" {
		t.Fatalf("unexpected error: %s", resp["error"])
	}
}

func TestNotifyWebhookTestSuccess(t *testing.T) {
	received := make(chan struct{}, 1)
	webhookSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var evt notify.ProposalWebhookEvent
		_ = json.NewDecoder(r.Body).Decode(&evt)
		if evt.Event != "proposal.created" {
			t.Errorf("expected event proposal.created, got %s", evt.Event)
		}
		w.WriteHeader(http.StatusOK)
		received <- struct{}{}
	}))
	defer webhookSrv.Close()

	ms, ownerToken := setupMockStoreWithSession(t)
	notifier := notify.New(nil, &notify.WebhookConfig{URL: webhookSrv.URL, Format: "generic"})
	srv := newTestServer(withStore(ms), withNotifier(notifier))

	req := httptest.NewRequest(http.MethodPost, "/v1/admin/notify/webhook/test", nil)
	req.Header.Set("Authorization", "Bearer "+ownerToken)
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	select {
	case <-received:
	default:
		t.Fatal("expected the test webhook handler to have received a request")
	}
}

func TestNotifyWebhookTestUpstreamFailure(t *testing.T) {
	webhookSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer webhookSrv.Close()

	ms, ownerToken := setupMockStoreWithSession(t)
	notifier := notify.New(nil, &notify.WebhookConfig{URL: webhookSrv.URL, Format: "generic"})
	srv := newTestServer(withStore(ms), withNotifier(notifier))

	req := httptest.NewRequest(http.MethodPost, "/v1/admin/notify/webhook/test", nil)
	req.Header.Set("Authorization", "Bearer "+ownerToken)
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestNotifyProposalCreatedFiresWebhookWithoutEmailRecipients verifies that the
// webhook channel fires independently of the email channel — a vault with no
// human members (so no email recipients) must still deliver the webhook.
func TestNotifyProposalCreatedFiresWebhookWithoutEmailRecipients(t *testing.T) {
	received := make(chan notify.ProposalWebhookEvent, 1)
	webhookSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var evt notify.ProposalWebhookEvent
		_ = json.NewDecoder(r.Body).Decode(&evt)
		w.WriteHeader(http.StatusOK)
		received <- evt
	}))
	defer webhookSrv.Close()

	ms := newMockStore()
	notifier := notify.New(nil, &notify.WebhookConfig{URL: webhookSrv.URL, Format: "generic"})
	srv := newTestServer(withStore(ms), withNotifier(notifier))

	// No vault members registered on ms for "root-ns-id", so the email path
	// (ListVaultMembersByType) returns zero grants and would previously have
	// short-circuited before the webhook was ever considered.
	srv.notifyProposalCreated("root-ns-id", "root", 99, "needs stripe access", "https://vault.example.com/approve/99?token=abc", "codegen-bot")

	select {
	case evt := <-received:
		if evt.ProposalID != 99 || evt.Vault != "root" || evt.Event != "proposal.created" {
			t.Fatalf("unexpected webhook payload: %+v", evt)
		}
	default:
		t.Fatal("expected webhook to fire even though there are no email recipients")
	}
}
