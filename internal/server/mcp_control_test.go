package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/acquisition"
	"github.com/Infisical/agent-vault/internal/store"
)

const mcpSentinel = "MCP_SENTINEL_SECRET_DO_NOT_RETURN"

func postMCP(t *testing.T, srv *Server, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Vault", "default")
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)
	return rec
}

func TestMCPInitializeAndExactlySixTools(t *testing.T) {
	srv, ms, token := setupProposalTest(t)
	ms.sessions[token].VaultRole = "admin"
	init := postMCP(t, srv, token, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}`)
	if init.Code != http.StatusOK || !strings.Contains(init.Body.String(), `"protocolVersion":"2025-03-26"`) {
		t.Fatalf("initialize: %d %s", init.Code, init.Body.String())
	}
	list := postMCP(t, srv, token, `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`)
	if list.Code != http.StatusOK {
		t.Fatalf("tools/list: %d %s", list.Code, list.Body.String())
	}
	var response struct {
		Result struct {
			Tools []struct {
				Name  string         `json:"name"`
				Input map[string]any `json:"inputSchema"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(list.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	want := []string{"vault_proposal_list", "vault_proposal_show", "vault_acquisition_start", "vault_acquisition_status", "vault_acquisition_cancel", "vault_approval_open"}
	if len(response.Result.Tools) != len(want) {
		t.Fatalf("tool count=%d, want %d: %s", len(response.Result.Tools), len(want), list.Body.String())
	}
	for i, name := range want {
		if response.Result.Tools[i].Name != name {
			t.Fatalf("tool[%d]=%q, want %q", i, response.Result.Tools[i].Name, name)
		}
		if response.Result.Tools[i].Input["additionalProperties"] != false {
			t.Errorf("%s schema must reject additional properties", name)
		}
	}
	for _, forbidden := range []string{`"credential"`, `"token"`, `"secret"`, `"value"`, `"context_binding_id"`, `"executable_path"`, `"sha256"`} {
		if strings.Contains(strings.ToLower(list.Body.String()), forbidden) {
			t.Errorf("tool schema unexpectedly accepts field %s", forbidden)
		}
	}
}

func TestMCPRequiresExistingSessionAndReviewRole(t *testing.T) {
	srv, ms, token := setupProposalTest(t)
	unauth := postMCP(t, srv, "", `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`)
	if unauth.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status=%d body=%s", unauth.Code, unauth.Body.String())
	}
	ms.sessions[token].VaultRole = "proxy"
	denied := postMCP(t, srv, token, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"vault_proposal_list","arguments":{}}}`)
	if denied.Code != http.StatusForbidden {
		t.Fatalf("proxy role status=%d body=%s", denied.Code, denied.Body.String())
	}
}

func TestMCPStrictToolArgumentsAndWrongVaultIsolation(t *testing.T) {
	srv, ms, token := setupProposalTest(t)
	ms.sessions[token].VaultRole = "admin"
	ms.vaults["other"] = &store.Vault{ID: "other-vault-id", Name: "other"}
	ms.proposals["other-vault-id"] = []store.Proposal{{ID: 7, VaultID: "other-vault-id", Status: "pending", Message: "other vault"}}
	strict := postMCP(t, srv, token, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"vault_proposal_show","arguments":{"proposal_id":7,"vault":"other"}}}`)
	if strict.Code != http.StatusOK || !strings.Contains(strict.Body.String(), `"isError":true`) {
		t.Fatalf("expected strict tool argument error, got %d %s", strict.Code, strict.Body.String())
	}
	wrongVault := postMCP(t, srv, token, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"vault_proposal_show","arguments":{"proposal_id":7}}}`)
	if wrongVault.Code != http.StatusOK || !strings.Contains(wrongVault.Body.String(), `"isError":true`) || strings.Contains(wrongVault.Body.String(), "other vault") {
		t.Fatalf("cross-vault proposal leaked or was not rejected: %d %s", wrongVault.Code, wrongVault.Body.String())
	}
}

func TestMCPProposalProjectionAndApprovalDestinationRedactSensitiveFields(t *testing.T) {
	srv, ms, token := setupProposalTest(t)
	ms.sessions[token].VaultRole = "admin"
	bindingID := "binding-secret-id"
	ms.proposals["root-ns-id"] = []store.Proposal{{
		ID: 3, VaultID: "root-ns-id", Status: "pending", Message: mcpSentinel, UserMessage: mcpSentinel,
		ServicesJSON:    `[{"action":"set","name":"github","host":"api.github.com","auth":{"type":"bearer","token":"` + mcpSentinel + `"}}]`,
		CredentialsJSON: `[{"action":"set","key":"GITHUB_TOKEN","type":"static","description":"` + mcpSentinel + `","value":"` + mcpSentinel + `","acquisition":{"handler":"github-cli","profile":"github.com","mode":"native"}}]`,
		ApprovalToken:   mcpSentinel, ContextBindingID: &bindingID, CreatedAt: time.Now(),
	}}
	show := postMCP(t, srv, token, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"vault_proposal_show","arguments":{"proposal_id":3}}}`)
	approval := postMCP(t, srv, token, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"vault_approval_open","arguments":{"proposal_id":3}}}`)
	list := postMCP(t, srv, token, `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"vault_proposal_list","arguments":{"status":"pending"}}}`)
	for name, rec := range map[string]*httptest.ResponseRecorder{"show": show, "approval_open": approval, "list": list} {
		if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), mcpSentinel) || strings.Contains(rec.Body.String(), "binding-secret-id") {
			t.Errorf("%s leaked sensitive data or failed: %d %s", name, rec.Code, rec.Body.String())
		}
		for _, forbidden := range []string{"credentials_json", "context_binding_id", "approval_token", "continuation_ticket", "executable_path", "sha256"} {
			if strings.Contains(strings.ToLower(rec.Body.String()), forbidden) {
				t.Errorf("%s contains forbidden field %q: %s", name, forbidden, rec.Body.String())
			}
		}
	}
	if strings.Contains(approval.Body.String(), "token=") || !strings.Contains(approval.Body.String(), "/vaults/default/proposals") {
		t.Fatalf("approval destination must be authenticated dashboard path only: %s", approval.Body.String())
	}
}

func TestMCPInitializeRejectsMalformedAndToolCallRejectsCredentialFields(t *testing.T) {
	srv, ms, token := setupProposalTest(t)
	ms.sessions[token].VaultRole = "admin"
	bad := postMCP(t, srv, token, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","unexpected":true}}`)
	if bad.Code != http.StatusBadRequest {
		t.Fatalf("malformed initialize status=%d body=%s", bad.Code, bad.Body.String())
	}
	call := postMCP(t, srv, token, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"vault_acquisition_start","arguments":{"proposal_id":1,"key":"GITHUB_TOKEN","value":"`+mcpSentinel+`"}}}`)
	if call.Code != http.StatusOK || !strings.Contains(call.Body.String(), `"isError":true`) || strings.Contains(call.Body.String(), mcpSentinel) {
		t.Fatalf("credential-bearing tool args must fail safely: %d %s", call.Code, call.Body.String())
	}
}

func TestMCPStartReusesProposalAcquisitionAdmission(t *testing.T) {
	srv, ms, token := setupProposalTest(t)
	ms.sessions[token].VaultRole = "admin"
	ms.proposals["root-ns-id"] = []store.Proposal{{ID: 9, VaultID: "root-ns-id", Status: "pending", CredentialsJSON: `[]`}}
	resp := postMCP(t, srv, token, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"vault_acquisition_start","arguments":{"proposal_id":9,"key":"GITHUB_TOKEN"}}}`)
	if resp.Code != http.StatusOK || !strings.Contains(resp.Body.String(), `"isError":true`) || !strings.Contains(resp.Body.String(), "declaration") {
		t.Fatalf("start bypassed proposal admission: %d %s", resp.Code, resp.Body.String())
	}
}

func TestMCPAcquisitionStartStatusAndCancelUseExistingAdmission(t *testing.T) {
	srv, ms, token := setupProposalAcquisitionEndpointTest(t)
	started := make(chan struct{})
	finished := make(chan struct{})
	srv.runAcquisitionProvider = func(ctx context.Context, _ acquisition.HandlerResolver, _ string, invocation acquisition.ProviderInvocation) (*acquisition.ProviderResult, error) {
		invocation.ProgressSink <- acquisition.Progress{Status: acquisition.ProgressAwaitingUser, ContextBindingID: invocation.ContextBindingID}
		close(started)
		<-ctx.Done()
		close(finished)
		return nil, ctx.Err()
	}
	start := postMCP(t, srv, token, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"vault_acquisition_start","arguments":{"proposal_id":1,"key":"GITHUB_TOKEN"}}}`)
	if start.Code != http.StatusOK || strings.Contains(start.Body.String(), mcpSentinel) {
		t.Fatalf("MCP acquisition start failed or leaked: %d %s", start.Code, start.Body.String())
	}
	for _, forbidden := range []string{"handler_id", "profile", "continuation_ticket_hash", "context_binding_id", "executable_path", "sha256"} {
		if strings.Contains(start.Body.String(), forbidden) {
			t.Fatalf("MCP acquisition start exposed %q: %s", forbidden, start.Body.String())
		}
	}
	<-started
	waitProposalAcquisitionState(t, ms, store.AcquisitionAwaitingUser)
	status := postMCP(t, srv, token, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"vault_acquisition_status","arguments":{"proposal_id":1,"key":"GITHUB_TOKEN"}}}`)
	for _, forbidden := range []string{"continuation_ticket_hash", "context_binding_id", "handler_id", "executable_path", "sha256", proposalAcquisitionSentinel} {
		if strings.Contains(status.Body.String(), forbidden) {
			t.Fatalf("MCP acquisition status leaked %q: %s", forbidden, status.Body.String())
		}
	}
	cancel := postMCP(t, srv, token, `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"vault_acquisition_cancel","arguments":{"proposal_id":1,"key":"GITHUB_TOKEN"}}}`)
	if cancel.Code != http.StatusOK || !strings.Contains(cancel.Body.String(), `"state":"cancelled"`) {
		t.Fatalf("MCP acquisition cancel failed: %d %s", cancel.Code, cancel.Body.String())
	}
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("MCP cancellation did not stop provider")
	}
}
