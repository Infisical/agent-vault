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
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)
	return rec
}

func TestMCPEnforcesStreamableHTTPMediaTypes(t *testing.T) {
	srv, ms, token := setupProposalTest(t)
	ms.sessions[token].VaultRole = "admin"
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`

	wrongContent := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	wrongContent.Header.Set("Authorization", "Bearer "+token)
	wrongContent.Header.Set("X-Vault", "default")
	wrongContent.Header.Set("Content-Type", "text/plain")
	wrongContent.Header.Set("Accept", "application/json, text/event-stream")
	contentRec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(contentRec, wrongContent)
	if contentRec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("unsupported Content-Type status=%d body=%s", contentRec.Code, contentRec.Body.String())
	}

	for _, accept := range []string{"application/json", "application/json, text/event-stream;q=0.0"} {
		wrongAccept := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
		wrongAccept.Header.Set("Authorization", "Bearer "+token)
		wrongAccept.Header.Set("X-Vault", "default")
		wrongAccept.Header.Set("Content-Type", "application/json; charset=utf-8")
		wrongAccept.Header.Set("Accept", accept)
		acceptRec := httptest.NewRecorder()
		srv.httpServer.Handler.ServeHTTP(acceptRec, wrongAccept)
		if acceptRec.Code != http.StatusNotAcceptable {
			t.Fatalf("Accept %q status=%d body=%s", accept, acceptRec.Code, acceptRec.Body.String())
		}
	}
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
		properties, _ := response.Result.Tools[i].Input["properties"].(map[string]any)
		if _, ok := properties["context_binding_id"]; !ok {
			t.Errorf("%s schema does not require context binding input", name)
		}
		required, _ := response.Result.Tools[i].Input["required"].([]any)
		if !containsMCPRequired(required, "context_binding_id") {
			t.Errorf("%s schema required=%v", name, required)
		}
	}
	for _, forbidden := range []string{`"credential"`, `"token"`, `"secret"`, `"value"`, `"executable_path"`, `"sha256"`} {
		if strings.Contains(strings.ToLower(list.Body.String()), forbidden) {
			t.Errorf("tool schema unexpectedly accepts field %s", forbidden)
		}
	}
}

func containsMCPRequired(values []any, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func mcpStringPtr(value string) *string { return &value }

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
	seedProposalContextBinding(ms, false)
	ms.vaults["other"] = &store.Vault{ID: "other-vault-id", Name: "other"}
	ms.proposals["other-vault-id"] = []store.Proposal{{ID: 7, VaultID: "other-vault-id", Status: "pending", Message: "other vault"}}
	strict := postMCP(t, srv, token, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"vault_proposal_show","arguments":{"context_binding_id":"`+testServerContextBindingID+`","proposal_id":7,"vault":"other"}}}`)
	if strict.Code != http.StatusOK || !strings.Contains(strict.Body.String(), `"isError":true`) {
		t.Fatalf("expected strict tool argument error, got %d %s", strict.Code, strict.Body.String())
	}
	wrongVault := postMCP(t, srv, token, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"vault_proposal_show","arguments":{"context_binding_id":"`+testServerContextBindingID+`","proposal_id":7}}}`)
	if wrongVault.Code != http.StatusOK || !strings.Contains(wrongVault.Body.String(), `"isError":true`) || strings.Contains(wrongVault.Body.String(), "other vault") {
		t.Fatalf("cross-vault proposal leaked or was not rejected: %d %s", wrongVault.Code, wrongVault.Body.String())
	}
}

func TestMCPControlActionsRequireExactActiveContextBinding(t *testing.T) {
	srv, ms, token := setupProposalTest(t)
	ms.sessions[token].VaultRole = "admin"
	seedProposalContextBinding(ms, false)
	otherID := "av_ctx_01JQ6T9J2WR8MVB7F2K4N6P8RB"
	other := *ms.contextBindings[testServerContextBindingID]
	other.ID = otherID
	other.Tuple.OriginCodexThreadID = "01a026f1-a339-77c3-bbc1-a0071b64171d"
	ms.contextBindings[otherID] = &other
	ms.proposals["root-ns-id"] = []store.Proposal{
		{ID: 1, VaultID: "root-ns-id", Status: "pending", ServicesJSON: `[]`, CredentialsJSON: `[]`, ContextBindingID: mcpStringPtr(testServerContextBindingID)},
		{ID: 2, VaultID: "root-ns-id", Status: "pending", ServicesJSON: `[]`, CredentialsJSON: `[]`, ContextBindingID: mcpStringPtr(otherID)},
		{ID: 3, VaultID: "root-ns-id", Status: "pending", ServicesJSON: `[]`, CredentialsJSON: `[]`},
	}

	missing := postMCP(t, srv, token, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"vault_proposal_show","arguments":{"proposal_id":1}}}`)
	wrong := postMCP(t, srv, token, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"vault_proposal_show","arguments":{"context_binding_id":"`+otherID+`","proposal_id":1}}}`)
	for name, response := range map[string]*httptest.ResponseRecorder{"missing": missing, "wrong": wrong} {
		if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"isError":true`) || !strings.Contains(response.Body.String(), "context binding mismatch") {
			t.Fatalf("%s context binding response=%d %s", name, response.Code, response.Body.String())
		}
	}

	list := postMCP(t, srv, token, `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"vault_proposal_list","arguments":{"context_binding_id":"`+testServerContextBindingID+`","status":"pending"}}}`)
	if list.Code != http.StatusOK || !strings.Contains(list.Body.String(), `"proposal_id":1`) || strings.Contains(list.Body.String(), `"proposal_id":2`) || strings.Contains(list.Body.String(), `"proposal_id":3`) {
		t.Fatalf("context-bound list leaked another context: %d %s", list.Code, list.Body.String())
	}
}

func TestMCPProposalProjectionAndApprovalDestinationRedactSensitiveFields(t *testing.T) {
	srv, ms, token := setupProposalTest(t)
	ms.sessions[token].VaultRole = "admin"
	seedProposalContextBinding(ms, false)
	ms.proposals["root-ns-id"] = []store.Proposal{{
		ID: 3, VaultID: "root-ns-id", Status: "pending", Message: mcpSentinel, UserMessage: mcpSentinel,
		ServicesJSON:    `[{"action":"set","name":"github","host":"api.github.com","auth":{"type":"bearer","token":"` + mcpSentinel + `"}}]`,
		CredentialsJSON: `[{"action":"set","key":"GITHUB_TOKEN","type":"static","description":"` + mcpSentinel + `","value":"` + mcpSentinel + `","acquisition":{"handler":"github-cli","profile":"github.com","mode":"native"}}]`,
		ApprovalToken:   mcpSentinel, ContextBindingID: mcpStringPtr(testServerContextBindingID), CreatedAt: time.Now(),
	}}
	show := postMCP(t, srv, token, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"vault_proposal_show","arguments":{"context_binding_id":"`+testServerContextBindingID+`","proposal_id":3}}}`)
	approval := postMCP(t, srv, token, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"vault_approval_open","arguments":{"context_binding_id":"`+testServerContextBindingID+`","proposal_id":3}}}`)
	list := postMCP(t, srv, token, `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"vault_proposal_list","arguments":{"context_binding_id":"`+testServerContextBindingID+`","status":"pending"}}}`)
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
	call := postMCP(t, srv, token, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"vault_acquisition_start","arguments":{"context_binding_id":"`+testServerContextBindingID+`","proposal_id":1,"key":"GITHUB_TOKEN","value":"`+mcpSentinel+`"}}}`)
	if call.Code != http.StatusOK || !strings.Contains(call.Body.String(), `"isError":true`) || strings.Contains(call.Body.String(), mcpSentinel) {
		t.Fatalf("credential-bearing tool args must fail safely: %d %s", call.Code, call.Body.String())
	}
}

func TestMCPStartReusesProposalAcquisitionAdmission(t *testing.T) {
	srv, ms, token := setupProposalTest(t)
	ms.sessions[token].VaultRole = "admin"
	seedProposalContextBinding(ms, false)
	ms.proposals["root-ns-id"] = []store.Proposal{{ID: 9, VaultID: "root-ns-id", Status: "pending", CredentialsJSON: `[]`, ContextBindingID: mcpStringPtr(testServerContextBindingID)}}
	resp := postMCP(t, srv, token, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"vault_acquisition_start","arguments":{"context_binding_id":"`+testServerContextBindingID+`","proposal_id":9,"key":"GITHUB_TOKEN"}}}`)
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
	start := postMCP(t, srv, token, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"vault_acquisition_start","arguments":{"context_binding_id":"`+testServerContextBindingID+`","proposal_id":1,"key":"GITHUB_TOKEN"}}}`)
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
	status := postMCP(t, srv, token, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"vault_acquisition_status","arguments":{"context_binding_id":"`+testServerContextBindingID+`","proposal_id":1,"key":"GITHUB_TOKEN"}}}`)
	for _, forbidden := range []string{"continuation_ticket_hash", "context_binding_id", "handler_id", "executable_path", "sha256", proposalAcquisitionSentinel} {
		if strings.Contains(status.Body.String(), forbidden) {
			t.Fatalf("MCP acquisition status leaked %q: %s", forbidden, status.Body.String())
		}
	}
	cancel := postMCP(t, srv, token, `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"vault_acquisition_cancel","arguments":{"context_binding_id":"`+testServerContextBindingID+`","proposal_id":1,"key":"GITHUB_TOKEN"}}}`)
	if cancel.Code != http.StatusOK || !strings.Contains(cancel.Body.String(), `"state":"cancelled"`) {
		t.Fatalf("MCP acquisition cancel failed: %d %s", cancel.Code, cancel.Body.String())
	}
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("MCP cancellation did not stop provider")
	}
}
