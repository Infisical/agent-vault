package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/approval"
	"github.com/Infisical/agent-vault/internal/broker"
	"github.com/Infisical/agent-vault/internal/store"
)

func TestRequestApprovalOnlyHumanVaultAdminCanDecide(t *testing.T) {
	ms, humanToken := setupMockStoreWithSession(t)
	ms.agents["worker"] = &store.Agent{ID: "agent-worker", Name: "worker", Role: "admin", Status: "active"}
	ms.sessions["agent-token"] = &store.Session{ID: "agent-token", AgentID: "agent-worker", VaultID: "root-ns-id", VaultRole: "admin", ExpiresAt: tp(time.Now().Add(time.Hour))}
	srv := newTestServer(withStore(ms))
	done := make(chan error, 1)
	go func() {
		done <- srv.approvals.Wait(context.Background(), approval.Request{VaultID: "root-ns-id", Method: "POST", Host: "api.example.com", Path: "/deploy"})
	}()
	var id string
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if items := srv.approvals.List("root-ns-id"); len(items) == 1 {
			id = items[0].ID
			break
		}
		time.Sleep(time.Millisecond)
	}
	if id == "" {
		t.Fatal("no pending approval")
	}
	path := "/v1/vaults/default/request-approvals/" + id + "/approve"
	for _, test := range []struct {
		token  string
		status int
	}{
		{"agent-token", http.StatusForbidden},
		{humanToken, http.StatusOK},
	} {
		req := httptest.NewRequest(http.MethodPost, path, nil)
		req.Header.Set("Authorization", "Bearer "+test.token)
		rec := httptest.NewRecorder()
		srv.httpServer.Handler.ServeHTTP(rec, req)
		if rec.Code != test.status {
			t.Fatalf("token %q: got %d: %s", test.token, rec.Code, rec.Body.String())
		}
	}
	if err := <-done; err != nil {
		t.Fatalf("approved request: %v", err)
	}
}

func TestAgentAdminCannotRemoveProtectedService(t *testing.T) {
	ms, _ := setupMockStoreWithSession(t)
	ms.agents["worker"] = &store.Agent{ID: "agent-worker", Name: "worker", Role: "admin", Status: "active"}
	ms.sessions["agent-token"] = &store.Session{ID: "agent-token", AgentID: "agent-worker", VaultID: "root-ns-id", VaultRole: "admin", ExpiresAt: tp(time.Now().Add(time.Hour))}
	services, err := json.Marshal([]broker.Service{{Name: "production", Host: "api.example.com", RequireApproval: true, Auth: broker.Auth{Type: "passthrough"}}})
	if err != nil {
		t.Fatal(err)
	}
	ms.brokerConfigs["root-ns-id"] = &store.BrokerConfig{VaultID: "root-ns-id", ServicesJSON: string(services)}
	srv := newTestServer(withStore(ms))
	for _, test := range []struct{ method, path, body string }{
		{http.MethodPut, "/v1/vaults/default/services", `{"services":[]}`},
		{http.MethodDelete, "/v1/vaults/default/services", ""},
	} {
		req := httptest.NewRequest(test.method, test.path, strings.NewReader(test.body))
		req.Header.Set("Authorization", "Bearer agent-token")
		rec := httptest.NewRecorder()
		srv.httpServer.Handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("%s %s: got %d: %s", test.method, test.path, rec.Code, rec.Body.String())
		}
		if !strings.Contains(ms.brokerConfigs["root-ns-id"].ServicesJSON, `"require_approval":true`) {
			t.Fatal("protected service changed")
		}
	}
	ms.proposals = map[string][]store.Proposal{"root-ns-id": {{
		ID: 1, VaultID: "root-ns-id", Status: "pending",
		ServicesJSON:    `[{"action":"delete","name":"production","host":"api.example.com"}]`,
		CredentialsJSON: `[]`,
	}}}
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/proposals/1/approve", strings.NewReader(`{"vault":"default","credentials":{}}`))
	req.Header.Set("Authorization", "Bearer agent-token")
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("agent approved removal proposal: %d: %s", rec.Code, rec.Body.String())
	}
}
