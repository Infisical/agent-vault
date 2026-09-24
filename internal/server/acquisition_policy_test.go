package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Infisical/agent-vault/internal/store"
)

func TestVaultAcquisitionPolicyLifecycleAndAuthorization(t *testing.T) {
	ms, ownerToken := setupMockStoreWithSession(t)
	memberToken := setupMemberSession(t, ms, "root-ns-id")
	proxyToken := setupProxyRoleSession(t, ms, "root-ns-id")
	ms.acquisitionHandlers["github-cli"] = &store.AcquisitionHandler{
		ID: "github-cli", Generation: "gen-1", Kind: "executable", Enabled: true,
		ExecutablePath: "/usr/local/bin/provider", SHA256: strings.Repeat("a", 64),
		AllowedKeys: []string{"GITHUB_TOKEN"}, AllowedVaults: []string{"root-ns-id"},
		AllowedProfiles: []string{"github.com"}, TimeoutSeconds: 10, OutputLimitBytes: 65536,
	}
	srv := newTestServer(withStore(ms))

	get := func(token string) (int, vaultAcquisitionPolicy) {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/v1/vaults/default/acquisition-policy", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		srv.httpServer.Handler.ServeHTTP(rec, req)
		var policy vaultAcquisitionPolicy
		if rec.Code == http.StatusOK {
			if err := json.NewDecoder(rec.Body).Decode(&policy); err != nil {
				t.Fatalf("decode policy: %v", err)
			}
		}
		return rec.Code, policy
	}

	if status, policy := get(ownerToken); status != http.StatusOK || len(policy.EnabledHandlers) != 0 || policy.BrowserDOMEnabled {
		t.Fatalf("default status=%d policy=%+v", status, policy)
	}

	patch := httptest.NewRequest(http.MethodPatch, "/v1/vaults/default/acquisition-policy",
		strings.NewReader(`{"enabled_handlers":["github-cli"],"browser_dom_enabled":true}`))
	patch.Header.Set("Authorization", "Bearer "+ownerToken)
	patchRec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(patchRec, patch)
	if patchRec.Code != http.StatusOK {
		t.Fatalf("PATCH status=%d body=%s", patchRec.Code, patchRec.Body.String())
	}
	if raw := ms.vaultSettings["root-ns-id"][settingCredentialAcquisitionPolicy]; !strings.Contains(raw, `"github-cli"`) || !strings.Contains(raw, `"browser_dom_enabled":true`) {
		t.Fatalf("stored policy=%q", raw)
	}
	if status, policy := get(memberToken); status != http.StatusOK || len(policy.EnabledHandlers) != 1 || policy.EnabledHandlers[0] != "github-cli" || !policy.BrowserDOMEnabled {
		t.Fatalf("member GET status=%d policy=%+v", status, policy)
	}
	if status, _ := get(proxyToken); status != http.StatusForbidden {
		t.Fatalf("proxy GET status=%d want=%d", status, http.StatusForbidden)
	}

	memberPatch := httptest.NewRequest(http.MethodPatch, "/v1/vaults/default/acquisition-policy", strings.NewReader(`{"enabled_handlers":[]}`))
	memberPatch.Header.Set("Authorization", "Bearer "+memberToken)
	memberRec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(memberRec, memberPatch)
	if memberRec.Code != http.StatusForbidden {
		t.Fatalf("member PATCH status=%d body=%s", memberRec.Code, memberRec.Body.String())
	}

	ms.acquisitionHandlers["github-cli"].Enabled = false
	if status, _ := get(memberToken); status != http.StatusConflict {
		t.Fatalf("stale policy GET status=%d want=%d", status, http.StatusConflict)
	}
}

func TestVaultAcquisitionPolicyRejectsUntrustedHandlerReferencesAndUnknownFields(t *testing.T) {
	ms, ownerToken := setupMockStoreWithSession(t)
	ms.acquisitionHandlers["disabled"] = &store.AcquisitionHandler{
		ID: "disabled", Generation: "gen-1", Kind: "executable", Enabled: false,
		ExecutablePath: "/usr/local/bin/provider", SHA256: strings.Repeat("a", 64),
		AllowedKeys: []string{"TOKEN"}, AllowedVaults: []string{"root-ns-id"},
		AllowedProfiles: []string{"default"}, TimeoutSeconds: 10, OutputLimitBytes: 65536,
	}
	ms.acquisitionHandlers["other-vault"] = &store.AcquisitionHandler{
		ID: "other-vault", Generation: "gen-2", Kind: "executable", Enabled: true,
		ExecutablePath: "/usr/local/bin/provider", SHA256: strings.Repeat("b", 64),
		AllowedKeys: []string{"TOKEN"}, AllowedVaults: []string{"another-vault"},
		AllowedProfiles: []string{"default"}, TimeoutSeconds: 10, OutputLimitBytes: 65536,
	}
	srv := newTestServer(withStore(ms))

	tests := []struct {
		name string
		body string
		code int
	}{
		{"unknown field", `{"enabled_handlers":[],"executable":"/tmp/pwn"}`, http.StatusBadRequest},
		{"null", `null`, http.StatusBadRequest},
		{"duplicate", `{"enabled_handlers":["disabled","disabled"]}`, http.StatusBadRequest},
		{"unknown handler", `{"enabled_handlers":["missing"]}`, http.StatusConflict},
		{"disabled handler", `{"enabled_handlers":["disabled"]}`, http.StatusConflict},
		{"handler outside vault", `{"enabled_handlers":["other-vault"]}`, http.StatusConflict},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPatch, "/v1/vaults/default/acquisition-policy", strings.NewReader(tt.body))
			req.Header.Set("Authorization", "Bearer "+ownerToken)
			rec := httptest.NewRecorder()
			srv.httpServer.Handler.ServeHTTP(rec, req)
			if rec.Code != tt.code {
				t.Fatalf("status=%d want=%d body=%s", rec.Code, tt.code, rec.Body.String())
			}
		})
	}
	if _, err := ms.GetVaultSetting(context.Background(), "root-ns-id", settingCredentialAcquisitionPolicy); err == nil {
		t.Fatal("rejected policy was persisted")
	}
}

func TestVaultAcquisitionPolicyStoreGuardRejectsHandlerRace(t *testing.T) {
	ms, ownerToken := setupMockStoreWithSession(t)
	ms.acquisitionHandlers["github-cli"] = &store.AcquisitionHandler{
		ID: "github-cli", Generation: "gen-1", Kind: "executable", Enabled: true,
		ExecutablePath: "/usr/local/bin/provider", SHA256: strings.Repeat("a", 64),
		AllowedKeys: []string{"GITHUB_TOKEN"}, AllowedVaults: []string{"root-ns-id"},
		AllowedProfiles: []string{"github.com"}, TimeoutSeconds: 10, OutputLimitBytes: 65536,
	}
	ms.setAcquisitionPolicyHook = func() { ms.acquisitionHandlers["github-cli"].Enabled = false }
	srv := newTestServer(withStore(ms))
	req := httptest.NewRequest(http.MethodPatch, "/v1/vaults/default/acquisition-policy",
		strings.NewReader(`{"enabled_handlers":["github-cli"]}`))
	req.Header.Set("Authorization", "Bearer "+ownerToken)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if _, err := ms.GetVaultSetting(context.Background(), "root-ns-id", settingCredentialAcquisitionPolicy); err == nil {
		t.Fatal("raced invalid policy was persisted")
	}
}

func TestVaultAcquisitionPolicyGetRejectsMalformedStoredPolicy(t *testing.T) {
	for _, raw := range []string{
		`null`,
		`{"enabled_handlers":null,"browser_dom_enabled":false}`,
	} {
		t.Run(raw, func(t *testing.T) {
			ms, ownerToken := setupMockStoreWithSession(t)
			if err := ms.SetVaultSetting(context.Background(), "root-ns-id", settingCredentialAcquisitionPolicy, raw); err != nil {
				t.Fatal(err)
			}
			srv := newTestServer(withStore(ms))
			req := httptest.NewRequest(http.MethodGet, "/v1/vaults/default/acquisition-policy", nil)
			req.Header.Set("Authorization", "Bearer "+ownerToken)
			rec := httptest.NewRecorder()
			srv.httpServer.Handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusInternalServerError {
				t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
			}
		})
	}
}
