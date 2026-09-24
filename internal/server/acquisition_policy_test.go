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

	get := func(token string) (int, vaultAcquisitionPolicy, string) {
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
		return rec.Code, policy, rec.Header().Get("X-Agent-Vault-Policy-Stale")
	}

	if status, policy, _ := get(ownerToken); status != http.StatusOK || len(policy.EnabledHandlers) != 0 || policy.BrowserDOMEnabled {
		t.Fatalf("default status=%d policy=%+v", status, policy)
	}

	patch := httptest.NewRequest(http.MethodPatch, "/v1/vaults/default/acquisition-policy",
		strings.NewReader(`{"enabled_handlers":["github-cli"],"browser_dom_enabled":false}`))
	patch.Header.Set("Authorization", "Bearer "+ownerToken)
	patchRec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(patchRec, patch)
	if patchRec.Code != http.StatusOK {
		t.Fatalf("PATCH status=%d body=%s", patchRec.Code, patchRec.Body.String())
	}
	if raw := ms.vaultSettings["root-ns-id"][settingCredentialAcquisitionPolicy]; !strings.Contains(raw, `"github-cli"`) || !strings.Contains(raw, `"browser_dom_enabled":false`) {
		t.Fatalf("stored policy=%q", raw)
	}
	if status, policy, _ := get(memberToken); status != http.StatusOK || len(policy.EnabledHandlers) != 1 || policy.EnabledHandlers[0] != "github-cli" || policy.BrowserDOMEnabled {
		t.Fatalf("member GET status=%d policy=%+v", status, policy)
	}
	if status, _, _ := get(proxyToken); status != http.StatusForbidden {
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
	if status, policy, stale := get(memberToken); status != http.StatusOK || stale != "true" || len(policy.EnabledHandlers) != 1 {
		t.Fatalf("stale policy GET status=%d stale=%q policy=%+v", status, stale, policy)
	}
}

func TestVaultAcquisitionHandlerCatalogIsVaultScopedAndRedacted(t *testing.T) {
	ms, ownerToken := setupMockStoreWithSession(t)
	memberToken := setupMemberSession(t, ms, "root-ns-id")
	ms.acquisitionHandlers["github-cli"] = &store.AcquisitionHandler{
		ID: "github-cli", Generation: "gen-1", Kind: "executable", Enabled: true,
		ExecutablePath: "/usr/local/bin/provider", SHA256: strings.Repeat("a", 64),
		SigningIdentity: "Developer ID Application: Example",
		AllowedKeys:     []string{"GITHUB_TOKEN"}, AllowedVaults: []string{"root-ns-id"},
		AllowedProfiles: []string{"github.com"}, TimeoutSeconds: 10, OutputLimitBytes: 65536,
	}
	ms.acquisitionHandlers["disabled"] = &store.AcquisitionHandler{
		ID: "disabled", Generation: "gen-2", Kind: "executable", Enabled: false,
		ExecutablePath: "/usr/local/bin/disabled", SHA256: strings.Repeat("b", 64),
		AllowedKeys: []string{"TOKEN"}, AllowedVaults: []string{"root-ns-id"},
		AllowedProfiles: []string{"default"}, TimeoutSeconds: 10, OutputLimitBytes: 65536,
	}
	ms.acquisitionHandlers["other-vault"] = &store.AcquisitionHandler{
		ID: "other-vault", Generation: "gen-3", Kind: "executable", Enabled: true,
		ExecutablePath: "/usr/local/bin/other", SHA256: strings.Repeat("c", 64),
		AllowedKeys: []string{"TOKEN"}, AllowedVaults: []string{"another-vault"},
		AllowedProfiles: []string{"default"}, TimeoutSeconds: 10, OutputLimitBytes: 65536,
	}
	ms.acquisitionHandlers["browser-dom"] = &store.AcquisitionHandler{
		ID: "browser-dom", Generation: "gen-4", Kind: store.AcquisitionHandlerKindBrowserDOM, Enabled: true,
		ExecutablePath: "/usr/local/bin/browser-provider", SHA256: strings.Repeat("d", 64),
		AllowedKeys: []string{"TOKEN"}, AllowedVaults: []string{"root-ns-id"},
		AllowedProfiles: []string{"default"}, TimeoutSeconds: 10, OutputLimitBytes: 65536,
	}
	srv := newTestServer(withStore(ms))

	get := func(token string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/v1/vaults/default/acquisition-handlers", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		srv.httpServer.Handler.ServeHTTP(rec, req)
		return rec
	}

	rec := get(ownerToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("owner GET status=%d body=%s", rec.Code, rec.Body.String())
	}
	raw := rec.Body.String()
	var body struct {
		Handlers []struct {
			ID              string   `json:"id"`
			Kind            string   `json:"kind"`
			AllowedKeys     []string `json:"allowed_keys"`
			AllowedProfiles []string `json:"allowed_profiles"`
		} `json:"handlers"`
	}
	if err := json.NewDecoder(strings.NewReader(raw)).Decode(&body); err != nil {
		t.Fatalf("decode catalog: %v", err)
	}
	if len(body.Handlers) != 1 || body.Handlers[0].ID != "github-cli" ||
		body.Handlers[0].Kind != "executable" || len(body.Handlers[0].AllowedKeys) != 1 ||
		body.Handlers[0].AllowedKeys[0] != "GITHUB_TOKEN" || len(body.Handlers[0].AllowedProfiles) != 1 ||
		body.Handlers[0].AllowedProfiles[0] != "github.com" {
		t.Fatalf("unexpected catalog: %+v", body.Handlers)
	}
	for _, forbidden := range []string{"executable_path", "sha256", "signing_identity", "allowed_vaults", "generation", "/usr/local/bin", strings.Repeat("a", 64)} {
		if strings.Contains(raw, forbidden) {
			t.Fatalf("catalog leaked %q: %s", forbidden, raw)
		}
	}

	ms.grants["member-user-id"]["root-ns-id"] = "admin"
	if adminRec := get(memberToken); adminRec.Code != http.StatusOK {
		t.Fatalf("vault admin GET status=%d body=%s", adminRec.Code, adminRec.Body.String())
	}
	ms.grants["member-user-id"]["root-ns-id"] = "member"
	if memberRec := get(memberToken); memberRec.Code != http.StatusForbidden {
		t.Fatalf("member GET status=%d want=%d body=%s", memberRec.Code, http.StatusForbidden, memberRec.Body.String())
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
	ms.acquisitionHandlers["browser-dom"] = &store.AcquisitionHandler{
		ID: "browser-dom", Generation: "gen-3", Kind: store.AcquisitionHandlerKindBrowserDOM, Enabled: true,
		ExecutablePath: "/usr/local/bin/browser-provider", SHA256: strings.Repeat("c", 64),
		AllowedKeys: []string{"TOKEN"}, AllowedVaults: []string{"root-ns-id"},
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
		{"browser DOM opt-in without handler", `{"enabled_handlers":[],"browser_dom_enabled":true}`, http.StatusConflict},
		{"browser DOM handler without opt-in", `{"enabled_handlers":["browser-dom"],"browser_dom_enabled":false}`, http.StatusConflict},
		{"browser DOM handler with opt-in", `{"enabled_handlers":["browser-dom"],"browser_dom_enabled":true}`, http.StatusConflict},
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
