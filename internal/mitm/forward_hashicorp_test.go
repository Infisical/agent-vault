package mitm

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Infisical/agent-vault/internal/broker"
	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/hashicorp"
	"github.com/Infisical/agent-vault/internal/store"
)

// credStoreAdapter layers the typed UnmatchedHostPolicy lookup onto the store
// so it satisfies brokercore.CredentialStore, mirroring the server package's
// production adapter. The fixed policy is only consulted when no service
// matches; this test always matches.
type credStoreAdapter struct{ *store.SQLStore }

func (credStoreAdapter) UnmatchedHostPolicy(_ context.Context, _ string) (brokercore.UnmatchedHostPolicy, error) {
	return brokercore.PolicyDeny, nil
}

// TestMITMForward_HashicorpSyncedCredentialInjected is the full end-to-end
// confirmation for the HashiCorp credential store: a secret living in a
// HashiCorp Vault KV mount is pulled by the real vault/api client + syncer into
// a real SQLite store, and then — when an agent sends a request through the
// actual MITM forward proxy — the broker injects that secret as the upstream
// Authorization header. The only stub is the Vault HTTP endpoint; everything
// downstream (client, syncer, crypto, store, broker matching, auth resolution,
// proxy transport) is production code.
func TestMITMForward_HashicorpSyncedCredentialInjected(t *testing.T) {
	ctx := context.Background()
	const secretKey = "ANTHROPIC_API_KEY"
	const secretValue = "sk-ant-from-hashicorp-vault"

	// --- 1. Stand up a stub HashiCorp Vault holding the secret (KV v2). ---
	vaultStub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/token/lookup-self":
			// NewClient probes the token at startup; answer so login succeeds.
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": map[string]interface{}{"id": "stub"}})
		case "/v1/secret/data/agent-vault/demo":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"data":     map[string]interface{}{secretKey: secretValue},
					"metadata": map[string]interface{}{"version": 1, "destroyed": false},
				},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"errors":[]}`)
		}
	}))
	defer vaultStub.Close()

	// --- 2. Real HashiCorp client via the production NewClient (env-driven). ---
	t.Setenv("VAULT_ADDR", vaultStub.URL)
	t.Setenv("VAULT_TOKEN", "stub-token")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	hcClient, err := hashicorp.NewClient(ctx, logger)
	if err != nil {
		t.Fatalf("hashicorp.NewClient: %v", err)
	}

	// --- 3. Real store + vault; sync the secret in via the real syncer. ---
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	vault, err := st.CreateVault(ctx, "demo-hc")
	if err != nil {
		t.Fatalf("CreateVault: %v", err)
	}
	dek := make([]byte, 32)
	for i := range dek {
		dek[i] = 0x42
	}
	syncer := hashicorp.NewSyncer(st, hcClient, dek, logger)
	// Persist the external-store row so the syncer's config-gated write path
	// (ReplaceVaultCredentialsForSync) applies; an in-memory-only row reads as
	// disconnected and the snapshot is dropped without writing credentials.
	const hcConfigJSON = `{"mount":"secret","secret_path":"agent-vault/demo","kv_version":2}`
	if _, err := st.SetVaultExternalStore(ctx, store.SetVaultExternalStoreParams{
		VaultID:             vault.ID,
		Kind:                store.CredentialStoreHashicorp,
		ConfigJSON:          hcConfigJSON,
		PollIntervalSeconds: 60,
	}); err != nil {
		t.Fatalf("SetVaultExternalStore: %v", err)
	}
	csRow, err := st.GetVaultCredentialStore(ctx, vault.ID)
	if err != nil {
		t.Fatalf("GetVaultCredentialStore: %v", err)
	}
	if err := syncer.RefreshOnce(ctx, *csRow); err != nil {
		t.Fatalf("syncer.RefreshOnce: %v", err)
	}

	// --- 4. Upstream the agent will call; capture what it actually receives. ---
	var gotAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_, _ = io.WriteString(w, "upstream-ok")
	}))
	defer upstream.Close()
	upstreamHost, _, _ := net.SplitHostPort(strings.TrimPrefix(upstream.URL, "http://"))

	// --- 5. Define a broker service: this host → Bearer <synced secret>. ---
	svcs := []broker.Service{{
		Host: upstreamHost,
		Auth: broker.Auth{Type: "bearer", Token: secretKey},
	}}
	svcJSON, _ := json.Marshal(svcs)
	if _, err := st.SetBrokerConfig(ctx, vault.ID, string(svcJSON)); err != nil {
		t.Fatalf("SetBrokerConfig: %v", err)
	}

	// --- 6. Real provider + real proxy; send a request through the proxy. ---
	// brokercore.CredentialStore needs UnmatchedHostPolicy, which production
	// layers on via an adapter over vault settings. Our service matches the
	// host, so the policy is never consulted; a trivial adapter satisfies the
	// interface.
	cp := brokercore.NewStoreCredentialProvider(credStoreAdapter{st}, dek)
	sr := validTokenResolver("av_sess_ok",
		&brokercore.ProxyScope{VaultID: vault.ID, VaultName: "demo-hc", VaultRole: "proxy"})
	proxyURL, clientRoots, _ := setupProxy(t, sr, cp)

	client := newTrustingClient(proxyURL, url.User("av_sess_ok"), clientRoots)
	req, err := http.NewRequest("POST", upstream.URL+"/v1/messages", strings.NewReader("hello"))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	// The agent supplies a bogus token; the broker-injected one must win.
	req.Header.Set("Authorization", "Bearer client-bogus-token")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("client.Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	// --- 7. Confirm the upstream received the HashiCorp secret, injected. ---
	if gotAuth != "Bearer "+secretValue {
		t.Fatalf("upstream Authorization = %q, want %q (HashiCorp secret injected through the proxy)",
			gotAuth, "Bearer "+secretValue)
	}
}
