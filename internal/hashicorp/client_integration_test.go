package hashicorp

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Infisical/agent-vault/internal/store"
	vaultapi "github.com/hashicorp/vault/api"
)

// stubVault stands up a minimal HashiCorp Vault HTTP API that answers the KV
// reads the real vault/api client issues, so these tests exercise the actual
// client + response parsing (Client.FetchSecrets) end-to-end without Docker or
// a live Vault. KV v2 reads hit /v1/{mount}/data/{path}; KV v1 reads hit
// /v1/{mount}/{path}.
func stubVault(t *testing.T, kvData map[string]map[string]interface{}) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Trim the /v1/ API prefix the client always sends.
		logical := strings.TrimPrefix(r.URL.Path, "/v1/")
		// KV v2 read: {mount}/data/{path}
		if data, ok := kvData[logical]; ok {
			if strings.Contains(logical, "/data/") {
				writeJSON(w, map[string]interface{}{
					"data": map[string]interface{}{
						"data":     data,
						"metadata": map[string]interface{}{"version": 1, "created_time": "2026-06-05T00:00:00Z", "destroyed": false},
					},
				})
				return
			}
			// KV v1 read: {mount}/{path}
			writeJSON(w, map[string]interface{}{"data": data})
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, `{"errors":[]}`)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// newClientForServer builds a Client whose underlying vault/api client points
// at the stub server. Mirrors what NewClient does after auth, minus the env
// reads, so tests stay hermetic.
func newClientForServer(t *testing.T, url string) *Client {
	t.Helper()
	cfg := vaultapi.DefaultConfig()
	cfg.Address = url
	api, err := vaultapi.NewClient(cfg)
	if err != nil {
		t.Fatalf("vault api client: %v", err)
	}
	api.SetToken("stub-token")
	return &Client{api: api, method: AuthToken, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

func TestClientFetchSecrets_KVv2(t *testing.T) {
	srv := stubVault(t, map[string]map[string]interface{}{
		"secret/data/agent-vault/demo": {
			"ANTHROPIC_API_KEY": "sk-ant-x",
			"GITHUB_PAT":        "ghp_x",
			"MAX_RETRIES":       5, // exercises stringValue numeric coercion
		},
	})
	c := newClientForServer(t, srv.URL)

	secs, err := c.FetchSecrets(context.Background(), VaultConfig{Mount: "secret", SecretPath: "agent-vault/demo", KVVersion: 2})
	if err != nil {
		t.Fatalf("FetchSecrets: %v", err)
	}
	// Keys come back sorted.
	want := []Secret{
		{Key: "ANTHROPIC_API_KEY", Value: "sk-ant-x"},
		{Key: "GITHUB_PAT", Value: "ghp_x"},
		{Key: "MAX_RETRIES", Value: "5"},
	}
	if len(secs) != len(want) {
		t.Fatalf("got %d secrets, want %d: %+v", len(secs), len(want), secs)
	}
	for i := range want {
		if secs[i] != want[i] {
			t.Errorf("secret[%d] = %+v, want %+v", i, secs[i], want[i])
		}
	}
}

func TestClientFetchSecrets_KVv1(t *testing.T) {
	srv := stubVault(t, map[string]map[string]interface{}{
		"kv/agent-vault/demo": {"STRIPE_SECRET_KEY": "sk_test_x"},
	})
	c := newClientForServer(t, srv.URL)

	secs, err := c.FetchSecrets(context.Background(), VaultConfig{Mount: "kv", SecretPath: "agent-vault/demo", KVVersion: 1})
	if err != nil {
		t.Fatalf("FetchSecrets: %v", err)
	}
	if len(secs) != 1 || secs[0].Key != "STRIPE_SECRET_KEY" || secs[0].Value != "sk_test_x" {
		t.Fatalf("unexpected secrets: %+v", secs)
	}
}

func TestClientFetchSecrets_NotFound(t *testing.T) {
	srv := stubVault(t, map[string]map[string]interface{}{}) // nothing registered
	c := newClientForServer(t, srv.URL)
	if _, err := c.FetchSecrets(context.Background(), VaultConfig{Mount: "secret", SecretPath: "missing", KVVersion: 2}); err == nil {
		t.Fatal("expected an error reading a non-existent path, got nil")
	}
}

// TestSyncerWithRealClient_PopulatesStore drives the real vault/api client
// through the syncer against the stub Vault and asserts the fetched secrets are
// encrypted and handed to ReplaceVaultCredentials — the full fetch→encrypt→store
// path that the demo exercised, now as an automated test.
func TestSyncerWithRealClient_PopulatesStore(t *testing.T) {
	srv := stubVault(t, map[string]map[string]interface{}{
		"secret/data/agent-vault/demo": {
			"ANTHROPIC_API_KEY": "sk-ant-x",
			"GITHUB_PAT":        "ghp_x",
			"STRIPE_SECRET_KEY": "sk_test_x",
		},
	})
	c := newClientForServer(t, srv.URL)
	fs := newFakeStore(hashicorpRow("v1"))
	s := NewSyncer(fs, c, makeDEK(t), slog.New(slog.NewTextHandler(io.Discard, nil)))

	if err := s.RefreshOnce(context.Background(), fs.rows[0]); err != nil {
		t.Fatalf("RefreshOnce: %v", err)
	}
	select {
	case got := <-fs.replaceCh:
		items := got["v1"]
		if len(items) != 3 {
			t.Fatalf("want 3 credentials stored, got %d", len(items))
		}
		// Keys are stored in cleartext; values are encrypted (ciphertext != key).
		for _, it := range items {
			if it.Key == "" || len(it.Ciphertext) == 0 || len(it.Nonce) == 0 {
				t.Fatalf("malformed stored credential: %+v", it)
			}
		}
	default:
		t.Fatal("ReplaceVaultCredentials was not called")
	}
	if h := fs.getHealth("v1"); h.Status != store.SyncStatusOK {
		t.Fatalf("health: want %q, got %q", store.SyncStatusOK, h.Status)
	}
}
