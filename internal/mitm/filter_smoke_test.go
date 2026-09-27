package mitm

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/broker"
	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/ca"
	"github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/store"
)

type countingStore struct {
	*store.SQLStore
	gets atomic.Int32
}

func (c *countingStore) GetCredential(ctx context.Context, vaultID, key string) (*store.Credential, error) {
	c.gets.Add(1)
	return c.SQLStore.GetCredential(ctx, vaultID, key)
}

func (c *countingStore) UnmatchedHostPolicy(context.Context, string) (brokercore.UnmatchedHostPolicy, error) {
	return brokercore.PolicyDeny, nil
}

type hybridResolver struct {
	inner *brokercore.StoreSessionResolver
	agent *brokercore.ProxyScope
}

func (h hybridResolver) ResolveForProxy(ctx context.Context, token, hint string) (*brokercore.ProxyScope, error) {
	if brokercore.IsHopToken(token) {
		return h.inner.ResolveForProxy(ctx, token, hint)
	}
	if token == "agent-token" {
		return h.agent, nil
	}
	return nil, brokercore.ErrInvalidSession
}

func TestSmoke_FilterSameVault(t *testing.T) {
	t.Setenv("AGENT_VAULT_ALLOW_PRIVATE_RANGES", "true")
	db, err := store.Open(filepath.Join(t.TempDir(), "agent-vault.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	vault, err := db.CreateVault(context.Background(), "dev")
	if err != nil {
		t.Fatal(err)
	}
	key := bytes32(0x44)
	ct, nonce, err := crypto.Encrypt([]byte("ghp_secret"), key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.SetCredential(context.Background(), vault.ID, "GITHUB_PAT", ct, nonce); err != nil {
		t.Fatal(err)
	}

	var originHits atomic.Int32
	var sawAuth string
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originHits.Add(1)
		sawAuth = r.Header.Get("Authorization")
		_, _ = io.WriteString(w, "origin")
	}))
	defer origin.Close()

	var allow atomic.Bool
	sidecar := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Errorf("sidecar saw Authorization %q", r.Header.Get("Authorization"))
		}
		if !allow.Load() {
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, "no")
			return
		}
		cont := r.Header.Get("X-Agent-Vault-Continuation-Token")
		original := r.Header.Get("X-Agent-Vault-Original-URL")
		callback := r.Header.Get("X-Agent-Vault-Continuation-Proxy")
		req, err := http.NewRequest(http.MethodGet, original, nil)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		pu, err := url.Parse(callback)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		pu.User = url.User(cont)
		resp, err := (&http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(pu)}}).Do(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	}))
	defer sidecar.Close()

	originURL, err := url.Parse(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(originURL.Port())
	if err != nil {
		t.Fatal(err)
	}
	host := originURL.Hostname()
	svc := broker.Service{
		Name: "push",
		Host: host,
		Port: &port,
		Auth: broker.Auth{Type: "bearer", Token: "GITHUB_PAT"},
		Filter: &broker.Filter{
			URL:         sidecar.URL,
			PolicyVault: "dev",
		},
	}
	raw, err := json.Marshal([]broker.Service{svc})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.SetBrokerConfig(context.Background(), vault.ID, string(raw)); err != nil {
		t.Fatal(err)
	}

	counted := &countingStore{SQLStore: db}
	caProv, err := ca.New(key, ca.Options{Dir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caProv.RootPEM()) {
		t.Fatal("ca pem")
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	advertised := "http://" + l.Addr().String()
	resolver := hybridResolver{
		inner: &brokercore.StoreSessionResolver{Store: db, HopDEK: key, Now: time.Now},
		agent: &brokercore.ProxyScope{UserID: "user-1", VaultID: vault.ID, VaultName: vault.Name, VaultRole: "proxy"},
	}
	p := New(l.Addr().String(), Options{
		CA:       caProv,
		Sessions: resolver,
		Credentials: &brokercore.StoreCredentialProvider{
			Store:  counted,
			EncKey: key,
		},
		BaseURL:        "http://127.0.0.1:14321",
		Logger:         slog.New(slog.DiscardHandler),
		Hop:            &brokercore.StoreHopMinter{Vaults: db, DEK: key},
		FilterProxyURL: advertised,
	})
	go func() { _ = p.Serve(l) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = p.Shutdown(ctx)
	})

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{Proxy: http.ProxyURL(&url.URL{
			Scheme: "http",
			Host:   l.Addr().String(),
			User:   url.User("agent-token"),
		})},
	}

	deny, err := client.Get(origin.URL + "/ping")
	if err != nil {
		t.Fatal(err)
	}
	deny.Body.Close()
	if deny.StatusCode != http.StatusForbidden || originHits.Load() != 0 || counted.gets.Load() != 0 {
		t.Fatalf("deny status=%d origin=%d creds=%d", deny.StatusCode, originHits.Load(), counted.gets.Load())
	}

	allow.Store(true)
	ok, err := client.Get(origin.URL + "/ping")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(ok.Body)
	ok.Body.Close()
	if ok.StatusCode != http.StatusOK || string(body) != "origin" {
		t.Fatalf("allow status=%d body=%q", ok.StatusCode, body)
	}
	if sawAuth != "Bearer ghp_secret" || counted.gets.Load() == 0 {
		t.Fatalf("auth=%q creds=%d", sawAuth, counted.gets.Load())
	}
}
