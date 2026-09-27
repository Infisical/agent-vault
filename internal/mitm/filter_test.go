package mitm

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/broker"
	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/store"
)

type staticVaults struct{}

func (staticVaults) GetVault(context.Context, string) (*store.Vault, error) {
	return &store.Vault{ID: "v1", Name: "dev"}, nil
}
func (staticVaults) GetVaultByID(context.Context, string) (*store.Vault, error) {
	return &store.Vault{ID: "v1", Name: "dev"}, nil
}

type filterCreds struct {
	svc      broker.Service
	resolves int
	inject   *brokercore.InjectResult
}

func (f *filterCreds) Match(context.Context, string, string, int, string) (*brokercore.MatchResult, error) {
	return &brokercore.MatchResult{Service: f.svc}, nil
}
func (f *filterCreds) Resolve(context.Context, string, broker.Service) (*brokercore.InjectResult, error) {
	f.resolves++
	if f.inject == nil {
		return &brokercore.InjectResult{MatchedName: f.svc.Name}, nil
	}
	return f.inject, nil
}
func (f *filterCreds) Inject(ctx context.Context, vault, host string, port int, path string) (*brokercore.InjectResult, error) {
	return f.Resolve(ctx, vault, f.svc)
}

func TestFilterHopDeniesWithoutCredentialOrOrigin(t *testing.T) {
	var originHits int
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originHits++
		w.WriteHeader(http.StatusOK)
	}))
	defer origin.Close()

	var sawAuth, sawAPIKey, sawCont, sawPolicy string
	sidecar := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuth = r.Header.Get("Authorization")
		sawAPIKey = r.Header.Get("X-Api-Key")
		sawCont = r.Header.Get("X-Agent-Vault-Continuation-Token")
		sawPolicy = r.Header.Get("X-Agent-Vault-Policy-Token")
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `{"error":"denied"}`)
	}))
	defer sidecar.Close()

	creds := &filterCreds{svc: broker.Service{
		Name: "push",
		Host: "github.com",
		Auth: broker.Auth{Type: "api-key", Key: "GITHUB_PAT", Header: "X-Api-Key"},
		Filter: &broker.Filter{
			URL: sidecar.URL,
		},
	}}
	sr := validTokenResolver("av_sess_ok", &brokercore.ProxyScope{VaultID: "v1", VaultName: "dev", VaultRole: "proxy", UserID: "u1"})
	proxyURL, roots, _ := setupProxy(t, sr, creds, func(o *Options) {
		o.FilterProxyURL = "http://127.0.0.1:14322"
		o.Hop = &brokercore.StoreHopMinter{Vaults: staticVaults{}, DEK: bytes32(0x11)}
	})
	client := newTrustingClient(proxyURL, url.User("av_sess_ok"), roots)
	req, _ := http.NewRequest(http.MethodGet, origin.URL+"/ping", nil)
	req.Header.Set("Authorization", "Bearer client-secret")
	req.Header.Set("X-Api-Key", "client-key")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if originHits != 0 || creds.resolves != 0 {
		t.Fatalf("origin hits=%d resolves=%d", originHits, creds.resolves)
	}
	if sawAPIKey != "" {
		t.Fatalf("sidecar saw credential header %q", sawAPIKey)
	}
	if sawAuth != "Bearer client-secret" {
		t.Fatalf("Authorization = %q, want the client value kept", sawAuth)
	}
	if !strings.HasPrefix(sawCont, "av_cont_") {
		t.Fatalf("continuation = %q", sawCont)
	}
	if sawPolicy != "" {
		t.Fatalf("omitted policy_vault minted %q", sawPolicy)
	}
}

func TestContinuationBindAndInject(t *testing.T) {
	var sawAuth string
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuth = r.Header.Get("Authorization")
		_, _ = io.WriteString(w, "ok")
	}))
	defer origin.Close()
	authority := strings.TrimPrefix(origin.URL, "https://")
	host, _, _ := net.SplitHostPort(authority)
	frozen := broker.Service{Name: "push", Host: host, Auth: broker.Auth{Type: "bearer", Token: "GITHUB_PAT"}}
	bind := brokercore.HopBind{Method: http.MethodGet, Scheme: "https", Authority: authority, Path: "/ping"}
	creds := &filterCreds{
		svc:    frozen,
		inject: &brokercore.InjectResult{Headers: map[string]string{"Authorization": "Bearer injected"}, MatchedName: "push", CredentialKeys: []string{"GITHUB_PAT"}},
	}
	sr := &fakeSessionResolver{resolve: func(token, _ string) (*brokercore.ProxyScope, error) {
		if token != "av_cont_good" {
			return nil, brokercore.ErrInvalidSession
		}
		return &brokercore.ProxyScope{
			HopActorID: "agent-1", VaultID: "v1", VaultName: "dev", VaultRole: "proxy",
			HopKind: "cont", Bind: &bind, Frozen: &frozen,
		}, nil
	}}
	proxyURL, roots, p := setupProxy(t, sr, creds)
	pool := x509.NewCertPool()
	pool.AddCert(origin.Certificate())
	p.upstream.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}
	client := newTrustingClient(proxyURL, url.User("av_cont_good"), roots)

	bad, err := client.Get(origin.URL + "/other")
	if err != nil {
		t.Fatal(err)
	}
	bad.Body.Close()
	if bad.StatusCode != http.StatusForbidden || creds.resolves != 0 {
		t.Fatalf("wrong path status=%d resolves=%d", bad.StatusCode, creds.resolves)
	}

	ok, err := client.Get(origin.URL + "/ping")
	if err != nil {
		t.Fatal(err)
	}
	ok.Body.Close()
	if ok.StatusCode != http.StatusOK {
		t.Fatalf("status %d", ok.StatusCode)
	}
	if sawAuth != "Bearer injected" || creds.resolves != 1 {
		t.Fatalf("auth=%q resolves=%d", sawAuth, creds.resolves)
	}
	again, err := client.Get(origin.URL + "/ping")
	if err != nil {
		t.Fatal(err)
	}
	again.Body.Close()
	if again.StatusCode != http.StatusOK || creds.resolves != 2 {
		t.Fatalf("second request status=%d resolves=%d", again.StatusCode, creds.resolves)
	}
}

func TestContinuationWrongAuthorityDoesNotDial(t *testing.T) {
	var hits int
	other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
	}))
	defer other.Close()
	bind := brokercore.HopBind{Method: http.MethodGet, Scheme: "https", Authority: "github.com:443", Path: "/"}
	frozen := broker.Service{Name: "push", Host: "github.com"}
	sr := &fakeSessionResolver{resolve: func(token, _ string) (*brokercore.ProxyScope, error) {
		if token != "av_cont_good" {
			return nil, brokercore.ErrInvalidSession
		}
		return &brokercore.ProxyScope{
			HopActorID: "agent-1", VaultID: "v1", VaultName: "dev", VaultRole: "proxy",
			HopKind: "cont", Bind: &bind, Frozen: &frozen,
		}, nil
	}}
	creds := &filterCreds{svc: frozen}
	proxyURL, roots, _ := setupProxy(t, sr, creds)
	client := newTrustingClient(proxyURL, url.User("av_cont_good"), roots)
	resp, err := client.Get(other.URL + "/")
	if resp != nil {
		resp.Body.Close()
	}
	if err == nil && (resp == nil || resp.StatusCode != http.StatusForbidden) {
		t.Fatalf("expected connect rejection, resp=%v err=%v", resp, err)
	}
	if hits != 0 || creds.resolves != 0 {
		t.Fatalf("hits=%d resolves=%d", hits, creds.resolves)
	}
}

func TestSidecarRedirectIsReturned(t *testing.T) {
	sidecar := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://127.0.0.1:1/elsewhere", http.StatusFound)
	}))
	defer sidecar.Close()
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("origin was contacted")
	}))
	defer origin.Close()
	creds := &filterCreds{svc: broker.Service{
		Name: "push", Host: "github.com", Auth: broker.Auth{Type: "passthrough"},
		Filter: &broker.Filter{URL: sidecar.URL},
	}}
	sr := validTokenResolver("av_sess_ok", &brokercore.ProxyScope{VaultID: "v1", VaultName: "dev", VaultRole: "proxy", UserID: "u1"})
	proxyURL, roots, _ := setupProxy(t, sr, creds, func(o *Options) {
		o.FilterProxyURL = "http://127.0.0.1:14322"
		o.Hop = &brokercore.StoreHopMinter{Vaults: staticVaults{}, DEK: bytes32(0x22)}
	})
	client := newTrustingClient(proxyURL, url.User("av_sess_ok"), roots)
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Get(origin.URL + "/ping")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

func TestFilterHTTPIgnoresAllowPrivateEnv(t *testing.T) {
	t.Setenv("AGENT_VAULT_ALLOW_PRIVATE_RANGES", "true")
	dial := filterDialContext("http", "example.com", false)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := dial(ctx, "tcp", "8.8.8.8:80"); err == nil {
		t.Fatal("public http dial should fail even when private ranges are allowed for origin")
	}
}

func TestPinnedCARejectsSystemRoots(t *testing.T) {
	sidecar := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer sidecar.Close()
	pem := pemCert(sidecar.Certificate())
	pinned, err := filterTransport(&broker.Filter{URL: sidecar.URL, CA: pem})
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodGet, sidecar.URL, nil)
	resp, err := pinned.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	unpinned, err := filterTransport(&broker.Filter{URL: sidecar.URL})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unpinned.RoundTrip(req); err == nil {
		t.Fatal("system roots accepted a private sidecar certificate")
	}
}

func pemCert(cert *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
}

func bytes32(b byte) []byte {
	out := make([]byte, 32)
	for i := range out {
		out[i] = b
	}
	return out
}

func TestWebSocketFilterDenialDoesNotResolve(t *testing.T) {
	sidecar := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isWebSocketUpgrade(r) {
			t.Errorf("upgrade not preserved: %v", r.Header)
		}
		w.WriteHeader(http.StatusForbidden)
	}))
	defer sidecar.Close()
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("origin contacted")
	}))
	defer origin.Close()
	creds := &filterCreds{svc: broker.Service{
		Name: "ws", Host: "example.com", Auth: broker.Auth{Type: "bearer", Token: "TOK"},
		Filter: &broker.Filter{URL: sidecar.URL},
	}}
	sr := validTokenResolver("av_sess_ok", &brokercore.ProxyScope{VaultID: "v1", VaultName: "dev", VaultRole: "proxy", UserID: "u1"})
	proxyURL, roots, _ := setupProxy(t, sr, creds, func(o *Options) {
		o.FilterProxyURL = "http://127.0.0.1:14322"
		o.Hop = &brokercore.StoreHopMinter{Vaults: staticVaults{}, DEK: bytes32(0x33)}
	})
	client := newTrustingClient(proxyURL, url.User("av_sess_ok"), roots)
	req, _ := http.NewRequest(http.MethodGet, origin.URL+"/socket", nil)
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	req.Header.Set("Sec-WebSocket-Version", "13")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if creds.resolves != 0 {
		t.Fatalf("resolves = %d", creds.resolves)
	}
}
