package mitm

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/ca"
)

// fakeSessionResolver delegates to a per-test closure. Tests supply
// whatever policy they need without adding fields to the struct.
type fakeSessionResolver struct {
	resolve func(token, hint string) (*brokercore.ProxyScope, error)
}

func (f *fakeSessionResolver) ResolveForProxy(_ context.Context, token, hint string) (*brokercore.ProxyScope, error) {
	return f.resolve(token, hint)
}

// validTokenResolver returns a resolver that succeeds with scope when
// token matches expected, and returns ErrInvalidSession otherwise.
func validTokenResolver(expected string, scope *brokercore.ProxyScope) *fakeSessionResolver {
	return &fakeSessionResolver{resolve: func(token, _ string) (*brokercore.ProxyScope, error) {
		if token != expected {
			return nil, brokercore.ErrInvalidSession
		}
		return scope, nil
	}}
}

// errResolver returns a resolver that always fails with err.
func errResolver(err error) *fakeSessionResolver {
	return &fakeSessionResolver{resolve: func(string, string) (*brokercore.ProxyScope, error) {
		return nil, err
	}}
}

// fakeCredProvider returns a canned InjectResult or error.
type fakeCredProvider struct {
	// byHost maps target host (without port) to the injection outcome.
	byHost map[string]fakeInjectResult
}

type fakeInjectResult struct {
	result *brokercore.InjectResult
	err    error
}

func (f *fakeCredProvider) Inject(_ context.Context, _, targetHost string) (*brokercore.InjectResult, error) {
	// Mirror StoreCredentialProvider: accept host:port and strip internally.
	host := targetHost
	if h, _, err := net.SplitHostPort(targetHost); err == nil {
		host = h
	}
	res, ok := f.byHost[host]
	if !ok {
		return nil, brokercore.ErrServiceNotFound
	}
	return res.result, res.err
}

// setupProxy starts a mitm.Proxy backed by a freshly-generated SoftCA and
// the given session + credential stubs. Returns the listening URL, the
// root-cert pool for client-side trust, and the proxy instance.
func setupProxy(t *testing.T, sr brokercore.SessionResolver, cp brokercore.CredentialProvider) (proxyURL *url.URL, clientRoots *x509.CertPool, p *Proxy) {
	t.Helper()

	t.Setenv("AGENT_VAULT_NETWORK_MODE", "private")

	masterKey := make([]byte, 32)
	if _, err := rand.Read(masterKey); err != nil {
		t.Fatalf("rand: %v", err)
	}
	caProv, err := ca.New(masterKey, ca.Options{Dir: t.TempDir()})
	if err != nil {
		t.Fatalf("ca.New: %v", err)
	}

	clientRoots = x509.NewCertPool()
	if !clientRoots.AppendCertsFromPEM(caProv.RootPEM()) {
		t.Fatal("failed to load CA root PEM into pool")
	}

	p = New("127.0.0.1:0", caProv, sr, cp, slog.New(slog.DiscardHandler))

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = p.Serve(l) }()

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = p.Shutdown(ctx)
	})

	proxyURL = &url.URL{Scheme: "http", Host: l.Addr().String()}
	return proxyURL, clientRoots, p
}

// newTrustingClient returns an http.Client that routes HTTPS through
// proxyURL (with the given userinfo encoded as Basic Proxy-Authorization)
// and trusts the given roots for the terminated client-side TLS.
func newTrustingClient(proxyURL *url.URL, userInfo *url.Userinfo, roots *x509.CertPool) *http.Client {
	u := *proxyURL
	u.User = userInfo
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(&u),
			TLSClientConfig: &tls.Config{RootCAs: roots},
		},
	}
}

func TestMITMInjectsCredentials(t *testing.T) {
	var sawAuth, sawClientAuth, sawProxyAuth string
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuth = r.Header.Get("Authorization")
		sawClientAuth = r.Header.Get("X-Client-Auth")
		sawProxyAuth = r.Header.Get("Proxy-Authorization")
		w.Header().Set("X-Upstream", "hello")
		_, _ = io.WriteString(w, "upstream-body")
	}))
	defer upstream.Close()

	upstreamHost, _, _ := net.SplitHostPort(strings.TrimPrefix(upstream.URL, "https://"))

	sr := validTokenResolver("av_sess_ok",
		&brokercore.ProxyScope{VaultID: "v1", VaultName: "default", VaultRole: "proxy"})
	cp := &fakeCredProvider{byHost: map[string]fakeInjectResult{
		upstreamHost: {result: &brokercore.InjectResult{
			Headers: map[string]string{"Authorization": "Bearer injected-secret"},
		}},
	}}

	proxyURL, clientRoots, p := setupProxy(t, sr, cp)

	upstreamRoots := x509.NewCertPool()
	upstreamRoots.AddCert(upstream.Certificate())
	p.upstream.TLSClientConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    upstreamRoots,
	}

	client := newTrustingClient(proxyURL, url.User("av_sess_ok"), clientRoots)

	req, err := http.NewRequest("GET", upstream.URL+"/ping", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	// Client-supplied Authorization must be dropped and replaced by injection.
	req.Header.Set("Authorization", "Bearer client-should-not-win")
	// Arbitrary non-allowlisted header must also be dropped.
	req.Header.Set("X-Client-Auth", "leaked")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("client.Do: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "upstream-body" {
		t.Fatalf("body = %q, want upstream-body", body)
	}
	if sawAuth != "Bearer injected-secret" {
		t.Fatalf("upstream saw Authorization %q, want injected value", sawAuth)
	}
	if sawClientAuth != "" {
		t.Fatalf("upstream saw X-Client-Auth %q; non-allowlisted header must be dropped", sawClientAuth)
	}
	if sawProxyAuth != "" {
		t.Fatalf("upstream saw Proxy-Authorization %q; must be stripped", sawProxyAuth)
	}
}

func TestMITMPassthroughForwardsClientAuthorization(t *testing.T) {
	// On the MITM ingress, Proxy-Authorization is the broker-scoped credential
	// and Authorization is the client's own upstream header — it must flow
	// through unchanged for passthrough services. Proxy-Authorization and
	// hop-by-hop headers must still be stripped.
	var sawAuth, sawCookie, sawTrace, sawProxyAuth string
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuth = r.Header.Get("Authorization")
		sawCookie = r.Header.Get("Cookie")
		sawTrace = r.Header.Get("X-Trace-Id")
		sawProxyAuth = r.Header.Get("Proxy-Authorization")
		_, _ = io.WriteString(w, "passthrough-ok")
	}))
	defer upstream.Close()

	upstreamHost, _, _ := net.SplitHostPort(strings.TrimPrefix(upstream.URL, "https://"))

	sr := validTokenResolver("av_sess_ok",
		&brokercore.ProxyScope{VaultID: "v1", VaultName: "default", VaultRole: "proxy"})
	cp := &fakeCredProvider{byHost: map[string]fakeInjectResult{
		upstreamHost: {result: &brokercore.InjectResult{
			MatchedHost: upstreamHost,
			Passthrough: true,
		}},
	}}

	proxyURL, clientRoots, p := setupProxy(t, sr, cp)

	upstreamRoots := x509.NewCertPool()
	upstreamRoots.AddCert(upstream.Certificate())
	p.upstream.TLSClientConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    upstreamRoots,
	}

	client := newTrustingClient(proxyURL, url.User("av_sess_ok"), clientRoots)

	req, err := http.NewRequest("GET", upstream.URL+"/data", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer upstream-token")
	req.Header.Set("Cookie", "session=abc")
	req.Header.Set("X-Trace-Id", "trace-123")
	// Set Proxy-Authorization on the tunneled request explicitly. Go's
	// http.Transport only emits Proxy-Authorization on the CONNECT
	// handshake (via url.User), not on in-tunnel requests, so without
	// this assignment the strip assertion below would be vacuous.
	req.Header.Set("Proxy-Authorization", "Basic c2hvdWxkLWJlLXN0cmlwcGVk")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("client.Do: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "passthrough-ok" {
		t.Fatalf("body = %q", body)
	}
	if sawAuth != "Bearer upstream-token" {
		t.Fatalf("upstream Authorization = %q, want passthrough of client value", sawAuth)
	}
	if sawCookie != "session=abc" {
		t.Fatalf("upstream Cookie = %q, want passthrough", sawCookie)
	}
	if sawTrace != "trace-123" {
		t.Fatalf("upstream X-Trace-Id = %q, want passthrough", sawTrace)
	}
	if sawProxyAuth != "" {
		t.Fatalf("upstream saw Proxy-Authorization %q; must be stripped on passthrough", sawProxyAuth)
	}
}

func TestMITMMissingProxyAuth(t *testing.T) {
	sr := errResolver(brokercore.ErrInvalidSession)
	cp := &fakeCredProvider{}
	proxyURL, _, _ := setupProxy(t, sr, cp)

	// Speak CONNECT manually so we can inspect the response without client
	// retries masking it.
	conn, err := net.Dial("tcp", proxyURL.Host)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	_, _ = fmt.Fprintf(conn, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("status = %d, want 407", resp.StatusCode)
	}
	if ch := resp.Header.Get("Proxy-Authenticate"); !strings.Contains(ch, "Basic") {
		t.Fatalf("Proxy-Authenticate = %q, want a Basic challenge", ch)
	}
}

func TestMITMInvalidSession(t *testing.T) {
	sr := validTokenResolver("not-this-one", nil)
	cp := &fakeCredProvider{}
	proxyURL, _, _ := setupProxy(t, sr, cp)

	auth := base64.StdEncoding.EncodeToString([]byte("bad-token:"))
	conn, err := net.Dial("tcp", proxyURL.Host)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	_, _ = fmt.Fprintf(conn,
		"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Authorization: Basic %s\r\n\r\n",
		auth)
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("status = %d, want 407", resp.StatusCode)
	}
}

func TestMITMAmbiguousAgentVault(t *testing.T) {
	sr := errResolver(brokercore.ErrAgentVaultAmbiguous)
	cp := &fakeCredProvider{}
	proxyURL, _, _ := setupProxy(t, sr, cp)

	auth := base64.StdEncoding.EncodeToString([]byte("av_agt_multi:"))
	conn, err := net.Dial("tcp", proxyURL.Host)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	_, _ = fmt.Fprintf(conn,
		"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Authorization: Basic %s\r\n\r\n",
		auth)
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "HTTPS_PROXY=http://<token>:<vault>@") {
		t.Fatalf("body = %q, missing vault-hint message", body)
	}
}

func TestMITMVaultHintMismatch(t *testing.T) {
	sr := errResolver(brokercore.ErrVaultHintMismatch)
	cp := &fakeCredProvider{}
	proxyURL, _, _ := setupProxy(t, sr, cp)

	auth := base64.StdEncoding.EncodeToString([]byte("scoped-token:prod"))
	conn, err := net.Dial("tcp", proxyURL.Host)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	_, _ = fmt.Fprintf(conn,
		"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Authorization: Basic %s\r\n\r\n",
		auth)
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
}

func TestMITMUnknownHostInTunnel(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "should-not-reach")
	}))
	defer upstream.Close()

	sr := validTokenResolver("av_sess_ok",
		&brokercore.ProxyScope{VaultID: "v1", VaultName: "default", VaultRole: "proxy"})
	// byHost empty → every Inject returns ErrServiceNotFound.
	cp := &fakeCredProvider{byHost: map[string]fakeInjectResult{}}

	proxyURL, clientRoots, _ := setupProxy(t, sr, cp)
	client := newTrustingClient(proxyURL, url.User("av_sess_ok"), clientRoots)

	resp, err := client.Get(upstream.URL + "/ping")
	if err != nil {
		t.Fatalf("client.Get: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	if resp.Header.Get(brokercore.ProxyErrorHeader) != "true" {
		t.Fatalf("missing %s header", brokercore.ProxyErrorHeader)
	}

	var body map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["error"] != "forbidden" {
		t.Fatalf("body.error = %v", body["error"])
	}
	hint, ok := body["proposal_hint"].(map[string]interface{})
	if !ok {
		t.Fatalf("missing proposal_hint")
	}
	if hint["endpoint"] != "POST /v1/proposals" {
		t.Fatalf("hint.endpoint = %v", hint["endpoint"])
	}
}

func TestMITMUpstreamCertUntrusted(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "should-not-reach")
	}))
	defer upstream.Close()
	upstreamHost, _, _ := net.SplitHostPort(strings.TrimPrefix(upstream.URL, "https://"))

	sr := validTokenResolver("av_sess_ok",
		&brokercore.ProxyScope{VaultID: "v1", VaultName: "default", VaultRole: "proxy"})
	cp := &fakeCredProvider{byHost: map[string]fakeInjectResult{
		upstreamHost: {result: &brokercore.InjectResult{
			Headers: map[string]string{"Authorization": "Bearer whatever"},
		}},
	}}

	proxyURL, clientRoots, _ := setupProxy(t, sr, cp)
	// NOTE: not adding upstream's cert to p.upstream; verification fails.

	client := newTrustingClient(proxyURL, url.User("av_sess_ok"), clientRoots)
	resp, err := client.Get(upstream.URL + "/ping")
	if err != nil {
		t.Fatalf("client.Get: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
}

func TestMITMRejectsNonConnectRequests(t *testing.T) {
	proxyURL, _, _ := setupProxy(t, errResolver(brokercore.ErrInvalidSession), &fakeCredProvider{})

	resp, err := http.Get(proxyURL.String() + "/anything")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", resp.StatusCode)
	}
}

func TestIsValidHost(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"example.com", true},
		{"api.github.com", true},
		{"localhost", true},
		{"127.0.0.1", true},
		{"", false},
		{"has space.com", false},
		{"has@at.com", false},
		{"has/slash.com", false},
		{"has?query.com", false},
		{".leading-dot.com", false},
		{"trailing-dot.", false},
		{strings.Repeat("a", 254), false},
	}
	for _, c := range cases {
		if got := isValidHost(c.in); got != c.want {
			t.Errorf("isValidHost(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

