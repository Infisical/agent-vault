package mitm

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/egress/egresstest"
)

// The MITM data plane is where operator intent (route this service through a
// proxy) meets the security guarantees an agent must not be able to weaken.
// These tests pin both sides: every entry form reaches the upstream through
// the configured proxy with credentials intact, and no request ever reaches a
// proxy for a target network policy has forbidden.

// fakeUpstreamProxyResolver stands in for the control-plane resolver. Unlike
// the real one it keeps no cache, so each request exercises routeFor fully.
type fakeUpstreamProxyResolver struct {
	mu     sync.Mutex
	calls  []resolvedCall
	err    error
	byKey  map[string]*brokercore.UpstreamProxy
	global *brokercore.UpstreamProxy
}

type resolvedCall struct {
	vaultID, serviceName string
}

func (f *fakeUpstreamProxyResolver) ResolveUpstreamProxy(_ context.Context, vaultID, serviceName string) (*brokercore.UpstreamProxy, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, resolvedCall{vaultID, serviceName})
	if f.err != nil {
		return nil, f.err
	}
	if p, ok := f.byKey[vaultID+"/"+serviceName]; ok {
		return p, nil
	}
	return f.global, nil
}

func (f *fakeUpstreamProxyResolver) recorded() []resolvedCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]resolvedCall, len(f.calls))
	copy(out, f.calls)
	return out
}

// withUpstreamProxyResolver installs a resolver before New() runs, matching
// how cmd/server.go wires the real one.
func withUpstreamProxyResolver(res brokercore.UpstreamProxyResolver) func(*Options) {
	return func(o *Options) { o.UpstreamProxies = res }
}

func profile(name, scheme, host string) *brokercore.UpstreamProxy {
	return &brokercore.UpstreamProxy{Name: name, Scheme: scheme, Host: host}
}

// upstreamRecap is what the upstream observed after the broker forwarded to
// it. Every test asserts on it, because "the upstream got the right thing"
// is the only outcome that proves the proxy hop did not corrupt the request.
type upstreamRecap struct {
	authorization string
	proxyAuth     string
	xVault        string
	path          string
	body          string
}

// --- Entry form 1: HTTPS through CONNECT ---

func TestMITMHTTPSUpstreamReachedThroughUpstreamProxy(t *testing.T) {
	var mu sync.Mutex
	var recap upstreamRecap
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		recap = upstreamRecap{
			authorization: r.Header.Get("Authorization"),
			proxyAuth:     r.Header.Get("Proxy-Authorization"),
			xVault:        r.Header.Get("X-Vault"),
			path:          r.URL.Path,
			body:          string(body),
		}
		mu.Unlock()
		w.Header().Set("X-Upstream", "reached")
		_, _ = io.WriteString(w, "hello-from-upstream")
	}))
	defer upstream.Close()

	authority := strings.TrimPrefix(upstream.URL, "https://")
	upstreamHost, _, _ := net.SplitHostPort(authority)

	egressProxy := egresstest.NewHTTPProxy(t, "", "")

	sr := validTokenResolver("av_sess_ok",
		&brokercore.ProxyScope{VaultID: "v1", VaultName: "default", VaultRole: "proxy"})
	cp := &fakeCredProvider{byHost: map[string]fakeInjectResult{
		upstreamHost: {result: &brokercore.InjectResult{
			Headers:     map[string]string{"Authorization": "Bearer injected-secret"},
			MatchedName: "anthropic",
		}},
	}}
	res := &fakeUpstreamProxyResolver{global: profile("corp", brokercore.UpstreamProxySchemeHTTP, egressProxy.Addr())}

	proxyURL, clientRoots, p := setupProxy(t, sr, cp, withUpstreamProxyResolver(res))
	pinUpstreamCertFor(t, p, upstream.Certificate())

	client := newTrustingClient(proxyURL, url.User("av_sess_ok"), clientRoots)
	resp, err := client.Post(upstream.URL+"/v1/messages", "application/json", strings.NewReader(`{"model":"x"}`))
	if err != nil {
		t.Fatalf("request via broker: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "hello-from-upstream" {
		t.Fatalf("body = %q, want upstream response", string(body))
	}

	mu.Lock()
	observed := recap
	mu.Unlock()

	if observed.authorization != "Bearer injected-secret" {
		t.Fatalf("upstream Authorization = %q, want the injected credential", observed.authorization)
	}
	if observed.path != "/v1/messages" {
		t.Fatalf("upstream path = %q, want /v1/messages", observed.path)
	}
	if observed.body != `{"model":"x"}` {
		t.Fatalf("upstream body = %q, want the request body intact", observed.body)
	}
	if observed.proxyAuth != "" {
		t.Fatalf("upstream Proxy-Authorization = %q; broker-scoped header must be stripped", observed.proxyAuth)
	}
	if observed.xVault != "" {
		t.Fatalf("upstream X-Vault = %q; broker-scoped header must be stripped", observed.xVault)
	}
	if got := egressProxy.LastConnect(); got != authority {
		t.Fatalf("egress proxy CONNECT target = %q, want upstream authority %q", got, authority)
	}
	if got := egressProxy.TunneledBytes(); got == 0 {
		t.Fatal("no bytes relayed through the egress proxy tunnel")
	}
}

// pinUpstreamCert makes the broker trust a test upstream, the same way the
// existing MITM tests do. Proxied routes read the baseline transport's TLS
// config when they first build their own, so this must happen before the
// first request rather than being lost to a stale clone.
func pinUpstreamCertFor(t *testing.T, p *Proxy, cert *x509.Certificate) {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	p.upstream.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}
}

// tlsClientOver completes the client-side handshake inside the MITM tunnel.
func tlsClientOver(conn net.Conn, serverName string, roots *x509.CertPool) *tls.Conn {
	tlsConn := tls.Client(conn, &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: serverName})
	if err := tlsConn.Handshake(); err != nil {
		panic("client tls handshake: " + err.Error())
	}
	_ = tlsConn.SetDeadline(time.Now().Add(5 * time.Second))
	return tlsConn
}

// --- Entry form 2: plain HTTP forwarded in absolute form ---

func TestMITMPlainHTTPUpstreamReachedThroughUpstreamProxy(t *testing.T) {
	var mu sync.Mutex
	var recap upstreamRecap
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		recap = upstreamRecap{
			authorization: r.Header.Get("Authorization"),
			proxyAuth:     r.Header.Get("Proxy-Authorization"),
			path:          r.URL.Path,
		}
		mu.Unlock()
		_, _ = io.WriteString(w, "hello-from-upstream")
	}))
	defer upstream.Close()

	authority := strings.TrimPrefix(upstream.URL, "http://")
	upstreamHost, _, _ := net.SplitHostPort(authority)

	egressProxy := egresstest.NewHTTPProxy(t, "", "")

	sr := validTokenResolver("av_sess_ok",
		&brokercore.ProxyScope{VaultID: "v1", VaultName: "default", VaultRole: "proxy"})
	cp := &fakeCredProvider{byHost: map[string]fakeInjectResult{
		upstreamHost: {result: &brokercore.InjectResult{
			Headers:     map[string]string{"Authorization": "Bearer injected-secret"},
			MatchedName: "internal-api",
		}},
	}}
	res := &fakeUpstreamProxyResolver{global: profile("corp", brokercore.UpstreamProxySchemeHTTP, egressProxy.Addr())}

	proxyURL, clientRoots, _ := setupProxy(t, sr, cp, withUpstreamProxyResolver(res))

	client := newTrustingClient(proxyURL, url.User("av_sess_ok"), clientRoots)
	resp, err := client.Get(upstream.URL + "/v1/ping")
	if err != nil {
		t.Fatalf("request via broker: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "hello-from-upstream" {
		t.Fatalf("body = %q, want upstream response", string(body))
	}

	mu.Lock()
	observed := recap
	mu.Unlock()
	if observed.authorization != "Bearer injected-secret" {
		t.Fatalf("upstream Authorization = %q, want the injected credential", observed.authorization)
	}
	if got := egressProxy.ForwardCount(); got != 1 {
		t.Fatalf("egress proxy absolute-form forwards = %d, want 1", got)
	}
	if got := egressProxy.ConnectCount(); got != 0 {
		t.Fatalf("egress proxy CONNECT count = %d, want 0 for a plain HTTP upstream", got)
	}
}

// --- Entry form 3: hijacked WebSocket upgrade ---
//
// This is the path that used to bypass proxying outright: dialWebSocketUpstream
// took the transport's dialer and ignored Transport.Proxy.

func TestMITMWebSocketFramesTunnelThroughUpstreamProxy(t *testing.T) {
	serverDone := make(chan error, 1)
	var mu sync.Mutex
	var sawAuth, sawProxyAuth string

	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		sawAuth = r.Header.Get("Authorization")
		sawProxyAuth = r.Header.Get("Proxy-Authorization")
		mu.Unlock()

		hj, ok := w.(http.Hijacker)
		if !ok {
			serverDone <- errors.New("upstream cannot hijack")
			return
		}
		conn, rw, err := hj.Hijack()
		if err != nil {
			serverDone <- err
			return
		}
		defer func() { _ = conn.Close() }()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

		_, _ = io.WriteString(conn,
			"HTTP/1.1 101 Switching Protocols\r\n"+
				"Upgrade: websocket\r\n"+
				"Connection: Upgrade\r\n"+
				"Sec-WebSocket-Accept: "+websocketAccept(r.Header.Get("Sec-Websocket-Key"))+"\r\n\r\n")

		text, err := readWebSocketTextFrame(rw.Reader)
		if err != nil {
			serverDone <- err
			return
		}
		if text != "ping" {
			serverDone <- errors.New("unexpected upstream frame " + text)
			return
		}
		if err := writeWebSocketTextFrame(conn, "pong", false); err != nil {
			serverDone <- err
			return
		}
		serverDone <- nil
	}))
	defer upstream.Close()

	authority := strings.TrimPrefix(upstream.URL, "https://")
	upstreamHost, _, _ := net.SplitHostPort(authority)

	egressProxy := egresstest.NewHTTPProxy(t, "", "")

	sr := validTokenResolver("av_sess_ok",
		&brokercore.ProxyScope{VaultID: "v1", VaultName: "default", VaultRole: "proxy"})
	cp := &fakeCredProvider{byHost: map[string]fakeInjectResult{
		upstreamHost: {result: &brokercore.InjectResult{
			Headers:     map[string]string{"Authorization": "Bearer injected-ws-secret"},
			MatchedName: "discord",
		}},
	}}
	res := &fakeUpstreamProxyResolver{global: profile("corp", brokercore.UpstreamProxySchemeHTTP, egressProxy.Addr())}

	proxyURL, clientRoots, p := setupProxy(t, sr, cp, withUpstreamProxyResolver(res))
	pinUpstreamCertFor(t, p, upstream.Certificate())

	conn := openMITMTunnel(t, proxyURL, clientRoots, authority, "av_sess_ok")
	defer func() { _ = conn.Close() }()
	tlsConn := tlsClientOver(conn, upstreamHost, clientRoots)
	defer func() { _ = tlsConn.Close() }()

	if _, err := io.WriteString(tlsConn,
		"GET /socket HTTP/1.1\r\n"+
			"Host: "+authority+"\r\n"+
			"Upgrade: websocket\r\n"+
			"Connection: Upgrade\r\n"+
			"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"+
			"Sec-WebSocket-Version: 13\r\n\r\n"); err != nil {
		t.Fatalf("write upgrade: %v", err)
	}
	reader := bufio.NewReader(tlsConn)
	resp, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatalf("read upgrade response: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d, want 101", resp.StatusCode)
	}

	if err := writeWebSocketTextFrame(tlsConn, "ping", true); err != nil {
		t.Fatalf("write frame: %v", err)
	}
	text, err := readWebSocketTextFrame(reader)
	if err != nil {
		t.Fatalf("read frame: %v", err)
	}
	if text != "pong" {
		t.Fatalf("frame = %q, want pong", text)
	}

	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatalf("upstream: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("upstream handler timed out")
	}

	mu.Lock()
	auth, proxyAuth := sawAuth, sawProxyAuth
	mu.Unlock()
	if auth != "Bearer injected-ws-secret" {
		t.Fatalf("upstream Authorization = %q, want the injected credential", auth)
	}
	if proxyAuth != "" {
		t.Fatalf("upstream Proxy-Authorization = %q; must be stripped", proxyAuth)
	}
	// The whole point: a hijacked upgrade must not silently skip the proxy.
	if got := egressProxy.ConnectCount(); got != 1 {
		t.Fatalf("egress proxy CONNECT count = %d, want 1 — the WebSocket path must honour the proxy", got)
	}
	if got := egressProxy.LastConnect(); got != authority {
		t.Fatalf("egress proxy CONNECT target = %q, want %q", got, authority)
	}
}

// --- SOCKS5 ---

func TestMITMUpstreamReachedThroughSOCKS5Proxy(t *testing.T) {
	var mu sync.Mutex
	var sawAuth string
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		sawAuth = r.Header.Get("Authorization")
		mu.Unlock()
		_, _ = io.WriteString(w, "hello-from-upstream")
	}))
	defer upstream.Close()

	authority := strings.TrimPrefix(upstream.URL, "https://")
	upstreamHost, _, _ := net.SplitHostPort(authority)

	socks := egresstest.NewSOCKS5Proxy(t, "socks-user", "socks-pass")

	sr := validTokenResolver("av_sess_ok",
		&brokercore.ProxyScope{VaultID: "v1", VaultName: "default", VaultRole: "proxy"})
	cp := &fakeCredProvider{byHost: map[string]fakeInjectResult{
		upstreamHost: {result: &brokercore.InjectResult{
			Headers:     map[string]string{"Authorization": "Bearer injected-secret"},
			MatchedName: "openai",
		}},
	}}
	p5 := profile("socks", brokercore.UpstreamProxySchemeSOCKS5, socks.Addr())
	p5.Username = "socks-user"
	p5.Password = "socks-pass"
	res := &fakeUpstreamProxyResolver{global: p5}

	proxyURL, clientRoots, p := setupProxy(t, sr, cp, withUpstreamProxyResolver(res))
	pinUpstreamCertFor(t, p, upstream.Certificate())

	client := newTrustingClient(proxyURL, url.User("av_sess_ok"), clientRoots)
	resp, err := client.Get(upstream.URL + "/v1/models")
	if err != nil {
		t.Fatalf("request via broker: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "hello-from-upstream" {
		t.Fatalf("body = %q, want upstream response", string(body))
	}

	mu.Lock()
	auth := sawAuth
	mu.Unlock()
	if auth != "Bearer injected-secret" {
		t.Fatalf("upstream Authorization = %q, want the injected credential", auth)
	}
	if got := socks.DialCount(); got != 1 {
		t.Fatalf("socks proxy CONNECT count = %d, want 1", got)
	}
}

// --- Scope: per-service selection ---

func TestMITMResolvesEgressProfilePerVaultAndService(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "hello-from-upstream")
	}))
	defer upstream.Close()

	authority := strings.TrimPrefix(upstream.URL, "http://")
	upstreamHost, _, _ := net.SplitHostPort(authority)

	used := egresstest.NewHTTPProxy(t, "", "")
	unused := egresstest.NewHTTPProxy(t, "", "")

	sr := validTokenResolver("av_sess_ok",
		&brokercore.ProxyScope{VaultID: "vault-7", VaultName: "default", VaultRole: "proxy"})
	cp := &fakeCredProvider{byHost: map[string]fakeInjectResult{
		upstreamHost: {result: &brokercore.InjectResult{MatchedName: "anthropic"}},
	}}
	res := &fakeUpstreamProxyResolver{
		byKey: map[string]*brokercore.UpstreamProxy{
			"vault-7/anthropic": profile("scoped", brokercore.UpstreamProxySchemeHTTP, used.Addr()),
			"other/anthropic":   profile("decoy", brokercore.UpstreamProxySchemeHTTP, unused.Addr()),
		},
	}

	proxyURL, clientRoots, _ := setupProxy(t, sr, cp, withUpstreamProxyResolver(res))

	client := newTrustingClient(proxyURL, url.User("av_sess_ok"), clientRoots)
	resp, err := client.Get(upstream.URL + "/")
	if err != nil {
		t.Fatalf("request via broker: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	calls := res.recorded()
	if len(calls) == 0 {
		t.Fatal("resolver was never consulted")
	}
	want := resolvedCall{"vault-7", "anthropic"}
	if calls[0] != want {
		t.Fatalf("resolver called with %+v, want %+v", calls[0], want)
	}
	if used.ForwardCount() != 1 {
		t.Fatalf("scoped proxy forwards = %d, want 1", used.ForwardCount())
	}
	if got := unused.RequestCount(); got != 0 {
		t.Fatalf("proxy scoped to another vault saw %d requests, want 0", got)
	}
}

// --- Red line: no_proxy bypasses the proxy entirely ---

func TestMITMNoProxySkipsUpstreamProxy(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "hello-from-upstream")
	}))
	defer upstream.Close()

	authority := strings.TrimPrefix(upstream.URL, "http://")
	upstreamHost, _, _ := net.SplitHostPort(authority)

	egressProxy := egresstest.NewHTTPProxy(t, "", "")

	sr := validTokenResolver("av_sess_ok",
		&brokercore.ProxyScope{VaultID: "v1", VaultName: "default", VaultRole: "proxy"})
	cp := &fakeCredProvider{byHost: map[string]fakeInjectResult{
		upstreamHost: {result: &brokercore.InjectResult{MatchedName: "internal"}},
	}}
	p1 := profile("corp", brokercore.UpstreamProxySchemeHTTP, egressProxy.Addr())
	p1.NoProxy = upstreamHost
	res := &fakeUpstreamProxyResolver{global: p1}

	proxyURL, clientRoots, _ := setupProxy(t, sr, cp, withUpstreamProxyResolver(res))
	client := newTrustingClient(proxyURL, url.User("av_sess_ok"), clientRoots)

	resp, err := client.Get(upstream.URL + "/healthz")
	if err != nil {
		t.Fatalf("request via broker: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "hello-from-upstream" {
		t.Fatalf("body = %q, want the bypass request to still succeed", string(body))
	}
	if got := egressProxy.RequestCount(); got != 0 {
		t.Fatalf("egress proxy saw %d requests for a no_proxy host, want 0", got)
	}
}

func TestMITMNoProxyNeverTrustsProxyCAForHTTPSUpstream(t *testing.T) {
	var reached atomic.Int32
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	authority := strings.TrimPrefix(upstream.URL, "https://")
	upstreamHost, _, _ := net.SplitHostPort(authority)
	sr := validTokenResolver("av_sess_ok",
		&brokercore.ProxyScope{VaultID: "v1", VaultName: "default", VaultRole: "proxy"})
	cp := &fakeCredProvider{byHost: map[string]fakeInjectResult{
		upstreamHost: {result: &brokercore.InjectResult{MatchedName: "internal"}},
	}}
	route := profile("proxy-ca", brokercore.UpstreamProxySchemeHTTPS, authority)
	route.NoProxy = authority
	route.ProxyCAPEM = string(pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE", Bytes: upstream.Certificate().Raw,
	}))
	res := &fakeUpstreamProxyResolver{global: route}
	proxyURL, clientRoots, _ := setupProxy(t, sr, cp, withUpstreamProxyResolver(res))

	client := newTrustingClient(proxyURL, url.User("av_sess_ok"), clientRoots)
	resp, err := client.Get(upstream.URL + "/healthz")
	if err != nil {
		t.Fatalf("request through broker: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502 when target TLS is not trusted", resp.StatusCode)
	}
	if got := reached.Load(); got != 0 {
		t.Fatalf("target with proxy-only CA received %d requests", got)
	}
}

// --- Red line: policy still applies behind the proxy ---

func TestMITMPolicyBlockedTargetNeverReachesUpstreamProxy(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "hello-from-upstream")
	}))
	defer upstream.Close()

	authority := strings.TrimPrefix(upstream.URL, "http://")
	upstreamHost, _, _ := net.SplitHostPort(authority)

	egressProxy := egresstest.NewHTTPProxy(t, "", "")
	socks := egresstest.NewSOCKS5Proxy(t, "", "")

	sr := validTokenResolver("av_sess_ok",
		&brokercore.ProxyScope{VaultID: "v1", VaultName: "default", VaultRole: "proxy"})
	cp := &fakeCredProvider{byHost: map[string]fakeInjectResult{
		upstreamHost: {result: &brokercore.InjectResult{MatchedName: "internal"}},
	}}

	// setupProxy opts into loopback; flip the policy back afterwards so the
	// loopback upstream is a forbidden destination.
	proxyURL, clientRoots, _ := setupProxy(t, sr, cp, withUpstreamProxyResolver(
		&fakeUpstreamProxyResolver{global: profile("corp", brokercore.UpstreamProxySchemeHTTP, egressProxy.Addr())}))
	t.Setenv("AGENT_VAULT_ALLOW_PRIVATE_RANGES", "false")

	client := newTrustingClient(proxyURL, url.User("av_sess_ok"), clientRoots)
	resp, err := client.Get(upstream.URL + "/")
	if err != nil {
		t.Fatalf("request via broker: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusBadGateway)
	}
	// The crux: the proxy must never be asked to dial a forbidden target,
	// otherwise it becomes an SSRF amplifier.
	if got := egressProxy.RequestCount(); got != 0 {
		t.Fatalf("egress proxy saw %d requests to a policy-blocked target, want 0", got)
	}
	if got := socks.DialCount(); got != 0 {
		t.Fatalf("socks proxy saw %d requests to a policy-blocked target, want 0", got)
	}
}

// --- Failure handling ---

func TestMITMUnusableProfileFailsClosed(t *testing.T) {
	var reached bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		_, _ = io.WriteString(w, "hello-from-upstream")
	}))
	defer upstream.Close()

	authority := strings.TrimPrefix(upstream.URL, "http://")
	upstreamHost, _, _ := net.SplitHostPort(authority)

	sr := validTokenResolver("av_sess_ok",
		&brokercore.ProxyScope{VaultID: "v1", VaultName: "default", VaultRole: "proxy"})
	cp := &fakeCredProvider{byHost: map[string]fakeInjectResult{
		upstreamHost: {result: &brokercore.InjectResult{MatchedName: "internal"}},
	}}
	// A host without a port can never become a dialler.
	res := &fakeUpstreamProxyResolver{global: profile("broken", brokercore.UpstreamProxySchemeHTTP, "proxy.internal")}

	proxyURL, clientRoots, _ := setupProxy(t, sr, cp, withUpstreamProxyResolver(res))
	client := newTrustingClient(proxyURL, url.User("av_sess_ok"), clientRoots)

	resp, err := client.Get(upstream.URL + "/")
	if err != nil {
		t.Fatalf("request via broker: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d (fail_closed must not leak traffic)", resp.StatusCode, http.StatusBadGateway)
	}
	if reached {
		t.Fatal("upstream was reached; fail_closed must stop the request instead")
	}
}

func TestMITMUnusableProfileFailsClosedEvenUnderFailOpen(t *testing.T) {
	var hits int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		_, _ = io.WriteString(w, "hello-from-upstream")
	}))
	defer upstream.Close()
	authority := strings.TrimPrefix(upstream.URL, "http://")
	upstreamHost, _, _ := net.SplitHostPort(authority)
	sr := validTokenResolver("av_sess_ok",
		&brokercore.ProxyScope{VaultID: "v1", VaultName: "default", VaultRole: "proxy"})
	cp := &fakeCredProvider{byHost: map[string]fakeInjectResult{
		upstreamHost: {result: &brokercore.InjectResult{MatchedName: "internal"}},
	}}
	broken := profile("broken", brokercore.UpstreamProxySchemeHTTP, "proxy.internal")
	broken.OnFailure = brokercore.UpstreamProxyFailOpen
	res := &fakeUpstreamProxyResolver{global: broken}
	proxyURL, clientRoots, _ := setupProxy(t, sr, cp, withUpstreamProxyResolver(res))
	client := newTrustingClient(proxyURL, url.User("av_sess_ok"), clientRoots)
	resp, err := client.Get(upstream.URL + "/")
	if err != nil {
		t.Fatalf("request via broker: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502 for invalid proxy configuration", resp.StatusCode)
	}
	if got := atomic.LoadInt32(&hits); got != 0 {
		t.Fatalf("upstream received %d requests for unusable profile", got)
	}
}

// --- Failure policy: what fail_open may and may not absorb ---

// fail_open promises "when the proxy cannot be reached, dial the target
// directly". It has to be that narrow: absorbing every transport error would
// turn any upstream problem into a silent egress-policy bypass.
func TestMITMUnreachableProxyFallsBackUnderFailOpen(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "hello-from-upstream")
	}))
	defer upstream.Close()

	authority := strings.TrimPrefix(upstream.URL, "http://")
	upstreamHost, _, _ := net.SplitHostPort(authority)

	egressProxy := egresstest.NewHTTPProxy(t, "", "")

	sr := validTokenResolver("av_sess_ok",
		&brokercore.ProxyScope{VaultID: "v1", VaultName: "default", VaultRole: "proxy"})
	cp := &fakeCredProvider{byHost: map[string]fakeInjectResult{
		upstreamHost: {result: &brokercore.InjectResult{MatchedName: "internal"}},
	}}
	prof := profile("corp", brokercore.UpstreamProxySchemeHTTP, egressProxy.Addr())
	prof.OnFailure = brokercore.UpstreamProxyFailClosed
	res := &fakeUpstreamProxyResolver{global: prof}

	proxyURL, clientRoots, _ := setupProxy(t, sr, cp, withUpstreamProxyResolver(res))
	client := newTrustingClient(proxyURL, url.User("av_sess_ok"), clientRoots)

	get := func() (int, string) {
		resp, err := client.Get(upstream.URL + "/")
		if err != nil {
			return 0, err.Error()
		}
		defer func() { _ = resp.Body.Close() }()
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(body)
	}

	// 1. Policy: fail_closed, proxy alive → the request goes through it.
	if code, body := get(); code != http.StatusOK || body != "hello-from-upstream" {
		t.Fatalf("with proxy up: code=%d body=%q, want 200/hello-from-upstream", code, body)
	}
	if got := egressProxy.RequestCount(); got != 1 {
		t.Fatalf("proxy saw %d requests, want 1", got)
	}

	// 2. Policy: fail_closed, proxy gone → refuse rather than leak.
	egressProxy.Close()
	if code, _ := get(); code != http.StatusBadGateway {
		t.Fatalf("fail_closed with an unreachable proxy = %d (%s), want 502", code, "see body above")
	}

	// 3. Policy: fail_open → the same request succeeds directly. The proxy
	//    stays shut, so a success here can only be a direct dial.
	prof.OnFailure = brokercore.UpstreamProxyFailOpen
	code, body := get()
	if code != http.StatusOK || body != "hello-from-upstream" {
		t.Fatalf("fail_open fell back incorrectly: code=%d body=%q, want 200/hello-from-upstream", code, body)
	}
	if got := egressProxy.RequestCount(); got != 1 {
		t.Fatalf("proxy saw %d requests after the fallback, want still 1", got)
	}
}

// Red line: a failure that is not about *reaching* the proxy must stay failed.
// Here the proxy accepts the connection and then hangs up, which looks exactly
// like a broken target — retrying it directly would bypass egress policy.
func TestMITMFailOpenDoesNotAbsorbTargetSideFailures(t *testing.T) {
	var hits int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		_, _ = io.WriteString(w, "hello-from-upstream")
	}))
	defer upstream.Close()

	authority := strings.TrimPrefix(upstream.URL, "http://")
	upstreamHost, _, _ := net.SplitHostPort(authority)

	// A proxy that answers TCP and then closes with nothing written.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	sr := validTokenResolver("av_sess_ok",
		&brokercore.ProxyScope{VaultID: "v1", VaultName: "default", VaultRole: "proxy"})
	cp := &fakeCredProvider{byHost: map[string]fakeInjectResult{
		upstreamHost: {result: &brokercore.InjectResult{MatchedName: "internal"}},
	}}
	prof := profile("flaky", brokercore.UpstreamProxySchemeHTTP, ln.Addr().String())
	prof.OnFailure = brokercore.UpstreamProxyFailOpen

	proxyURL, clientRoots, _ := setupProxy(t, sr, cp, withUpstreamProxyResolver(&fakeUpstreamProxyResolver{global: prof}))
	client := newTrustingClient(proxyURL, url.User("av_sess_ok"), clientRoots)

	resp, err := client.Get(upstream.URL + "/")
	if err == nil {
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			t.Fatal("fail_open retried a target-side failure directly; the upstream must not be reachable this way")
		}
	}
	if got := atomic.LoadInt32(&hits); got != 0 {
		t.Fatalf("upstream was hit %d times; a target-side failure must not fall back to a direct dial", got)
	}
}

func TestMITMResolverFailureFailsClosed(t *testing.T) {
	var hits int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		_, _ = io.WriteString(w, "hello-from-upstream")
	}))
	defer upstream.Close()

	authority := strings.TrimPrefix(upstream.URL, "http://")
	upstreamHost, _, _ := net.SplitHostPort(authority)

	egressProxy := egresstest.NewHTTPProxy(t, "", "")

	sr := validTokenResolver("av_sess_ok",
		&brokercore.ProxyScope{VaultID: "v1", VaultName: "default", VaultRole: "proxy"})
	cp := &fakeCredProvider{byHost: map[string]fakeInjectResult{
		upstreamHost: {result: &brokercore.InjectResult{MatchedName: "internal"}},
	}}
	res := &fakeUpstreamProxyResolver{
		err:    errors.New("store unavailable"),
		global: profile("corp", brokercore.UpstreamProxySchemeHTTP, egressProxy.Addr()),
	}

	proxyURL, clientRoots, _ := setupProxy(t, sr, cp, withUpstreamProxyResolver(res))
	client := newTrustingClient(proxyURL, url.User("av_sess_ok"), clientRoots)

	resp, err := client.Get(upstream.URL + "/")
	if err != nil {
		t.Fatalf("request via broker: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502 on resolver failure", resp.StatusCode)
	}
	if got := atomic.LoadInt32(&hits); got != 0 {
		t.Fatalf("target received %d requests during resolver failure", got)
	}
}

// --- Red line: proxy credentials stay on the proxy hop ---

func TestMITMUpstreamProxyCredentialsDoNotReachUpstream(t *testing.T) {
	var mu sync.Mutex
	var sawProxyAuth, sawAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		sawProxyAuth = r.Header.Get("Proxy-Authorization")
		sawAuth = r.Header.Get("Authorization")
		mu.Unlock()
		_, _ = io.WriteString(w, "hello-from-upstream")
	}))
	defer upstream.Close()

	authority := strings.TrimPrefix(upstream.URL, "http://")
	upstreamHost, _, _ := net.SplitHostPort(authority)

	egressProxy := egresstest.NewHTTPProxy(t, "egress-user", "egress-pass")

	sr := validTokenResolver("av_sess_ok",
		&brokercore.ProxyScope{VaultID: "v1", VaultName: "default", VaultRole: "proxy"})
	cp := &fakeCredProvider{byHost: map[string]fakeInjectResult{
		upstreamHost: {result: &brokercore.InjectResult{
			Headers:     map[string]string{"Authorization": "Bearer injected-secret"},
			MatchedName: "internal",
		}},
	}}
	p1 := profile("corp-auth", brokercore.UpstreamProxySchemeHTTP, egressProxy.Addr())
	p1.Username = "egress-user"
	p1.Password = "egress-pass"
	res := &fakeUpstreamProxyResolver{global: p1}

	proxyURL, clientRoots, _ := setupProxy(t, sr, cp, withUpstreamProxyResolver(res))
	client := newTrustingClient(proxyURL, url.User("av_sess_ok"), clientRoots)

	resp, err := client.Get(upstream.URL + "/")
	if err != nil {
		t.Fatalf("request via broker: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "hello-from-upstream" {
		t.Fatalf("body = %q; the authenticated proxy hop must succeed", string(body))
	}

	mu.Lock()
	upstreamProxyAuth, upstreamAuth := sawProxyAuth, sawAuth
	mu.Unlock()
	if upstreamProxyAuth != "" {
		t.Fatalf("upstream saw Proxy-Authorization %q; egress credentials belong to the proxy hop only", upstreamProxyAuth)
	}
	if upstreamAuth != "Bearer injected-secret" {
		t.Fatalf("upstream Authorization = %q, want only the injected credential", upstreamAuth)
	}
	if got := egressProxy.RefusedAuthCount(); got != 0 {
		t.Fatalf("egress proxy refused %d requests; credentials were not presented", got)
	}
}
