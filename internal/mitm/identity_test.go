package mitm

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Infisical/agent-vault/internal/brokercore"
)

// boundListener hands out connections carrying a fixed proxy identity, as
// connections passed with an identity (connpass TagProxyAs) are.
type boundListener struct {
	net.Listener
	token, vault string
}

func (l boundListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return boundTestConn{Conn: c, token: l.token, vault: l.vault}, nil
}

type boundTestConn struct {
	net.Conn
	token, vault string
}

func (c boundTestConn) ProxyIdentity() (string, string) { return c.token, c.vault }

// serveBound serves p on a second listener whose connections carry
// token and vault; returns its URL.
func serveBound(t *testing.T, p *Proxy, token, vault string) *url.URL {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = p.Serve(boundListener{Listener: l, token: token, vault: vault}) }()
	t.Cleanup(func() { _ = l.Close() })
	return &url.URL{Scheme: "http", Host: l.Addr().String()}
}

func plainUpstream(t *testing.T, hits *atomic.Int32, sawAuth *atomic.Value) (string, string) {
	t.Helper()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		sawAuth.Store(r.Header.Get("Authorization") + "|" + r.Header.Get("Proxy-Authorization"))
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(upstream.Close)
	host, _, _ := net.SplitHostPort(strings.TrimPrefix(upstream.URL, "http://"))
	return upstream.URL, host
}

func injecting(host string) *fakeCredProvider {
	return &fakeCredProvider{byHost: map[string]fakeInjectResult{
		host: {result: &brokercore.InjectResult{
			Headers: map[string]string{"Authorization": "Bearer injected-secret"},
		}},
	}}
}

var okScope = &brokercore.ProxyScope{VaultID: "v1", VaultName: "default", VaultRole: "proxy"}

// A connection passed with an identity needs no Proxy-Authorization: the
// identity Crate bound to it authenticates every request (Crate's VM holds
// no proxy token).
func TestMITMForwardUsesABoundConnectionsIdentityWithoutProxyAuthorization(t *testing.T) {
	var hits atomic.Int32
	var saw atomic.Value
	target, host := plainUpstream(t, &hits, &saw)
	_, _, p := setupProxy(t, validTokenResolver("av_sess_ok", okScope), injecting(host))
	bound := serveBound(t, p, "av_sess_ok", "default")

	resp, err := newTrustingClient(bound, nil, nil).Get(target + "/x")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if got := saw.Load(); got != "Bearer injected-secret|" {
		t.Fatalf("upstream saw %q, want the injected bearer and no Proxy-Authorization", got)
	}
}

// What a client sends as Proxy-Authorization on a bound connection is
// ignored, so a project can't present another identity, and it never
// reaches the upstream.
func TestMITMForwardIgnoresProxyAuthorizationOnABoundConnection(t *testing.T) {
	var hits atomic.Int32
	var saw atomic.Value
	target, host := plainUpstream(t, &hits, &saw)
	_, _, p := setupProxy(t, validTokenResolver("av_sess_ok", okScope), injecting(host))
	bound := serveBound(t, p, "av_sess_ok", "default")

	resp, err := newTrustingClient(bound, url.UserPassword("av_sess_someone_else", "other"), nil).Get(target + "/x")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (the bound identity, not the header)", resp.StatusCode)
	}
	if got := saw.Load(); got != "Bearer injected-secret|" {
		t.Fatalf("upstream saw %q, want the injected bearer and no Proxy-Authorization", got)
	}
}

// The identity holds for every request on a kept-alive connection, not
// just the first.
func TestMITMForwardKeepsABoundIdentityAcrossKeepAlive(t *testing.T) {
	var hits atomic.Int32
	var saw atomic.Value
	target, host := plainUpstream(t, &hits, &saw)
	_, _, p := setupProxy(t, validTokenResolver("av_sess_ok", okScope), injecting(host))
	bound := serveBound(t, p, "av_sess_ok", "default")
	client := newTrustingClient(bound, nil, nil)

	for i := 0; i < 3; i++ {
		resp, err := client.Get(target + "/x")
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d: status = %d", i, resp.StatusCode)
		}
	}
	if got := hits.Load(); got != 3 {
		t.Fatalf("upstream hits = %d, want 3", got)
	}
}

// A bound identity that doesn't resolve is refused like a bad token.
func TestMITMForwardRefusesABoundIdentityThatDoesNotResolve(t *testing.T) {
	var hits atomic.Int32
	var saw atomic.Value
	target, host := plainUpstream(t, &hits, &saw)
	_, _, p := setupProxy(t, validTokenResolver("av_sess_ok", okScope), injecting(host))
	bound := serveBound(t, p, "av_sess_revoked", "default")

	resp, err := newTrustingClient(bound, url.User("av_sess_ok"), nil).Get(target + "/x")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("status = %d, want 407", resp.StatusCode)
	}
	if hits.Load() != 0 {
		t.Fatal("the upstream was reached")
	}
}

// CONNECT on a bound connection uses the identity too, for the requests
// inside the tunnel.
func TestMITMConnectUsesABoundConnectionsIdentity(t *testing.T) {
	var sawAuth atomic.Value
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuth.Store(r.Header.Get("Authorization"))
		_, _ = io.WriteString(w, "tls-ok")
	}))
	defer upstream.Close()
	host, _, _ := net.SplitHostPort(strings.TrimPrefix(upstream.URL, "https://"))

	_, roots, p := setupProxy(t, validTokenResolver("av_sess_ok", okScope), injecting(host))
	upstreamRoots := x509.NewCertPool()
	upstreamRoots.AddCert(upstream.Certificate())
	p.upstream.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: upstreamRoots}
	bound := serveBound(t, p, "av_sess_ok", "default")

	resp, err := newTrustingClient(bound, nil, roots).Get(upstream.URL + "/ping")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if got := sawAuth.Load(); got != "Bearer injected-secret" {
		t.Fatalf("upstream saw %q, want the injected bearer", got)
	}
}
