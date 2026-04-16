package mitm

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/ca"
)

// setupProxy starts a mitm.Proxy backed by a freshly-generated SoftCA on
// a loopback :0 port. Returns the listening URL, the root-cert pool for
// client-side trust, and the proxy instance (so the test can mutate its
// upstream transport, e.g. to trust a test upstream's self-signed cert).
func setupProxy(t *testing.T) (proxyURL *url.URL, clientRoots *x509.CertPool, p *Proxy) {
	t.Helper()

	// Default netguard mode is "public" which blocks loopback.
	// httptest upstreams listen on 127.0.0.1, so switch to "private" for tests.
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

	p = New("127.0.0.1:0", caProv)

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
// proxyURL and trusts the given roots for the terminated client-side TLS.
func newTrustingClient(proxyURL *url.URL, roots *x509.CertPool) *http.Client {
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: roots},
		},
	}
}

func TestProxyForwardsHTTPSRequest(t *testing.T) {
	var sawAuth, sawProxyAuth string
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuth = r.Header.Get("Authorization")
		sawProxyAuth = r.Header.Get("Proxy-Authorization")
		w.Header().Set("X-Upstream", "hello")
		_, _ = io.WriteString(w, "upstream-body")
	}))
	defer upstream.Close()

	proxyURL, clientRoots, p := setupProxy(t)

	// Teach the proxy's upstream transport to trust the httptest server's
	// self-signed cert. In production this stays at system trust.
	upstreamRoots := x509.NewCertPool()
	upstreamRoots.AddCert(upstream.Certificate())
	p.upstream.TLSClientConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    upstreamRoots,
	}

	client := newTrustingClient(proxyURL, clientRoots)
	req, err := http.NewRequest("GET", upstream.URL+"/ping", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer client-token")
	req.Header.Set("Proxy-Authorization", "Basic should-not-forward")

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
	if got := resp.Header.Get("X-Upstream"); got != "hello" {
		t.Fatalf("X-Upstream = %q, want hello", got)
	}
	if sawAuth != "Bearer client-token" {
		t.Fatalf("upstream saw Authorization %q, want Bearer client-token", sawAuth)
	}
	if sawProxyAuth != "" {
		t.Fatalf("upstream saw Proxy-Authorization %q, expected it to be stripped", sawProxyAuth)
	}
}

func TestProxyReturns502WhenUpstreamCertUntrusted(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "should-not-reach")
	}))
	defer upstream.Close()

	proxyURL, clientRoots, _ := setupProxy(t)
	// NOTE: not adding the upstream's cert to p.upstream, so verification fails.

	client := newTrustingClient(proxyURL, clientRoots)
	resp, err := client.Get(upstream.URL + "/ping")
	if err != nil {
		t.Fatalf("client.Get: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
}

func TestProxyRejectsNonConnectRequests(t *testing.T) {
	proxyURL, _, _ := setupProxy(t)

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
