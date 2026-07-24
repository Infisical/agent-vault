package mitm

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/brokercore"
)

// TestMITMCleartextConnectTunnel reproduces an undici-style client
// (Pi and other agents whose HTTP stack is undici's EnvHttpProxyAgent):
// it opens a CONNECT tunnel even for an http:// upstream and then speaks
// cleartext HTTP inside the tunnel, not TLS. The MITM must detect the
// non-TLS first byte, serve the tunnel in cleartext, forward to the
// http:// upstream, inject the credential, and pass arbitrary client
// headers through.
//
// Before the first-byte sniff, handleConnect ran an unconditional TLS
// handshake on the tunnel and dropped the connection here.
func TestMITMCleartextConnectTunnel(t *testing.T) {
	var sawAuth, sawUserID, sawTrace, sawProxyAuth, sawHost string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuth = r.Header.Get("Authorization")
		sawUserID = r.Header.Get("Af-User-Id")
		sawTrace = r.Header.Get("X-Trace-Id")
		sawProxyAuth = r.Header.Get("Proxy-Authorization")
		sawHost = r.Host
		_, _ = io.WriteString(w, "cleartext-upstream-ok")
	}))
	defer upstream.Close()

	upstreamAuthority := strings.TrimPrefix(upstream.URL, "http://") // host:port
	upstreamHost, _, _ := net.SplitHostPort(upstreamAuthority)

	sr := validTokenResolver("av_sess_ok",
		&brokercore.ProxyScope{VaultID: "v1", VaultName: "default", VaultRole: "proxy"})
	cp := &fakeCredProvider{byHost: map[string]fakeInjectResult{
		upstreamHost: {result: &brokercore.InjectResult{
			Headers: map[string]string{"Authorization": "Bearer injected-secret"},
		}},
	}}

	proxyURL, clientRoots, _ := setupProxy(t, sr, cp)

	// Open the CONNECT tunnel, then — unlike every other CONNECT test —
	// do NOT wrap the conn in tls.Client. Speak cleartext HTTP directly,
	// exactly as undici does for an http:// upstream tunnelled over CONNECT.
	conn := openMITMTunnel(t, proxyURL, clientRoots, upstreamAuthority, "av_sess_ok")
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	_, _ = fmt.Fprintf(conn,
		"POST /mcp HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Authorization: Bearer client-should-not-win\r\n"+
			"Af-User-Id: u_test_123\r\n"+
			"X-Trace-Id: trace-123\r\n"+
			"Content-Length: 0\r\n\r\n",
		upstreamAuthority,
	)

	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodPost})
	if err != nil {
		t.Fatalf("read cleartext response through tunnel: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "cleartext-upstream-ok" {
		t.Fatalf("body = %q, want cleartext-upstream-ok", body)
	}
	// Injected credential wins the auth slot even in a cleartext tunnel.
	if sawAuth != "Bearer injected-secret" {
		t.Fatalf("upstream Authorization = %q, want injected value", sawAuth)
	}
	// Arbitrary client headers pass through (identity + tracing).
	if sawUserID != "u_test_123" {
		t.Fatalf("upstream Af-User-Id = %q, want passthrough", sawUserID)
	}
	if sawTrace != "trace-123" {
		t.Fatalf("upstream X-Trace-Id = %q, want passthrough", sawTrace)
	}
	// Broker-scoped Proxy-Authorization must never reach the upstream.
	if sawProxyAuth != "" {
		t.Fatalf("upstream saw Proxy-Authorization %q; must be stripped", sawProxyAuth)
	}
	if sawHost != upstreamAuthority {
		t.Errorf("upstream Host = %q, want %q", sawHost, upstreamAuthority)
	}
}
