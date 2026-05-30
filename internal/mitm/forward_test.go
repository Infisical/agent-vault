package mitm

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
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
	"github.com/Infisical/agent-vault/internal/netguard"
	"github.com/Infisical/agent-vault/internal/requestlog"
)

// recordingSink captures records from the forward path so tests can
// assert the audit log shape end-to-end.
type recordingSink struct {
	mu      sync.Mutex
	records []requestlog.Record
}

func (s *recordingSink) Record(_ context.Context, r requestlog.Record) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records = append(s.records, r)
}

func (s *recordingSink) snapshot() []requestlog.Record {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]requestlog.Record, len(s.records))
	copy(out, s.records)
	return out
}

// dialProxy opens a plain TCP connection to the proxy listener (no
// CONNECT, no absolute-form request). Tests use it to write malformed
// or hand-shaped request lines so we can exercise the dispatch
// validator directly.
func dialProxy(t *testing.T, proxyURL *url.URL) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", proxyURL.Host)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	return conn
}

// writeRawRequestLine writes an arbitrary request line + headers to the
// proxy and returns the parsed response. The HTTP method passed to
// http.ReadResponse is informational only (controls how the reader
// handles bodies for HEAD); for our tests "GET" is fine across the
// board.
func writeRawRequestLine(t *testing.T, conn net.Conn, line string, headers map[string]string) *http.Response {
	t.Helper()
	var buf bytes.Buffer
	buf.WriteString(line + "\r\n")
	for k, v := range headers {
		fmt.Fprintf(&buf, "%s: %s\r\n", k, v)
	}
	buf.WriteString("\r\n")
	if _, err := conn.Write(buf.Bytes()); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	return resp
}

// TestMITMForwardPlainHTTPInjectsCredentials is the flagship test for
// the plain-HTTP forward-proxy path. A standard Go client with
// HTTPS_PROXY pointing at the proxy sends an absolute-form
// request to a plain-HTTP upstream; the proxy authenticates, injects
// the configured credential, strips broker-scoped headers, and returns
// the upstream response.
func TestMITMForwardPlainHTTPInjectsCredentials(t *testing.T) {
	var sawAuth, sawClientHeader, sawProxyAuth, sawHost, sawMethod, sawPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuth = r.Header.Get("Authorization")
		sawClientHeader = r.Header.Get("X-Client-Header")
		sawProxyAuth = r.Header.Get("Proxy-Authorization")
		sawHost = r.Host
		sawMethod = r.Method
		sawPath = r.URL.Path
		_, _ = io.WriteString(w, "plain-http-ok")
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

	client := newTrustingClient(proxyURL, url.User("av_sess_ok"), clientRoots)

	req, err := http.NewRequest("POST", upstream.URL+"/v1/messages", strings.NewReader("hello"))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer client-should-not-win")
	req.Header.Set("X-Client-Header", "client-value")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("client.Do: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "plain-http-ok" {
		t.Fatalf("body = %q", body)
	}
	if sawMethod != "POST" {
		t.Errorf("upstream method = %q, want POST", sawMethod)
	}
	if sawPath != "/v1/messages" {
		t.Errorf("upstream path = %q, want /v1/messages", sawPath)
	}
	if sawAuth != "Bearer injected-secret" {
		t.Errorf("upstream Authorization = %q, want injected", sawAuth)
	}
	if sawClientHeader != "client-value" {
		t.Errorf("upstream X-Client-Header = %q, want passthrough", sawClientHeader)
	}
	if sawProxyAuth != "" {
		t.Errorf("upstream Proxy-Authorization = %q; must be stripped", sawProxyAuth)
	}
	// RFC 7230 §5.4: forwarded Host MUST equal the URI authority,
	// including non-default port. handleForward canonicalises target
	// as host:port and forwardRequest sets outReq.Host = target.
	if sawHost != upstreamAuthority {
		t.Errorf("upstream Host = %q, want %q", sawHost, upstreamAuthority)
	}
}

// TestMITMForwardRejectsHTTPSScheme: a client erroneously sending
// `POST https://upstream/...` (absolute form) to the forward-proxy
// must be rejected with 400, not silently TLS-stripped. The hint
// nudges the client toward CONNECT for HTTPS upstreams.
func TestMITMForwardRejectsHTTPSScheme(t *testing.T) {
	proxyURL, _, _ := setupProxy(t,
		validTokenResolver("av_sess_ok", &brokercore.ProxyScope{VaultID: "v1", VaultName: "default", VaultRole: "proxy"}),
		&fakeCredProvider{})

	conn := dialProxy(t, proxyURL)
	defer conn.Close()

	auth := base64.StdEncoding.EncodeToString([]byte("av_sess_ok:"))
	resp := writeRawRequestLine(t, conn,
		"POST https://api.example.com/x HTTP/1.1",
		map[string]string{
			"Host":                "api.example.com",
			"Proxy-Authorization": "Basic " + auth,
			"Content-Length":      "0",
		})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for https:// forward-proxy form", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(strings.ToLower(string(body)), "connect") {
		t.Errorf("400 body should hint at CONNECT for https; got %q", body)
	}
}

// TestMITMForwardRejectsNonHTTPSchemes: schemes other than http (file,
// gopher, ftp, ws) reach the listener over TLS but are rejected as
// malformed forward-proxy requests.
func TestMITMForwardRejectsNonHTTPSchemes(t *testing.T) {
	proxyURL, _, _ := setupProxy(t,
		validTokenResolver("av_sess_ok", &brokercore.ProxyScope{VaultID: "v1", VaultName: "default", VaultRole: "proxy"}),
		&fakeCredProvider{})

	auth := base64.StdEncoding.EncodeToString([]byte("av_sess_ok:"))
	for _, scheme := range []string{"file", "gopher", "ftp", "ws"} {
		t.Run(scheme, func(t *testing.T) {
			conn := dialProxy(t, proxyURL)
			defer conn.Close()

			line := fmt.Sprintf("GET %s://example.com/x HTTP/1.1", scheme)
			resp := writeRawRequestLine(t, conn, line, map[string]string{
				"Host":                "example.com",
				"Proxy-Authorization": "Basic " + auth,
			})
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("scheme %q: status = %d, want 400", scheme, resp.StatusCode)
			}
		})
	}
}

// TestMITMForwardRequiresProxyAuthorization: a forward request without
// Proxy-Authorization gets a 407 challenge with Proxy-Authenticate.
func TestMITMForwardRequiresProxyAuthorization(t *testing.T) {
	proxyURL, _, _ := setupProxy(t,
		validTokenResolver("av_sess_ok", &brokercore.ProxyScope{VaultID: "v1", VaultName: "default", VaultRole: "proxy"}),
		&fakeCredProvider{})

	conn := dialProxy(t, proxyURL)
	defer conn.Close()

	resp := writeRawRequestLine(t, conn,
		"GET http://example.com/x HTTP/1.1",
		map[string]string{"Host": "example.com"})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("status = %d, want 407", resp.StatusCode)
	}
	if got := resp.Header.Get("Proxy-Authenticate"); !strings.Contains(got, "Basic") {
		t.Errorf("Proxy-Authenticate = %q, want Basic challenge", got)
	}
}

// TestMITMForwardInvalidSessionReturns407: a forward request with an
// unknown token gets the same 407 challenge.
func TestMITMForwardInvalidSessionReturns407(t *testing.T) {
	proxyURL, _, _ := setupProxy(t,
		errResolver(brokercore.ErrInvalidSession),
		&fakeCredProvider{})

	conn := dialProxy(t, proxyURL)
	defer conn.Close()

	auth := base64.StdEncoding.EncodeToString([]byte("av_sess_bad:"))
	resp := writeRawRequestLine(t, conn,
		"GET http://example.com/x HTTP/1.1",
		map[string]string{
			"Host":                "example.com",
			"Proxy-Authorization": "Basic " + auth,
		})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("status = %d, want 407", resp.StatusCode)
	}
}

// TestMITMForwardVaultHintMismatchReturns403: parallels the CONNECT-
// path test — ErrVaultHintMismatch from the resolver maps to 403.
func TestMITMForwardVaultHintMismatchReturns403(t *testing.T) {
	proxyURL, _, _ := setupProxy(t,
		errResolver(brokercore.ErrVaultHintMismatch),
		&fakeCredProvider{})

	conn := dialProxy(t, proxyURL)
	defer conn.Close()

	auth := base64.StdEncoding.EncodeToString([]byte("av_sess_ok:wrongvault"))
	resp := writeRawRequestLine(t, conn,
		"GET http://example.com/x HTTP/1.1",
		map[string]string{
			"Host":                "example.com",
			"Proxy-Authorization": "Basic " + auth,
		})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
}

// TestMITMForwardStripsHopByHopHeaders verifies RFC 7230 §6.1: any
// header named in the client's Connection field is stripped before
// forwarding, alongside the static hop-by-hop set and the broker-
// scoped Proxy-Authorization / X-Vault headers.
func TestMITMForwardStripsHopByHopHeaders(t *testing.T) {
	var sawCustom, sawConnection, sawProxyAuth, sawXVault, sawTE string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawCustom = r.Header.Get("X-Custom")
		sawConnection = r.Header.Get("Connection")
		sawProxyAuth = r.Header.Get("Proxy-Authorization")
		sawXVault = r.Header.Get("X-Vault")
		sawTE = r.Header.Get("Te")
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()

	upstreamHost, _, _ := net.SplitHostPort(strings.TrimPrefix(upstream.URL, "http://"))
	sr := validTokenResolver("av_sess_ok",
		&brokercore.ProxyScope{VaultID: "v1", VaultName: "default", VaultRole: "proxy"})
	cp := &fakeCredProvider{byHost: map[string]fakeInjectResult{
		upstreamHost: {result: &brokercore.InjectResult{Passthrough: true}},
	}}

	proxyURL, _, _ := setupProxy(t, sr, cp)

	conn := dialProxy(t, proxyURL)
	defer conn.Close()

	auth := base64.StdEncoding.EncodeToString([]byte("av_sess_ok:"))
	resp := writeRawRequestLine(t, conn,
		"GET "+upstream.URL+"/x HTTP/1.1",
		map[string]string{
			"Host":                upstreamHost,
			"Proxy-Authorization": "Basic " + auth,
			"X-Vault":             "default",
			"Connection":          "X-Custom, close",
			"X-Custom":            "secret",
			"Te":                  "trailers",
		})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if sawCustom != "" {
		t.Errorf("upstream X-Custom = %q; must be stripped (named in Connection)", sawCustom)
	}
	if sawConnection != "" {
		t.Errorf("upstream Connection = %q; must be stripped (hop-by-hop)", sawConnection)
	}
	if sawProxyAuth != "" {
		t.Errorf("upstream Proxy-Authorization = %q; must be stripped (broker-scoped)", sawProxyAuth)
	}
	if sawXVault != "" {
		t.Errorf("upstream X-Vault = %q; must be stripped (broker-scoped)", sawXVault)
	}
	if sawTE != "" {
		t.Errorf("upstream TE = %q; must be stripped (hop-by-hop)", sawTE)
	}
}

// TestMITMForwardWebSocketPlainHTTP: a ws:// upgrade through the
// forward proxy succeeds; frames pipe both ways. Exercises the
// scheme-aware branch in dialWebSocketUpstream that skips TLS for
// http:// upstreams.
func TestMITMForwardWebSocketPlainHTTP(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			http.Error(w, "expected websocket", http.StatusBadRequest)
			return
		}
		key := r.Header.Get("Sec-WebSocket-Key")
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "no hijacker", http.StatusInternalServerError)
			return
		}
		conn, buf, err := hijacker.Hijack()
		if err != nil {
			t.Errorf("upstream hijack: %v", err)
			return
		}
		defer conn.Close()

		acc := websocketAccept(key)
		fmt.Fprintf(buf,
			"HTTP/1.1 101 Switching Protocols\r\n"+
				"Upgrade: websocket\r\n"+
				"Connection: Upgrade\r\n"+
				"Sec-WebSocket-Accept: %s\r\n\r\n",
			acc)
		_ = buf.Flush()

		frame, ferr := readWebSocketTextFrame(buf.Reader)
		if ferr != nil {
			return
		}
		_ = writeWebSocketTextFrame(conn, "echo:"+frame, false)
	}))
	defer upstream.Close()

	upstreamHost, _, _ := net.SplitHostPort(strings.TrimPrefix(upstream.URL, "http://"))
	sr := validTokenResolver("av_sess_ok",
		&brokercore.ProxyScope{VaultID: "v1", VaultName: "default", VaultRole: "proxy"})
	cp := &fakeCredProvider{byHost: map[string]fakeInjectResult{
		upstreamHost: {result: &brokercore.InjectResult{Passthrough: true}},
	}}
	proxyURL, _, _ := setupProxy(t, sr, cp)

	conn := dialProxy(t, proxyURL)
	defer conn.Close()

	keyBytes := make([]byte, 16)
	for i := range keyBytes {
		keyBytes[i] = byte(i + 1)
	}
	clientKey := base64.StdEncoding.EncodeToString(keyBytes)
	auth := base64.StdEncoding.EncodeToString([]byte("av_sess_ok:"))
	fmt.Fprintf(conn,
		"GET %s/ws HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Proxy-Authorization: Basic %s\r\n"+
			"Upgrade: websocket\r\n"+
			"Connection: Upgrade\r\n"+
			"Sec-WebSocket-Key: %s\r\n"+
			"Sec-WebSocket-Version: 13\r\n\r\n",
		upstream.URL, upstreamHost, auth, clientKey)

	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatalf("read switching response: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d, want 101", resp.StatusCode)
	}
	wantAccept := websocketAccept(clientKey)
	if got := resp.Header.Get("Sec-WebSocket-Accept"); got != wantAccept {
		t.Errorf("Sec-WebSocket-Accept = %q, want %q", got, wantAccept)
	}

	if err := writeWebSocketTextFrame(conn, "hi", true); err != nil {
		t.Fatalf("write frame: %v", err)
	}
	got, err := readWebSocketTextFrame(reader)
	if err != nil {
		t.Fatalf("read frame: %v", err)
	}
	if got != "echo:hi" {
		t.Fatalf("got %q, want echo:hi", got)
	}
}

// TestMITMForwardSSRFLoopbackBlocked: with the upstream Transport
// configured with netguard.SafeDialContext(false) (no allowlist), a
// forward request to 127.0.0.1 must be rejected at dial time and
// surfaced as 502.
func TestMITMForwardSSRFLoopbackBlocked(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "should-not-reach")
	}))
	defer upstream.Close()

	upstreamHost, _, _ := net.SplitHostPort(strings.TrimPrefix(upstream.URL, "http://"))
	sr := validTokenResolver("av_sess_ok",
		&brokercore.ProxyScope{VaultID: "v1", VaultName: "default", VaultRole: "proxy"})
	cp := &fakeCredProvider{byHost: map[string]fakeInjectResult{
		upstreamHost: {result: &brokercore.InjectResult{Passthrough: true}},
	}}
	proxyURL, clientRoots, p := setupProxy(t, sr, cp)
	// Override the dialler with a stricter SafeDialContext that blocks
	// loopback (setupProxy seeded ALLOW_PRIVATE_RANGES=true for the
	// other tests; we bypass that policy here directly).
	p.upstream.DialContext = netguard.SafeDialContext(false)

	client := newTrustingClient(proxyURL, url.User("av_sess_ok"), clientRoots)
	resp, err := client.Get(upstream.URL + "/x")
	if err != nil {
		t.Fatalf("client.Get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502 (loopback blocked at dial)", resp.StatusCode)
	}
}

// TestMITMForwardEmitsRequestLogRow asserts the audit row shape on the
// plain-HTTP forward path: ingress, method, host (with port), path,
// vault id, actor type+id, status.
func TestMITMForwardEmitsRequestLogRow(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()

	upstreamHost, _, _ := net.SplitHostPort(strings.TrimPrefix(upstream.URL, "http://"))
	sr := validTokenResolver("av_sess_ok",
		&brokercore.ProxyScope{
			AgentID:   "agent-42",
			VaultID:   "v1",
			VaultName: "default",
			VaultRole: "proxy",
		})
	cp := &fakeCredProvider{byHost: map[string]fakeInjectResult{
		upstreamHost: {result: &brokercore.InjectResult{
			MatchedName: "upstream-svc",
			MatchedHost: upstreamHost,
			MatchedPath: "/v1/*",
			Headers:     map[string]string{"Authorization": "Bearer x"},
		}},
	}}
	sink := &recordingSink{}
	proxyURL, clientRoots, _ := setupProxy(t, sr, cp, func(o *Options) { o.LogSink = sink })

	client := newTrustingClient(proxyURL, url.User("av_sess_ok"), clientRoots)
	req, err := http.NewRequest("POST", upstream.URL+"/v1/things", strings.NewReader("payload"))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("client.Do: %v", err)
	}
	_ = resp.Body.Close()

	rows := sink.snapshot()
	if len(rows) != 1 {
		t.Fatalf("got %d records, want 1", len(rows))
	}
	row := rows[0]
	if row.Ingress != brokercore.IngressMITM {
		t.Errorf("Ingress = %q, want %q", row.Ingress, brokercore.IngressMITM)
	}
	if row.Method != "POST" {
		t.Errorf("Method = %q, want POST", row.Method)
	}
	// handleForward canonicalises the target so event.Host is "host:port".
	if !strings.Contains(row.Host, ":") {
		t.Errorf("Host = %q, want host:port form (handleForward canonicalises)", row.Host)
	}
	if !strings.HasPrefix(row.Host, strings.SplitN(upstreamHost, ":", 2)[0]) {
		t.Errorf("Host = %q, want it to reference upstream host %q", row.Host, upstreamHost)
	}
	if row.Path != "/v1/things" {
		t.Errorf("Path = %q, want /v1/things", row.Path)
	}
	if row.VaultID != "v1" {
		t.Errorf("VaultID = %q, want v1", row.VaultID)
	}
	if row.ActorType != brokercore.ActorTypeAgent {
		t.Errorf("ActorType = %q, want agent", row.ActorType)
	}
	if row.ActorID != "agent-42" {
		t.Errorf("ActorID = %q, want agent-42", row.ActorID)
	}
	if row.Status != http.StatusOK {
		t.Errorf("Status = %d, want 200", row.Status)
	}
	if row.MatchedService != "upstream-svc" {
		t.Errorf("MatchedService = %q, want upstream-svc (canonical name)", row.MatchedService)
	}
	if row.MatchedHost != upstreamHost {
		t.Errorf("MatchedHost = %q, want %q", row.MatchedHost, upstreamHost)
	}
	if row.MatchedPath != "/v1/*" {
		t.Errorf("MatchedPath = %q, want /v1/*", row.MatchedPath)
	}
}

// TestMITMForwardKeepalivePersistsAcrossRequests: two back-to-back
// forward requests over the same TLS-to-proxy connection both succeed.
// Per-request scope resolution and per-request EnforceProxy must work
// without state leaks between requests on the keepalive channel.
func TestMITMForwardKeepalivePersistsAcrossRequests(t *testing.T) {
	var hits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()

	upstreamHost, _, _ := net.SplitHostPort(strings.TrimPrefix(upstream.URL, "http://"))
	sr := validTokenResolver("av_sess_ok",
		&brokercore.ProxyScope{VaultID: "v1", VaultName: "default", VaultRole: "proxy"})
	cp := &fakeCredProvider{byHost: map[string]fakeInjectResult{
		upstreamHost: {result: &brokercore.InjectResult{Passthrough: true}},
	}}
	sink := &recordingSink{}
	proxyURL, clientRoots, _ := setupProxy(t, sr, cp, func(o *Options) { o.LogSink = sink })

	client := newTrustingClient(proxyURL, url.User("av_sess_ok"), clientRoots)

	for i := 0; i < 2; i++ {
		resp, err := client.Get(upstream.URL + "/x")
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d: status = %d, want 200", i, resp.StatusCode)
		}
	}

	if got := hits.Load(); got != 2 {
		t.Fatalf("upstream hits = %d, want 2", got)
	}
	if rows := sink.snapshot(); len(rows) != 2 {
		t.Fatalf("got %d log rows, want 2", len(rows))
	}
}

// TestMITMForwardIPv6PreservesHostHeader locks in the Host-header
// port-preservation fix on the IPv6 forward-proxy path: outReq.Host
// must equal target ("[::1]:port"), not the port-stripped form ("::1")
// the old code emitted. The request line carries an explicit port so
// the no-port canonicalisation branch (URL.Hostname/Port instead of
// net.SplitHostPort) is not driven here — exercising that end-to-end
// would require binding port 80 on ::1. Sending raw via dialProxyTLS
// because Go's http.Client rewrites URLs through ProxyURL in ways
// that would obscure what we want to assert.
func TestMITMForwardIPv6PreservesHostHeader(t *testing.T) {
	// Bind an upstream on an ephemeral ::1 port so we can send an
	// IPv6-literal-with-port URL through the forward proxy. SkipNow if
	// the host has no IPv6 loopback (CI sometimes).
	l, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 loopback available: %v", err)
	}
	_, port, _ := net.SplitHostPort(l.Addr().String())
	var sawHost string
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawHost = r.Host
		_, _ = io.WriteString(w, "v6-ok")
	}), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	sr := validTokenResolver("av_sess_ok",
		&brokercore.ProxyScope{VaultID: "v1", VaultName: "default", VaultRole: "proxy"})
	cp := &fakeCredProvider{byHost: map[string]fakeInjectResult{
		"::1": {result: &brokercore.InjectResult{Passthrough: true}},
	}}
	proxyURL, _, _ := setupProxy(t, sr, cp)

	conn := dialProxy(t, proxyURL)
	defer conn.Close()

	auth := base64.StdEncoding.EncodeToString([]byte("av_sess_ok:"))
	resp := writeRawRequestLine(t, conn,
		fmt.Sprintf("GET http://[::1]:%s/x HTTP/1.1", port),
		map[string]string{
			"Host":                "[::1]:" + port,
			"Proxy-Authorization": "Basic " + auth,
		})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, body)
	}
	wantHost := "[::1]:" + port
	if sawHost != wantHost {
		t.Errorf("upstream Host = %q, want %q (IPv6 brackets must round-trip)", sawHost, wantHost)
	}
}
