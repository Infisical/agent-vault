// Package egresstest provides working, in-process proxies that the egress
// and MITM test suites share.
//
// They are not stubs: the HTTP proxy performs real CONNECT tunnelling and
// absolute-form forwarding, the TLS variant terminates TLS with its own
// certificate, and the SOCKS5 server performs the real RFC 1928 handshake
// including RFC 1929 username/password authentication. Anything that would
// break against squid or dante-server should break here too, with no network
// access and no Docker.
//
// Sharing one implementation across test layers matters: the same proxy that
// proves a transport dials correctly also proves the MITM proxy reaches it
// after injecting credentials. Divergent fixtures would let one layer pass
// while the other fails on identical configuration.
package egresstest

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// --- HTTP forward proxy ---

// HTTPProxy is a recording HTTP forward proxy. It forwards to whatever
// target the caller names, so tests can assert what the *upstream* actually
// received, and it records enough about the proxy hop to prove the request
// took that path.
type HTTPProxy struct {
	addr string
	logs func(format string, args ...any)
	srv  *http.Server

	// requireUser/requirePass make the proxy demand Proxy-Authorization.
	// Leave empty for an open proxy.
	requireUser string
	requirePass string

	mu            sync.Mutex
	connects      []string
	forwarded     []string
	sawProxyAuth  string
	refusedAuth   int
	tunneledBytes int64
}

// NewHTTPProxy starts a local proxy supporting both CONNECT tunnelling and
// absolute-form forwarding.
func NewHTTPProxy(t *testing.T, requireUser, requirePass string) *HTTPProxy {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	p := &HTTPProxy{
		addr:        l.Addr().String(),
		logs:        t.Logf,
		requireUser: requireUser,
		requirePass: requirePass,
	}
	srv := &http.Server{Handler: http.HandlerFunc(p.serveHTTP), ReadHeaderTimeout: 10 * time.Second}
	p.srv = srv
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })

	p.logs("test HTTP proxy listening on %s", p.addr)
	return p
}

// Close stops the proxy so a test can model an egress hop that has gone away.
// Recorded counters survive the shutdown — they are the evidence for what the
// last request did.
func (p *HTTPProxy) Close() {
	if p.srv != nil {
		_ = p.srv.Close()
	}
}

// Addr is the listening address in host:port form.
func (p *HTTPProxy) Addr() string { return p.addr }

// ConnectCount counts CONNECT requests the proxy accepted.
func (p *HTTPProxy) ConnectCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.connects)
}

// ForwardCount counts absolute-form requests the proxy relayed.
func (p *HTTPProxy) ForwardCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.forwarded)
}

// LastConnect returns the target of the most recent CONNECT, or "".
func (p *HTTPProxy) LastConnect() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.connects) == 0 {
		return ""
	}
	return p.connects[len(p.connects)-1]
}

// SeenProxyAuth returns the Proxy-Authorization header the proxy received.
func (p *HTTPProxy) SeenProxyAuth() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.sawProxyAuth
}

// RefusedAuthCount counts requests the proxy rejected for bad credentials.
func (p *HTTPProxy) RefusedAuthCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.refusedAuth
}

// TunneledBytes counts bytes relayed through CONNECT tunnels.
func (p *HTTPProxy) TunneledBytes() int64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.tunneledBytes
}

// RequestCount is ConnectCount plus ForwardCount: how many requests reached
// the proxy at all. Asserting zero is how the SSRF red line is proven.
func (p *HTTPProxy) RequestCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.connects) + len(p.forwarded)
}

func (p *HTTPProxy) authorized(r *http.Request) bool {
	if p.requireUser == "" && p.requirePass == "" {
		return true
	}
	p.mu.Lock()
	p.sawProxyAuth = r.Header.Get("Proxy-Authorization")
	p.mu.Unlock()

	user, pass := parseBasic(r.Header.Get("Proxy-Authorization"))
	if user == "" && pass == "" {
		// Some clients send ordinary Authorization; accept either but
		// never treat an absent header as a match.
		if u, pw, ok := r.BasicAuth(); ok {
			user, pass = u, pw
		}
	}
	return user == p.requireUser && pass == p.requirePass
}

func (p *HTTPProxy) serveHTTP(w http.ResponseWriter, r *http.Request) {
	if !p.authorized(r) {
		p.mu.Lock()
		p.refusedAuth++
		p.mu.Unlock()
		w.Header().Set("Proxy-Authenticate", `Basic realm="test"`)
		http.Error(w, "proxy authentication required", http.StatusProxyAuthRequired)
		return
	}
	if r.Method == http.MethodConnect {
		p.serveConnect(w, r)
		return
	}
	p.serveAbsoluteForm(w, r)
}

func (p *HTTPProxy) serveConnect(w http.ResponseWriter, r *http.Request) {
	target := r.Host
	p.mu.Lock()
	p.connects = append(p.connects, target)
	p.mu.Unlock()

	upstream, err := net.DialTimeout("tcp", target, 5*time.Second)
	if err != nil {
		http.Error(w, "connect failed", http.StatusBadGateway)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		_ = upstream.Close()
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}
	client, buf, err := hj.Hijack()
	if err != nil {
		_ = upstream.Close()
		return
	}
	if _, err := client.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); err != nil {
		_ = upstream.Close()
		_ = client.Close()
		return
	}

	done := make(chan struct{}, 2)
	// Count bytes per read rather than after io.Copy returns: with
	// keep-alive connections neither copy finishes until the tunnel is torn
	// down, so a post-copy tally would never observe live traffic.
	relay := func(dst net.Conn, src io.Reader) {
		buf := make([]byte, 32*1024)
		for {
			n, err := src.Read(buf)
			if n > 0 {
				p.addTunneled(n)
				if _, werr := dst.Write(buf[:n]); werr != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
		done <- struct{}{}
	}
	// Flush anything the client already buffered into the tunnel first.
	if buf.Reader != nil && buf.Reader.Buffered() > 0 {
		n, _ := io.CopyN(upstream, buf.Reader, int64(buf.Reader.Buffered()))
		p.addTunneled(int(n))
	}
	go relay(upstream, client)
	go relay(client, upstream)
	<-done
	_ = upstream.Close()
	_ = client.Close()
	<-done
}

func (p *HTTPProxy) serveAbsoluteForm(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Host
	if target == "" {
		http.Error(w, "no absolute URL", http.StatusBadRequest)
		return
	}
	if !strings.Contains(target, ":") {
		target += ":80"
	}
	p.mu.Lock()
	p.forwarded = append(p.forwarded, target)
	p.mu.Unlock()

	upstream, err := net.DialTimeout("tcp", target, 5*time.Second)
	if err != nil {
		http.Error(w, "upstream dial failed", http.StatusBadGateway)
		return
	}
	defer func() { _ = upstream.Close() }()

	// Strip hop-by-hop headers before relaying, exactly as a forward proxy
	// is required to. This matters for credentials: net/http puts
	// Proxy-Authorization on every request it sends through the proxy in
	// absolute form (only CONNECT keeps it out of band), so the credential
	// reaching the upstream would be entirely the proxy's fault.
	original := r.Header
	r.Header = stripHopByHop(original)
	writeErr := r.Write(upstream)
	r.Header = original
	if writeErr != nil {
		http.Error(w, "upstream write failed", http.StatusBadGateway)
		return
	}
	resp, err := http.ReadResponse(bufio.NewReader(upstream), r)
	if err != nil {
		http.Error(w, "upstream read failed", http.StatusBadGateway)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func (p *HTTPProxy) addTunneled(n int) {
	p.mu.Lock()
	p.tunneledBytes += int64(n)
	p.mu.Unlock()
}

// hopByHopHeaders must never be relayed from one hop to the next.
var hopByHopHeaders = map[string]bool{
	"Connection":          true,
	"Proxy-Connection":    true,
	"Keep-Alive":          true,
	"Proxy-Authenticate":  true,
	"Proxy-Authorization": true,
	"Te":                  true,
	"Trailer":             true,
	"Transfer-Encoding":   true,
	"Upgrade":             true,
}

func stripHopByHop(h http.Header) http.Header {
	out := make(http.Header, len(h))
	for k, vv := range h {
		if hopByHopHeaders[http.CanonicalHeaderKey(k)] {
			continue
		}
		out[k] = append([]string(nil), vv...)
	}
	return out
}

func parseBasic(header string) (user, pass string) {
	if !strings.HasPrefix(header, "Basic ") {
		return "", ""
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(header, "Basic "))
	if err != nil {
		return "", ""
	}
	decoded := string(raw)
	i := strings.IndexByte(decoded, ':')
	if i < 0 {
		return "", ""
	}
	return decoded[:i], decoded[i+1:]
}

// --- HTTPS (TLS-terminating) forward proxy ---
//
// Exercises the `https` scheme end to end: the proxy hop itself is wrapped in
// TLS, verified against a certificate no public CA would ever issue, so
// ProfileCA round-tripping through the profile is observable.

// HTTPSProxy is HTTPProxy behind a TLS listener.
type HTTPSProxy struct {
	*HTTPProxy
	pem string
}

// NewHTTPSProxy starts a forwarding proxy behind a TLS listener, exposing the
// PEM required to trust it via UpstreamProxy.ProxyCAPEM.
func NewHTTPSProxy(t *testing.T, requireUser, requirePass string) *HTTPSProxy {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	certPEM, keyPEM := localCert(t)
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}

	p := &HTTPProxy{
		addr:        l.Addr().String(),
		logs:        t.Logf,
		requireUser: requireUser,
		requirePass: requirePass,
	}
	srv := &http.Server{Handler: http.HandlerFunc(p.serveHTTP), ReadHeaderTimeout: 10 * time.Second}
	tlsLn := tls.NewListener(l, &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12})
	go func() { _ = srv.Serve(tlsLn) }()
	t.Cleanup(func() { _ = srv.Close() })

	p.logs("test HTTPS proxy listening on %s", p.addr)
	return &HTTPSProxy{HTTPProxy: p, pem: string(certPEM)}
}

// PEM returns the proxy's leaf certificate for use as a pinned trust anchor.
func (p *HTTPSProxy) PEM() string { return p.pem }

// localCert mints a throwaway server certificate for 127.0.0.1. Verification
// uses the IP SAN, which is what the egress layer passes as ServerName when
// the proxy is addressed by IP.
func localCert(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "agent-vault-test-https-proxy"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey: %v", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}

// --- SOCKS5 server ---
//
// Implements just enough of RFC 1928/1929 to exercise the real x/net/proxy
// client: greeting, optional username/password authentication, CONNECT, and
// the reply — then relays bytes.

// SOCKS5Proxy is a minimal SOCKS5 server that records every CONNECT target.
type SOCKS5Proxy struct {
	addr    string
	ln      net.Listener
	user    string
	pass    string
	mu      sync.Mutex
	dials   []string
	atypes  []byte
	refused int
}

// NewSOCKS5Proxy starts a SOCKS5 server. Leave user/pass empty to skip the
// username/password sub-negotiation.
func NewSOCKS5Proxy(t *testing.T, user, pass string) *SOCKS5Proxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &SOCKS5Proxy{addr: ln.Addr().String(), ln: ln, user: user, pass: pass}
	go s.serve()
	t.Cleanup(func() { _ = ln.Close() })
	return s
}

// Addr is the listening address in host:port form.
func (s *SOCKS5Proxy) Addr() string { return s.addr }

// DialCount counts CONNECT requests the server accepted.
func (s *SOCKS5Proxy) DialCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.dials)
}

// LastATYP reports the address type from the latest request (1=IPv4,
// 3=domain, 4=IPv6), or zero when no request was recorded.
func (s *SOCKS5Proxy) LastATYP() byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.atypes) == 0 {
		return 0
	}
	return s.atypes[len(s.atypes)-1]
}

func (s *SOCKS5Proxy) record(target string, atyp byte) {
	s.mu.Lock()
	s.dials = append(s.dials, target)
	s.atypes = append(s.atypes, atyp)
	s.mu.Unlock()
}

func (s *SOCKS5Proxy) serve() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handle(conn)
	}
}

func (s *SOCKS5Proxy) handle(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))

	r := bufio.NewReader(conn)

	// Greeting: VER NMETHODS METHODS
	if ver, err := r.ReadByte(); err != nil || ver != 0x05 {
		return
	}
	nMethods, err := r.ReadByte()
	if err != nil {
		return
	}
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(r, methods); err != nil {
		return
	}

	const methodUsername = 0x02
	if s.user != "" || s.pass != "" {
		supported := false
		for _, m := range methods {
			if m == methodUsername {
				supported = true
			}
		}
		if !supported {
			_, _ = conn.Write([]byte{0x05, 0xFF})
			return
		}
		if _, err := conn.Write([]byte{0x05, methodUsername}); err != nil {
			return
		}
		// Username/password sub-negotiation (RFC 1929).
		if _, err := r.ReadByte(); err != nil {
			return
		}
		ulen, err := r.ReadByte()
		if err != nil {
			return
		}
		user := make([]byte, ulen)
		if _, err := io.ReadFull(r, user); err != nil {
			return
		}
		plen, err := r.ReadByte()
		if err != nil {
			return
		}
		pass := make([]byte, plen)
		if _, err := io.ReadFull(r, pass); err != nil {
			return
		}
		status := byte(0x01)
		if string(user) == s.user && string(pass) == s.pass {
			status = 0x00
		}
		if _, err := conn.Write([]byte{0x01, status}); err != nil {
			return
		}
		if status != 0x00 {
			s.mu.Lock()
			s.refused++
			s.mu.Unlock()
			return
		}
	} else if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	// Request: VER CMD RSV ATYP DST.ADDR DST.PORT
	head := make([]byte, 4)
	if _, err := io.ReadFull(r, head); err != nil || head[1] != 0x01 {
		return
	}
	var target string
	switch head[3] {
	case 0x01: // IPv4
		b := make([]byte, 4)
		if _, err := io.ReadFull(r, b); err != nil {
			return
		}
		target = net.IPv4(b[0], b[1], b[2], b[3]).String()
	case 0x03: // domain name
		l, err := r.ReadByte()
		if err != nil {
			return
		}
		name := make([]byte, l)
		if _, err := io.ReadFull(r, name); err != nil {
			return
		}
		target = string(name)
	case 0x04: // IPv6
		b := make([]byte, 16)
		if _, err := io.ReadFull(r, b); err != nil {
			return
		}
		target = net.IP(b).String()
	default:
		return
	}
	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(r, portBytes); err != nil {
		return
	}
	port := int(portBytes[0])<<8 | int(portBytes[1])
	target = net.JoinHostPort(target, fmt.Sprint(port))
	s.record(target, head[3])

	upstream, err := net.DialTimeout("tcp", target, 5*time.Second)
	if err != nil {
		_, _ = conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer func() { _ = upstream.Close() }()
	_ = conn.SetDeadline(time.Time{})

	// Reply: success, bound addr = 0.0.0.0:0 (the client ignores it).
	if _, err := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}

	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(upstream, r); done <- struct{}{} }()
	go func() { _, _ = io.Copy(conn, upstream); done <- struct{}{} }()
	<-done
	<-done
}

// --- Blackhole proxy ---

// BlackholeProxy accepts connections and never answers, so dial failures can
// be distinguished from hangs.
type BlackholeProxy struct {
	ln    net.Listener
	addr  string
	count int
	mu    sync.Mutex
}

// NewBlackholeProxy starts a listener that speaks no protocol at all.
func NewBlackholeProxy(t *testing.T) *BlackholeProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	b := &BlackholeProxy{ln: ln, addr: ln.Addr().String()}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			b.mu.Lock()
			b.count++
			b.mu.Unlock()
			// Hold the socket open without ever speaking a protocol.
			_ = conn.SetDeadline(time.Time{})
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return b
}

// Addr is the listening address in host:port form.
func (b *BlackholeProxy) Addr() string { return b.addr }

// ConnectionCount counts accepted connections.
func (b *BlackholeProxy) ConnectionCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.count
}
