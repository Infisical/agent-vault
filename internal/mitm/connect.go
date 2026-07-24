package mitm

import (
	"bufio"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/ratelimit"
)

// mitmIPKey is the rate-limit key for the per-IP flood gate shared by
// the CONNECT and absolute-form forward-proxy paths. X-Forwarded-For
// doesn't exist at this layer (the HTTP request is tunnelled or sent
// over the proxy connection); only the direct peer IP is
// meaningful. CONNECT and forward share one budget — a peer is one peer
// regardless of which ingress shape they use.
func mitmIPKey(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil || host == "" {
		host = r.RemoteAddr
	}
	return "mitm:" + host
}

// isLoopbackPeer reports whether the HTTP request came from a loopback
// peer (127.0.0.0/8 or ::1). Used to skip the CONNECT flood gate for
// local `vault run` clients — a single agent legitimately opens dozens
// of CONNECTs (one per distinct upstream host) on startup, and a
// cooperating or higher-privilege local process can trivially DoS the
// proxy by other means regardless, so rate-limiting loopback only
// breaks legitimate agents without adding defense.
func isLoopbackPeer(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil || host == "" {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// handleConnect terminates a CONNECT tunnel and serves HTTP/1.1 off the
// resulting TLS connection. The upstream target is taken from the
// CONNECT request line (r.Host) and captured in a closure so subsequent
// Host-header rewrites by the client cannot redirect the tunnel.
func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	// Read-only pre-gate: if this IP has exhausted its auth-failure
	// budget, reject immediately. Only auth failures are recorded
	// (below) so legitimate agents don't burn the budget. Loopback
	// is exempt — see isLoopbackPeer.
	if p.rateLimit != nil && !isLoopbackPeer(r) {
		if d := p.rateLimit.Check(ratelimit.TierAuth, mitmIPKey(r)); !d.Allow {
			ratelimit.WriteDenial(w, d, "Too many CONNECT attempts")
			return
		}
	}

	target := r.Host
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		http.Error(w, "CONNECT target must be host:port", http.StatusBadRequest)
		return
	}
	port, _ := strconv.Atoi(portStr)
	if !isValidHost(host) {
		http.Error(w, "invalid host", http.StatusBadRequest)
		return
	}

	// Authenticate the CONNECT request via Proxy-Authorization and resolve
	// the target vault. All error responses must be written BEFORE the
	// connection is hijacked — once hijacked, no HTTP status can be sent.
	token, hint, err := brokercore.ParseProxyAuth(r)
	if err != nil {
		p.recordAuthFailure(r)
		writeProxyAuthChallenge(w, "Proxy-Authorization required")
		return
	}
	scope, err := p.sessions.ResolveForProxy(r.Context(), token, hint)
	if err != nil {
		p.recordAuthFailure(r)
		writeAuthError(w, err)
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hj.Hijack()
	if err != nil {
		http.Error(w, "hijack failed", http.StatusInternalServerError)
		return
	}

	if _, err := io.WriteString(clientConn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		_ = clientConn.Close()
		return
	}

	// A CONNECT tunnel conventionally carries TLS, and terminating it is how
	// the MITM sees the request to inject credentials. But some proxy clients
	// tunnel http:// upstreams over CONNECT too and then speak cleartext HTTP
	// inside — undici's EnvHttpProxyAgent does this, so Node-based agents
	// (Pi and others in knownAgents) land here with a plain-HTTP payload.
	// Committing to a TLS handshake unconditionally drops those tunnels. Peek
	// the first byte to disambiguate without consuming it: a TLS record for a
	// handshake begins with 0x16, while every HTTP method starts with an
	// uppercase ASCII letter.
	br := bufio.NewReader(clientConn)
	_ = clientConn.SetReadDeadline(time.Now().Add(10 * time.Second))
	first, err := br.Peek(1)
	_ = clientConn.SetReadDeadline(time.Time{})
	if err != nil {
		p.logger.Warn("mitm tunnel peek failed", "host", host, "err", err.Error())
		_ = clientConn.Close()
		return
	}
	tunnel := &prefixedConn{Conn: clientConn, r: br}

	// Cleartext inside the tunnel ⟹ the upstream is plain http://; serve it
	// directly without terminating TLS. forwardRequest picks the same scheme
	// via useTLSUpstream, so the outbound leg stays http as well.
	if first[0] != tlsRecordTypeHandshake {
		p.serveTunnel(tunnel, target, host, port, false, scope)
		return
	}

	tlsConf := &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			sni := hello.ServerName
			if sni == "" {
				sni = host
			}
			return p.ca.MintLeaf(sni)
		},
	}

	tlsConn := tls.Server(tunnel, tlsConf)
	_ = tlsConn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := tlsConn.Handshake(); err != nil {
		// err may carry TLS alert detail from the client — diagnostic, not secret.
		p.logger.Warn("mitm TLS handshake failed", "host", host, "err", err.Error())
		_ = tlsConn.Close()
		return
	}
	_ = tlsConn.SetDeadline(time.Time{})

	p.serveTunnel(tlsConn, target, host, port, true, scope)
}

// tlsRecordTypeHandshake is the TLS record content type for a handshake
// (RFC 8446 §5.1). It is the first byte of a ClientHello and never a valid
// leading byte of an HTTP request line, which distinguishes a TLS tunnel
// from a cleartext one.
const tlsRecordTypeHandshake = 0x16

// serveTunnel serves HTTP/1.1 requests off an established tunnel connection —
// either a terminated TLS conn or a cleartext one. useTLSUpstream selects the
// scheme forwardRequest uses for the upstream leg (https for a TLS tunnel,
// http for a cleartext one). The one-shot listener yields conn once, then
// blocks until Close so http.Serve stays alive while the connection goroutine
// is active; ConnState closes the listener once the connection leaves the
// hijacked state so Serve returns.
func (p *Proxy) serveTunnel(conn net.Conn, target, host string, port int, useTLSUpstream bool, scope *brokercore.ProxyScope) {
	listener := newOneShotListener(conn)
	srv := &http.Server{
		Handler: p.forwardHandler(target, host, port, useTLSUpstream, scope),
		// ReadHeaderTimeout and ReadTimeout bound the request side
		// (slow-loris defense). IdleTimeout caps keep-alives between
		// requests. The upstream transport's ResponseHeaderTimeout
		// (5 min) prevents stalled upstreams. WriteTimeout is 30 min
		// to allow long-running streaming transfers (git clone, SSE).
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      30 * time.Minute,
		IdleTimeout:       2 * time.Minute,
		ConnState: func(c net.Conn, state http.ConnState) {
			// Either terminal state means Serve should return. The
			// underlying conn is owned by http.Server (Closed) or by
			// the hijack handler (Hijacked); we must not close it here.
			if state == http.StateHijacked || state == http.StateClosed {
				_ = listener.Close()
			}
		},
	}
	_ = srv.Serve(listener)
}

// prefixedConn is a net.Conn whose Read draws from a bufio.Reader wrapping
// the underlying conn, so bytes Peeked before the conn is handed to
// tls.Server / http.Server are not lost. All other methods (Write, Close,
// deadlines) delegate to the embedded conn.
type prefixedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *prefixedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// recordAuthFailure records one auth-failure event against the per-IP
// TierAuth budget so the read-only pre-gate in handleConnect /
// handleForward will reject subsequent requests once the budget is
// exhausted. Only called on auth failure — successful requests skip
// TierAuth entirely (TierProxy covers them). Loopback peers are exempt.
func (p *Proxy) recordAuthFailure(r *http.Request) {
	if p.rateLimit != nil && !isLoopbackPeer(r) {
		p.rateLimit.Allow(ratelimit.TierAuth, mitmIPKey(r))
	}
}

// writeProxyAuthChallenge writes a 407 with a Proxy-Authenticate header so
// well-behaved clients re-issue the CONNECT with credentials.
func writeProxyAuthChallenge(w http.ResponseWriter, msg string) {
	w.Header().Set("Proxy-Authenticate", `Basic realm="agent-vault"`)
	http.Error(w, msg, http.StatusProxyAuthRequired)
}

// writeAuthError maps a brokercore session-resolution error to an HTTP
// response. All writes happen before the connection is hijacked.
func writeAuthError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, brokercore.ErrInvalidSession):
		writeProxyAuthChallenge(w, "invalid or expired session")
	case errors.Is(err, brokercore.ErrAgentVaultAmbiguous),
		errors.Is(err, brokercore.ErrNoVaultContext):
		http.Error(w, "set vault via HTTPS_PROXY=http://<token>:<vault>@host:port", http.StatusBadRequest)
	case errors.Is(err, brokercore.ErrVaultHintMismatch),
		errors.Is(err, brokercore.ErrVaultAccessDenied):
		http.Error(w, "forbidden", http.StatusForbidden)
	case errors.Is(err, brokercore.ErrVaultNotFound):
		http.Error(w, "vault not found", http.StatusNotFound)
	default:
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

// isValidHost is a local alias for brokercore.IsValidHost so existing
// callers and the #nosec G706 justification below stay readable.
func isValidHost(h string) bool { return brokercore.IsValidHost(h) }

// oneShotListener yields a single net.Conn to http.Serve, then blocks
// Accept until Close so Serve stays alive while the connection goroutine
// handles requests.
type oneShotListener struct {
	conn   net.Conn
	yield  chan net.Conn
	closed chan struct{}
}

func newOneShotListener(c net.Conn) *oneShotListener {
	l := &oneShotListener{
		conn:   c,
		yield:  make(chan net.Conn, 1),
		closed: make(chan struct{}),
	}
	l.yield <- c
	return l
}

var errListenerClosed = errors.New("mitm: one-shot listener closed")

func (l *oneShotListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.yield:
		return c, nil
	case <-l.closed:
		return nil, errListenerClosed
	}
}

func (l *oneShotListener) Close() error {
	select {
	case <-l.closed:
	default:
		close(l.closed)
	}
	return nil
}

func (l *oneShotListener) Addr() net.Addr { return l.conn.LocalAddr() }
