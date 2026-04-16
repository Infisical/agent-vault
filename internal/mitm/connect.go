package mitm

import (
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

// handleConnect terminates a CONNECT tunnel and serves HTTP/1.1 off the
// resulting TLS connection. The upstream target is taken from the
// CONNECT request line (r.Host) and captured in a closure so subsequent
// Host-header rewrites by the client cannot redirect the tunnel.
func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	target := r.Host
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		http.Error(w, "CONNECT target must be host:port", http.StatusBadRequest)
		return
	}
	if !isValidHost(host) {
		http.Error(w, "invalid host", http.StatusBadRequest)
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

	tlsConn := tls.Server(clientConn, tlsConf)
	_ = tlsConn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := tlsConn.Handshake(); err != nil {
		log.Printf("mitm: TLS handshake failed for %s: %v", host, err) // #nosec G706 -- host passes isValidHost, which rejects control chars and path separators
		_ = tlsConn.Close()
		return
	}
	_ = tlsConn.SetDeadline(time.Time{})

	// Serve HTTP/1.1 requests off the terminated TLS connection. The
	// listener yields the connection once, then blocks until Close so
	// http.Serve stays alive while the connection goroutine is active.
	// ConnState tracks when the connection leaves the hijacked state and
	// closes the listener so Serve returns.
	listener := newOneShotListener(tlsConn)
	srv := &http.Server{
		Handler:           p.forwardHandler(target),
		ReadHeaderTimeout: 10 * time.Second,
		ConnState: func(c net.Conn, state http.ConnState) {
			if state == http.StateClosed || state == http.StateHijacked {
				_ = listener.Close()
			}
		},
	}
	_ = srv.Serve(listener)
}

func isValidHost(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	for _, c := range h {
		if c == '@' || c == '?' || c == '#' || c == '/' || c == '\\' || c == ' ' || c == '%' || c < 0x20 || c == 0x7f {
			return false
		}
	}
	return !strings.HasPrefix(h, ".") && !strings.HasSuffix(h, ".")
}

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
	return l.conn.Close()
}

func (l *oneShotListener) Addr() net.Addr { return l.conn.LocalAddr() }
