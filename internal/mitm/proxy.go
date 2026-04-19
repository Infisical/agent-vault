// Package mitm implements a transparent TLS-intercepting HTTP proxy.
//
// A Proxy accepts HTTP CONNECT on a TLS-encrypted listener, hijacks the
// connection, terminates client-side TLS using a certificate minted on
// demand by a ca.Provider, and forwards each HTTP/1.1 request to the
// originally-requested upstream over a fresh TLS connection with strict
// verification against the system trust store.
//
// The listener itself is TLS-wrapped so that the CONNECT handshake
// (which carries session tokens in Proxy-Authorization) is encrypted.
// Clients use HTTPS_PROXY=https://... and trust the same CA that signs
// the per-host MITM leaves.
//
// v1 scope: HTTP/1.1 only (ALPN pinned).
package mitm

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/ca"
	"github.com/Infisical/agent-vault/internal/netguard"
)

// Proxy is a transparent MITM proxy. It is safe to start at most once;
// reuse across Shutdown is not supported.
type Proxy struct {
	ca          ca.Provider
	sessions    brokercore.SessionResolver
	creds       brokercore.CredentialProvider
	httpServer  *http.Server
	tlsConfig   *tls.Config
	upstream    *http.Transport
	isListening atomic.Bool
	baseURL     string // externally-reachable control-plane URL for help links
	logger      *slog.Logger
}

// New builds a Proxy bound to addr using caProv for leaf certificates and
// the brokercore sessions/creds for authentication and credential injection.
// baseURL is the externally-reachable control-plane URL (e.g.
// "http://127.0.0.1:14321") used to build help links in error responses.
// The returned Proxy does not begin listening until ListenAndServe is
// called. logger must be non-nil; tests can pass slog.New(slog.DiscardHandler).
func New(addr string, caProv ca.Provider, sessions brokercore.SessionResolver, creds brokercore.CredentialProvider, baseURL string, logger *slog.Logger) *Proxy {
	upstream := &http.Transport{
		DialContext:           netguard.SafeDialContext(netguard.ModeFromEnv()),
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
	}

	p := &Proxy{
		ca:       caProv,
		sessions: sessions,
		creds:    creds,
		upstream: upstream,
		baseURL:  baseURL,
		logger:   logger,
	}

	p.tlsConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			sni := hello.ServerName
			if sni == "" {
				// No SNI (IP-literal connection per RFC 6066). Use the
				// actual local address the client connected to so the
				// cert SAN matches regardless of IPv4/IPv6 or which
				// interface was used on a wildcard bind.
				if host, _, err := net.SplitHostPort(hello.Conn.LocalAddr().String()); err == nil && host != "" {
					sni = host
				} else {
					sni = "127.0.0.1"
				}
			}
			return caProv.MintLeaf(sni)
		},
	}

	p.httpServer = &http.Server{
		Addr:              addr,
		Handler:           http.HandlerFunc(p.dispatch),
		ReadHeaderTimeout: 10 * time.Second,
	}
	return p
}

// Addr returns the listener address the Proxy was configured with.
func (p *Proxy) Addr() string { return p.httpServer.Addr }

// RootPEM returns the root CA certificate in PEM form. Safe for public
// distribution — clients install this into trust stores to validate the
// leaves minted on demand during CONNECT.
func (p *Proxy) RootPEM() []byte { return p.ca.RootPEM() }

// IsListening reports whether the Proxy has successfully bound its
// listener and is accepting connections. Callers that gate operator-
// visible behavior (like advertising the root CA) on proxy reachability
// should check this rather than nil-checking the Proxy itself — a bind
// failure leaves the Proxy value alive but unreachable.
func (p *Proxy) IsListening() bool { return p.isListening.Load() }

// ListenAndServe starts accepting connections. It binds the listener
// eagerly so callers can detect bind failures; on success, IsListening
// reports true for the lifetime of the accept loop. Blocks until
// Shutdown, returning http.ErrServerClosed in that case.
func (p *Proxy) ListenAndServe() error {
	l, err := net.Listen("tcp", p.httpServer.Addr)
	if err != nil {
		return err
	}
	return p.Serve(l)
}

// Serve accepts connections on the provided listener, wrapping it in
// TLS so the CONNECT handshake is encrypted. It blocks until Shutdown
// is called, returning http.ErrServerClosed in that case.
// Useful for tests that need to bind :0 and learn the resulting port.
func (p *Proxy) Serve(l net.Listener) error {
	p.isListening.Store(true)
	defer p.isListening.Store(false)
	return p.httpServer.Serve(tls.NewListener(l, p.tlsConfig))
}

// Shutdown gracefully stops the listener. In-flight CONNECT tunnels are
// not tracked by http.Server's shutdown machinery (they detach from the
// handler on Hijack), so callers should allow the process to exit after
// Shutdown returns; the tunnels will die with it.
func (p *Proxy) Shutdown(ctx context.Context) error {
	p.upstream.CloseIdleConnections()
	return p.httpServer.Shutdown(ctx)
}

func (p *Proxy) dispatch(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
		return
	}
	http.Error(w, fmt.Sprintf("method %s not supported on transparent proxy", r.Method), http.StatusMethodNotAllowed)
}
