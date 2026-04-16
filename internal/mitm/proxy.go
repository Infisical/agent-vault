// Package mitm implements a transparent TLS-intercepting HTTP proxy.
//
// A Proxy accepts HTTP CONNECT on a plain TCP listener, hijacks the
// connection, terminates client-side TLS using a certificate minted on
// demand by a ca.Provider, and forwards each HTTP/1.1 request to the
// originally-requested upstream over a fresh TLS connection with strict
// verification against the system trust store.
//
// v1 scope: HTTP/1.1 only (ALPN pinned), no credential injection, no
// audit hooks. These are the next steps of the transparent-proxy
// initiative; this package is deliberately shaped so they plug in at
// well-defined points (forwardHandler in forward.go).
package mitm

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/Infisical/agent-vault/internal/ca"
	"github.com/Infisical/agent-vault/internal/netguard"
)

// Proxy is a transparent MITM proxy. It is safe to start at most once;
// reuse across Shutdown is not supported.
type Proxy struct {
	ca         ca.Provider
	httpServer *http.Server
	upstream   *http.Transport
}

// New builds a Proxy bound to addr using caProv for leaf certificates.
// The returned Proxy does not begin listening until ListenAndServe is
// called.
func New(addr string, caProv ca.Provider) *Proxy {
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
		upstream: upstream,
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

// ListenAndServe starts accepting connections. It blocks until Shutdown
// is called, returning http.ErrServerClosed in that case.
func (p *Proxy) ListenAndServe() error {
	return p.httpServer.ListenAndServe()
}

// Serve accepts connections on the provided listener. It blocks until
// Shutdown is called, returning http.ErrServerClosed in that case.
// Useful for tests that need to bind :0 and learn the resulting port.
func (p *Proxy) Serve(l net.Listener) error {
	return p.httpServer.Serve(l)
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
