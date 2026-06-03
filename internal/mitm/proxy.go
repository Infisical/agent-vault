// Package mitm implements an HTTP/1.1 forward-proxy ingress for agent
// traffic.
//
// A Proxy accepts two request shapes on the same listener:
//
//   - CONNECT host:port — for HTTPS upstreams. The proxy hijacks the
//     connection, terminates client-side TLS using a leaf minted on
//     demand by a ca.Provider, and forwards each tunnelled HTTP/1.1
//     request to the originally-requested upstream over a fresh TLS
//     connection with strict verification against the system trust
//     store.
//
//   - Absolute-form forward-proxy requests (e.g. POST http://host/path
//     HTTP/1.1, RFC 7230 §5.3.2) — for plain-HTTP upstreams. The proxy
//     authenticates the request inline (no hijack), forwards the body
//     to the upstream over plain HTTP, and applies the same credential
//     injection, host policy, and request logging as the CONNECT path.
//
// The listener is plain HTTP (standard forward-proxy convention).
// Clients use HTTPS_PROXY and HTTP_PROXY pointing at http://... and
// trust the CA that signs the per-host MITM leaves for upstream
// certificate verification.
//
// v1 scope: HTTP/1.1 only (ALPN pinned). HTTPS upstreams must use
// CONNECT — the forward-proxy path rejects https:// URLs to avoid
// silently TLS-stripping.
package mitm

import (
	"context"
	"log/slog"
	"crypto/tls"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/ca"
	"github.com/Infisical/agent-vault/internal/netguard"
	"github.com/Infisical/agent-vault/internal/ratelimit"
	"github.com/Infisical/agent-vault/internal/requestlog"
)

// Proxy is a transparent MITM proxy. It is safe to start at most once;
// reuse across Shutdown is not supported.
type Proxy struct {
	ca               ca.Provider
	sessions         brokercore.SessionResolver
	creds            brokercore.CredentialProvider
	httpServer       *http.Server
	upstream         *http.Transport
	isListening      atomic.Bool
	baseURL          string // externally-reachable control-plane URL for help links
	logger           *slog.Logger
	rateLimit        *ratelimit.Registry // shared with the HTTP server; nil = no-op
	logSink          requestlog.Sink     // never nil (Nop default); shared with the HTTP server
	maxResponseBytes int64               // 0 = unlimited
	maxRequestBytes  int64
}

// Options carries the dependencies a Proxy needs. BaseURL is the
// externally-reachable control-plane URL used in help-link error
// responses. Logger must be non-nil; tests can pass
// slog.New(slog.DiscardHandler). RateLimit is shared with the HTTP
// server so proxy limits and control-plane limits live in one registry;
// nil disables rate limiting on the MITM path.
type Options struct {
	CA               ca.Provider
	Sessions         brokercore.SessionResolver
	Credentials      brokercore.CredentialProvider
	BaseURL          string
	Logger           *slog.Logger
	RateLimit        *ratelimit.Registry
	LogSink          requestlog.Sink // nil → Nop
	MaxResponseBytes int64           // 0 = unlimited (default); >0 = cap in bytes
	MaxRequestBytes  int64           // 0 → DefaultMaxRequestBytes (1 GiB)
}

// New builds a Proxy bound to addr. The returned Proxy does not begin
// listening until ListenAndServe is called.
func New(addr string, opts Options) *Proxy {
	upstream := &http.Transport{
		DialContext:           netguard.SafeDialContext(netguard.AllowPrivateFromEnv()),
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 5 * time.Minute,
	}

	sink := opts.LogSink
	if sink == nil {
		sink = requestlog.Nop{}
	}

	maxReq := opts.MaxRequestBytes
	if maxReq <= 0 {
		maxReq = brokercore.DefaultMaxRequestBytes
	}

	p := &Proxy{
		ca:               opts.CA,
		sessions:         opts.Sessions,
		creds:            opts.Credentials,
		upstream:         upstream,
		baseURL:          opts.BaseURL,
		logger:           opts.Logger,
		rateLimit:        opts.RateLimit,
		logSink:          sink,
		maxResponseBytes: opts.MaxResponseBytes, // 0 = unlimited
		maxRequestBytes:  maxReq,
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

// Serve accepts connections on the provided listener. The listener
// itself is plain HTTP (standard forward-proxy convention); TLS is
// only used inside CONNECT tunnels where the MITM presents a leaf
// cert to the client. It blocks until Shutdown is called, returning
// http.ErrServerClosed in that case.
// Useful for tests that need to bind :0 and learn the resulting port.
func (p *Proxy) Serve(l net.Listener) error {
	p.isListening.Store(true)
	defer p.isListening.Store(false)
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
	if isAbsoluteForwardProxyRequest(r) {
		p.handleForward(w, r)
		return
	}
	// Origin-form (no scheme/host), https://, ws://, file://, gopher://,
	// etc. all land here. The CONNECT-vs-forward split above already
	// covers every legitimate forward-proxy shape; anything else is a
	// malformed request, not a method-not-allowed.
	http.Error(w, "this endpoint is an HTTP forward proxy; non-CONNECT requests must use absolute-form URLs (http://host/path). Use CONNECT for https:// upstreams.", http.StatusBadRequest)
}
