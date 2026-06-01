package mitm

import (
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/ratelimit"
	"github.com/Infisical/agent-vault/internal/requestlog"
)

// actorFromScope returns the (type, id) pair used in request log rows.
// Empty strings when neither principal is set on the scope.
func actorFromScope(scope *brokercore.ProxyScope) (string, string) {
	if scope == nil {
		return "", ""
	}
	if scope.UserID != "" {
		return brokercore.ActorTypeUser, scope.UserID
	}
	if scope.AgentID != "" {
		return brokercore.ActorTypeAgent, scope.AgentID
	}
	return "", ""
}

// isAbsoluteForwardProxyRequest reports whether r is a well-formed
// absolute-form forward-proxy request that handleForward can serve.
//
// Per RFC 7230 §5.3.2 a forward-proxy request looks like:
//
//	POST http://upstream.example/path HTTP/1.1
//
// We accept only http://. https:// is rejected because we will not
// silently TLS-strip — clients must use CONNECT for HTTPS upstreams.
// Origin-form (POST /path) lacks a scheme/host and is rejected so the
// proxy ingress can never be used as if it were an origin server.
// Other schemes (ws, ftp, file, gopher, …) are rejected likewise.
func isAbsoluteForwardProxyRequest(r *http.Request) bool {
	if r.URL == nil {
		return false
	}
	if !strings.EqualFold(r.URL.Scheme, "http") {
		return false
	}
	if r.URL.Host == "" {
		return false
	}
	// url.ParseRequestURI rejects fragments in the request line, but be
	// belt-and-braces — RFC 7230 §5.3.2 forbids them.
	if r.URL.Fragment != "" {
		return false
	}
	return true
}

// handleForward serves an absolute-form forward-proxy request for an
// http:// upstream. Compared to the CONNECT path: no hijack (the
// response is a normal HTTP/1.1 reply over the existing connection),
// and the scope is resolved per request rather than once
// per tunnel.
func (p *Proxy) handleForward(w http.ResponseWriter, r *http.Request) {
	// Per-IP flood gate before ParseProxyAuth + session lookup so a
	// bad-auth flood can't burn CPU. Loopback is exempt — see
	// isLoopbackPeer. Shares the TierAuth budget and key shape with
	// CONNECT: one peer = one budget regardless of ingress shape.
	if p.rateLimit != nil && !isLoopbackPeer(r) {
		if d := p.rateLimit.Allow(ratelimit.TierAuth, mitmIPKey(r)); !d.Allow {
			ratelimit.WriteDenial(w, d, "Too many proxy requests")
			return
		}
	}

	// Canonicalise host and target. URL.Hostname() strips brackets from
	// IPv6 literals; URL.Port() returns "" when omitted. Default port to
	// 80 (http scheme) so event.Host and outURL.Host stay consistent
	// with the CONNECT-path invariant ("host:port present"). Going
	// through Hostname()/Port() rather than net.SplitHostPort is what
	// makes "http://[::1]/path" round-trip cleanly — SplitHostPort
	// rejects bracketed hosts without a port and the fallback path
	// would feed a still-bracketed string back through JoinHostPort,
	// double-bracketing it.
	host := r.URL.Hostname()
	port := r.URL.Port()
	if port == "" {
		port = "80"
	}
	target := net.JoinHostPort(host, port)

	if !isValidHost(host) {
		http.Error(w, "invalid host", http.StatusBadRequest)
		return
	}

	// Some upstreams reject empty request-targets. Per RFC 7230 §5.3.1
	// a client SHOULD send "/" when no path is present; normalise so
	// the outbound URL we build always has one.
	if r.URL.Path == "" {
		r.URL.Path = "/"
	}

	// Per RFC 7230 §5.4 a proxy receiving an absolute-form request MUST
	// ignore the Host header — r.URL.Host is authoritative. We don't
	// reject on mismatch; we just don't read r.Host for routing.

	token, hint, err := brokercore.ParseProxyAuth(r)
	if err != nil {
		writeProxyAuthChallenge(w, "Proxy-Authorization required")
		return
	}
	scope, err := p.sessions.ResolveForProxy(r.Context(), token, hint)
	if err != nil {
		writeAuthError(w, err)
		return
	}

	p.forwardRequest(w, r, target, host, false, scope)
}

// hostHeaderForScheme strips target's port when it matches the default for
// scheme so SigV4/GCS/Azure-SAS signatures over Host match; non-default
// ports are preserved for vhost routing on internal upstreams.
func hostHeaderForScheme(scheme, target string) string {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return target
	}
	var defaultPort string
	switch strings.ToLower(scheme) {
	case "https":
		defaultPort = "443"
	case "http":
		defaultPort = "80"
	default:
		return target
	}
	if port != defaultPort {
		return target
	}
	if strings.ContainsRune(host, ':') {
		return "[" + host + "]"
	}
	return host
}

// forwardHandler returns an http.Handler that forwards each request to
// target (the host:port captured from the original CONNECT line). Using
// a closed-over target rather than r.Host defeats post-tunnel host
// rewriting. host is the port-stripped form, already validated in
// handleConnect; scope is the vault context resolved at CONNECT time.
func (p *Proxy) forwardHandler(target, host string, scope *brokercore.ProxyScope) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.forwardRequest(w, r, target, host, true, scope)
	})
}

// forwardRequest is the shared body for both the CONNECT-tunnelled HTTPS
// path (forwardHandler) and the plain-HTTP forward-proxy path
// (handleForward). target is the canonical "host:port"; host is the
// port-stripped form used for credential lookup. useTLSUpstream selects
// https vs http for the outbound URL.
func (p *Proxy) forwardRequest(
	w http.ResponseWriter,
	r *http.Request,
	target, host string,
	useTLSUpstream bool,
	scope *brokercore.ProxyScope,
) {
	start := time.Now()
	event := brokercore.ProxyEvent{
		Ingress: brokercore.IngressMITM,
		Method:  r.Method,
		Host:    target,
		Path:    r.URL.Path,
	}
	actorType, actorID := actorFromScope(scope)
	emit := func(status int, errCode string) {
		event.Emit(p.logger, start, status, errCode)
		p.logSink.Record(r.Context(), requestlog.FromEvent(event, scope.VaultID, actorType, actorID))
	}

	enf := p.rateLimit.EnforceProxy(r.Context(), scope.ActorID(), scope.VaultID)
	if !enf.Allowed {
		ratelimit.WriteDenial(w, enf.Decision, enf.Message)
		emit(http.StatusTooManyRequests, enf.ErrCode)
		return
	}
	defer enf.Release()

	r.Body = http.MaxBytesReader(w, r.Body, brokercore.MaxProxyBodyBytes)

	scheme := "http"
	if useTLSUpstream {
		scheme = "https"
	}
	outURL := &url.URL{
		Scheme:   scheme,
		Host:     target,
		Path:     r.URL.Path,
		RawPath:  r.URL.RawPath,
		RawQuery: r.URL.RawQuery,
	}

	body, contentLength, err := brokercore.MaterializeRequestBody(r.Body)
	if err != nil {
		status, code := brokercore.RequestBodyErrorCode(err)
		http.Error(w, http.StatusText(status), status)
		emit(status, code)
		return
	}

	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, outURL.String(), body)
	if err != nil {
		http.Error(w, "bad gateway", http.StatusBadGateway)
		emit(http.StatusBadGateway, "internal")
		return
	}
	outReq.Host = hostHeaderForScheme(scheme, target)
	outReq.ContentLength = contentLength

	inject, err := p.creds.Inject(r.Context(), scope.VaultID, host, r.URL.Path)
	if inject != nil {
		event.MatchedService = inject.MatchedName
		event.MatchedHost = inject.MatchedHost
		event.MatchedPath = inject.MatchedPath
		event.CredentialKeys = inject.CredentialKeys
		event.Passthrough = inject.Passthrough
	}
	if err != nil {
		errCode := "no_match"
		status := http.StatusForbidden
		if errors.Is(err, brokercore.ErrCredentialMissing) {
			errCode = "credential_not_found"
			status = http.StatusBadGateway
			brokercore.LogCredentialMissing(p.logger, scope.VaultID, event.MatchedService, event.CredentialKeys)
		}
		brokercore.WriteInjectError(w, err, host, scope.VaultName, p.baseURL)
		emit(status, errCode)
		return
	}

	wsUpgrade := isWebSocketUpgrade(r)

	// WS handshake needs Connection/Upgrade through, but ApplyInjection
	// would drop them as hop-by-hop. Copy the full handshake set
	// manually, then tell ApplyInjection to skip them so the
	// non-hop-by-hop ones (Origin, Sec-*) aren't duplicated. Injection
	// still wins on overlapping names (Authorization etc.) because
	// inject.Headers is Set last by ApplyInjection.
	if wsUpgrade {
		copyWebSocketHandshakeHeaders(r.Header, outReq.Header)
		brokercore.ApplyInjection(r.Header, outReq.Header, inject, websocketHandshakeHeaderNames...)
	} else {
		// No extraStrip: Proxy-Authorization is already in the broker
		// denylist, and Authorization is the client's upstream header.
		brokercore.ApplyInjection(r.Header, outReq.Header, inject)
	}

	// Apply any declared substitutions to the outbound URL and
	// headers. Surfaces not listed in the substitution's `in:` are
	// not scanned — scope is the security boundary.
	if err := brokercore.ApplySubstitutions(outReq.URL, outReq.Header, inject.Substitutions); err != nil {
		http.Error(w, "bad gateway", http.StatusBadGateway)
		emit(http.StatusBadGateway, "substitution_error")
		return
	}

	if wsUpgrade {
		p.forwardWebSocket(w, r, outReq, emit)
		return
	}

	resp, err := p.upstream.RoundTrip(outReq)
	if err != nil {
		// Log the actual error for operators while sending generic message to client.
		p.logger.Debug("upstream request failed",
			slog.String("vault_id", scope.VaultID),
			slog.String("vault_name", scope.VaultName),
			slog.String("target_host", target),
			slog.String("error", err.Error()),
		)
		http.Error(w, "bad gateway", http.StatusBadGateway)
		emit(http.StatusBadGateway, "upstream_error")
		return
	}
	defer func() { _ = resp.Body.Close() }()

	for k, vv := range resp.Header {
		if brokercore.ShouldStripResponseHeader(k) {
			continue
		}
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	// Strip Transfer-Encoding above means the response is delivered to the
	// client via Go's auto-chunking based on what we write here. For
	// non-streaming responses (single JSON body with Content-Length) that's
	// fine — a single Write covers it. For streaming protocols though (git
	// smart-HTTP's sideband pack, SSE, anything that flushes partial bytes
	// upstream), the client needs each upstream chunk to arrive promptly;
	// otherwise the parser hits a stall at end-of-stream and aborts (git:
	// "fatal: early EOF / fetch-pack: invalid index-pack output").
	//
	// Use a periodic flusher (50ms) rather than flushing on every Write:
	// Flush-per-Write is too aggressive — upstream Reads on chunked TLS
	// can return MTU-sized fragments, and a syscall+TLS write per fragment
	// throttles throughput to ~tens of KB/s, slow enough that anything
	// non-trivial (a real git clone) hits the agent's tool timeout long
	// before finishing. 50ms is what httputil.ReverseProxy uses for the
	// same purpose and is below any reasonable parser idle timeout.
	var (
		copied  int64
		copyErr error
	)
	if f, ok := w.(http.Flusher); ok {
		fw := newFlushingWriter(w, f, 50*time.Millisecond)
		copied, copyErr = io.Copy(fw, io.LimitReader(resp.Body, brokercore.MaxResponseBytes))
		fw.Stop() // final Flush + halt the ticker goroutine
	} else {
		copied, copyErr = io.Copy(w, io.LimitReader(resp.Body, brokercore.MaxResponseBytes))
	}
	// Surface upstream body copy errors. A successful HTTP response can
	// still be truncated mid-body if upstream resets or our http.Server
	// fires a deadline — io.Copy returns the partial byte count plus the
	// error, but the client just sees a short HTTP body and is left to
	// puzzle out the cause. Log loudly when it happens.
	if copyErr != nil {
		p.logger.Warn("upstream body copy truncated",
			slog.String("vault_id", scope.VaultID),
			slog.String("vault_name", scope.VaultName),
			slog.String("target_host", target),
			slog.String("path", r.URL.Path),
			slog.Int64("bytes_copied", copied),
			slog.String("upstream_content_length", resp.Header.Get("Content-Length")),
			slog.String("upstream_transfer_encoding", strings.Join(resp.TransferEncoding, ",")),
			slog.String("error", copyErr.Error()),
		)
	} else {
		p.logger.Debug("upstream body copy ok",
			slog.String("target_host", target),
			slog.Int64("bytes_copied", copied),
		)
	}
	emit(resp.StatusCode, "")
}

// flushingWriter forwards Writes to w and asks f to flush on a periodic
// timer (or once at Stop), so upstream byte boundaries propagate to the
// client without the ResponseWriter's default coalescing — but without
// the per-Write Flush cost that throttled real streaming throughput.
// Used for proxying streaming responses (chunked transfers, SSE, git
// sideband). Modeled on net/http/httputil.maxLatencyWriter.
type flushingWriter struct {
	mu       sync.Mutex
	w        io.Writer
	f        http.Flusher
	latency  time.Duration
	t        *time.Timer
	flushPnd bool // a Write happened since the last Flush
	stopped  bool
}

func newFlushingWriter(w io.Writer, f http.Flusher, latency time.Duration) *flushingWriter {
	return &flushingWriter{w: w, f: f, latency: latency}
}

func (fw *flushingWriter) Write(p []byte) (int, error) {
	fw.mu.Lock()
	defer fw.mu.Unlock()
	n, err := fw.w.Write(p)
	if n > 0 {
		fw.flushPnd = true
		if fw.t == nil {
			fw.t = time.AfterFunc(fw.latency, fw.delayedFlush)
		}
	}
	return n, err
}

func (fw *flushingWriter) delayedFlush() {
	fw.mu.Lock()
	defer fw.mu.Unlock()
	if fw.stopped || !fw.flushPnd {
		return
	}
	fw.f.Flush()
	fw.flushPnd = false
	// Reschedule for the next tick; the next Write will reuse this timer
	// (via the nil check) if Writes have stopped.
	fw.t = nil
}

// Stop drains any pending flush and prevents future scheduled flushes.
// Must be called when the copy finishes (success OR error) so the timer
// goroutine doesn't outlive the response.
func (fw *flushingWriter) Stop() {
	fw.mu.Lock()
	defer fw.mu.Unlock()
	fw.stopped = true
	if fw.t != nil {
		fw.t.Stop()
		fw.t = nil
	}
	if fw.flushPnd {
		fw.f.Flush()
		fw.flushPnd = false
	}
}
