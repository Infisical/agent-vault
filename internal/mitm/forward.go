package mitm

import (
	"errors"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/ratelimit"
)

// forwardHandler returns an http.Handler that forwards each request to
// target (the host:port captured from the original CONNECT line). Using
// a closed-over target rather than r.Host defeats post-tunnel host
// rewriting. host is the port-stripped form, already validated in
// handleConnect; scope is the vault context resolved at CONNECT time.
func (p *Proxy) forwardHandler(target, host string, scope *brokercore.ProxyScope) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		event := brokercore.ProxyEvent{
			Ingress: "mitm",
			Method:  r.Method,
			Host:    target,
			Path:    r.URL.Path,
		}
		emit := func(status int, errCode string) {
			event.Emit(p.logger, start, status, errCode)
		}

		// Shares one budget with /proxy so switching ingress can't bypass.
		enf := p.rateLimit.EnforceProxy(r.Context(), scope.ActorID(), scope.VaultID)
		if !enf.Allowed {
			ratelimit.WriteDenial(w, enf.Decision, enf.Message)
			emit(http.StatusTooManyRequests, enf.ErrCode)
			return
		}
		defer enf.Release()

		r.Body = http.MaxBytesReader(w, r.Body, brokercore.MaxProxyBodyBytes)

		outURL := &url.URL{
			Scheme:   "https",
			Host:     target,
			Path:     r.URL.Path,
			RawPath:  r.URL.RawPath,
			RawQuery: r.URL.RawQuery,
		}

		outReq, err := http.NewRequestWithContext(r.Context(), r.Method, outURL.String(), r.Body)
		if err != nil {
			http.Error(w, "bad gateway", http.StatusBadGateway)
			emit(http.StatusBadGateway, "internal")
			return
		}
		outReq.Host = host

		inject, err := p.creds.Inject(r.Context(), scope.VaultID, host)
		if inject != nil {
			event.MatchedService = inject.MatchedHost
			event.CredentialKeys = inject.CredentialKeys
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

		// No extraStrip: Proxy-Authorization (the broker-scoped credential
		// on this ingress) is already filtered by the denylist, and
		// Authorization is the client's own upstream header.
		brokercore.ApplyInjection(r.Header, outReq.Header, inject)

		resp, err := p.upstream.RoundTrip(outReq)
		if err != nil {
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
		_, _ = io.Copy(w, io.LimitReader(resp.Body, brokercore.MaxResponseBytes))
		emit(resp.StatusCode, "")
	})
}
