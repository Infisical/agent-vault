package mitm

import (
	"io"
	"net/http"
	"net/url"

	"github.com/Infisical/agent-vault/internal/brokercore"
)

// forwardHandler returns an http.Handler that forwards each request to
// target (the host:port captured from the original CONNECT line). Using
// a closed-over target rather than r.Host defeats post-tunnel host
// rewriting. host is the port-stripped form, already validated in
// handleConnect; scope is the vault context resolved at CONNECT time.
func (p *Proxy) forwardHandler(target, host string, scope *brokercore.ProxyScope) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
			return
		}
		outReq.Host = host

		// Allowlist passthrough: Authorization and Proxy-Authorization are
		// not on the list, so injected credentials always win and the
		// client cannot shadow them.
		for _, k := range brokercore.PassthroughHeaders {
			for _, v := range r.Header.Values(k) {
				outReq.Header.Add(k, v)
			}
		}

		inject, err := p.creds.Inject(r.Context(), scope.VaultID, host)
		if err != nil {
			brokercore.WriteInjectError(w, err, host, scope.VaultName)
			return
		}
		for k, v := range inject.Headers {
			outReq.Header.Set(k, v)
		}

		resp, err := p.upstream.RoundTrip(outReq)
		if err != nil {
			http.Error(w, "bad gateway", http.StatusBadGateway)
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
	})
}
