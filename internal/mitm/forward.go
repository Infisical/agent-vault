package mitm

import (
	"io"
	"net"
	"net/http"
	"net/url"
)

// maxResponseBytes caps the body returned to the client. Matches the
// limit used by the existing /proxy handler; credential injection work
// in the next step should consolidate both constants.
const maxResponseBytes = 100 << 20

// hopByHopHeaders are HTTP/1.1 hop-by-hop headers that must not be
// forwarded by a proxy. Duplicated from internal/server to avoid a
// dependency cycle; if credential injection unifies both paths into a
// shared package, this should be pulled up alongside it.
var hopByHopHeaders = map[string]bool{
	"Connection":          true,
	"Keep-Alive":          true,
	"Proxy-Authenticate":  true,
	"Proxy-Authorization": true,
	"Te":                  true,
	"Trailer":             true,
	"Transfer-Encoding":   true,
	"Upgrade":             true,
}

// forwardHandler returns an http.Handler that forwards each request to
// target (the host:port captured from the original CONNECT line). Using
// a closed-over target rather than r.Host defeats post-tunnel host
// rewriting.
func (p *Proxy) forwardHandler(target string) http.Handler {
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
		if h, _, splitErr := net.SplitHostPort(target); splitErr == nil {
			outReq.Host = h
		} else {
			outReq.Host = target
		}
		copyRequestHeaders(outReq.Header, r.Header)

		resp, err := p.upstream.RoundTrip(outReq)
		if err != nil {
			http.Error(w, "bad gateway", http.StatusBadGateway)
			return
		}
		defer func() { _ = resp.Body.Close() }()

		for k, vv := range resp.Header {
			if hopByHopHeaders[http.CanonicalHeaderKey(k)] {
				continue
			}
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, io.LimitReader(resp.Body, maxResponseBytes))
	})
}

func copyRequestHeaders(dst, src http.Header) {
	for k, vv := range src {
		if hopByHopHeaders[http.CanonicalHeaderKey(k)] {
			continue
		}
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}
