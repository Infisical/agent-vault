package mitm

import (
	"context"
	"encoding/base64"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/Infisical/agent-vault/internal/broker"
	"github.com/Infisical/agent-vault/internal/brokercore"
)

// forwardFilter reverse-proxies the live request to the sidecar. The sidecar
// is the origin server for this hop. No destination credential is resolved.
func (p *Proxy) forwardFilter(
	w http.ResponseWriter,
	r *http.Request,
	scope *brokercore.ProxyScope,
	svc broker.Service,
	scheme, authority string,
	emit func(status int, errCode string),
) {
	if svc.Filter == nil || svc.Filter.URL == "" || p.hop == nil || p.filterProxyURL == "" {
		brokercore.WriteProxyError(w, http.StatusBadGateway, "filter_misconfigured",
			"The matched service has a filter but the proxy cannot run it.")
		emit(http.StatusBadGateway, "filter_misconfigured")
		return
	}
	target, err := url.Parse(svc.Filter.URL)
	if err != nil || target.Host == "" {
		brokercore.WriteProxyError(w, http.StatusBadGateway, "filter_misconfigured",
			"The matched service filter URL is not usable.")
		emit(http.StatusBadGateway, "filter_misconfigured")
		return
	}
	transport, err := filterTransport(svc.Filter)
	if err != nil {
		brokercore.WriteProxyError(w, http.StatusBadGateway, "filter_misconfigured",
			"The matched service filter is not usable.")
		emit(http.StatusBadGateway, "filter_misconfigured")
		return
	}
	defer transport.CloseIdleConnections()
	bind := brokercore.HopBind{
		Method:    r.Method,
		Scheme:    scheme,
		Authority: authority,
		Path:      escapedPath(r.URL),
		Query:     r.URL.RawQuery,
	}
	cont, policy, err := p.hop.Mint(r.Context(), brokercore.HopMintInput{
		SourceVaultID: scope.VaultID,
		ActorID:       scope.ActorID(),
		Bind:          bind,
		Service:       svc,
		PolicyVault:   svc.Filter.PolicyVault,
	})
	if err != nil {
		code := "filter_unreachable"
		status := http.StatusBadGateway
		if errors.Is(err, brokercore.ErrFilterMisconfigured) {
			code = "filter_misconfigured"
		}
		brokercore.WriteProxyError(w, status, code, "The filter hop could not be started.")
		emit(status, code)
		return
	}

	original := &url.URL{Scheme: scheme, Host: authority, Path: r.URL.Path, RawPath: r.URL.RawPath, RawQuery: r.URL.RawQuery}
	inHost := r.Host
	hopStatus := http.StatusBadGateway
	hopErr := ""
	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			if inHost != "" {
				pr.Out.Host = inHost
			}
			prepareSidecarRequest(pr.Out, svc, p.filterProxyURL, original.String(), cont, policy, p.caPEM())
		},
		Transport: transport,
		ModifyResponse: func(resp *http.Response) error {
			hopStatus = resp.StatusCode
			stripFilterResponseHeaders(resp.Header, resp.StatusCode)
			return nil
		},
		ErrorHandler: func(rw http.ResponseWriter, _ *http.Request, err error) {
			status, code := filterDialError(err)
			hopStatus = status
			hopErr = code
			brokercore.WriteProxyError(rw, status, code, "The filter sidecar did not complete the hop.")
		},
		FlushInterval: -1,
	}
	proxy.ServeHTTP(w, r)
	if p.logger != nil {
		p.logger.Debug("filter hop",
			slog.String("service", svc.Name),
			slog.String("host", svc.Host),
			slog.String("path", svc.Path),
		)
	}
	emit(hopStatus, hopErr)
}

func (p *Proxy) caPEM() string {
	if p.ca == nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(p.ca.RootPEM())
}

func prepareSidecarRequest(out *http.Request, svc broker.Service, proxyURL, original, cont, policy, caPEM string) {
	stripSidecarRequestHeaders(out.Header, svc.Auth)
	out.Header.Set("X-Agent-Vault-Original-URL", original)
	out.Header.Set("X-Agent-Vault-Continuation-Proxy", proxyURL)
	out.Header.Set("X-Agent-Vault-Continuation-Token", cont)
	if policy != "" {
		out.Header.Set("X-Agent-Vault-Policy-Proxy", proxyURL)
		out.Header.Set("X-Agent-Vault-Policy-Token", policy)
	}
	if caPEM != "" {
		out.Header.Set("X-Agent-Vault-CA", caPEM)
	}
	if svc.Name != "" {
		out.Header.Set("X-Agent-Vault-Service", svc.Name)
	}
}

func stripSidecarRequestHeaders(h http.Header, auth broker.Auth) {
	for _, name := range broker.CredentialHeaderNames(auth) {
		h.Del(name)
	}
	h.Del("Proxy-Authorization")
	h.Del("X-Vault")
	for name := range h {
		if !brokercore.IsHopByHop(name) {
			continue
		}
		// The sidecar hop must keep the WebSocket upgrade headers.
		if strings.EqualFold(name, "Upgrade") || strings.EqualFold(name, "Connection") {
			continue
		}
		h.Del(name)
	}
	stripAgentVaultHeaders(h)
}

func stripAgentVaultHeaders(h http.Header) {
	for name := range h {
		if strings.HasPrefix(http.CanonicalHeaderKey(name), "X-Agent-Vault-") {
			h.Del(name)
		}
	}
}

func stripFilterResponseHeaders(h http.Header, status int) {
	var upgrade, connection []string
	if status == http.StatusSwitchingProtocols {
		upgrade = append([]string(nil), h.Values("Upgrade")...)
		connection = append([]string(nil), h.Values("Connection")...)
	}
	stripReservedResponseHeaders(h)
	if status != http.StatusSwitchingProtocols {
		return
	}
	h.Del("Upgrade")
	h.Del("Connection")
	for _, v := range upgrade {
		h.Add("Upgrade", v)
	}
	for _, v := range connection {
		h.Add("Connection", v)
	}
}

func stripReservedResponseHeaders(h http.Header) {
	stripAgentVaultHeaders(h)
	h.Del("Proxy-Authorization")
	h.Del("X-Vault")
	for name := range h {
		if brokercore.ShouldStripResponseHeader(name) {
			h.Del(name)
		}
	}
}

func filterDialError(err error) (int, string) {
	if err == nil {
		return http.StatusBadGateway, "filter_unreachable"
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return http.StatusGatewayTimeout, "filter_timeout"
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return http.StatusGatewayTimeout, "filter_timeout"
	}
	msg := err.Error()
	if strings.Contains(msg, "Timeout") || strings.Contains(msg, "timeout") {
		return http.StatusGatewayTimeout, "filter_timeout"
	}
	return http.StatusBadGateway, "filter_unreachable"
}

func escapedPath(u *url.URL) string {
	if u == nil {
		return ""
	}
	if u.RawPath != "" {
		return u.RawPath
	}
	return u.EscapedPath()
}
