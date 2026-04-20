// Package brokercore is the runtime glue shared by both Agent Vault ingress
// paths: the explicit /proxy HTTP endpoint and the transparent MITM proxy.
//
// It extracts the credential-resolution pipeline from the server handler
// behind a CredentialProvider interface and the session+vault resolution
// behind a SessionResolver interface. Both ingresses call the same code;
// audit hooks will plug in here next.
//
// brokercore depends on broker, store, and crypto. broker stays a pure
// config library with no runtime coupling.
package brokercore

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/Infisical/agent-vault/internal/broker"
)

// MaxResponseBytes caps response bodies streamed back to agents. Shared by
// both ingresses so resource limits are unified.
const MaxResponseBytes = 100 << 20

// ProxyErrorHeader is the response header Agent Vault sets on broker-layer
// error responses so SDK clients can distinguish them from upstream
// responses that happen to share the same status code.
const ProxyErrorHeader = "X-Agent-Vault-Proxy-Error"

// HopByHopHeaders are HTTP/1.1 hop-by-hop headers that must not be
// forwarded by a proxy.
var HopByHopHeaders = map[string]bool{
	"Connection":          true,
	"Keep-Alive":          true,
	"Proxy-Authenticate":  true,
	"Proxy-Authorization": true,
	"Te":                  true,
	"Trailer":             true,
	"Transfer-Encoding":   true,
	"Upgrade":             true,
}

// IsHopByHop reports whether the given header name is hop-by-hop.
func IsHopByHop(name string) bool {
	return HopByHopHeaders[http.CanonicalHeaderKey(name)]
}

// IsValidHost reports whether h is a safe hostname for use in an outbound
// URL or CONNECT target. Rejects characters that could cause URL parsing
// issues (userinfo injection, path separators, whitespace, control chars)
// and enforces DNS length + no leading/trailing dot. h must NOT include a
// port — strip it first with net.SplitHostPort if applicable.
func IsValidHost(h string) bool {
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

// PassthroughHeaders is the allowlist of headers forwarded from agent
// requests to upstream services for credentialed (non-passthrough) auth
// types. All other agent headers are dropped; in particular Authorization
// is NOT on this list so injected credentials always win over any
// client-supplied value.
//
// Passthrough services use CopyPassthroughRequestHeaders instead, which
// is a denylist — the client's request is forwarded unchanged apart from
// hop-by-hop headers and broker-scoped headers.
var PassthroughHeaders = []string{
	"Content-Type",
	"Content-Encoding",
	"Accept",
	"Accept-Encoding",
	"Accept-Language",
	"User-Agent",
	"Idempotency-Key",
	"X-Request-Id",
}

// brokerScopedRequestHeaders are headers that authenticate the client to
// Agent Vault itself (explicit /proxy ingress uses X-Vault;
// HTTPS_PROXY-compatible ingress uses Proxy-Authorization). They must
// never traverse the broker → target hop, even on passthrough services.
var brokerScopedRequestHeaders = map[string]bool{
	"X-Vault":             true,
	"Proxy-Authorization": true,
}

// IsBrokerScopedRequestHeader reports whether a request header
// authenticates the client to Agent Vault itself and must be stripped
// before forwarding to the target service.
func IsBrokerScopedRequestHeader(name string) bool {
	return brokerScopedRequestHeaders[http.CanonicalHeaderKey(name)]
}

// CopyPassthroughRequestHeaders forwards headers from src to dst for
// passthrough services: everything except hop-by-hop, broker-scoped
// (X-Vault, Proxy-Authorization), and any extra names in extraStrip.
// Callers pass the header that authenticates the client to Agent Vault
// on their ingress so that credential never reaches the target.
func CopyPassthroughRequestHeaders(src, dst http.Header, extraStrip ...string) {
	strip := make(map[string]bool, len(extraStrip))
	for _, s := range extraStrip {
		strip[http.CanonicalHeaderKey(s)] = true
	}
	for k, vv := range src {
		ck := http.CanonicalHeaderKey(k)
		if IsHopByHop(ck) || IsBrokerScopedRequestHeader(ck) || strip[ck] {
			continue
		}
		for _, v := range vv {
			dst.Add(ck, v)
		}
	}
}

// ApplyInjection writes the outbound request headers for a resolved
// InjectResult. Passthrough services forward client headers via the
// denylist (hop-by-hop + broker-scoped + extraStrip); credentialed
// services copy the PassthroughHeaders allowlist and then overlay
// injected credentials. Used by both ingress paths so header handling
// for the two branches stays in lockstep.
func ApplyInjection(src, dst http.Header, inject *InjectResult, extraStrip ...string) {
	if inject.Passthrough {
		CopyPassthroughRequestHeaders(src, dst, extraStrip...)
		return
	}
	for _, k := range PassthroughHeaders {
		for _, v := range src.Values(k) {
			dst.Add(k, v)
		}
	}
	for k, v := range inject.Headers {
		dst.Set(k, v)
	}
}

// helpLinks returns the standard "see available services / usage instructions"
// suffix appended to broker-layer error messages when baseURL is known.
func helpLinks(baseURL string) string {
	return fmt.Sprintf(
		"To see available services, GET %s/discover. For usage instructions including how to create a proposal, GET %s/v1/skills/http",
		baseURL, baseURL,
	)
}

// ForbiddenHintBody returns the JSON-shaped body for a 403 response when
// the target host is not matched by any broker service in the vault. Both
// ingresses emit identical bytes so agents can uniformly parse the hint.
// baseURL is the externally-reachable control-plane URL used to build
// actionable help links so agents without the skill file pre-loaded can
// self-discover available services and usage instructions.
func ForbiddenHintBody(targetHost, vaultName, baseURL string) map[string]interface{} {
	body := map[string]interface{}{
		"error":   "forbidden",
		"message": fmt.Sprintf("No broker service matching host %q in vault %q", targetHost, vaultName),
		"proposal_hint": map[string]interface{}{
			"host":                 targetHost,
			"endpoint":             "POST /v1/proposals",
			"supported_auth_types": broker.SupportedAuthTypes,
		},
	}
	if baseURL != "" {
		body["help"] = "This request was intercepted by Agent Vault. " + helpLinks(baseURL)
	}
	return body
}

// ShouldStripResponseHeader reports whether an upstream response header
// must not be forwarded to the agent: hop-by-hop headers plus Set-Cookie.
// Stripping Set-Cookie prevents the upstream from planting cookies in the
// agent's jar.
func ShouldStripResponseHeader(name string) bool {
	return IsHopByHop(name) || strings.EqualFold(name, "Set-Cookie")
}

// WriteProxyError writes a JSON error response with Content-Type, the
// X-Agent-Vault-Proxy-Error header (so SDKs can distinguish broker-layer
// errors from upstream status codes that happen to match), and a
// {error, message} body.
func WriteProxyError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set(ProxyErrorHeader, "true")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "message": message})
}

// writeProxyErrorWithHelp is like WriteProxyError but appends an optional
// help field when baseURL is non-empty.
func writeProxyErrorWithHelp(w http.ResponseWriter, status int, code, message, baseURL string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set(ProxyErrorHeader, "true")
	w.WriteHeader(status)
	body := map[string]interface{}{"error": code, "message": message}
	if baseURL != "" {
		body["help"] = helpLinks(baseURL)
	}
	_ = json.NewEncoder(w).Encode(body)
}

// WriteForbiddenHint writes a 403 with the shared proposal_hint body so
// both ingress paths emit identical bytes for the "host not brokerable"
// case.
func WriteForbiddenHint(w http.ResponseWriter, targetHost, vaultName, baseURL string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set(ProxyErrorHeader, "true")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(ForbiddenHintBody(targetHost, vaultName, baseURL))
}

// WriteInjectError maps a CredentialProvider.Inject error to the standard
// HTTP response for both ingress paths. baseURL is the externally-reachable
// control-plane URL for help links. Callers that want to log before
// responding (e.g. the /proxy path logs credential-resolution failures)
// should do so before calling this helper.
func WriteInjectError(w http.ResponseWriter, err error, targetHost, vaultName, baseURL string) {
	switch {
	case errors.Is(err, ErrServiceNotFound):
		WriteForbiddenHint(w, targetHost, vaultName, baseURL)
	case errors.Is(err, ErrServiceDisabled):
		writeProxyErrorWithHelp(w, http.StatusForbidden, "service_disabled",
			fmt.Sprintf("Broker service matching host %q in vault %q is currently disabled", targetHost, vaultName), baseURL)
	case errors.Is(err, ErrCredentialMissing):
		writeProxyErrorWithHelp(w, http.StatusBadGateway, "credential_not_found",
			"A required credential could not be resolved; check vault configuration", baseURL)
	default:
		WriteProxyError(w, http.StatusInternalServerError, "internal",
			"Failed to resolve broker services")
	}
}
