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
// requests to upstream services. All other agent headers are dropped;
// in particular Authorization is NOT on this list so injected credentials
// always win over any client-supplied value.
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

// ForbiddenHintBody returns the JSON-shaped body for a 403 response when
// the target host is not matched by any broker service in the vault. Both
// ingresses emit identical bytes so agents can uniformly parse the hint.
func ForbiddenHintBody(targetHost, vaultName string) map[string]interface{} {
	return map[string]interface{}{
		"error":   "forbidden",
		"message": fmt.Sprintf("No broker service matching host %q in vault %q", targetHost, vaultName),
		"proposal_hint": map[string]interface{}{
			"host":                 targetHost,
			"endpoint":             "POST /v1/proposals",
			"supported_auth_types": broker.SupportedAuthTypes,
		},
	}
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

// WriteForbiddenHint writes a 403 with the shared proposal_hint body so
// both ingress paths emit identical bytes for the "host not brokerable"
// case.
func WriteForbiddenHint(w http.ResponseWriter, targetHost, vaultName string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set(ProxyErrorHeader, "true")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(ForbiddenHintBody(targetHost, vaultName))
}

// WriteInjectError maps a CredentialProvider.Inject error to the standard
// HTTP response for both ingress paths. Callers that want to log before
// responding (e.g. the /proxy path logs credential-resolution failures)
// should do so before calling this helper.
func WriteInjectError(w http.ResponseWriter, err error, targetHost, vaultName string) {
	switch {
	case errors.Is(err, ErrServiceNotFound):
		WriteForbiddenHint(w, targetHost, vaultName)
	case errors.Is(err, ErrCredentialMissing):
		WriteProxyError(w, http.StatusBadGateway, "credential_not_found",
			"A required credential could not be resolved; check vault configuration")
	default:
		WriteProxyError(w, http.StatusInternalServerError, "internal",
			"Failed to resolve broker services")
	}
}
