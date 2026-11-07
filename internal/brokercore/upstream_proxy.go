package brokercore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// Wire-protocol values for UpstreamProxy.Scheme. Each scheme describes how
// the broker reaches the requested upstream through an operator-configured
// egress proxy.
const (
	// UpstreamProxySchemeHTTP routes through a plain HTTP proxy. HTTPS
	// upstreams use CONNECT tunnelling; plain-HTTP upstreams are forwarded
	// in absolute-form (RFC 7230 §5.3.2).
	UpstreamProxySchemeHTTP = "http"
	// UpstreamProxySchemeHTTPS routes through an HTTP proxy over TLS. The
	// broker terminates TLS against the proxy (optionally trusting a
	// custom CA) before issuing CONNECT.
	UpstreamProxySchemeHTTPS = "https"
	// UpstreamProxySchemeSOCKS5 routes through a SOCKS5 proxy, resolving
	// the target hostname locally (RFC 1928, ATYP 0x03).
	UpstreamProxySchemeSOCKS5 = "socks5"
	// UpstreamProxySchemeSOCKS5H behaves like socks5 but asks the proxy to
	// resolve the target hostname remotely. Local DNS-based target
	// validation still runs when the name resolves locally.
	UpstreamProxySchemeSOCKS5H = "socks5h"
)

// Wire-protocol values for UpstreamProxy.OnFailure.
const (
	// UpstreamProxyFailClosed rejects the request when the egress proxy
	// cannot be reached. Default, and the safe choice: it guarantees
	// traffic never silently leaks out over a direct connection.
	UpstreamProxyFailClosed = "fail_closed"
	// UpstreamProxyFailOpen falls back to a direct connection when the
	// egress proxy cannot be reached, logging a warning. Useful for
	// migrations, not for egress-policy enforcement.
	UpstreamProxyFailOpen = "fail_open"
)

// DefaultUpstreamProxyFailure is the failure policy used when none is set.
const DefaultUpstreamProxyFailure = UpstreamProxyFailClosed

// IsValidUpstreamProxyScheme reports whether scheme is one of the supported
// egress proxy schemes.
func IsValidUpstreamProxyScheme(scheme string) bool {
	switch strings.ToLower(strings.TrimSpace(scheme)) {
	case UpstreamProxySchemeHTTP,
		UpstreamProxySchemeHTTPS,
		UpstreamProxySchemeSOCKS5,
		UpstreamProxySchemeSOCKS5H:
		return true
	default:
		return false
	}
}

// IsValidUpstreamProxyFailure reports whether policy is a supported failure
// mode. The empty string is valid and means "use the default".
func IsValidUpstreamProxyFailure(policy string) bool {
	switch policy {
	case "", UpstreamProxyFailClosed, UpstreamProxyFailOpen:
		return true
	default:
		return false
	}
}

// UpstreamProxy is a resolved egress proxy profile. It crosses an internal
// boundary only — the server decrypts stored credentials into this struct
// and hands it to the egress layer, which never persists it.
//
// Username and Password are SECRET. Never log them; log Name instead.
type UpstreamProxy struct {
	// Name is the operator-facing profile identifier; services reference
	// it by name. Safe to log.
	Name string

	// Scheme is one of the UpstreamProxyScheme* constants.
	Scheme string

	// Host is the proxy endpoint in host:port form, port required.
	Host string

	// Username/Password authenticate the broker to the proxy itself.
	// Empty means no proxy authentication. SECRET — never log.
	Username string
	Password string

	// NoProxy is a comma-separated list of upstream hosts that must bypass
	// the proxy and be dialled directly (same matching rules as the
	// conventional NO_PROXY environment variable).
	NoProxy string

	// ProxyCAPEM holds optional PEM-encoded root certificates trusted when
	// speaking TLS to the proxy (Scheme = https). Empty means system roots.
	ProxyCAPEM string

	// OnFailure selects fail_closed (default) or fail_open behaviour when
	// the proxy cannot be reached.
	OnFailure string
}

// FailureMode returns p.OnFailure with the default applied.
func (p *UpstreamProxy) FailureMode() string {
	if p.OnFailure == "" {
		return DefaultUpstreamProxyFailure
	}
	return p.OnFailure
}

// HasAuth reports whether proxy-side credentials are configured.
func (p *UpstreamProxy) HasAuth() bool {
	return p != nil && (p.Username != "" || p.Password != "")
}

// UsesDNSRemotely reports whether hostname resolution is delegated to the
// proxy rather than performed locally. With socks5h the local DNS-based
// target validation cannot see the address the proxy will actually connect
// to, so callers must treat the validation result accordingly.
func (p *UpstreamProxy) UsesDNSRemotely() bool {
	return p != nil && p.Scheme == UpstreamProxySchemeSOCKS5H
}

// Fingerprint returns a stable identifier for the profile's effective
// configuration. The egress registry keys cached transports on it so that
// editing a profile (including rotating its password) invalidates the cache
// without a restart. Only non-secret inputs feed the hash.
func (p *UpstreamProxy) Fingerprint() string {
	if p == nil {
		return "direct"
	}
	h := sha256.New()
	for _, part := range []string{
		p.Name, p.Scheme, p.Host, p.Username, p.Password,
		p.NoProxy, p.ProxyCAPEM, p.FailureMode(),
	} {
		_, _ = h.Write([]byte(part))
		// 0x1f (unit separator) cannot appear in any field value and keeps
		// the concatenation unambiguous.
		_, _ = h.Write([]byte{0x1f})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// UpstreamProxyResolver maps a brokered request to the egress proxy that
// should carry it to the real upstream. Returning a nil profile means "no
// egress proxy for this request" — the broker dials the upstream directly,
// exactly as it did before this feature existed.
//
// Implementations are consulted once per brokered request, after credential
// injection, so they run on the hot path and must be cheap or cached.
type UpstreamProxyResolver interface {
	// ResolveUpstreamProxy returns the profile named by serviceName within
	// vaultID, or nil when neither the service nor the instance defines
	// one. serviceName is empty for unmatched-host passthrough traffic.
	ResolveUpstreamProxy(ctx context.Context, vaultID, serviceName string) (*UpstreamProxy, error)
}
