package mitm

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/Infisical/agent-vault/internal/broker"
	"github.com/Infisical/agent-vault/internal/netguard"
)

// filterTransport builds a dedicated hop transport. It does not consult
// AGENT_VAULT_ALLOW_PRIVATE_RANGES. HTTPS allows public destinations and
// still blocks metadata addresses. HTTP to a literal loopback IP is
// allowed. Any other HTTP destination requires allow_insecure_private_http,
// and every resolved address must be loopback or private address space.
// The validated IP is what gets dialed.
//
// RoundTrip on this transport does not follow redirects. httputil.ReverseProxy
// calls Transport.RoundTrip directly, so a sidecar 302 is returned to the
// client.
func filterTransport(f *broker.Filter) (*http.Transport, error) {
	if f == nil || f.URL == "" {
		return nil, fmt.Errorf("filter url is empty")
	}
	u, err := url.Parse(f.URL)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("filter url is invalid")
	}
	tlsConf := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: u.Hostname()}
	if f.CA != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(f.CA)) {
			return nil, fmt.Errorf("filter ca is not a PEM certificate")
		}
		tlsConf.RootCAs = pool
	}
	return &http.Transport{
		DialContext:           filterDialContext(u.Scheme, u.Hostname(), f.AllowInsecurePrivateHTTP),
		TLSClientConfig:       tlsConf,
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          32,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 5 * time.Minute,
	}, nil
}

func filterDialContext(scheme, hostname string, allowInsecurePrivate bool) func(ctx context.Context, network, addr string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	httpsDial := netguard.SafeDialContext(true)

	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("filter dial: invalid address %q: %w", addr, err)
		}
		if scheme == "https" {
			return httpsDial(ctx, network, addr)
		}
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			return dialer.DialContext(ctx, network, addr)
		}
		if !allowInsecurePrivate {
			return nil, fmt.Errorf("filter dial: cleartext http to %q requires a literal loopback address or allow_insecure_private_http", host)
		}
		ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("filter dial: DNS lookup failed for %q: %w", host, err)
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("filter dial: no addresses for %q", host)
		}
		for _, ipAddr := range ips {
			if !filterHTTPIPAllowed(ipAddr.IP) {
				return nil, fmt.Errorf("filter dial: resolved address %s for %q is not a private or loopback address", ipAddr.IP, host)
			}
		}
		return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].IP.String(), port))
	}
}

func filterHTTPIPAllowed(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsLoopback() {
		return true
	}
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return false
	}
	if ip4 := ip.To4(); ip4 != nil {
		if ip4[0] == 10 {
			return true
		}
		if ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31 {
			return true
		}
		if ip4[0] == 192 && ip4[1] == 168 {
			return true
		}
		return false
	}
	// IPv6 unique local (fc00::/7).
	return len(ip) == net.IPv6len && (ip[0]&0xfe) == 0xfc
}
