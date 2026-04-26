package netguard

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// AllowPrivateFromEnv reads AGENT_VAULT_ALLOW_PRIVATE_RANGES and returns whether
// the proxy should allow connections to private/reserved IP ranges (RFC-1918,
// loopback, link-local, IPv6 ULA, CGN). Defaults to false (block) when unset
// or unparseable — the safe default for network-exposed deployments. Cloud
// metadata endpoints are blocked regardless of this setting.
func AllowPrivateFromEnv() bool {
	v := os.Getenv("AGENT_VAULT_ALLOW_PRIVATE_RANGES")
	if v == "" {
		return false
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false
	}
	return b
}

// AllowlistFromEnv reads AGENT_VAULT_NETWORK_ALLOWLIST and returns a list of
// IP networks to allow when private-range blocking is on.
func AllowlistFromEnv() []net.IPNet {
	return ParseCIDRList(os.Getenv("AGENT_VAULT_NETWORK_ALLOWLIST"), "AGENT_VAULT_NETWORK_ALLOWLIST")
}

// ParseCIDRList parses a comma-separated list of CIDRs or bare IPs. Bare IPv4
// addresses are expanded to /32, bare IPv6 to /128. Invalid entries are logged
// via slog.Warn and skipped. Entries that cover an entire address family
// (mask 0, i.e. 0.0.0.0/0 or ::/0) are accepted but logged as warnings —
// they're rarely intended and effectively disable any per-range policy.
// envName labels the source in log messages.
func ParseCIDRList(raw, envName string) []net.IPNet {
	if raw == "" {
		return nil
	}

	var out []net.IPNet
	for _, p := range strings.Split(raw, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}

		cidr := p
		if !strings.Contains(p, "/") {
			ip := net.ParseIP(p)
			if ip == nil {
				slog.Warn("netguard: invalid IP, skipping", //nolint:gosec // G706: structured slog attrs, handlers quote control chars
					slog.String("env", envName), slog.String("value", p))
				continue
			}
			if ip.To4() != nil {
				cidr = p + "/32"
			} else {
				cidr = p + "/128"
			}
		}

		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			slog.Warn("netguard: invalid CIDR, skipping", //nolint:gosec // G706: structured slog attrs, handlers quote control chars
				slog.String("env", envName), slog.String("value", p), slog.String("error", err.Error()))
			continue
		}

		if mask, _ := ipNet.Mask.Size(); mask == 0 {
			slog.Warn("netguard: CIDR list entry covers an entire address family", //nolint:gosec // G706: structured slog attrs, handlers quote control chars
				slog.String("env", envName), slog.String("value", p))
		}

		out = append(out, *ipNet)
	}

	if len(out) > 0 {
		slog.Debug("netguard: loaded CIDR list", //nolint:gosec // G706: structured slog attrs, handlers quote control chars
			slog.String("env", envName), slog.Int("count", len(out)))
	}

	return out
}

// alwaysBlocked contains IP ranges that are blocked regardless of policy.
// These are metadata service endpoints and other dangerous destinations.
var alwaysBlocked = []net.IPNet{
	// AWS/GCP/Azure IMDS
	parseCIDR("169.254.169.254/32"),
	// AWS IMDSv2 IPv6
	parseCIDR("fd00:ec2::254/128"),
}

// privateRanges contains RFC-1918 and other private/reserved ranges.
// Blocked unless AGENT_VAULT_ALLOW_PRIVATE_RANGES=true or the IP is in the
// AGENT_VAULT_NETWORK_ALLOWLIST.
var privateRanges = []net.IPNet{
	// IPv4 private
	parseCIDR("10.0.0.0/8"),
	parseCIDR("172.16.0.0/12"),
	parseCIDR("192.168.0.0/16"),
	// IPv4 loopback
	parseCIDR("127.0.0.0/8"),
	// IPv4 link-local
	parseCIDR("169.254.0.0/16"),
	// IPv4 shared address space (CGN)
	parseCIDR("100.64.0.0/10"),
	// IPv6 loopback
	parseCIDR("::1/128"),
	// IPv6 link-local
	parseCIDR("fe80::/10"),
	// IPv6 unique local
	parseCIDR("fc00::/7"),
	// 0.0.0.0 (often routes to localhost)
	parseCIDR("0.0.0.0/32"),
}

func parseCIDR(s string) net.IPNet {
	_, ipNet, err := net.ParseCIDR(s)
	if err != nil {
		panic("netguard: bad CIDR: " + s)
	}
	return *ipNet
}

// isBlockedIP checks if an IP is blocked. When allowPrivate is false,
// private/reserved ranges are blocked unless the IP is in the allowlist.
// IMDS endpoints are always blocked, even when allowlisted.
func isBlockedIP(ip net.IP, allowPrivate bool, allowed []net.IPNet) bool {
	for _, n := range alwaysBlocked {
		if n.Contains(ip) {
			return true
		}
	}

	if allowPrivate {
		return false
	}

	for _, n := range allowed {
		if n.Contains(ip) {
			return false
		}
	}

	for _, n := range privateRanges {
		if n.Contains(ip) {
			return true
		}
	}

	return false
}

// SafeDialContext returns a DialContext function that blocks connections to
// forbidden IP ranges. When allowPrivate is true, only IMDS endpoints are
// blocked. When false, private/reserved ranges are also blocked unless
// allowlisted via AGENT_VAULT_NETWORK_ALLOWLIST.
func SafeDialContext(allowPrivate bool) func(ctx context.Context, network, addr string) (net.Conn, error) {
	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	var allowed []net.IPNet
	if !allowPrivate {
		allowed = AllowlistFromEnv()
	}

	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("netguard: invalid address %q: %w", addr, err)
		}

		// Resolve the hostname to IP addresses.
		ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("netguard: DNS lookup failed for %q: %w", host, err)
		}

		// Check all resolved IPs before connecting.
		for _, ipAddr := range ips {
			if isBlockedIP(ipAddr.IP, allowPrivate, allowed) {
				return nil, fmt.Errorf("netguard: connection to %s (%s) blocked by network policy",
					host, ipAddr.IP.String())
			}
		}

		// All IPs are safe — connect directly to a validated IP to prevent
		// DNS rebinding (TOCTOU: a second resolution could return a different IP).
		return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].IP.String(), port))
	}
}
