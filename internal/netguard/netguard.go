package netguard

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"time"
)

// Mode controls which network ranges the proxy is allowed to reach.
type Mode string

const (
	// ModePrivate allows all outbound connections including private ranges.
	// This is the default for local/private deployments.
	ModePrivate Mode = "private"
	// ModePublic blocks connections to private/reserved IP ranges.
	// Use this when Agent Vault is deployed on a public network or cloud.
	ModePublic Mode = "public"
)

// ModeFromEnv reads AGENT_VAULT_NETWORK_MODE and returns the corresponding Mode.
// Returns ModePublic if unset or unrecognized.
func ModeFromEnv() Mode {
	switch strings.ToLower(os.Getenv("AGENT_VAULT_NETWORK_MODE")) {
	case "private":
		return ModePrivate
	default:
		return ModePublic
	}
}

// AllowedRangesFromEnv reads AGENT_VAULT_NETWORK_ALLOW_RANGES and returns a list
// of allowed IP networks. Empty string returns nil (no whitelist).
// Invalid entries are logged as warnings and skipped.
// Bare IPs are automatically converted to /32 CIDR notation.
func AllowedRangesFromEnv() []net.IPNet {
	env := os.Getenv("AGENT_VAULT_NETWORK_ALLOW_RANGES")
	if env == "" {
		return nil
	}

	var allowed []net.IPNet
	parts := strings.Split(env, ",")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}

		// If it doesn't contain a slash, assume it's a bare IP and add /32
		cidr := p
		if !strings.Contains(p, "/") {
			// Check if it's a valid IP first
			if ip := net.ParseIP(p); ip == nil {
				slog.Warn("netguard: invalid IP in AGENT_VAULT_NETWORK_ALLOW_RANGES, skipping",
					slog.String("value", p))
				continue
			}
			cidr = p + "/32"
		}

		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			slog.Warn("netguard: invalid CIDR in AGENT_VAULT_NETWORK_ALLOW_RANGES, skipping",
				slog.String("value", p),
				slog.String("error", err.Error()))
			continue
		}

		allowed = append(allowed, *ipNet)
	}

	if len(allowed) > 0 {
		slog.Debug("netguard: loaded network whitelist",
			slog.Int("count", len(allowed)))
	}

	return allowed
}

// alwaysBlocked contains IP ranges that are blocked regardless of mode.
// These are metadata service endpoints and other dangerous destinations.
var alwaysBlocked = []net.IPNet{
	// AWS/GCP/Azure IMDS
	parseCIDR("169.254.169.254/32"),
	// AWS IMDSv2 IPv6
	parseCIDR("fd00:ec2::254/128"),
}

// privateRanges contains RFC-1918 and other private/reserved ranges,
// blocked only in "public" mode.
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

// isBlockedIP checks if an IP is blocked for the given mode.
// In public mode, private/reserved ranges are blocked unless explicitly allowed.
func isBlockedIP(ip net.IP, mode Mode, allowed []net.IPNet) bool {
	// Always block metadata endpoints.
	for _, n := range alwaysBlocked {
		if n.Contains(ip) {
			return true
		}
	}

	// In public mode, also block private/reserved ranges unless whitelisted.
	if mode == ModePublic {
		// First check if IP is in whitelist
		for _, n := range allowed {
			if n.Contains(ip) {
				return false // Whitelisted - allow
			}
		}

		// Check private ranges
		for _, n := range privateRanges {
			if n.Contains(ip) {
				return true // Blocked private range
			}
		}
	}

	return false
}

// SafeDialContext returns a DialContext function that blocks connections to
// forbidden IP ranges based on the network mode.
func SafeDialContext(mode Mode) func(ctx context.Context, network, addr string) (net.Conn, error) {
	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	// Parse allowed ranges once at initialization
	allowed := AllowedRangesFromEnv()

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
			if isBlockedIP(ipAddr.IP, mode, allowed) {
				return nil, fmt.Errorf("netguard: connection to %s (%s) blocked by network policy (mode=%s)",
					host, ipAddr.IP.String(), mode)
			}
		}

		// All IPs are safe — connect directly to a validated IP to prevent
		// DNS rebinding (TOCTOU: a second resolution could return a different IP).
		return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].IP.String(), port))
	}
}
