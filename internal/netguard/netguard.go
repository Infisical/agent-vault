package netguard

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"syscall"
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
//
// Resolution and address selection are left to net.Dialer, which tries every
// resolved address and races IPv6 against IPv4 (RFC 6555 Fast Fallback), so
// one broken address family does not fail or stall the dial. The policy check
// runs in the dialer's ControlContext hook on each address right before
// connect, so blocked addresses are skipped and DNS rebinding cannot swap in
// an unchecked IP between validation and connection.
func SafeDialContext(allowPrivate bool) func(ctx context.Context, network, addr string) (net.Conn, error) {
	var allowed []net.IPNet
	if !allowPrivate {
		allowed = AllowlistFromEnv()
	}
	return newSafeDialer(allowPrivate, allowed).DialContext
}

func newSafeDialer(allowPrivate bool, allowed []net.IPNet) *net.Dialer {
	return &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
		ControlContext: func(_ context.Context, _, address string, _ syscall.RawConn) error {
			err := checkDialAddress(address, allowPrivate, allowed)
			if err != nil {
				// A refused address may be skipped in favor of another one, in
				// which case the request succeeds and this is the only trace.
				slog.Warn("netguard: dial attempt refused", //nolint:gosec // G706: structured slog attrs, handlers quote control chars
					slog.String("address", address), slog.String("error", err.Error()))
			}
			return err
		},
	}
}

// checkDialAddress applies the network policy to the ip:port net.Dialer is
// about to connect to. Anything that does not parse as an IP address is
// rejected, so an unexpected address form cannot slip past the policy.
func checkDialAddress(address string, allowPrivate bool, allowed []net.IPNet) error {
	addrPort, err := netip.ParseAddrPort(address)
	if err != nil {
		return fmt.Errorf("netguard: cannot validate dial address %q: %w", address, err)
	}
	ip := addrPort.Addr().Unmap()
	if isBlockedIP(ip.AsSlice(), allowPrivate, allowed) {
		return fmt.Errorf("netguard: connection to %s blocked by network policy", ip)
	}
	return nil
}
