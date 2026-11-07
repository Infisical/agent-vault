package netguard

import (
	"context"
	"errors"
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
	// 0.0.0.0 and :: (unspecified; connecting to them reaches localhost)
	parseCIDR("0.0.0.0/32"),
	parseCIDR("::/128"),
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

// currentPolicy returns the allow-private flag and allowlist in effect for
// this process, honouring AGENT_VAULT_ALLOW_PRIVATE_RANGES and
// AGENT_VAULT_NETWORK_ALLOWLIST. Exported helpers below read it fresh on
// every call so runtime configuration changes are picked up.
func currentPolicy() (bool, []net.IPNet) {
	allowPrivate := AllowPrivateFromEnv()
	var allowed []net.IPNet
	if !allowPrivate {
		allowed = AllowlistFromEnv()
	}
	return allowPrivate, allowed
}

// ResolveTargetIPs resolves host and applies the same private-range and IMDS
// policy that direct connections enforce. The returned addresses are the
// exact addresses checked by policy, allowing callers to avoid a second DNS
// lookup before dialing.
func ResolveTargetIPs(ctx context.Context, host string) ([]net.IPAddr, error) {
	allowPrivate, allowed := currentPolicy()
	return resolveTargetIPs(ctx, host, allowPrivate, allowed)
}

func resolveTargetIPs(ctx context.Context, host string, allowPrivate bool, allowed []net.IPNet) ([]net.IPAddr, error) {
	if host == "" {
		return nil, fmt.Errorf("netguard: empty target host")
	}
	if ip := net.ParseIP(host); ip != nil {
		if isBlockedIP(ip, allowPrivate, allowed) {
			return nil, fmt.Errorf("netguard: connection to %s (%s) blocked by network policy", host, ip)
		}
		return []net.IPAddr{{IP: ip}}, nil
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("netguard: DNS lookup failed for %q: %w", host, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("netguard: DNS lookup returned no addresses for %q", host)
	}
	for _, ipAddr := range ips {
		if isBlockedIP(ipAddr.IP, allowPrivate, allowed) {
			return nil, fmt.Errorf("netguard: connection to %s (%s) blocked by network policy",
				host, ipAddr.IP.String())
		}
	}
	return ips, nil
}

// ValidateTargetName resolves host and applies the target network policy.
func ValidateTargetName(ctx context.Context, host string) error {
	_, err := ResolveTargetIPs(ctx, host)
	return err
}

// ValidateTargetAddr applies ValidateTargetName to the host portion of an
// host:port address.
func ValidateTargetAddr(ctx context.Context, addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("netguard: invalid address %q: %w", addr, err)
	}
	return ValidateTargetName(ctx, host)
}

// ValidateRemoteTargetName checks a name before sending it to a proxy that
// resolves DNS remotely. Only a definitive NXDOMAIN may be deferred to that
// trusted proxy; cancellation and transient resolver failures remain errors.
func ValidateRemoteTargetName(ctx context.Context, host string) error {
	_, err := ResolveTargetIPs(ctx, host)
	if err == nil {
		return nil
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) && dnsErr.IsNotFound && ctx.Err() == nil {
		return nil
	}
	return err
}

// SafeDialContext returns a DialContext function that blocks connections to
// forbidden IP ranges. When allowPrivate is true, only IMDS endpoints are
// blocked. When false, private/reserved ranges are also blocked unless
// allowlisted via AGENT_VAULT_NETWORK_ALLOWLIST.
//
// SafeDialContext preflights every resolved address, then delegates address
// selection and dialing to net.Dialer. Its ControlContext policy check runs
// immediately before each connection, protecting against DNS changes between
// preflight and connect while retaining net.Dialer's address failover.
func SafeDialContext(allowPrivate bool) func(ctx context.Context, network, addr string) (net.Conn, error) {
	var allowed []net.IPNet
	if !allowPrivate {
		allowed = AllowlistFromEnv()
	}
	dialer := newSafeDialer(allowPrivate, allowed)
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("netguard: invalid address %q: %w", addr, err)
		}
		if _, err := resolveTargetIPs(ctx, host, allowPrivate, allowed); err != nil {
			return nil, fmt.Errorf("netguard: dialing %q: %w", addr, err)
		}
		return dialer.DialContext(ctx, network, addr)
	}
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
