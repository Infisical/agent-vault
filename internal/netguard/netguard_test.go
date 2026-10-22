package netguard

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func TestIsBlockedIP_AlwaysBlocked(t *testing.T) {
	// IMDS endpoints are blocked regardless of policy (allowlist does NOT bypass).
	imds := net.ParseIP("169.254.169.254")

	if !isBlockedIP(imds, false, nil) {
		t.Error("169.254.169.254 should be blocked when private ranges are blocked")
	}
	if !isBlockedIP(imds, true, nil) {
		t.Error("169.254.169.254 should be blocked even when private ranges are allowed")
	}

	// Even with allowlist containing the IMDS IP, it should still be blocked.
	allowlist := []net.IPNet{parseCIDR("169.254.169.254/32")}
	if !isBlockedIP(imds, false, allowlist) {
		t.Error("169.254.169.254 should be blocked even when allowlisted (always-blocked takes precedence)")
	}

	// AWS IMDSv2 IPv6
	imdsV6 := net.ParseIP("fd00:ec2::254")
	if !isBlockedIP(imdsV6, true, nil) {
		t.Error("fd00:ec2::254 should be blocked even when private ranges are allowed")
	}
}

func TestIsBlockedIP_AllowPrivate(t *testing.T) {
	// When private ranges are allowed, RFC-1918 etc. should NOT be blocked.
	cases := []string{
		"10.0.0.1",
		"172.16.0.1",
		"192.168.0.1",
		"fe80::1",
		"127.0.0.1",
	}
	for _, ip := range cases {
		if isBlockedIP(net.ParseIP(ip), true, nil) {
			t.Errorf("%s should NOT be blocked when private ranges are allowed", ip)
		}
	}
}

func TestIsBlockedIP_BlockPrivate(t *testing.T) {
	// When private ranges are blocked, RFC-1918, loopback, link-local, CGN should be blocked.
	blocked := []string{
		"10.0.0.1",
		"172.16.0.1",
		"192.168.0.1",
		"127.0.0.1",
		"169.254.0.1",
		"100.64.0.1",
		"0.0.0.0",
		"::",
	}
	for _, ip := range blocked {
		if !isBlockedIP(net.ParseIP(ip), false, nil) {
			t.Errorf("%s should be blocked when private ranges are blocked", ip)
		}
	}

	// Public IPs should NOT be blocked.
	allowed := []string{
		"8.8.8.8",
		"1.1.1.1",
		"104.18.0.1",
	}
	for _, ip := range allowed {
		if isBlockedIP(net.ParseIP(ip), false, nil) {
			t.Errorf("%s should NOT be blocked (public IP)", ip)
		}
	}
}

func TestIsBlockedIP_Allowlist(t *testing.T) {
	allowlist := []net.IPNet{
		parseCIDR("10.163.0.0/16"),
		parseCIDR("192.168.1.1/32"),
	}

	// IPs in allowlist should NOT be blocked.
	allowlisted := []string{
		"10.163.0.1",
		"10.163.255.254",
		"192.168.1.1",
	}
	for _, ip := range allowlisted {
		if isBlockedIP(net.ParseIP(ip), false, allowlist) {
			t.Errorf("%s should NOT be blocked when allowlisted", ip)
		}
	}

	// Private IPs not in allowlist should be blocked.
	blocked := []string{
		"10.0.0.1",
		"192.168.1.2",
		"172.16.0.1",
	}
	for _, ip := range blocked {
		if !isBlockedIP(net.ParseIP(ip), false, allowlist) {
			t.Errorf("%s should be blocked (not allowlisted)", ip)
		}
	}
}

func TestAllowPrivateFromEnv(t *testing.T) {
	cases := []struct {
		env  string
		want bool
	}{
		{"", false},
		{"true", true},
		{"TRUE", true},
		{"True", true},
		{"1", true},
		{"t", true},
		{"false", false},
		{"FALSE", false},
		{"0", false},
		{"f", false},
		{"garbage", false}, // unparseable falls back to safe default
	}
	for _, c := range cases {
		t.Setenv("AGENT_VAULT_ALLOW_PRIVATE_RANGES", c.env)
		if got := AllowPrivateFromEnv(); got != c.want {
			t.Errorf("AllowPrivateFromEnv() with env=%q = %v, want %v", c.env, got, c.want)
		}
	}
}

func TestAllowlistFromEnv(t *testing.T) {
	// Empty env var returns nil.
	t.Setenv("AGENT_VAULT_NETWORK_ALLOWLIST", "")
	if ranges := AllowlistFromEnv(); ranges != nil {
		t.Error("empty AGENT_VAULT_NETWORK_ALLOWLIST should return nil")
	}

	// Single CIDR.
	t.Setenv("AGENT_VAULT_NETWORK_ALLOWLIST", "10.163.0.0/16")
	ranges := AllowlistFromEnv()
	if len(ranges) != 1 {
		t.Fatalf("expected 1 range, got %d", len(ranges))
	}
	if !ranges[0].Contains(net.ParseIP("10.163.0.38")) {
		t.Error("10.163.0.0/16 should contain 10.163.0.38")
	}

	// Multiple CIDRs.
	t.Setenv("AGENT_VAULT_NETWORK_ALLOWLIST", "10.163.0.0/16,192.168.1.0/24")
	ranges = AllowlistFromEnv()
	if len(ranges) != 2 {
		t.Fatalf("expected 2 ranges, got %d", len(ranges))
	}

	// Bare IPv4 → /32.
	t.Setenv("AGENT_VAULT_NETWORK_ALLOWLIST", "192.168.1.1")
	ranges = AllowlistFromEnv()
	if len(ranges) != 1 {
		t.Fatalf("expected 1 range, got %d", len(ranges))
	}
	if !ranges[0].Contains(net.ParseIP("192.168.1.1")) {
		t.Error("bare IPv4 192.168.1.1 should be /32 and contain itself")
	}
	if ranges[0].Contains(net.ParseIP("192.168.1.2")) {
		t.Error("192.168.1.1/32 should NOT contain 192.168.1.2")
	}

	// Bare IPv6 → /128, NOT /32 (regression for IPv6 sizing bug).
	t.Setenv("AGENT_VAULT_NETWORK_ALLOWLIST", "fd00::1")
	ranges = AllowlistFromEnv()
	if len(ranges) != 1 {
		t.Fatalf("expected 1 range, got %d", len(ranges))
	}
	if !ranges[0].Contains(net.ParseIP("fd00::1")) {
		t.Error("bare IPv6 fd00::1 should be /128 and contain itself")
	}
	if ranges[0].Contains(net.ParseIP("fd00::2")) {
		t.Error("bare IPv6 fd00::1 must NOT expand to a /32 prefix (IPv6 sizing regression)")
	}

	// Mixed CIDR and bare IP.
	t.Setenv("AGENT_VAULT_NETWORK_ALLOWLIST", "10.163.0.0/16,192.168.1.1")
	ranges = AllowlistFromEnv()
	if len(ranges) != 2 {
		t.Fatalf("expected 2 ranges, got %d", len(ranges))
	}

	// Whitespace is trimmed.
	t.Setenv("AGENT_VAULT_NETWORK_ALLOWLIST", "  10.163.0.0/16  ,  192.168.1.1  ")
	ranges = AllowlistFromEnv()
	if len(ranges) != 2 {
		t.Fatalf("expected 2 ranges after trimming, got %d", len(ranges))
	}

	// Invalid entries are skipped.
	t.Setenv("AGENT_VAULT_NETWORK_ALLOWLIST", "10.163.0.0/16,invalid,192.168.1.0/24")
	ranges = AllowlistFromEnv()
	if len(ranges) != 2 {
		t.Fatalf("expected 2 valid ranges (invalid skipped), got %d", len(ranges))
	}

	// Whole-family entries are accepted (operator escape hatch) — startup warns separately.
	t.Setenv("AGENT_VAULT_NETWORK_ALLOWLIST", "0.0.0.0/0")
	ranges = AllowlistFromEnv()
	if len(ranges) != 1 {
		t.Fatalf("expected 1 range, got %d", len(ranges))
	}
}

func TestParseCIDRList(t *testing.T) {
	// Empty input returns nil.
	if got := ParseCIDRList("", "TEST"); got != nil {
		t.Errorf("empty input should return nil, got %v", got)
	}

	// Mixed valid and invalid entries: bad-IP, valid CIDR, malformed CIDR,
	// bare IPv4, bare IPv6. Only the three valid forms should survive.
	got := ParseCIDRList("invalid,10.0.0.0/8,bad/x,192.168.1.1,fd00::1", "TEST")
	if len(got) != 3 {
		t.Fatalf("expected 3 valid ranges, got %d: %v", len(got), got)
	}
	if !got[0].Contains(net.ParseIP("10.255.255.1")) {
		t.Error("range[0] should be 10.0.0.0/8")
	}
	if !got[1].Contains(net.ParseIP("192.168.1.1")) || got[1].Contains(net.ParseIP("192.168.1.2")) {
		t.Error("range[1] should be 192.168.1.1/32")
	}
	if !got[2].Contains(net.ParseIP("fd00::1")) || got[2].Contains(net.ParseIP("fd00::2")) {
		t.Error("range[2] should be fd00::1/128, not a wider IPv6 prefix")
	}
}

func TestResolveTargetIPsAppliesPolicyToIPLiterals(t *testing.T) {
	ctx := context.Background()
	t.Setenv("AGENT_VAULT_ALLOW_PRIVATE_RANGES", "false")
	t.Setenv("AGENT_VAULT_NETWORK_ALLOWLIST", "")
	if _, err := ResolveTargetIPs(ctx, "169.254.169.254"); err == nil {
		t.Fatal("metadata IP literal must be rejected")
	}
	if _, err := ResolveTargetIPs(ctx, "10.0.0.1"); err == nil {
		t.Fatal("private IP literal must be rejected by default")
	}
	t.Setenv("AGENT_VAULT_ALLOW_PRIVATE_RANGES", "true")
	ips, err := ResolveTargetIPs(ctx, "10.0.0.1")
	if err != nil {
		t.Fatalf("allowed private IP: %v", err)
	}
	if len(ips) != 1 || !ips[0].IP.Equal(net.ParseIP("10.0.0.1")) {
		t.Fatalf("resolved literal IPs = %#v", ips)
	}
	if err := ValidateRemoteTargetName(ctx, "169.254.169.254"); err == nil {
		t.Fatal("remote DNS validation must still reject metadata IP literals")
	}
}

func TestCheckDialAddress(t *testing.T) {
	allowlist := ParseCIDRList("10.1.2.0/24", "test")
	tests := []struct {
		name         string
		address      string
		allowPrivate bool
		wantBlocked  bool
	}{
		{"public IPv4", "203.0.113.10:443", false, false},
		{"public IPv6", "[2001:db8::10]:443", false, false},
		{"IMDS", "169.254.169.254:80", true, true},
		{"IMDS IPv6", "[fd00:ec2::254]:80", true, true},
		{"IMDS IPv6 with zone", "[fd00:ec2::254%eth0]:80", true, true},
		{"IPv4-mapped IMDS", "[::ffff:169.254.169.254]:80", true, true},
		{"link-local with zone", "[fe80::1%eth0]:443", false, true},
		{"loopback blocked by default", "127.0.0.1:443", false, true},
		{"loopback allowed with private ranges", "127.0.0.1:443", true, false},
		{"IPv6 unspecified reaches loopback", "[::]:443", false, true},
		{"allowlisted private", "10.1.2.3:443", false, false},
		{"private outside allowlist", "10.9.9.9:443", false, true},
		{"hostname fails closed", "example.com:443", true, true},
		{"missing port fails closed", "203.0.113.10", true, true},
		{"empty fails closed", "", true, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var allowed []net.IPNet
			if !tt.allowPrivate {
				allowed = allowlist
			}
			err := checkDialAddress(tt.address, tt.allowPrivate, allowed)
			if blocked := err != nil; blocked != tt.wantBlocked {
				t.Fatalf("checkDialAddress(%q) error = %v, want blocked = %v", tt.address, err, tt.wantBlocked)
			}
		})
	}
}

func TestSafeDialContext_BlocksBeforeConnecting(t *testing.T) {
	t.Setenv("AGENT_VAULT_NETWORK_ALLOWLIST", "")
	listener := listenTCP(t, "tcp4", "127.0.0.1:0")

	_, err := SafeDialContext(false)(context.Background(), "tcp", listener.Addr().String())
	if err == nil || !strings.Contains(err.Error(), "blocked by network policy") {
		t.Fatalf("error = %v, want network policy error", err)
	}
	if !strings.Contains(err.Error(), listener.Addr().String()) {
		t.Errorf("error %q does not name the requested address", err)
	}

	// A completed connect would already be queued on the listener.
	_ = listener.(*net.TCPListener).SetDeadline(time.Now().Add(50 * time.Millisecond))
	if conn, err := listener.Accept(); err == nil {
		_ = conn.Close()
		t.Fatal("blocked address was connected to")
	}
}

func TestSafeDialContext_ConnectsToAllowedAddress(t *testing.T) {
	listener := listenTCP(t, "tcp4", "127.0.0.1:0")

	conn, err := SafeDialContext(true)(context.Background(), "tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_ = conn.Close()
}

func TestSafeDialer_FallsBackToOtherAddressFamily(t *testing.T) {
	listener := listenTCP(t, "tcp4", "127.0.0.1:0")
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	d := newSafeDialer(true, nil)
	d.Resolver = fakeResolver(t, map[string][]netip.Addr{
		"dual.test.": {netip.MustParseAddr("::1"), netip.MustParseAddr("127.0.0.1")},
	})
	policy := d.ControlContext
	d.ControlContext = func(ctx context.Context, network, address string, c syscall.RawConn) error {
		if network == "tcp6" {
			// Simulate an IPv6 path that is refused outright, without relying
			// on nothing else listening on [::1]:port.
			return syscall.ECONNREFUSED
		}
		return policy(ctx, network, address, c)
	}

	// Whichever family is tried first, the dial has to end up on IPv4.
	conn, err := d.DialContext(context.Background(), "tcp", net.JoinHostPort("dual.test", port))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if got := conn.RemoteAddr().String(); got != listener.Addr().String() {
		t.Fatalf("connected to %s, want %s", got, listener.Addr())
	}
}

func TestSafeDialer_SilentlyDroppedFamilyDoesNotStall(t *testing.T) {
	listener := listenTCP(t, "tcp4", "127.0.0.1:0")
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	d := newSafeDialer(true, nil)
	d.Resolver = fakeResolver(t, map[string][]netip.Addr{
		"dual.test.": {netip.MustParseAddr("::1"), netip.MustParseAddr("127.0.0.1")},
	})
	policy := d.ControlContext
	var ipv6Attempted atomic.Bool
	d.ControlContext = func(ctx context.Context, network, address string, c syscall.RawConn) error {
		if network == "tcp6" {
			// Simulate a path that drops packets without replying: the
			// attempt only ends when the dialer gives up on it.
			ipv6Attempted.Store(true)
			<-ctx.Done()
			return ctx.Err()
		}
		return policy(ctx, network, address, c)
	}

	started := time.Now()
	conn, err := d.DialContext(context.Background(), "tcp", net.JoinHostPort("dual.test", port))
	elapsed := time.Since(started)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if !ipv6Attempted.Load() {
		t.Skip("resolver ordered IPv4 first on this host; the fallback race was not exercised")
	}
	// The IPv4 attempt starts after the 300ms fallback delay. Waiting for
	// the dropped IPv6 attempt instead would take most of the 10s timeout.
	if elapsed > 3*time.Second {
		t.Fatalf("dial took %v; IPv4 fallback should not wait for the dropped IPv6 attempt", elapsed)
	}
}

func TestSafeDialer_SkipsBlockedAddresses(t *testing.T) {
	listener := listenTCP(t, "tcp4", "127.0.0.1:0")
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	// Loopback is blocked except for the allowlisted 127.0.0.1, so ::1 (tried
	// first on hosts with IPv6) must be refused and 127.0.0.1 used instead.
	d := newSafeDialer(false, ParseCIDRList("127.0.0.1", "test"))
	d.Resolver = fakeResolver(t, map[string][]netip.Addr{
		"mixed.test.": {netip.MustParseAddr("::1"), netip.MustParseAddr("127.0.0.1")},
	})
	policy := d.ControlContext
	var mu sync.Mutex
	var attempts, refused []string
	d.ControlContext = func(ctx context.Context, network, address string, c syscall.RawConn) error {
		err := policy(ctx, network, address, c)
		mu.Lock()
		attempts = append(attempts, address)
		if err != nil {
			refused = append(refused, address)
		}
		mu.Unlock()
		return err
	}

	conn, err := d.DialContext(context.Background(), "tcp", net.JoinHostPort("mixed.test", port))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if got := conn.RemoteAddr().String(); got != listener.Addr().String() {
		t.Fatalf("connected to %s, want %s", got, listener.Addr())
	}
	mu.Lock()
	defer mu.Unlock()
	if len(attempts) == 0 || !strings.HasPrefix(attempts[0], "[::1]:") {
		t.Skipf("resolver ordered IPv4 first on this host (attempts %v); the skip was not exercised", attempts)
	}
	if len(refused) != 1 || refused[0] != attempts[0] {
		t.Fatalf("refused = %v, want exactly the blocked %s", refused, attempts[0])
	}
}

func TestSafeDialer_AllAddressesBlocked(t *testing.T) {
	d := newSafeDialer(false, nil)
	d.Resolver = fakeResolver(t, map[string][]netip.Addr{
		"blocked.test.": {
			netip.MustParseAddr("169.254.169.254"),
			netip.MustParseAddr("10.1.2.3"),
			netip.MustParseAddr("::1"),
		},
	})

	_, err := d.DialContext(context.Background(), "tcp", "blocked.test:443")
	if err == nil || !strings.Contains(err.Error(), "blocked by network policy") {
		t.Fatalf("error = %v, want network policy error", err)
	}
}

func listenTCP(t *testing.T, network, address string) net.Listener {
	t.Helper()
	listener, err := net.Listen(network, address)
	if err != nil {
		t.Fatalf("listen %s %s: %v", network, address, err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	return listener
}

// fakeResolver returns a resolver backed by an in-process DNS server that
// answers A and AAAA queries from records (keyed by FQDN) and NXDOMAIN for
// anything else, so dial tests control exactly what net.Dialer resolves.
func fakeResolver(t *testing.T, records map[string][]netip.Addr) *net.Resolver {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen dns: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })

	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if resp, err := fakeDNSAnswer(buf[:n], records); err == nil {
				_, _ = pc.WriteTo(resp, from)
			}
		}
	}()

	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "udp", pc.LocalAddr().String())
		},
	}
}

func fakeDNSAnswer(query []byte, records map[string][]netip.Addr) ([]byte, error) {
	var p dnsmessage.Parser
	hdr, err := p.Start(query)
	if err != nil {
		return nil, err
	}
	q, err := p.Question()
	if err != nil {
		return nil, err
	}

	addrs, ok := records[q.Name.String()]
	rcode := dnsmessage.RCodeSuccess
	if !ok {
		rcode = dnsmessage.RCodeNameError
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: hdr.ID, Response: true, Authoritative: true, RCode: rcode})
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	if err := b.Question(q); err != nil {
		return nil, err
	}
	if err := b.StartAnswers(); err != nil {
		return nil, err
	}
	rh := dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: 60}
	for _, addr := range addrs {
		switch {
		case q.Type == dnsmessage.TypeA && addr.Is4():
			err = b.AResource(rh, dnsmessage.AResource{A: addr.As4()})
		case q.Type == dnsmessage.TypeAAAA && addr.Is6():
			err = b.AAAAResource(rh, dnsmessage.AAAAResource{AAAA: addr.As16()})
		}
		if err != nil {
			return nil, err
		}
	}
	return b.Finish()
}
