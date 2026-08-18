package netguard

import (
	"context"
	"errors"
	"net"
	"reflect"
	"testing"
	"time"
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

func TestSafeDialContext_AddressFamilies(t *testing.T) {
	tests := []struct {
		name    string
		network string
		address string
		ip      net.IP
	}{
		{name: "IPv4", network: "tcp4", address: "127.0.0.1:0", ip: net.ParseIP("127.0.0.1")},
		{name: "IPv6", network: "tcp6", address: "[::1]:0", ip: net.ParseIP("::1")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			listener, err := net.Listen(tt.network, tt.address)
			if err != nil {
				if tt.network == "tcp6" {
					t.Skipf("IPv6 loopback is unavailable: %v", err)
				}
				t.Fatalf("listen: %v", err)
			}
			t.Cleanup(func() { _ = listener.Close() })

			_, port, err := net.SplitHostPort(listener.Addr().String())
			if err != nil {
				t.Fatalf("split listener address: %v", err)
			}
			lookup := func(context.Context, string) ([]net.IPAddr, error) {
				return []net.IPAddr{{IP: tt.ip}}, nil
			}
			dial := safeDialContext(true, time.Second, lookup, (&net.Dialer{Timeout: time.Second}).DialContext)

			conn, err := dial(context.Background(), "tcp", net.JoinHostPort("dual-stack.test", port))
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			_ = conn.Close()
		})
	}
}

func TestSafeDialContext_FallsBackInResolverOrder(t *testing.T) {
	tests := []struct {
		name string
		ips  []net.IPAddr
		want []string
	}{
		{
			name: "IPv6 to IPv4",
			ips:  []net.IPAddr{{IP: net.ParseIP("::1")}, {IP: net.ParseIP("127.0.0.1")}},
			want: []string{"[::1]:443", "127.0.0.1:443"},
		},
		{
			name: "IPv4 to IPv6",
			ips:  []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}, {IP: net.ParseIP("::1")}},
			want: []string{"127.0.0.1:443", "[::1]:443"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lookup := func(context.Context, string) ([]net.IPAddr, error) { return tt.ips, nil }
			var attempts []string
			var attemptBudgets []time.Duration
			dialContext := func(ctx context.Context, _, addr string) (net.Conn, error) {
				attempts = append(attempts, addr)
				deadline, _ := ctx.Deadline()
				attemptBudgets = append(attemptBudgets, time.Until(deadline))
				if len(attempts) == 1 {
					return nil, errors.New("first family unavailable")
				}
				client, server := net.Pipe()
				_ = server.Close()
				return client, nil
			}
			dial := safeDialContext(true, time.Second, lookup, dialContext)

			conn, err := dial(context.Background(), "tcp", "dual-stack.test:443")
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			_ = conn.Close()

			if !reflect.DeepEqual(attempts, tt.want) {
				t.Fatalf("dial attempts = %v, want %v", attempts, tt.want)
			}
			if attemptBudgets[1] <= attemptBudgets[0] {
				t.Fatalf("second attempt budget = %v, want more than first attempt budget %v", attemptBudgets[1], attemptBudgets[0])
			}
		})
	}
}

func TestSafeDialContext_ValidatesAllAddressesBeforeDialing(t *testing.T) {
	t.Setenv("AGENT_VAULT_NETWORK_ALLOWLIST", "")
	lookup := func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("8.8.8.8")}, {IP: net.ParseIP("127.0.0.1")}}, nil
	}
	dialCalled := false
	dialContext := func(context.Context, string, string) (net.Conn, error) {
		dialCalled = true
		return nil, errors.New("unexpected dial")
	}
	dial := safeDialContext(false, time.Second, lookup, dialContext)

	_, err := dial(context.Background(), "tcp", "mixed-policy.test:443")
	if err == nil {
		t.Fatal("expected network policy error")
	}
	if dialCalled {
		t.Fatal("dial was attempted before every resolved address passed policy validation")
	}
}

func TestSafeDialContext_ReturnsAllConnectionFailures(t *testing.T) {
	firstErr := errors.New("IPv6 unavailable")
	secondErr := errors.New("IPv4 unavailable")
	lookup := func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("::1")}, {IP: net.ParseIP("127.0.0.1")}}, nil
	}
	attempt := 0
	dialContext := func(context.Context, string, string) (net.Conn, error) {
		attempt++
		if attempt == 1 {
			return nil, firstErr
		}
		return nil, secondErr
	}
	dial := safeDialContext(true, time.Second, lookup, dialContext)

	_, err := dial(context.Background(), "tcp", "unreachable.test:443")
	if !errors.Is(err, firstErr) || !errors.Is(err, secondErr) {
		t.Fatalf("error %v does not preserve both connection failures", err)
	}
}

func TestSafeDialContext_StopsFallbackOnCancellation(t *testing.T) {
	lookup := func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("::1")}, {IP: net.ParseIP("127.0.0.1")}}, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	attempts := 0
	dialContext := func(ctx context.Context, _, _ string) (net.Conn, error) {
		attempts++
		cancel()
		<-ctx.Done()
		return nil, ctx.Err()
	}
	dial := safeDialContext(true, time.Second, lookup, dialContext)

	_, err := dial(ctx, "tcp", "canceled.test:443")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
	if attempts != 1 {
		t.Fatalf("dial attempts = %d, want 1", attempts)
	}
}

func TestSafeDialContext_SharesRemainingTimeoutAcrossAddresses(t *testing.T) {
	const timeout = 100 * time.Millisecond
	lookup := func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("::1")}, {IP: net.ParseIP("127.0.0.1")}}, nil
	}
	attempts := 0
	dialContext := func(ctx context.Context, _, _ string) (net.Conn, error) {
		attempts++
		if attempts == 1 {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		client, server := net.Pipe()
		_ = server.Close()
		return client, nil
	}
	dial := safeDialContext(true, timeout, lookup, dialContext)

	started := time.Now()
	conn, err := dial(context.Background(), "tcp", "dual-stack.test:443")
	elapsed := time.Since(started)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_ = conn.Close()

	if attempts != 2 {
		t.Fatalf("dial attempts = %d, want 2", attempts)
	}
	if elapsed >= timeout {
		t.Fatalf("dial elapsed = %v, want less than total timeout %v", elapsed, timeout)
	}
}

func TestSafeDialContext_PreservesEarlierCallerDeadline(t *testing.T) {
	const callerTimeout = 25 * time.Millisecond
	lookup := func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("::1")}}, nil
	}
	attempts := 0
	dialContext := func(ctx context.Context, _, _ string) (net.Conn, error) {
		attempts++
		<-ctx.Done()
		return nil, ctx.Err()
	}
	dial := safeDialContext(true, time.Second, lookup, dialContext)
	ctx, cancel := context.WithTimeout(context.Background(), callerTimeout)
	defer cancel()

	started := time.Now()
	_, err := dial(ctx, "tcp", "deadline.test:443")
	elapsed := time.Since(started)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want context.DeadlineExceeded", err)
	}
	if attempts != 1 {
		t.Fatalf("dial attempts = %d, want 1", attempts)
	}
	if elapsed >= 2*callerTimeout {
		t.Fatalf("dial elapsed = %v, want bounded by caller deadline %v", elapsed, callerTimeout)
	}
}
