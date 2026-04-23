package netguard

import (
	"net"
	"testing"
)

func TestIsBlockedIP_AlwaysBlocked(t *testing.T) {
	// IMDS endpoints are blocked in both modes (whitelist does NOT bypass).
	imds := net.ParseIP("169.254.169.254")

	if !isBlockedIP(imds, ModePrivate, nil) {
		t.Error("169.254.169.254 should be blocked in private mode")
	}
	if !isBlockedIP(imds, ModePublic, nil) {
		t.Error("169.254.169.254 should be blocked in public mode")
	}

	// Even with whitelist containing the IMDS IP, it should still be blocked
	whitelist := []net.IPNet{parseCIDR("169.254.169.254/32")}
	if !isBlockedIP(imds, ModePublic, whitelist) {
		t.Error("169.254.169.254 should be blocked even when whitelisted (always-blocked takes precedence)")
	}

	// AWS IMDSv2 IPv6
	imdsV6 := net.ParseIP("fd00:ec2::254")
	if !isBlockedIP(imdsV6, ModePrivate, nil) {
		t.Error("fd00:ec2::254 should be blocked in private mode")
	}
}

func TestIsBlockedIP_PrivateMode(t *testing.T) {
	// Private ranges should NOT be blocked in private mode.
	cases := []string{
		"10.0.0.1",
		"172.16.0.1",
		"192.168.1.1",
		"127.0.0.1",
	}
	for _, ip := range cases {
		if isBlockedIP(net.ParseIP(ip), ModePrivate, nil) {
			t.Errorf("%s should NOT be blocked in private mode", ip)
		}
	}
}

func TestIsBlockedIP_PublicMode(t *testing.T) {
	// Private ranges should be blocked in public mode.
	blocked := []string{
		"10.0.0.1",
		"172.16.0.1",
		"192.168.1.1",
		"127.0.0.1",
		"0.0.0.0",
		"100.64.0.1",
	}
	for _, ip := range blocked {
		if !isBlockedIP(net.ParseIP(ip), ModePublic, nil) {
			t.Errorf("%s should be blocked in public mode", ip)
		}
	}

	// Public IPs should NOT be blocked.
	allowed := []string{
		"8.8.8.8",
		"1.1.1.1",
		"104.18.0.1",
	}
	for _, ip := range allowed {
		if isBlockedIP(net.ParseIP(ip), ModePublic, nil) {
			t.Errorf("%s should NOT be blocked in public mode", ip)
		}
	}
}

func TestIsBlockedIP_Whitelist(t *testing.T) {
	// Create whitelist: 10.163.0.0/16 and 192.168.1.1/32
	whitelist := []net.IPNet{
		parseCIDR("10.163.0.0/16"),
		parseCIDR("192.168.1.1/32"),
	}

	// IPs in whitelist should NOT be blocked in public mode
	whitelistedIPs := []string{
		"10.163.0.1",
		"10.163.255.254",
		"192.168.1.1",
	}
	for _, ip := range whitelistedIPs {
		if isBlockedIP(net.ParseIP(ip), ModePublic, whitelist) {
			t.Errorf("%s should NOT be blocked when whitelisted", ip)
		}
	}

	// IPs NOT in whitelist but in private ranges should be blocked
	blockedIPs := []string{
		"10.0.0.1",        // Different 10.x subnet, not whitelisted
		"192.168.1.2",     // Same subnet as whitelisted IP, but not exact match
		"172.16.0.1",      // Private, not whitelisted
	}
	for _, ip := range blockedIPs {
		if !isBlockedIP(net.ParseIP(ip), ModePublic, whitelist) {
			t.Errorf("%s should be blocked in public mode (not whitelisted)", ip)
		}
	}
}

func TestModeFromEnv(t *testing.T) {
	// Default is public.
	t.Setenv("AGENT_VAULT_NETWORK_MODE", "")
	if ModeFromEnv() != ModePublic {
		t.Error("empty AGENT_VAULT_NETWORK_MODE should default to public")
	}

	t.Setenv("AGENT_VAULT_NETWORK_MODE", "private")
	if ModeFromEnv() != ModePrivate {
		t.Error("AGENT_VAULT_NETWORK_MODE=private should return ModePrivate")
	}

	t.Setenv("AGENT_VAULT_NETWORK_MODE", "PRIVATE")
	if ModeFromEnv() != ModePrivate {
		t.Error("AGENT_VAULT_NETWORK_MODE=PRIVATE should return ModePrivate (case-insensitive)")
	}

	t.Setenv("AGENT_VAULT_NETWORK_MODE", "public")
	if ModeFromEnv() != ModePublic {
		t.Error("AGENT_VAULT_NETWORK_MODE=public should return ModePublic")
	}

	t.Setenv("AGENT_VAULT_NETWORK_MODE", "garbage")
	if ModeFromEnv() != ModePublic {
		t.Error("unrecognized AGENT_VAULT_NETWORK_MODE should default to public")
	}
}

func TestAllowedRangesFromEnv(t *testing.T) {
	// Empty env var returns nil
	t.Setenv("AGENT_VAULT_NETWORK_ALLOW_RANGES", "")
	ranges := AllowedRangesFromEnv()
	if ranges != nil {
		t.Error("empty AGENT_VAULT_NETWORK_ALLOW_RANGES should return nil")
	}

	// Single CIDR
	t.Setenv("AGENT_VAULT_NETWORK_ALLOW_RANGES", "10.163.0.0/16")
	ranges = AllowedRangesFromEnv()
	if len(ranges) != 1 {
		t.Fatalf("expected 1 range, got %d", len(ranges))
	}
	if !ranges[0].Contains(net.ParseIP("10.163.0.38")) {
		t.Error("10.163.0.0/16 should contain 10.163.0.38")
	}

	// Multiple CIDRs
	t.Setenv("AGENT_VAULT_NETWORK_ALLOW_RANGES", "10.163.0.0/16,192.168.1.0/24")
	ranges = AllowedRangesFromEnv()
	if len(ranges) != 2 {
		t.Fatalf("expected 2 ranges, got %d", len(ranges))
	}

	// Bare IP (auto-converted to /32)
	t.Setenv("AGENT_VAULT_NETWORK_ALLOW_RANGES", "192.168.1.1")
	ranges = AllowedRangesFromEnv()
	if len(ranges) != 1 {
		t.Fatalf("expected 1 range, got %d", len(ranges))
	}
	if !ranges[0].Contains(net.ParseIP("192.168.1.1")) {
		t.Error("bare IP 192.168.1.1 should be converted to /32 and contain itself")
	}
	if ranges[0].Contains(net.ParseIP("192.168.1.2")) {
		t.Error("192.168.1.1/32 should NOT contain 192.168.1.2")
	}

	// Mixed: CIDR and bare IP
	t.Setenv("AGENT_VAULT_NETWORK_ALLOW_RANGES", "10.163.0.0/16,192.168.1.1")
	ranges = AllowedRangesFromEnv()
	if len(ranges) != 2 {
		t.Fatalf("expected 2 ranges, got %d", len(ranges))
	}

	// With whitespace (should be trimmed)
	t.Setenv("AGENT_VAULT_NETWORK_ALLOW_RANGES", "  10.163.0.0/16  ,  192.168.1.1  ")
	ranges = AllowedRangesFromEnv()
	if len(ranges) != 2 {
		t.Fatalf("expected 2 ranges after trimming, got %d", len(ranges))
	}

	// Invalid entries are skipped
	t.Setenv("AGENT_VAULT_NETWORK_ALLOW_RANGES", "10.163.0.0/16,invalid,192.168.1.0/24")
	ranges = AllowedRangesFromEnv()
	if len(ranges) != 2 {
		t.Fatalf("expected 2 valid ranges (invalid skipped), got %d", len(ranges))
	}
}
