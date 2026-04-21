package server

import (
	"net/http/httptest"
	"testing"
)

// TestIPKeyerLoopbackExempt verifies the server-wide ipKeyer skips
// rate-limit bucketing for loopback callers. Regression: `vault run`
// and the dashboard both hit public endpoints like /v1/mitm/ca.pem
// from 127.0.0.1 and tripped the 10-per-5min TierAuth ceiling.
func TestIPKeyerLoopbackExempt(t *testing.T) {
	s := &Server{}
	keyer := s.ipKeyer()

	cases := []struct {
		name    string
		remote  string
		wantKey string
	}{
		{"ipv4 loopback", "127.0.0.1:54321", ""},
		{"ipv4 loopback range", "127.5.6.7:54321", ""},
		{"ipv6 loopback", "[::1]:54321", ""},
		{"non-loopback ipv4", "203.0.113.42:54321", "ip:203.0.113.42"},
		{"non-loopback ipv6", "[2001:db8::1]:54321", "ip:2001:db8::1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/v1/mitm/ca.pem", nil)
			req.RemoteAddr = tc.remote
			if got := keyer(req); got != tc.wantKey {
				t.Fatalf("ipKeyer(%q) = %q, want %q", tc.remote, got, tc.wantKey)
			}
		})
	}
}
