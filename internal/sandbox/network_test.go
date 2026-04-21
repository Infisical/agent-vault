package sandbox

import (
	"net"
	"regexp"
	"runtime"
	"testing"
	"time"
)

func TestNewSessionID_Format(t *testing.T) {
	sid, err := NewSessionID()
	if err != nil {
		t.Fatalf("NewSessionID: %v", err)
	}
	if !regexp.MustCompile(`^[0-9a-f]{16}$`).MatchString(sid) {
		t.Errorf("sid = %q, want 16 lowercase hex chars", sid)
	}
	// Two calls must produce distinct IDs; probabilistic but safe in
	// practice with 8 bytes of randomness.
	other, _ := NewSessionID()
	if sid == other {
		t.Error("two NewSessionID calls returned the same value")
	}
}

func TestNetworkName_Format(t *testing.T) {
	if got := networkName("abcd1234ef567890"); got != "agent-vault-abcd1234ef567890" {
		t.Errorf("networkName = %q", got)
	}
	if want := NetworkNamePrefix + "X"; want != "agent-vault-X" {
		t.Errorf("prefix const drifted: %q", NetworkNamePrefix)
	}
}

func TestShouldPrune_GracePeriodProtectsRecentNetworks(t *testing.T) {
	now := time.Now()
	cutoff := now.Add(-60 * time.Second)
	tests := []struct {
		name       string
		info       networkInfo
		wantPrune  bool
		wantReason string
	}{
		{
			name:       "empty + old: prune",
			info:       networkInfo{Created: now.Add(-120 * time.Second)},
			wantPrune:  true,
			wantReason: "stale",
		},
		{
			name:       "empty + young (in grace): keep",
			info:       networkInfo{Created: now.Add(-10 * time.Second)},
			wantPrune:  false,
			wantReason: "grace-period (racing invocation may be attaching)",
		},
		{
			name:       "has containers + old: keep",
			info:       networkInfo{Created: now.Add(-120 * time.Second), Containers: map[string]any{"c1": nil}},
			wantPrune:  false,
			wantReason: "in use",
		},
		{
			name:       "has containers + young: keep",
			info:       networkInfo{Created: now.Add(-10 * time.Second), Containers: map[string]any{"c1": nil}},
			wantPrune:  false,
			wantReason: "in use",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := shouldPrune(tc.info, cutoff)
			if got != tc.wantPrune {
				t.Errorf("shouldPrune(%+v, cutoff=%v) = %v, want %v (%s)",
					tc.info, cutoff, got, tc.wantPrune, tc.wantReason)
			}
		})
	}
}

func TestParseNetworkInspect(t *testing.T) {
	data := []byte(`{"Created":"2026-04-20T12:34:56Z","Containers":{"abc123":{}}}`)
	got, err := parseNetworkInspect(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got.Containers) != 1 {
		t.Errorf("Containers len = %d, want 1", len(got.Containers))
	}
	if got.Created.IsZero() {
		t.Error("Created is zero")
	}
}

func TestParseNetworkInspect_EmptyContainers(t *testing.T) {
	data := []byte(`{"Created":"2026-04-20T12:34:56Z","Containers":{}}`)
	got, err := parseNetworkInspect(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got.Containers) != 0 {
		t.Errorf("expected empty Containers")
	}
}

func TestHostBindIP(t *testing.T) {
	// macOS/Windows: 0.0.0.0 so Docker Desktop can deliver
	// host.docker.internal traffic regardless of which host interface
	// its VM backend routes through.
	if runtime.GOOS == "darwin" || runtime.GOOS == "windows" {
		n := &Network{GatewayIP: net.ParseIP("172.20.0.1")}
		got := HostBindIP(n)
		if !got.Equal(net.IPv4(0, 0, 0, 0)) {
			t.Errorf("HostBindIP on %s = %v, want 0.0.0.0", runtime.GOOS, got)
		}
	}
	// Linux path (or whatever host we're on): gateway IP passthrough.
	if runtime.GOOS == "linux" {
		want := net.ParseIP("172.20.0.1")
		got := HostBindIP(&Network{GatewayIP: want})
		if !got.Equal(want) {
			t.Errorf("HostBindIP on linux = %v, want %v", got, want)
		}
		if HostBindIP(nil) != nil {
			t.Error("HostBindIP(nil) should return nil on linux")
		}
	}
}
