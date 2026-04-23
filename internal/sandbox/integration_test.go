//go:build docker_integration

// To run: go test -tags docker_integration ./internal/sandbox/ -run Integration -v
// Requires: docker daemon, network access to node:22-bookworm-slim +
// debian apt mirrors on first run (for the image build).
package sandbox

import (
	"bytes"
	"context"
	"io"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func requireDocker(t *testing.T) {
	t.Helper()
	if err := exec.Command("docker", "version").Run(); err != nil {
		t.Skipf("docker unavailable: %v", err)
	}
}

func newTestSessionID(t *testing.T) string {
	t.Helper()
	sid, err := NewSessionID()
	if err != nil {
		t.Fatalf("NewSessionID: %v", err)
	}
	return sid
}

func cleanupNetwork(t *testing.T, name string) {
	t.Helper()
	cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = exec.CommandContext(cleanup, "docker", "network", "rm", name).Run()
}

func TestIntegration_NetworkCRUD(t *testing.T) {
	requireDocker(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	sid := newTestSessionID(t)
	n, err := CreatePerInvocationNetwork(ctx, sid)
	if err != nil {
		t.Fatalf("CreatePerInvocationNetwork: %v", err)
	}
	defer cleanupNetwork(t, n.Name)

	if n.Name != "agent-vault-"+sid {
		t.Errorf("name = %q, want agent-vault-%s", n.Name, sid)
	}
	if n.GatewayIP == nil || n.GatewayIP.To4() == nil {
		t.Errorf("gateway IP = %v, want a non-nil IPv4", n.GatewayIP)
	}

	// Label roundtrip: `docker network inspect` output must show our
	// label, proving PruneStaleNetworks's filter will match.
	out, err := exec.CommandContext(ctx, "docker", "network", "inspect", n.Name,
		"--format", "{{index .Labels \""+NetworkLabelKey+"\"}}").Output()
	if err != nil {
		t.Fatalf("inspect label: %v", err)
	}
	if got := strings.TrimSpace(string(out)); got != NetworkLabelValue {
		t.Errorf("label %q = %q, want %q", NetworkLabelKey, got, NetworkLabelValue)
	}

	if err := RemoveNetwork(ctx, n.Name); err != nil {
		t.Errorf("RemoveNetwork: %v", err)
	}
}

// TestIntegration_PruneRespectsGrace verifies the race fix: a network
// Created just now must NOT be pruned when grace > its age.
func TestIntegration_PruneRespectsGrace(t *testing.T) {
	requireDocker(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	sid := newTestSessionID(t)
	n, err := CreatePerInvocationNetwork(ctx, sid)
	if err != nil {
		t.Fatalf("CreatePerInvocationNetwork: %v", err)
	}
	defer cleanupNetwork(t, n.Name)

	// Grace 60s: our just-created network must survive a prune pass.
	if err := PruneStaleNetworks(ctx, 60*time.Second); err != nil {
		t.Fatalf("PruneStaleNetworks: %v", err)
	}
	if !networkExists(ctx, n.Name) {
		t.Error("newly-created network pruned despite being within grace period — the grace-window fix regressed")
	}

	// Grace 0: now it's eligible for prune.
	if err := PruneStaleNetworks(ctx, 1*time.Nanosecond); err != nil {
		t.Fatalf("PruneStaleNetworks (0 grace): %v", err)
	}
	if networkExists(ctx, n.Name) {
		t.Error("empty network outside grace window was not pruned")
	}
}

func networkExists(ctx context.Context, name string) bool {
	return exec.CommandContext(ctx, "docker", "network", "inspect", name).Run() == nil
}

// TestIntegration_ImageBuildCaches covers EnsureImage's fast path: the
// second call must skip `docker build`.
func TestIntegration_ImageBuildCaches(t *testing.T) {
	requireDocker(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	var out1 bytes.Buffer
	ref1, err := EnsureImage(ctx, "", &out1)
	if err != nil {
		t.Fatalf("EnsureImage (first): %v", err)
	}
	if !strings.HasPrefix(ref1, sandboxImageRepo+":") {
		t.Errorf("ref = %q, want %s:<hash>", ref1, sandboxImageRepo)
	}

	var out2 bytes.Buffer
	ref2, err := EnsureImage(ctx, "", &out2)
	if err != nil {
		t.Fatalf("EnsureImage (second): %v", err)
	}
	if ref2 != ref1 {
		t.Errorf("second call ref = %q, want %q (deterministic)", ref2, ref1)
	}
	if out2.Len() != 0 {
		t.Errorf("cached second call should not print build output, got %q", out2.String())
	}
}

// runInFirewalledContainer runs a one-off bash command inside the sandbox
// image on a per-invocation network with init-firewall.sh already applied.
// The network is cleaned up on test exit.
func runInFirewalledContainer(t *testing.T, ctx context.Context, shellCmd string) ([]byte, error) {
	t.Helper()
	imageRef, err := EnsureImage(ctx, "", io.Discard)
	if err != nil {
		t.Fatalf("EnsureImage: %v", err)
	}
	sid := newTestSessionID(t)
	n, err := CreatePerInvocationNetwork(ctx, sid)
	if err != nil {
		t.Fatalf("CreatePerInvocationNetwork: %v", err)
	}
	t.Cleanup(func() { cleanupNetwork(t, n.Name) })
	return exec.CommandContext(ctx, "docker", "run", "--rm",
		"--network", n.Name,
		"--cap-drop=ALL", "--cap-add=NET_ADMIN", "--cap-add=NET_RAW",
		"--security-opt=no-new-privileges",
		"--add-host=host.docker.internal:host-gateway",
		"-e", "VAULT_HTTP_PORT=14321",
		"-e", "VAULT_MITM_PORT=14322",
		"--entrypoint", "/bin/bash",
		imageRef,
		"-c",
		"/usr/local/sbin/init-firewall.sh >/dev/null 2>&1 && "+shellCmd,
	).CombinedOutput()
}

// TestIntegration_EgressBlockedEndToEnd is the big-hammer test: it also
// proves init-firewall.sh is actually executed (as opposed to
// runInFirewalledContainer's asserted-on-exit behavior) — curl to a
// routable IPv4 literal must fail because iptables DROPs the SYN.
func TestIntegration_EgressBlockedEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("skip in -short mode; builds the sandbox image")
	}
	requireDocker(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	out, err := runInFirewalledContainer(t, ctx,
		"curl --max-time 3 -fsS https://1.1.1.1 && echo SHOULD_NOT_REACH || echo BLOCKED")
	if err != nil {
		t.Fatalf("docker run: %v\n%s", err, string(out))
	}
	if !strings.Contains(string(out), "BLOCKED") {
		t.Errorf("expected BLOCKED in output, got:\n%s", string(out))
	}
	if strings.Contains(string(out), "SHOULD_NOT_REACH") {
		t.Errorf("container reached external network despite init-firewall; output:\n%s", string(out))
	}
}

// TestIntegration_EgressBlocked_Bypasses is the "bypasses the threat
// model actually cares about" suite. A non-cooperative sandbox has to
// block malicious escape attempts, not just well-behaved clients — each
// case probes a different channel a compromised agent might try.
//
// Each probe prints either REACHED (bypass worked; test fails) or
// BLOCKED (firewall held; test passes).
func TestIntegration_EgressBlocked_Bypasses(t *testing.T) {
	if testing.Short() {
		t.Skip("skip in -short mode; builds the sandbox image")
	}
	requireDocker(t)

	// Python-based UDP probe: sendto may succeed locally (iptables drops
	// silently), but recvfrom must time out. A functioning bypass would
	// receive the DNS reply and print REACHED.
	const udpProbe = `python3 -c 'import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); ` +
		`s.settimeout(2); ` +
		`s.sendto(b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01",("8.8.8.8",53)); ` +
		`print("REACHED" if s.recvfrom(4096) else "BLOCKED")' 2>&1 || echo BLOCKED`

	cases := []struct {
		name, cmd, reason string
	}{
		{"IPv6Literal",
			"curl --max-time 3 -fsS 'https://[2606:4700:4700::1111]' >/dev/null && echo REACHED || echo BLOCKED",
			"IPv6 egress dropped by ip6tables"},
		{"UDP",
			udpProbe,
			"UDP dropped by iptables OUTPUT policy"},
		{"ICMP",
			"ping -c1 -W1 1.1.1.1 >/dev/null 2>&1 && echo REACHED || echo BLOCKED",
			"ICMP has no OUTPUT ACCEPT rule"},
		{"ExplicitNoProxy",
			"curl --max-time 3 -fsS --noproxy '*' https://example.com >/dev/null && echo REACHED || echo BLOCKED",
			"--noproxy bypass must still hit kernel-level block"},
		{"ProxyEnvStripped",
			"env -u HTTPS_PROXY -u https_proxy curl --max-time 3 -fsS https://example.com >/dev/null && echo REACHED || echo BLOCKED",
			"env-stripped bypass must still hit kernel-level block"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			out, err := runInFirewalledContainer(t, ctx, tc.cmd)
			if err != nil {
				t.Fatalf("docker run: %v\n%s", err, string(out))
			}
			if !strings.Contains(string(out), "BLOCKED") || strings.Contains(string(out), "REACHED") {
				t.Errorf("expected BLOCKED (%s), got:\n%s", tc.reason, string(out))
			}
		})
	}
}

// TestIntegration_EntrypointDropsToClaudeUser proves that gosu actually
// drops privileges under --security-opt=no-new-privileges. If this
// breaks, every "container runs as claude, not root" claim in the
// threat model is wrong.
func TestIntegration_EntrypointDropsToClaudeUser(t *testing.T) {
	if testing.Short() {
		t.Skip("skip in -short mode; builds the sandbox image")
	}
	requireDocker(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	imageRef, err := EnsureImage(ctx, "", io.Discard)
	if err != nil {
		t.Fatalf("EnsureImage: %v", err)
	}
	sid := newTestSessionID(t)
	n, err := CreatePerInvocationNetwork(ctx, sid)
	if err != nil {
		t.Fatalf("CreatePerInvocationNetwork: %v", err)
	}
	defer cleanupNetwork(t, n.Name)

	out, err := exec.CommandContext(ctx, "docker", "run", "--rm",
		"--network", n.Name,
		"--cap-drop=ALL", "--cap-add=NET_ADMIN", "--cap-add=NET_RAW",
		"--security-opt=no-new-privileges",
		"--add-host=host.docker.internal:host-gateway",
		"-e", "VAULT_HTTP_PORT=14321",
		"-e", "VAULT_MITM_PORT=14322",
		"-e", "AGENT_VAULT_NO_FIREWALL=1", // test identity, not firewall
		imageRef,
		"whoami",
	).CombinedOutput()
	if err != nil {
		t.Fatalf("docker run whoami: %v\n%s", err, string(out))
	}
	if user := strings.TrimSpace(string(out)); user != "claude" {
		t.Errorf("whoami = %q, want claude (gosu × no-new-privileges regression?)", user)
	}
}
