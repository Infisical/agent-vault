package sandbox

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

func baseConfig(t *testing.T) Config {
	t.Helper()
	return Config{
		ImageRef:    "agent-vault/sandbox:deadbeef1234",
		SessionID:   "abcd1234ef567890",
		WorkDir:     t.TempDir(),
		HostCAPath:  filepath.Join(t.TempDir(), "ca.pem"),
		NetworkName: "agent-vault-abcd1234ef567890",
		Env:         []string{"HTTPS_PROXY=https://tok:v@host.docker.internal:14322", "VAULT_MITM_PORT=14322"},
		CommandArgs: []string{"claude", "--version"},
	}
}

func hasFlagValue(args []string, flag, value string) bool {
	for i := 0; i < len(args)-1; i++ {
		if args[i] == flag && args[i+1] == value {
			return true
		}
	}
	return false
}

func TestBuildRunArgs_Default(t *testing.T) {
	cfg := baseConfig(t)
	args, err := BuildRunArgs(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if args[0] != "run" {
		t.Errorf("args[0] = %q, want run", args[0])
	}
	if !slices.Contains(args, "--rm") {
		t.Error("expected --rm by default")
	}
	if !slices.Contains(args, "-i") {
		t.Error("expected -i")
	}
	if slices.Contains(args, "-t") {
		t.Error("did not expect -t when AttachTTY=false")
	}
	if !slices.Contains(args, "--init") {
		t.Error("expected --init (tini) for clean signal fan-out")
	}
	if !hasFlagValue(args, "--network", cfg.NetworkName) {
		t.Error("expected --network with per-invocation network name")
	}
	if !hasFlagValue(args, "--cap-drop", "ALL") {
		t.Error("expected --cap-drop ALL")
	}
	for _, cap := range []string{"NET_ADMIN", "NET_RAW", "SETUID", "SETGID"} {
		if !hasFlagValue(args, "--cap-add", cap) {
			t.Errorf("expected --cap-add %s", cap)
		}
	}
	if !hasFlagValue(args, "--security-opt", "no-new-privileges") {
		t.Error("expected --security-opt no-new-privileges")
	}
	if !hasFlagValue(args, "--add-host", "host.docker.internal:host-gateway") {
		t.Error("expected --add-host host.docker.internal:host-gateway")
	}
	// Image + command are the tail.
	if args[len(args)-3] != cfg.ImageRef {
		t.Errorf("expected image just before command, got %v", args[len(args)-3:])
	}
	if args[len(args)-2] != "claude" || args[len(args)-1] != "--version" {
		t.Errorf("expected trailing command args, got %v", args[len(args)-2:])
	}
}

func TestBuildRunArgs_Keep(t *testing.T) {
	cfg := baseConfig(t)
	cfg.Keep = true
	args, err := BuildRunArgs(cfg)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if slices.Contains(args, "--rm") {
		t.Error("--keep should omit --rm")
	}
}

func TestBuildRunArgs_AttachTTY(t *testing.T) {
	cfg := baseConfig(t)
	cfg.AttachTTY = true
	args, err := BuildRunArgs(cfg)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if !slices.Contains(args, "-t") {
		t.Error("expected -t when AttachTTY=true")
	}
}

func TestBuildRunArgs_NoFirewall(t *testing.T) {
	cfg := baseConfig(t)
	cfg.NoFirewall = true
	args, err := BuildRunArgs(cfg)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if !hasFlagValue(args, "-e", "AGENT_VAULT_NO_FIREWALL=1") {
		t.Error("expected -e AGENT_VAULT_NO_FIREWALL=1 when NoFirewall=true")
	}
}

func TestBuildRunArgs_HomeVolumePerInvocation(t *testing.T) {
	cfg := baseConfig(t)
	args, _ := BuildRunArgs(cfg)
	want := "agent-vault-claude-home-" + cfg.SessionID + ":/home/claude/.claude"
	if !hasFlagValue(args, "-v", want) {
		t.Errorf("expected per-invocation volume %q in args", want)
	}
}

func TestBuildRunArgs_HomeVolumeShared(t *testing.T) {
	cfg := baseConfig(t)
	cfg.HomeVolumeShared = true
	args, _ := BuildRunArgs(cfg)
	want := "agent-vault-claude-home:/home/claude/.claude"
	if !hasFlagValue(args, "-v", want) {
		t.Errorf("expected shared volume %q in args", want)
	}
	bad := "agent-vault-claude-home-" + cfg.SessionID + ":/home/claude/.claude"
	if hasFlagValue(args, "-v", bad) {
		t.Errorf("shared mode should not produce per-invocation volume %q", bad)
	}
}

func TestBuildRunArgs_Env(t *testing.T) {
	cfg := baseConfig(t)
	args, _ := BuildRunArgs(cfg)
	for _, kv := range cfg.Env {
		if !hasFlagValue(args, "-e", kv) {
			t.Errorf("missing -e %q", kv)
		}
	}
}

func TestBuildRunArgs_CAMount(t *testing.T) {
	cfg := baseConfig(t)
	args, _ := BuildRunArgs(cfg)
	want := cfg.HostCAPath + ":" + ContainerCAPath + ":ro"
	if !hasFlagValue(args, "-v", want) {
		t.Errorf("expected CA bind mount %q", want)
	}
}

func TestBuildRunArgs_MissingRequired(t *testing.T) {
	for _, tc := range []struct {
		name  string
		mut   func(*Config)
		field string
	}{
		{"ImageRef", func(c *Config) { c.ImageRef = "" }, "ImageRef"},
		{"NetworkName", func(c *Config) { c.NetworkName = "" }, "NetworkName"},
		{"SessionID", func(c *Config) { c.SessionID = "" }, "SessionID"},
		{"WorkDir", func(c *Config) { c.WorkDir = "" }, "WorkDir"},
		{"HostCAPath", func(c *Config) { c.HostCAPath = "" }, "HostCAPath"},
		{"CommandArgs", func(c *Config) { c.CommandArgs = nil }, "CommandArgs"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := baseConfig(t)
			tc.mut(&cfg)
			_, err := BuildRunArgs(cfg)
			if err == nil {
				t.Fatalf("expected error for missing %s", tc.field)
			}
			if !strings.Contains(err.Error(), tc.field) {
				t.Errorf("err = %q, want to mention %q", err.Error(), tc.field)
			}
		})
	}
}

func TestBuildRunArgs_UserMountAccepted(t *testing.T) {
	// Use the work dir as a legitimate mount source — it's a real
	// directory outside $HOME/.agent-vault.
	cfg := baseConfig(t)
	src := cfg.WorkDir
	cfg.Mounts = []string{src + ":/data:ro"}
	args, err := BuildRunArgs(cfg)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	resolved, _ := filepath.EvalSymlinks(src)
	want := resolved + ":/data:ro"
	if !hasFlagValue(args, "-v", want) {
		t.Errorf("expected resolved --mount %q", want)
	}
}

// TestBuildRunArgs_RejectsCWDInsideAgentVaultDir pins the fix for the
// case where `vault run --sandbox=container` is invoked with the CWD
// inside ~/.agent-vault — the vault's encrypted CA key and database
// must not be bind-mounted into the container.
func TestBuildRunArgs_RejectsCWDInsideAgentVaultDir(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	vaultDir := filepath.Join(home, ".agent-vault")
	inside := filepath.Join(vaultDir, "some-project")
	if err := os.MkdirAll(inside, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	cfg := baseConfig(t)
	cfg.WorkDir = inside

	_, err := BuildRunArgs(cfg)
	if err == nil {
		t.Fatal("expected BuildRunArgs to reject a workdir inside ~/.agent-vault")
	}
	if !strings.Contains(err.Error(), ".agent-vault") {
		t.Errorf("err = %q, want to mention .agent-vault", err.Error())
	}
}

func TestParseAndValidateMount_RejectReservedContainerDst(t *testing.T) {
	tmp := t.TempDir()
	home := t.TempDir()
	for _, dst := range []string{"/workspace", "/workspace/sub", ContainerCAPath, "/home/claude/.claude", "/home/claude/.claude/x"} {
		t.Run(dst, func(t *testing.T) {
			_, err := parseAndValidateMount(tmp+":"+dst, home)
			if err == nil || !strings.Contains(err.Error(), "reserved") {
				t.Errorf("expected reserved-path error for dst=%s, got %v", dst, err)
			}
		})
	}
}

func TestParseAndValidateMount_RejectDockerSocket(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("docker socket path is POSIX-specific")
	}
	// We need an actual readable path to symlink to /var/run/docker.sock.
	// On most systems the socket may or may not exist; skip if absent.
	if _, err := os.Lstat("/var/run/docker.sock"); err != nil {
		t.Skip("/var/run/docker.sock not present; cannot test socket rejection")
	}
	_, err := parseAndValidateMount("/var/run/docker.sock:/sock", "")
	if err == nil || !strings.Contains(err.Error(), "docker socket") {
		t.Errorf("expected docker-socket rejection, got %v", err)
	}
}

// TestParseAndValidateMount_SymlinkLaunderingRejected is the substantive
// security test: a symlink under a normal-looking src must not launder
// a forbidden target ($HOME/.agent-vault) past the prefix check.
func TestParseAndValidateMount_SymlinkLaunderingRejected(t *testing.T) {
	home := t.TempDir()
	vaultDir := filepath.Join(home, ".agent-vault")
	if err := os.MkdirAll(vaultDir, 0o700); err != nil {
		t.Fatalf("mkdir vault: %v", err)
	}
	// A legitimate-looking src that actually resolves to $HOME/.agent-vault.
	link := filepath.Join(t.TempDir(), "innocent-looking")
	if err := os.Symlink(vaultDir, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	_, err := parseAndValidateMount(link+":/data", home)
	if err == nil {
		t.Fatal("expected rejection for symlink pointing into $HOME/.agent-vault")
	}
	if !strings.Contains(err.Error(), ".agent-vault") {
		t.Errorf("err = %q, want to mention .agent-vault", err.Error())
	}
}

func TestParseAndValidateMount_MalformedSpec(t *testing.T) {
	tmp := t.TempDir()
	for _, raw := range []string{
		"onlyone",
		tmp + ":/dst:ro:extra",
		"relative:/dst",
		tmp + ":relative",
		tmp + ":/dst:bogusmode",
	} {
		t.Run(raw, func(t *testing.T) {
			_, err := parseAndValidateMount(raw, "")
			if err == nil {
				t.Errorf("expected error for %q", raw)
			}
		})
	}
}
