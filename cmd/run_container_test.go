package cmd

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestSandboxFlagsRegistered(t *testing.T) {
	vCmd := findSubcommand(rootCmd, "vault")
	if vCmd == nil {
		t.Fatal("vault command not found")
	}
	rCmd := findSubcommand(vCmd, "run")
	if rCmd == nil {
		t.Fatal("vault run subcommand not found")
	}

	for _, name := range []string{"sandbox", "image", "mount", "keep", "no-firewall", "home-volume-shared", "share-agent-dir"} {
		if rCmd.Flags().Lookup(name) == nil {
			t.Errorf("expected vault run flag --%s to be registered", name)
		}
	}

	// --sandbox must be pflag.Value-typed so invalid values fail at parse time.
	f := rCmd.Flags().Lookup("sandbox")
	if f == nil {
		t.Fatal("--sandbox not registered")
	}
	if err := f.Value.Set("not-a-mode"); err == nil {
		t.Error("expected --sandbox to reject invalid values at flag-parse time")
	}
}

func TestSandboxMode_Set(t *testing.T) {
	var m SandboxMode
	for _, v := range []string{"process", "container"} {
		if err := (&m).Set(v); err != nil {
			t.Errorf("Set(%q): unexpected err %v", v, err)
		}
		if string(m) != v {
			t.Errorf("after Set(%q), m = %q", v, m)
		}
	}
	for _, bad := range []string{"", "Process", "CONTAINER", "vm", "docker"} {
		err := (&m).Set(bad)
		if err == nil {
			t.Errorf("Set(%q): expected error, got nil", bad)
			continue
		}
		if !strings.Contains(err.Error(), "must be one of") {
			t.Errorf("Set(%q) error = %q, want substring 'must be one of'", bad, err)
		}
	}
}

func TestValidateSandboxFlagConflicts(t *testing.T) {
	tests := []struct {
		name    string
		mode    SandboxMode
		setArgs []string
		wantErr string // substring; empty means expect nil
	}{
		{"process mode, no container flags set", SandboxProcess, nil, ""},
		{"container mode, all flags allowed", SandboxContainer, []string{"--image=foo", "--keep", "--no-firewall", "--home-volume-shared", "--mount=/a:/b"}, ""},
		{"process mode rejects --image", SandboxProcess, []string{"--image=foo"}, "--image requires --sandbox=container"},
		{"process mode rejects --mount", SandboxProcess, []string{"--mount=/a:/b"}, "--mount requires --sandbox=container"},
		{"process mode rejects --keep", SandboxProcess, []string{"--keep"}, "--keep requires --sandbox=container"},
		{"process mode rejects --no-firewall", SandboxProcess, []string{"--no-firewall"}, "--no-firewall requires --sandbox=container"},
		{"process mode rejects --home-volume-shared", SandboxProcess, []string{"--home-volume-shared"}, "--home-volume-shared requires --sandbox=container"},
		{"process mode rejects --share-agent-dir", SandboxProcess, []string{"--share-agent-dir"}, "--share-agent-dir requires --sandbox=container"},
		{"container mode accepts --share-agent-dir alone", SandboxContainer, []string{"--share-agent-dir"}, ""},
		{"container mode rejects --no-mitm", SandboxContainer, []string{"--no-mitm"}, "--no-mitm requires --sandbox=process"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cmd := newRunCommandForTest()
			if err := cmd.ParseFlags(tc.setArgs); err != nil {
				t.Fatalf("ParseFlags(%v): %v", tc.setArgs, err)
			}
			err := validateSandboxFlagConflicts(cmd, tc.mode)
			if tc.wantErr == "" {
				if err != nil {
					t.Errorf("expected nil err, got %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("err = %q, want substring %q", err.Error(), tc.wantErr)
			}
		})
	}
}

func TestValidateContainerFlagCombos(t *testing.T) {
	tests := []struct {
		name    string
		setArgs []string
		wantErr string
	}{
		{"neither set", nil, ""},
		{"only home-volume-shared", []string{"--home-volume-shared"}, ""},
		{"only share-agent-dir", []string{"--share-agent-dir"}, ""},
		{"both set — mutually exclusive", []string{"--home-volume-shared", "--share-agent-dir"}, "mutually exclusive"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cmd := newRunCommandForTest()
			if err := cmd.ParseFlags(tc.setArgs); err != nil {
				t.Fatalf("ParseFlags: %v", err)
			}
			err := validateContainerFlagCombos(cmd)
			if tc.wantErr == "" {
				if err != nil {
					t.Errorf("expected nil, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("err = %v, want substring %q", err, tc.wantErr)
			}
		})
	}
}

// newRunCommandForTest isolates flag `Changed` state per subtest; runCmd
// itself would leak pflag state across ParseFlags calls.
func newRunCommandForTest() *cobra.Command {
	var sbx SandboxMode
	c := &cobra.Command{Use: "run-test"}
	c.Flags().Var(&sbx, "sandbox", "")
	c.Flags().String("image", "", "")
	c.Flags().StringArray("mount", nil, "")
	c.Flags().Bool("keep", false, "")
	c.Flags().Bool("no-firewall", false, "")
	c.Flags().Bool("home-volume-shared", false, "")
	c.Flags().Bool("share-agent-dir", false, "")
	c.Flags().Bool("no-mitm", false, "")
	return c
}

func TestAgentContainerInfo_KnownAgents(t *testing.T) {
	tests := []struct {
		cmd            string
		wantBaseDir    string
		wantStateDir   string
		wantSiblingCfg string
		wantHostSetup  bool
	}{
		{"claude", ".claude", ".claude", ".claude.json", true},
		{"cursor", ".cursor", ".cursor", "", false},
		{"agent", ".cursor", ".cursor", "", false},
		{"codex", ".agents", ".codex", "", false},
		{"hermes", ".hermes", ".hermes", "", false},
		{"opencode", ".opencode", ".opencode", "", false},
		{"/usr/local/bin/codex", ".agents", ".codex", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.cmd, func(t *testing.T) {
			info, ok := agentContainerInfo(tc.cmd)
			if !ok {
				t.Fatalf("agentContainerInfo(%q): expected known agent", tc.cmd)
			}
			if info.baseDir != tc.wantBaseDir {
				t.Errorf("baseDir = %q, want %q", info.baseDir, tc.wantBaseDir)
			}
			if got := info.effectiveStateDir(); got != tc.wantStateDir {
				t.Errorf("effectiveStateDir() = %q, want %q", got, tc.wantStateDir)
			}
			if info.siblingConfig != tc.wantSiblingCfg {
				t.Errorf("siblingConfig = %q, want %q", info.siblingConfig, tc.wantSiblingCfg)
			}
			if (info.hostSetup != nil) != tc.wantHostSetup {
				t.Errorf("hostSetup != nil = %v, want %v", info.hostSetup != nil, tc.wantHostSetup)
			}
		})
	}
}

func TestAgentContainerInfo_Unknown(t *testing.T) {
	if _, ok := agentContainerInfo("unknown-agent"); ok {
		t.Fatal("expected unknown-agent to be rejected")
	}
}

func TestRequireCustomImageForNonClaudeShare(t *testing.T) {
	claude, _ := agentContainerInfo("claude")
	codex, _ := agentContainerInfo("codex")
	cursor, _ := agentContainerInfo("cursor")

	tests := []struct {
		name    string
		agent   knownAgent
		image   string
		cmdName string
		wantErr string
	}{
		{"claude with bundled image passes", claude, "", "claude", ""},
		{"claude with custom image passes", claude, "my/image:v1", "claude", ""},
		{"codex with bundled image is rejected", codex, "", "codex", "--image"},
		{"codex with custom image passes", codex, "my/codex:v1", "codex", ""},
		{"cursor with bundled image is rejected", cursor, "", "cursor", "--image"},
		{"cursor with custom image passes", cursor, "my/cursor:v1", "cursor", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := requireCustomImageForNonClaudeShare(tc.agent, tc.image, tc.cmdName)
			if tc.wantErr == "" {
				if err != nil {
					t.Errorf("expected nil, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("err = %v, want substring %q", err, tc.wantErr)
			}
			if err != nil && !strings.Contains(err.Error(), tc.cmdName) {
				t.Errorf("err = %v, want substring %q (the command name)", err, tc.cmdName)
			}
		})
	}
}

func TestKnownAgentBases(t *testing.T) {
	got := knownAgentBases()
	want := []string{"claude", "cursor", "agent", "codex", "hermes", "opencode"}
	if len(got) != len(want) {
		t.Fatalf("len(knownAgentBases) = %d, want %d (%v)", len(got), len(want), got)
	}
	for _, base := range want {
		if !slices.Contains(got, base) {
			t.Errorf("knownAgentBases missing %q in %v", base, got)
		}
	}
	for _, base := range got {
		if strings.Contains(base, string(filepath.Separator)) {
			t.Errorf("knownAgentBases entry %q must be a base command", base)
		}
	}
}
