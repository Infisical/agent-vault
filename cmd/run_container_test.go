package cmd

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
)


func TestIsolationFlagsRegistered(t *testing.T) {
	vCmd := findSubcommand(rootCmd, "vault")
	if vCmd == nil {
		t.Fatal("vault command not found")
	}
	rCmd := findSubcommand(vCmd, "run")
	if rCmd == nil {
		t.Fatal("vault run subcommand not found")
	}

	for _, name := range []string{"isolation", "image", "mount", "keep", "no-firewall", "home-volume-shared", "share-agent-dir"} {
		if rCmd.Flags().Lookup(name) == nil {
			t.Errorf("expected vault run flag --%s to be registered", name)
		}
	}

	// --isolation must be pflag.Value-typed so invalid values fail at parse time.
	f := rCmd.Flags().Lookup("isolation")
	if f == nil {
		t.Fatal("--isolation not registered")
	}
	if err := f.Value.Set("not-a-mode"); err == nil {
		t.Error("expected --isolation to reject invalid values at flag-parse time")
	}
}

func TestIsolationMode_Set(t *testing.T) {
	var m IsolationMode
	for _, v := range []string{"host", "container"} {
		if err := (&m).Set(v); err != nil {
			t.Errorf("Set(%q): unexpected err %v", v, err)
		}
		if string(m) != v {
			t.Errorf("after Set(%q), m = %q", v, m)
		}
	}
	for _, bad := range []string{"", "Host", "CONTAINER", "vm", "docker", "process"} {
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

func TestValidateIsolationFlagConflicts(t *testing.T) {
	tests := []struct {
		name    string
		mode    IsolationMode
		setArgs []string
		wantErr string // substring; empty means expect nil
	}{
		{"host mode, no container flags set", IsolationHost, nil, ""},
		{"container mode, all flags allowed", IsolationContainer, []string{"--image=foo", "--keep", "--no-firewall", "--home-volume-shared", "--mount=/a:/b"}, ""},
		{"host mode rejects --image", IsolationHost, []string{"--image=foo"}, "--image requires --isolation=container"},
		{"host mode rejects --mount", IsolationHost, []string{"--mount=/a:/b"}, "--mount requires --isolation=container"},
		{"host mode rejects --keep", IsolationHost, []string{"--keep"}, "--keep requires --isolation=container"},
		{"host mode rejects --no-firewall", IsolationHost, []string{"--no-firewall"}, "--no-firewall requires --isolation=container"},
		{"host mode rejects --home-volume-shared", IsolationHost, []string{"--home-volume-shared"}, "--home-volume-shared requires --isolation=container"},
		{"host mode rejects --share-agent-dir", IsolationHost, []string{"--share-agent-dir"}, "--share-agent-dir requires --isolation=container"},
		{"container mode accepts --share-agent-dir alone", IsolationContainer, []string{"--share-agent-dir"}, ""},
		{"container mode rejects --no-mitm", IsolationContainer, []string{"--no-mitm"}, "--no-mitm requires --isolation=host"},
		{"container mode rejects --no-proxy", IsolationContainer, []string{"--no-proxy=ai"}, "--no-proxy requires --isolation=host"},
		{"host mode accepts --no-proxy", IsolationHost, []string{"--no-proxy=ai"}, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cmd := newRunCommandForTest()
			if err := cmd.ParseFlags(tc.setArgs); err != nil {
				t.Fatalf("ParseFlags(%v): %v", tc.setArgs, err)
			}
			err := validateIsolationFlagConflicts(cmd, tc.mode)
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

// TestValidateIsolationFlagConflicts_NoProxyEnvVarBlocked covers the
// env-var twin of --no-proxy. Without this guard, AGENT_VAULT_NO_PROXY
// would silently slip past the flag walk in container mode, the in-
// container client would dial the bypassed host directly, and the
// iptables egress lock would drop the connection — leaving the
// operator to chase an opaque connection error.
func TestValidateIsolationFlagConflicts_NoProxyEnvVarBlocked(t *testing.T) {
	t.Setenv("AGENT_VAULT_NO_PROXY", "ai")
	cmd := newRunCommandForTest()
	if err := cmd.ParseFlags(nil); err != nil {
		t.Fatalf("ParseFlags: %v", err)
	}
	err := validateIsolationFlagConflicts(cmd, IsolationContainer)
	if err == nil || !strings.Contains(err.Error(), "AGENT_VAULT_NO_PROXY") {
		t.Errorf("err = %v, want substring AGENT_VAULT_NO_PROXY", err)
	}
}

// TestValidateIsolationFlagConflicts_NoProxyEnvVarAllowedInHost guards
// the inverse: in host mode, AGENT_VAULT_NO_PROXY is the intended
// extension mechanism and must not trigger the rejection.
func TestValidateIsolationFlagConflicts_NoProxyEnvVarAllowedInHost(t *testing.T) {
	t.Setenv("AGENT_VAULT_NO_PROXY", "ai")
	cmd := newRunCommandForTest()
	if err := cmd.ParseFlags(nil); err != nil {
		t.Fatalf("ParseFlags: %v", err)
	}
	if err := validateIsolationFlagConflicts(cmd, IsolationHost); err != nil {
		t.Errorf("expected nil err in host mode, got %v", err)
	}
}

// newRunCommandForTest isolates flag `Changed` state per subtest; runCmd
// itself would leak pflag state across ParseFlags calls.
func newRunCommandForTest() *cobra.Command {
	var iso IsolationMode
	c := &cobra.Command{Use: "run-test"}
	c.Flags().Var(&iso, "isolation", "")
	c.Flags().String("image", "", "")
	c.Flags().StringArray("mount", nil, "")
	c.Flags().Bool("keep", false, "")
	c.Flags().Bool("no-firewall", false, "")
	c.Flags().Bool("home-volume-shared", false, "")
	c.Flags().Bool("share-agent-dir", false, "")
	c.Flags().Bool("no-mitm", false, "")
	c.Flags().StringSlice("no-proxy", nil, "")
	return c
}
