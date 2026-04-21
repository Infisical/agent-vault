package cmd

import (
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

	for _, name := range []string{"sandbox", "image", "mount", "keep", "no-firewall", "home-volume-shared"} {
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
	return c
}
