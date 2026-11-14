package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func writeRunProfiles(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "profiles.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write profiles: %v", err)
	}
	return path
}

func profileTestCommand() *cobra.Command {
	cmd := newRunCmd("agent-vault run")
	cmd.Flags().String("vault", "", "target vault")
	return cmd
}

func TestApplyRunProfile(t *testing.T) {
	path := writeRunProfiles(t, `profiles:
  planner:
    vault: planning
    ttl: 1800
    isolation: container
    image: agent-vault/planner:latest
    mounts:
      - ./specs:/workspace/specs:ro
    keep: true
`)
	cmd := profileTestCommand()
	if err := cmd.ParseFlags([]string{"--profile", "planner", "--profiles-file", path}); err != nil {
		t.Fatalf("parse flags: %v", err)
	}
	if err := applyRunProfile(cmd); err != nil {
		t.Fatalf("applyRunProfile: %v", err)
	}

	assertStringFlag(t, cmd, "vault", "planning")
	assertStringFlag(t, cmd, "ttl", "1800")
	assertStringFlag(t, cmd, "isolation", "container")
	assertStringFlag(t, cmd, "image", "agent-vault/planner:latest")
	mounts, _ := cmd.Flags().GetStringArray("mount")
	if len(mounts) != 1 || mounts[0] != "./specs:/workspace/specs:ro" {
		t.Fatalf("unexpected mounts: %v", mounts)
	}
	keep, _ := cmd.Flags().GetBool("keep")
	if !keep {
		t.Fatal("expected profile to enable keep")
	}
}

func TestRunProfileExplicitFlagsWin(t *testing.T) {
	path := writeRunProfiles(t, `profiles:
  worker:
    vault: profile-vault
    ttl: 1800
    isolation: container
    mounts: ["profile:/workspace/profile:ro"]
    keep: true
`)
	cmd := profileTestCommand()
	args := []string{
		"--profile", "worker",
		"--profiles-file", path,
		"--vault", "cli-vault",
		"--ttl", "600",
		"--mount", "cli:/workspace/cli:ro",
		"--keep=false",
	}
	if err := cmd.ParseFlags(args); err != nil {
		t.Fatalf("parse flags: %v", err)
	}
	if err := applyRunProfile(cmd); err != nil {
		t.Fatalf("applyRunProfile: %v", err)
	}

	assertStringFlag(t, cmd, "vault", "cli-vault")
	assertStringFlag(t, cmd, "ttl", "600")
	mounts, _ := cmd.Flags().GetStringArray("mount")
	if len(mounts) != 1 || mounts[0] != "cli:/workspace/cli:ro" {
		t.Fatalf("explicit mount did not replace profile mounts: %v", mounts)
	}
	keep, _ := cmd.Flags().GetBool("keep")
	if keep {
		t.Fatal("explicit --keep=false must override profile")
	}
}

func TestRunProfileRejectsUnknownFields(t *testing.T) {
	path := writeRunProfiles(t, `profiles:
  planner:
    vault: planning
    network: unrestricted
`)
	cmd := profileTestCommand()
	if err := cmd.ParseFlags([]string{"--profile", "planner", "--profiles-file", path}); err != nil {
		t.Fatalf("parse flags: %v", err)
	}
	err := applyRunProfile(cmd)
	if err == nil || !strings.Contains(err.Error(), "field network not found") {
		t.Fatalf("expected strict unknown-field error, got %v", err)
	}
}

func TestRunProfileValidationPrecedesSessionLookup(t *testing.T) {
	cmd := profileTestCommand()
	cmd.SetArgs([]string{"--profile", "missing", "--profiles-file", filepath.Join(t.TempDir(), "missing.yaml"), "--", "echo"})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "open run profiles") {
		t.Fatalf("expected profile file error before session lookup, got %v", err)
	}
}

func TestRunProfileIsolationConflictPrecedesSessionLookup(t *testing.T) {
	path := writeRunProfiles(t, `profiles:
  planner:
    isolation: host
    image: agent-vault/planner:latest
`)
	cmd := profileTestCommand()
	cmd.SetArgs([]string{"--profile", "planner", "--profiles-file", path, "--", "echo"})
	err := cmd.Execute()
	if err == nil || err.Error() != "--image requires --isolation=container" {
		t.Fatalf("expected isolation conflict before session lookup, got %v", err)
	}
}

func TestProfilesFileRequiresProfile(t *testing.T) {
	cmd := profileTestCommand()
	if err := cmd.ParseFlags([]string{"--profiles-file", "profiles.yaml"}); err != nil {
		t.Fatalf("parse flags: %v", err)
	}
	if err := applyRunProfile(cmd); err == nil || err.Error() != "--profiles-file requires --profile" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func assertStringFlag(t *testing.T, cmd *cobra.Command, name, want string) {
	t.Helper()
	flag := cmd.Flags().Lookup(name)
	if flag == nil {
		t.Fatalf("missing flag %s", name)
	}
	if got := flag.Value.String(); got != want {
		t.Fatalf("--%s = %q, want %q", name, got, want)
	}
}
