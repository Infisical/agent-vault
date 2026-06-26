package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWrapAndUnwrap(t *testing.T) {
	// Set up a temporary home directory so we don't mess with the actual user's home
	tmpHome, err := os.MkdirTemp("", "agent-vault-test-home")
	if err != nil {
		t.Fatalf("failed to create temp home directory: %v", err)
	}
	defer os.RemoveAll(tmpHome)

	// Save original HOME/USERPROFILE env vars
	origHome := os.Getenv("HOME")
	origUserProfile := os.Getenv("USERPROFILE")

	t.Setenv("HOME", tmpHome)
	t.Setenv("USERPROFILE", tmpHome)

	defer func() {
		os.Setenv("HOME", origHome)
		os.Setenv("USERPROFILE", origUserProfile)
	}()

	// 1. Test wrapping a command
	cmdName := "test-agent-cmd"
	output, err := executeCommand("wrap", cmdName)
	if err != nil {
		t.Fatalf("failed to execute wrap command: %v", err)
	}

	if !strings.Contains(output, "Shim created successfully") {
		t.Errorf("expected success message in output, got: %q", output)
	}

	shimsDir := filepath.Join(tmpHome, ".agent-vault", "shims")
	shimPath := filepath.Join(shimsDir, cmdName)

	if _, err := os.Stat(shimPath); os.IsNotExist(err) {
		t.Fatalf("shim file was not created at expected path: %s", shimPath)
	}

	// Verify content of the shim file
	content, err := os.ReadFile(shimPath)
	if err != nil {
		t.Fatalf("failed to read created shim file: %v", err)
	}

	expectedShebang := "#!/usr/bin/env sh"
	if !strings.Contains(string(content), expectedShebang) {
		t.Errorf("expected shebang %q in shim content, got: %q", expectedShebang, string(content))
	}

	expectedCommand := "run -- \"" + cmdName + "\""
	if !strings.Contains(string(content), expectedCommand) {
		t.Errorf("expected %q in shim content, got: %q", expectedCommand, string(content))
	}

	// 2. Test unwrapping the command
	output, err = executeCommand("unwrap", cmdName)
	if err != nil {
		t.Fatalf("failed to execute unwrap command: %v", err)
	}

	if !strings.Contains(output, "Shim removed successfully") {
		t.Errorf("expected success message in output, got: %q", output)
	}

	if _, err := os.Stat(shimPath); !os.IsNotExist(err) {
		t.Errorf("expected shim file to be deleted, but it still exists")
	}

	// 3. Test unwrapping a non-existent command
	_, err = executeCommand("unwrap", "non-existent")
	if err == nil {
		t.Error("expected error when unwrapping non-existent command, got nil")
	}
}
