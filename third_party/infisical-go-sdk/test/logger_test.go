package test

import (
	"bytes"
	"context"
	"io"
	"os"
	"testing"

	infisical "github.com/infisical/go-sdk"
)

const initLogMarker = "Infisical SDK log level set to debug"

// captureStdStreams swaps os.Stdout / os.Stderr for pipes, invokes fn, then
// restores the originals and returns whatever was written to each stream.
func captureStdStreams(t *testing.T, fn func()) (stdout, stderr []byte) {
	t.Helper()

	origStdout, origStderr := os.Stdout, os.Stderr

	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create stdout pipe: %v", err)
	}
	stderrR, stderrW, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create stderr pipe: %v", err)
	}

	os.Stdout, os.Stderr = stdoutW, stderrW
	defer func() {
		os.Stdout, os.Stderr = origStdout, origStderr
	}()

	fn()

	// Close writers so ReadAll on the readers terminates.
	err = stdoutW.Close()
	if err != nil {
		t.Fatalf("failed to close stdout pipe: %v", err)
	}

	err = stderrW.Close()
	if err != nil {
		t.Fatalf("failed to close stderr pipe: %v", err)
	}

	stdout, err = io.ReadAll(stdoutR)
	if err != nil {
		t.Fatalf("failed to read stdout pipe: %v", err)
	}
	stderr, err = io.ReadAll(stderrR)
	if err != nil {
		t.Fatalf("failed to read stderr pipe: %v", err)
	}
	return stdout, stderr
}

// TestLoggerWritesToStdoutWhenConfigured verifies that when Config.LogWriter is
// explicitly set to os.Stdout, the SDK's init-time debug log lands on stdout
// and nothing leaks onto stderr.
func TestLoggerWritesToStdoutWhenConfigured(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stdout, stderr := captureStdStreams(t, func() {
		_ = infisical.NewInfisicalClient(ctx, infisical.Config{
			LogLevel:  infisical.LogLevelDebug,
			LogWriter: os.Stdout,
		})
	})

	if !bytes.Contains(stdout, []byte(initLogMarker)) {
		t.Fatalf("expected init log on stdout, got stdout=%q stderr=%q", stdout, stderr)
	}
	if len(stderr) != 0 {
		t.Fatalf("expected stderr to be empty, got %q", stderr)
	}
}

// TestLoggerDefaultsToStderr pins down the current default: with no LogWriter
// set, SDK logs go to stderr, not stdout.
func TestLoggerDefaultsToStderr(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stdout, stderr := captureStdStreams(t, func() {
		_ = infisical.NewInfisicalClient(ctx, infisical.Config{
			LogLevel: infisical.LogLevelDebug,
		})
	})

	if !bytes.Contains(stderr, []byte(initLogMarker)) {
		t.Fatalf("expected init log on stderr, got stdout=%q stderr=%q", stdout, stderr)
	}
	if len(stdout) != 0 {
		t.Fatalf("expected stdout to be empty, got %q", stdout)
	}
}
