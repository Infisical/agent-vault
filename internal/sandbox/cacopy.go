package sandbox

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	// sandboxDirName lives under ~/.agent-vault so ungraceful exits can
	// be cleaned up by PruneHostCAFiles on the next run.
	sandboxDirName = "sandbox"
	caPrefix       = "ca-"
	caSuffix       = ".pem"
	caStaleTTL     = 24 * time.Hour
)

// sessionIDRE matches the output of NewSessionID — hex-only, so a
// sessionID value can't contain path separators or "..".
var sessionIDRE = regexp.MustCompile(`^[0-9a-f]+$`)

// WriteHostCAFile writes the MITM CA cert to
// ~/.agent-vault/sandbox/ca-<sessionID>.pem with mode 0o644 (the
// container's unprivileged claude user must read it via the bind
// mount). The enclosing directory stays 0o700 so only the host user
// and root can read the file on the host side.
//
// Returns the full host path for use as a docker -v source.
func WriteHostCAFile(pem []byte, sessionID string) (string, error) {
	if !sessionIDRE.MatchString(sessionID) {
		return "", fmt.Errorf("WriteHostCAFile: sessionID must be hex, got %q", sessionID)
	}
	dir, err := hostSandboxDir()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create sandbox dir: %w", err)
	}
	path := filepath.Join(dir, caPrefix+sessionID+caSuffix)
	if err := os.WriteFile(path, pem, 0o600); err != nil {
		return "", fmt.Errorf("write CA file: %w", err)
	}
	// WriteFile with 0o600 is default-safe; Chmod to 0o644 is the
	// explicit step that lets the container read its own bind mount.
	// Parent dir is 0o700 so the host attack surface is unchanged.
	if err := os.Chmod(path, 0o644); err != nil {
		return "", fmt.Errorf("chmod CA file: %w", err)
	}
	return path, nil
}

// PruneHostCAFiles removes ca-*.pem files in ~/.agent-vault/sandbox/
// older than caStaleTTL. Best-effort — errors are ignored because this
// is background cleanup, not correctness-critical. Called at the top of
// each container-mode vault run.
func PruneHostCAFiles() {
	dir, err := hostSandboxDir()
	if err != nil {
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	cutoff := time.Now().Add(-caStaleTTL)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasPrefix(name, caPrefix) || !strings.HasSuffix(name, caSuffix) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if info.ModTime().After(cutoff) {
			continue
		}
		_ = os.Remove(filepath.Join(dir, name))
	}
}

func hostSandboxDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home dir: %w", err)
	}
	return filepath.Join(home, ".agent-vault", sandboxDirName), nil
}
