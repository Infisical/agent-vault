// Package openclawcompat embeds and writes the Node compatibility preload
// that `agent-vault run` injects when wrapping the OpenClaw gateway.
//
// The preload patches axios in-process to (a) bypass axios v1.x's broken
// `https://` proxy URL parsing, and (b) move @slack/web-api's body-token
// to an Authorization header so Agent Vault's header-surface substitution
// can resolve it. Both issues are inherent to OpenClaw's dependency stack
// and can't be fixed proxy-side without invasive surgery. See preload.js
// for the longer explanation.
//
// The package exposes a single user-facing call, EnsurePreload, that
// writes the embedded script to ~/.agent-vault/openclaw-compat.js if
// missing or stale. It's idempotent: callers can invoke it on every
// `agent-vault run` without measurable cost.
package openclawcompat

import (
	"bytes"
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
)

//go:embed preload.js
var preloadJS []byte

// fileName is the on-disk basename used inside ~/.agent-vault/. Exported
// indirectly via PreloadPath so callers don't construct paths themselves.
const fileName = "openclaw-compat.js"

// PreloadPath returns the canonical on-disk location of the preload. The
// path is `<UserHomeDir>/.agent-vault/openclaw-compat.js`, matching the
// existing ~/.agent-vault/ convention used for the MITM CA bundle and the
// server PID file.
func PreloadPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home dir: %w", err)
	}
	return filepath.Join(home, ".agent-vault", fileName), nil
}

// EnsurePreload writes the embedded preload to PreloadPath() if it's
// missing or its bytes differ from the embed (which happens after an
// agent-vault upgrade ships an updated preload). The write is atomic
// via a same-directory temp file + rename, so a concurrent `agent-vault
// run` invocation can't read a partially-written script.
//
// Returns the path the caller should pass to NODE_OPTIONS=--require=<path>.
//
// Permissions: 0700 on the parent directory (private to the user) and
// 0644 on the script itself. The script content is not secret — it's
// embedded in the AV binary and extractable by anyone who can run AV —
// so world-read is fine and avoids surprises when an agent process runs
// as a different user from the AV invocation.
func EnsurePreload() (string, error) {
	path, err := PreloadPath()
	if err != nil {
		return "", err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("mkdir %s: %w", dir, err)
	}

	// Fast path: already up to date.
	if existing, err := os.ReadFile(path); err == nil && bytes.Equal(existing, preloadJS) {
		return path, nil
	}

	tmp, err := os.CreateTemp(dir, fileName+".tmp-*")
	if err != nil {
		return "", fmt.Errorf("create temp: %w", err)
	}
	tmpName := tmp.Name()
	// Best-effort cleanup if anything below fails.
	defer func() { _ = os.Remove(tmpName) }()

	if _, err := tmp.Write(preloadJS); err != nil {
		_ = tmp.Close()
		return "", fmt.Errorf("write temp: %w", err)
	}
	if err := tmp.Chmod(0o644); err != nil {
		_ = tmp.Close()
		return "", fmt.Errorf("chmod temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return "", fmt.Errorf("close temp: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return "", fmt.Errorf("rename temp into place: %w", err)
	}
	return path, nil
}

