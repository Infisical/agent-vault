package openclawcompat

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestEnsurePreload_WritesAtCanonicalPath(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	path, err := EnsurePreload()
	if err != nil {
		t.Fatalf("EnsurePreload: %v", err)
	}
	want := filepath.Join(tmpHome, ".agent-vault", "openclaw-compat.js")
	if path != want {
		t.Errorf("path = %q, want %q", path, want)
	}

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read preload: %v", err)
	}
	if !bytes.Equal(content, preloadJS) {
		t.Error("preload bytes on disk don't match the embed")
	}
}

func TestEnsurePreload_Idempotent(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	path1, err := EnsurePreload()
	if err != nil {
		t.Fatalf("first EnsurePreload: %v", err)
	}
	info1, err := os.Stat(path1)
	if err != nil {
		t.Fatalf("stat first: %v", err)
	}

	path2, err := EnsurePreload()
	if err != nil {
		t.Fatalf("second EnsurePreload: %v", err)
	}
	if path1 != path2 {
		t.Errorf("path differs across calls: %q vs %q", path1, path2)
	}
	info2, err := os.Stat(path2)
	if err != nil {
		t.Fatalf("stat second: %v", err)
	}
	// Second call should be a pure no-op (no rewrite), so ModTime
	// shouldn't budge. Goes through the bytes.Equal fast path.
	if !info1.ModTime().Equal(info2.ModTime()) {
		t.Errorf("second call rewrote the file: mtime %v vs %v", info1.ModTime(), info2.ModTime())
	}
}

func TestEnsurePreload_RecoversFromStaleContent(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	path, err := EnsurePreload()
	if err != nil {
		t.Fatal(err)
	}
	// Simulate an old AV version having written different content.
	if err := os.WriteFile(path, []byte("stale content from older agent-vault"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := EnsurePreload(); err != nil {
		t.Fatalf("EnsurePreload after stale: %v", err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(content, preloadJS) {
		t.Error("EnsurePreload did not overwrite stale content")
	}
}

func TestEnsurePreload_ParentDirPermissions(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	if _, err := EnsurePreload(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(tmpHome, ".agent-vault"))
	if err != nil {
		t.Fatal(err)
	}
	// 0700 means owner-only; required so a multi-user box doesn't
	// expose other ~/.agent-vault contents.
	if got := info.Mode().Perm(); got != 0o700 {
		t.Errorf("parent dir perms = %o, want 0700", got)
	}
}

func TestPreloadContainsAxiosHook(t *testing.T) {
	// Sanity guard: if someone refactors preload.js into something
	// that doesn't reference axios, the package is no longer fit for
	// purpose. Compile-time embed plus this test catches that.
	if !bytes.Contains(preloadJS, []byte("axios")) {
		t.Error("preload no longer mentions axios; refusing to ship")
	}
	if !bytes.Contains(preloadJS, []byte("Module._load")) {
		t.Error("preload no longer hooks Module._load; the in-process patch is gone")
	}
}

