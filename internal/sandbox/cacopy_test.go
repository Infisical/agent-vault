package sandbox

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWriteHostCAFile_WritesAt0o644(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	const pem = "-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----\n"
	path, err := WriteHostCAFile([]byte(pem), "deadbeef12345678")
	if err != nil {
		t.Fatalf("WriteHostCAFile: %v", err)
	}

	wantDir := filepath.Join(home, ".agent-vault", sandboxDirName)
	wantFile := filepath.Join(wantDir, caPrefix+"deadbeef12345678"+caSuffix)
	if path != wantFile {
		t.Errorf("path = %q, want %q", path, wantFile)
	}

	dirInfo, err := os.Stat(wantDir)
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if dirInfo.Mode().Perm() != 0o700 {
		t.Errorf("dir perms = %v, want 0o700 (host-private)", dirInfo.Mode().Perm())
	}

	fileInfo, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat file: %v", err)
	}
	if fileInfo.Mode().Perm() != 0o644 {
		t.Errorf("file perms = %v, want 0o644 (container must read bind mount)", fileInfo.Mode().Perm())
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != pem {
		t.Errorf("contents mismatch")
	}
}

func TestWriteHostCAFile_RejectsNonHexSessionID(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	for _, bad := range []string{"", "../../etc/passwd", "nothex!!", "has space", "UPPERCASE"} {
		if _, err := WriteHostCAFile([]byte("x"), bad); err == nil {
			t.Errorf("expected error for sessionID %q, got nil", bad)
		}
	}
}

func TestWriteHostCAFile_OverwriteIsSafe(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	sid := "abcdef0123456789"
	if _, err := WriteHostCAFile([]byte("first"), sid); err != nil {
		t.Fatalf("first write: %v", err)
	}
	path, err := WriteHostCAFile([]byte("second"), sid)
	if err != nil {
		t.Fatalf("second write: %v", err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != "second" {
		t.Errorf("expected overwrite, got %q", got)
	}
}

func TestPruneHostCAFiles_RemovesStaleOnly(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	dir := filepath.Join(home, ".agent-vault", sandboxDirName)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	stale := filepath.Join(dir, caPrefix+"old-sid"+caSuffix)
	fresh := filepath.Join(dir, caPrefix+"new-sid"+caSuffix)
	unrelated := filepath.Join(dir, "claude-home.lock") // not a CA file
	for _, p := range []string{stale, fresh, unrelated} {
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatalf("prep %s: %v", p, err)
		}
	}
	// Backdate the stale file past caStaleTTL.
	old := time.Now().Add(-caStaleTTL - time.Hour)
	if err := os.Chtimes(stale, old, old); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	PruneHostCAFiles()

	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Errorf("stale file should be removed, err=%v", err)
	}
	if _, err := os.Stat(fresh); err != nil {
		t.Errorf("fresh file should remain, err=%v", err)
	}
	if _, err := os.Stat(unrelated); err != nil {
		t.Errorf("non-ca-prefixed file should be ignored, err=%v", err)
	}
}

func TestPruneHostCAFiles_NoDirectoryIsNoError(t *testing.T) {
	t.Setenv("HOME", t.TempDir()) // fresh home, no sandbox dir created
	// Must not panic or error even when the dir doesn't exist.
	PruneHostCAFiles()
}
