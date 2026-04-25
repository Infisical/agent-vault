package pidfile

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteRead(t *testing.T) {
	// Use a temp dir to avoid touching real ~/.agent-vault.
	tmp := t.TempDir()
	origHome := os.Getenv("HOME")
	t.Setenv("HOME", tmp)
	defer os.Setenv("HOME", origHome)

	// Ensure the .agent-vault directory exists.
	os.MkdirAll(filepath.Join(tmp, ".agent-vault"), 0700)

	pid := 12345
	if err := Write(pid); err != nil {
		t.Fatalf("Write(%d) error: %v", pid, err)
	}

	got, err := Read()
	if err != nil {
		t.Fatalf("Read() error: %v", err)
	}
	if got != pid {
		t.Errorf("Read() = %d, want %d", got, pid)
	}
}

func TestRemove(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	os.MkdirAll(filepath.Join(tmp, ".agent-vault"), 0700)

	Write(99999)

	if err := Remove(); err != nil {
		t.Fatalf("Remove() error: %v", err)
	}

	_, err := Read()
	if !os.IsNotExist(err) {
		t.Errorf("Read() after Remove() should return os.ErrNotExist, got: %v", err)
	}
}

func TestRemoveNonExistent(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	os.MkdirAll(filepath.Join(tmp, ".agent-vault"), 0700)

	if err := Remove(); err != nil {
		t.Errorf("Remove() on non-existent file should not error, got: %v", err)
	}
}

func TestReadNotExist(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	os.MkdirAll(filepath.Join(tmp, ".agent-vault"), 0700)

	_, err := Read()
	if !os.IsNotExist(err) {
		t.Errorf("Read() should return os.ErrNotExist when no PID file, got: %v", err)
	}
}

func TestIsRunning(t *testing.T) {
	// Current process should be running.
	if !IsRunning(os.Getpid()) {
		t.Error("IsRunning(os.Getpid()) = false, want true")
	}

	// A very high PID should not exist.
	if IsRunning(4194304) {
		t.Error("IsRunning(4194304) = true, want false")
	}
}

func TestWriteIfFreeNoExistingFile(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	os.MkdirAll(filepath.Join(tmp, ".agent-vault"), 0700)

	if err := WriteIfFree(os.Getpid()); err != nil {
		t.Fatalf("WriteIfFree on empty slot: %v", err)
	}
	got, err := Read()
	if err != nil {
		t.Fatalf("Read after WriteIfFree: %v", err)
	}
	if got != os.Getpid() {
		t.Errorf("Read = %d, want %d", got, os.Getpid())
	}
}

func TestWriteIfFreeStalePID(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	os.MkdirAll(filepath.Join(tmp, ".agent-vault"), 0700)

	// Seed with a PID that cannot be live.
	if err := Write(4194304); err != nil {
		t.Fatalf("seed Write: %v", err)
	}
	if err := WriteIfFree(os.Getpid()); err != nil {
		t.Fatalf("WriteIfFree over stale PID: %v", err)
	}
	got, err := Read()
	if err != nil {
		t.Fatalf("Read after WriteIfFree: %v", err)
	}
	if got != os.Getpid() {
		t.Errorf("Read = %d, want %d (stale PID should have been overwritten)", got, os.Getpid())
	}
}

func TestWriteIfFreeLiveOwner(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	os.MkdirAll(filepath.Join(tmp, ".agent-vault"), 0700)

	// Seed with our own PID, which is definitely live.
	owner := os.Getpid()
	if err := Write(owner); err != nil {
		t.Fatalf("seed Write: %v", err)
	}

	// A different PID asking to claim the slot should be rejected.
	err := WriteIfFree(owner + 1)
	if !errors.Is(err, ErrAlreadyRunning) {
		t.Fatalf("WriteIfFree against live owner: got %v, want ErrAlreadyRunning", err)
	}

	// File contents must be unchanged.
	got, err := Read()
	if err != nil {
		t.Fatalf("Read after rejected WriteIfFree: %v", err)
	}
	if got != owner {
		t.Errorf("Read = %d, want %d (file should be untouched)", got, owner)
	}
}

func TestWriteIfFreeSamePIDNoOp(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	os.MkdirAll(filepath.Join(tmp, ".agent-vault"), 0700)

	// Same PID re-claiming its own slot must succeed (idempotent).
	owner := os.Getpid()
	if err := Write(owner); err != nil {
		t.Fatalf("seed Write: %v", err)
	}
	if err := WriteIfFree(owner); err != nil {
		t.Fatalf("WriteIfFree with same PID: %v", err)
	}
}
