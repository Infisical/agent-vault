package acquisition

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Infisical/agent-vault/internal/store"
)

func testHandler(path, digest string) store.AcquisitionHandler {
	return store.AcquisitionHandler{
		ID:               "test-provider",
		Kind:             "executable",
		ExecutablePath:   path,
		SHA256:           digest,
		AllowedKeys:      []string{"TEST_TOKEN"},
		AllowedVaults:    []string{"test-vault"},
		AllowedProfiles:  []string{"default"},
		TimeoutSeconds:   10,
		OutputLimitBytes: 65536,
	}
}

func TestVerifyExecutableAcceptsExactRegularFileHash(t *testing.T) {
	path := filepath.Join(t.TempDir(), "provider")
	content := []byte("provider bytes")
	if err := os.WriteFile(path, content, 0o700); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(content)
	if err := VerifyExecutable(context.Background(), testHandler(path, hex.EncodeToString(digest[:]))); err != nil {
		t.Fatalf("VerifyExecutable: %v", err)
	}
}

func TestPrepareExecutableReturnsVerifiedPrivateCopy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "provider")
	content := []byte("provider bytes")
	if err := os.WriteFile(path, content, 0o700); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(content)
	prepared, err := PrepareExecutable(context.Background(), testHandler(path, hex.EncodeToString(digest[:])))
	if err != nil {
		t.Fatal(err)
	}
	preparedPath := prepared.Path()
	if preparedPath == path || !filepath.IsAbs(preparedPath) {
		t.Fatalf("prepared path must be a separate absolute path: %q", preparedPath)
	}
	got, err := os.ReadFile(preparedPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(content) {
		t.Fatalf("prepared bytes=%q want=%q", got, content)
	}
	if err := prepared.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(preparedPath); !os.IsNotExist(err) {
		t.Fatalf("prepared executable still exists after Close: %v", err)
	}
}

func TestVerifyExecutableRejectsHashMismatchWithoutPathLeak(t *testing.T) {
	path := filepath.Join(t.TempDir(), "provider")
	if err := os.WriteFile(path, []byte("provider bytes"), 0o700); err != nil {
		t.Fatal(err)
	}
	err := VerifyExecutable(context.Background(), testHandler(path, strings.Repeat("0", 64)))
	if !errors.Is(err, ErrHashMismatch) {
		t.Fatalf("expected ErrHashMismatch, got %v", err)
	}
	if strings.Contains(err.Error(), path) {
		t.Fatalf("verification error leaked path: %v", err)
	}
}

func TestVerifyExecutableRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "provider")
	if err := os.WriteFile(target, []byte("provider bytes"), 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "provider-link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("provider bytes"))
	err := VerifyExecutable(context.Background(), testHandler(link, hex.EncodeToString(digest[:])))
	if !errors.Is(err, ErrNotRegular) {
		t.Fatalf("expected ErrNotRegular, got %v", err)
	}
}

func TestVerifyExecutableRejectsNonExecutableFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "provider")
	content := []byte("provider bytes")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(content)
	err := VerifyExecutable(context.Background(), testHandler(path, hex.EncodeToString(digest[:])))
	if !errors.Is(err, ErrNotExecutable) {
		t.Fatalf("expected ErrNotExecutable, got %v", err)
	}
}

func TestFirstCodesignAuthorityReturnsLeafOnly(t *testing.T) {
	details := []byte("Executable=/tmp/provider\nAuthority=Developer ID Application: Leaf (TEAM123)\nAuthority=Developer ID Certification Authority\nAuthority=Apple Root CA\n")
	if got := firstCodesignAuthority(details); got != "Developer ID Application: Leaf (TEAM123)" {
		t.Fatalf("leaf authority=%q", got)
	}
	if got := firstCodesignAuthority([]byte("Identifier=unsigned\n")); got != "" {
		t.Fatalf("unsigned authority=%q", got)
	}
}
