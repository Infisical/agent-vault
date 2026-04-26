package sandbox

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

func TestAssetsHash_Format(t *testing.T) {
	h, err := assetsHash()
	if err != nil {
		t.Fatalf("assetsHash: %v", err)
	}
	if !regexp.MustCompile(`^[0-9a-f]{12}$`).MatchString(h) {
		t.Errorf("hash = %q, want 12 lowercase hex chars", h)
	}
}

// TestAssetsHash_Stable guards against unintentional asset edits that
// would bust every user's local image cache without them realizing.
// If an embedded asset changes, this test must be updated alongside
// the change — forcing the PR author to acknowledge that users will
// rebuild the image on their next `vault run --sandbox=container`.
//
// Treat a diff on this constant as intentional. Update when changing
// Dockerfile / init-firewall.sh / entrypoint.sh.
func TestAssetsHash_Stable(t *testing.T) {
	const want = "17980b6cccb1"
	got, err := assetsHash()
	if err != nil {
		t.Fatalf("assetsHash: %v", err)
	}
	if got != want {
		t.Errorf("asset hash drift: got %q, want %q — update this constant alongside any intentional edit to assets/{Dockerfile,init-firewall.sh,entrypoint.sh}", got, want)
	}
}

func TestUnpackAssets_WritesFilesWithModes(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	h, _ := assetsHash()
	dir, err := unpackAssets(h)
	if err != nil {
		t.Fatalf("unpackAssets: %v", err)
	}

	expect := map[string]os.FileMode{
		"Dockerfile":        0o644,
		"entrypoint.sh":     0o755,
		"init-firewall.sh":  0o755,
	}
	for name, wantMode := range expect {
		p := filepath.Join(dir, name)
		info, err := os.Stat(p)
		if err != nil {
			t.Errorf("stat %s: %v", p, err)
			continue
		}
		if info.Mode().Perm() != wantMode {
			t.Errorf("%s mode = %v, want %v", name, info.Mode().Perm(), wantMode)
		}
	}
}

func TestEnsureImage_OverrideSkipsBuild(t *testing.T) {
	// With an override, EnsureImage must return it unchanged and not
	// shell out to docker (verified implicitly — we'd fail if it did,
	// because nothing in the Config points at a real docker).
	var stderr bytes.Buffer
	got, err := EnsureImage(context.Background(), "my.registry/example:v1", &stderr)
	if err != nil {
		t.Fatalf("EnsureImage: %v", err)
	}
	if got != "my.registry/example:v1" {
		t.Errorf("ref = %q, want passthrough", got)
	}
	if stderr.Len() != 0 {
		t.Errorf("override path should be silent, got stderr = %q", stderr.String())
	}
}
