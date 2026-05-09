package isolation

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
)

// embedded isolation assets: Dockerfile + init/entrypoint scripts. The
// sha256 of their concatenated bytes (sorted by name for stability)
// becomes the image tag, so a binary that ships different assets
// automatically produces a different tag on first use.
//
//go:embed assets/Dockerfile assets/init-firewall.sh assets/entrypoint.sh
var isolationAssets embed.FS

const (
	isolationImageRepo = "agent-vault/isolation"
	// assetsHashLen is 12 hex chars — plenty of collision resistance
	// for this purpose and short enough to read in docker image ls.
	assetsHashLen = 12
)

// assetFiles lists embedded assets in the canonical order used for
// hashing. Order is load-bearing — changing it invalidates every
// user's cached image.
var assetFiles = []string{
	"assets/Dockerfile",
	"assets/entrypoint.sh",
	"assets/init-firewall.sh",
}

// TODO: concurrent vault-run invocations that both miss the image
// cache each docker-build the same content. Last writer wins, same
// bytes — one extra minute of wasted CPU. Acceptable for v1.

// EnsureImage guarantees the isolation image exists locally and returns
// the fully qualified tag. If override is non-empty, the user's own
// image is used as-is and no build is performed.
//
// Content-hash tag pinning means that bumping agent-vault with changed
// assets automatically triggers a rebuild on next use.
func EnsureImage(ctx context.Context, override string, stderr io.Writer) (string, error) {
	if override != "" {
		return override, nil
	}
	hash, err := assetsHash()
	if err != nil {
		return "", err
	}
	tag := isolationImageRepo + ":" + hash
	if imageExists(ctx, tag) {
		return tag, nil
	}

	dir, err := unpackAssets(hash)
	if err != nil {
		return "", err
	}
	fmt.Fprintln(stderr, "agent-vault: building isolation image (one-time setup)...")
	build := exec.CommandContext(ctx, "docker", "build",
		"-t", tag,
		"-t", isolationImageRepo+":latest",
		dir,
	)
	build.Stdout = stderr
	build.Stderr = stderr
	if err := build.Run(); err != nil {
		return "", fmt.Errorf("docker build: %w", err)
	}
	return tag, nil
}

func imageExists(ctx context.Context, tag string) bool {
	return exec.CommandContext(ctx, "docker", "image", "inspect", tag).Run() == nil
}

func assetsHash() (string, error) {
	h := sha256.New()
	for _, name := range assetFiles {
		data, err := isolationAssets.ReadFile(name)
		if err != nil {
			return "", fmt.Errorf("read embedded asset %s: %w", name, err)
		}
		_, _ = h.Write([]byte(name))
		_, _ = h.Write([]byte{0})
		_, _ = h.Write(data)
	}
	return hex.EncodeToString(h.Sum(nil))[:assetsHashLen], nil
}

// unpackAssets writes the embedded files to
// ~/.agent-vault/isolation/<hash>/ (idempotent) and returns the path.
// Scripts are emitted 0o755 so docker build's COPY preserves mode.
func unpackAssets(hash string) (string, error) {
	dir, err := hostIsolationDir()
	if err != nil {
		return "", err
	}
	outDir := filepath.Join(dir, hash)
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return "", fmt.Errorf("mkdir %s: %w", outDir, err)
	}
	for _, name := range assetFiles {
		data, err := isolationAssets.ReadFile(name)
		if err != nil {
			return "", err
		}
		base := filepath.Base(name)
		mode := os.FileMode(0o644)
		if filepath.Ext(base) == ".sh" {
			mode = 0o755
		}
		if err := os.WriteFile(filepath.Join(outDir, base), data, mode); err != nil {
			return "", fmt.Errorf("write %s: %w", base, err)
		}
	}
	return outDir, nil
}
