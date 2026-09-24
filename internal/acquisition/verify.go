package acquisition

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/Infisical/agent-vault/internal/store"
)

var (
	ErrExecutableUnavailable   = errors.New("handler executable unavailable")
	ErrNotRegular              = errors.New("handler executable is not a regular file")
	ErrNotExecutable           = errors.New("handler executable lacks execute permission")
	ErrHashMismatch            = errors.New("handler executable hash mismatch")
	ErrSigningUnsupported      = errors.New("handler signing verification is unsupported on this platform")
	ErrSignatureInvalid        = errors.New("handler code signature is invalid")
	ErrSigningIdentityMismatch = errors.New("handler signing identity mismatch")
)

const (
	codesignPath        = "/usr/bin/codesign"
	codesignOutputLimit = 64 * 1024
	codesignTimeout     = 10 * time.Second
)

// PreparedExecutable is a private verified copy of a registered provider.
// The provider runner must execute Path rather than reopening the registry
// pathname, then call Close after the child exits.
type PreparedExecutable struct {
	path      string
	dir       string
	closeOnce sync.Once
	closeErr  error
}

func (p *PreparedExecutable) Path() string { return p.path }

func (p *PreparedExecutable) Close() error {
	p.closeOnce.Do(func() { p.closeErr = os.RemoveAll(p.dir) })
	return p.closeErr
}

// PrepareExecutable opens the registry pathname without following symlinks,
// copies that opened descriptor into a private executable, and performs the
// hash and optional code-signature checks against the copy. This binds future
// execution to the exact bytes that were verified.
func PrepareExecutable(ctx context.Context, handler store.AcquisitionHandler) (*PreparedExecutable, error) {
	if err := handler.ValidateRegistration(); err != nil {
		return nil, err
	}
	file, err := openExecutableNoFollow(handler.ExecutablePath)
	if err != nil {
		if errors.Is(err, ErrNotRegular) {
			return nil, ErrNotRegular
		}
		return nil, ErrExecutableUnavailable
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, ErrExecutableUnavailable
	}
	if !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, ErrNotRegular
	}
	if info.Mode().Perm()&0o111 == 0 {
		_ = file.Close()
		return nil, ErrNotExecutable
	}

	dir, err := os.MkdirTemp("", "agent-vault-provider-")
	if err != nil {
		_ = file.Close()
		return nil, ErrExecutableUnavailable
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.RemoveAll(dir)
		}
	}()
	if err := os.Chmod(dir, 0o700); err != nil {
		_ = file.Close()
		return nil, ErrExecutableUnavailable
	}
	preparedPath := filepath.Join(dir, "provider")
	preparedFile, err := os.OpenFile(preparedPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o700)
	if err != nil {
		_ = file.Close()
		return nil, ErrExecutableUnavailable
	}
	hasher := sha256.New()
	_, copyErr := io.Copy(io.MultiWriter(preparedFile, hasher), file)
	fileCloseErr := file.Close()
	syncErr := preparedFile.Sync()
	preparedCloseErr := preparedFile.Close()
	if copyErr != nil || fileCloseErr != nil || syncErr != nil || preparedCloseErr != nil {
		return nil, ErrExecutableUnavailable
	}
	expected, err := hex.DecodeString(handler.SHA256)
	if err != nil {
		return nil, fmt.Errorf("invalid registered sha256: %w", err)
	}
	if subtle.ConstantTimeCompare(hasher.Sum(nil), expected) != 1 {
		return nil, ErrHashMismatch
	}

	if handler.SigningIdentity != "" {
		if err := verifyDarwinSigningIdentity(ctx, preparedPath, handler.SigningIdentity); err != nil {
			return nil, err
		}
	}
	cleanup = false
	return &PreparedExecutable{path: preparedPath, dir: dir}, nil
}

// VerifyExecutable is the registration-time check. The provider runner uses
// PrepareExecutable directly so it can execute the exact verified copy.
func VerifyExecutable(ctx context.Context, handler store.AcquisitionHandler) error {
	prepared, err := PrepareExecutable(ctx, handler)
	if err != nil {
		return err
	}
	if err := prepared.Close(); err != nil {
		return ErrExecutableUnavailable
	}
	return nil
}

func VerificationCode(err error) string {
	switch {
	case errors.Is(err, ErrExecutableUnavailable):
		return "executable_unavailable"
	case errors.Is(err, ErrNotRegular):
		return "executable_not_regular"
	case errors.Is(err, ErrNotExecutable):
		return "executable_not_executable"
	case errors.Is(err, ErrHashMismatch):
		return "hash_mismatch"
	case errors.Is(err, ErrSigningUnsupported):
		return "signing_unsupported"
	case errors.Is(err, ErrSignatureInvalid):
		return "signature_invalid"
	case errors.Is(err, ErrSigningIdentityMismatch):
		return "signing_identity_mismatch"
	default:
		return "verification_failed"
	}
}

func verifyDarwinSigningIdentity(ctx context.Context, path, expectedIdentity string) error {
	if runtime.GOOS != "darwin" {
		return ErrSigningUnsupported
	}
	if _, err := runCodesign(ctx, "--verify", "--strict", "--verbose=4", path); err != nil {
		return err
	}
	details, err := runCodesign(ctx, "--display", "--verbose=4", path)
	if err != nil {
		return err
	}
	if firstCodesignAuthority(details) == expectedIdentity {
		return nil
	}
	return ErrSigningIdentityMismatch
}

func firstCodesignAuthority(details []byte) string {
	for _, line := range strings.Split(string(details), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Authority=") {
			return strings.TrimPrefix(line, "Authority=")
		}
	}
	return ""
}

func runCodesign(ctx context.Context, args ...string) ([]byte, error) {
	commandCtx, cancel := context.WithTimeout(ctx, codesignTimeout)
	defer cancel()
	var output cappedBuffer
	output.limit = codesignOutputLimit
	cmd := exec.CommandContext(commandCtx, codesignPath, args...)
	cmd.Dir = "/"
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C"}
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Run(); err != nil || output.overflowed {
		return nil, ErrSignatureInvalid
	}
	return output.Bytes(), nil
}

type cappedBuffer struct {
	mu sync.Mutex
	bytes.Buffer
	limit      int
	overflowed bool
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	originalLen := len(p)
	remaining := b.limit - b.Len()
	if remaining <= 0 {
		b.overflowed = true
		return originalLen, nil
	}
	if len(p) > remaining {
		p = p[:remaining]
		b.overflowed = true
	}
	_, _ = b.Buffer.Write(p)
	return originalLen, nil
}
