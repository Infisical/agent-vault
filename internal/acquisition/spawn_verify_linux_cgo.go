//go:build linux && cgo

package acquisition

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/Infisical/agent-vault/internal/store"
)

var errSpawnedProviderIdentity = errors.New("spawned provider executable identity mismatch")

// verifySpawnedProvider binds the live child to the private file whose hash
// and optional signing identity PrepareExecutable already verified.
func verifySpawnedProvider(ctx context.Context, pid int, preparedPath string, _ store.AcquisitionHandler) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if pid <= 0 || preparedPath == "" {
		return errSpawnedProviderIdentity
	}
	liveInfo, err := os.Stat(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return errSpawnedProviderIdentity
	}
	preparedInfo, err := os.Stat(preparedPath)
	if err != nil {
		return errSpawnedProviderIdentity
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !os.SameFile(liveInfo, preparedInfo) {
		return errSpawnedProviderIdentity
	}
	return nil
}
