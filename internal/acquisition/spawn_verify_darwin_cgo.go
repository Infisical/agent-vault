//go:build darwin && cgo

package acquisition

/*
#cgo LDFLAGS: -lproc
#include <libproc.h>
*/
import "C"

import (
	"context"
	"errors"
	"os"
	"unsafe"

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
	var path [C.PROC_PIDPATHINFO_MAXSIZE]C.char
	if C.proc_pidpath(C.int(pid), unsafe.Pointer(&path[0]), C.uint32_t(len(path))) <= 0 {
		return errSpawnedProviderIdentity
	}
	livePath := C.GoString(&path[0])
	liveInfo, err := os.Stat(livePath)
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
