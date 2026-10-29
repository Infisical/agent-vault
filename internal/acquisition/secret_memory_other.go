//go:build !darwin && !linux

package acquisition

import "errors"

func allocateSecretRegion(_ int) ([]byte, error) {
	return nil, errors.New("locked secret memory is unsupported on this platform")
}

func releaseSecretMemory([]byte) {}
