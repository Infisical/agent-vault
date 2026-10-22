//go:build darwin

package acquisition

import (
	"os"

	"golang.org/x/sys/unix"
)

func allocateSecretRegion(length int) ([]byte, error) {
	region, err := unix.Mmap(-1, 0, roundedSecretRegionSize(length), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_ANON|unix.MAP_PRIVATE)
	if err != nil {
		return nil, err
	}
	if err := unix.Mlock(region); err != nil {
		_ = unix.Munmap(region)
		return nil, err
	}
	return region, nil
}

func releaseSecretMemory(region []byte) {
	_ = unix.Munlock(region)
	_ = unix.Munmap(region)
}

func roundedSecretRegionSize(length int) int {
	pageSize := os.Getpagesize()
	return ((length + pageSize - 1) / pageSize) * pageSize
}
