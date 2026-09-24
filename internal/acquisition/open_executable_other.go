//go:build !darwin && !linux

package acquisition

import "os"

// openExecutableNoFollow is a conservative fallback for unsupported build
// targets. Agent Vault's V1 provider runner ships on macOS and Linux, where
// O_NOFOLLOW is used atomically. Other targets still reject a symlink observed
// before opening and verify that the opened file is the same current path.
func openExecutableNoFollow(path string) (*os.File, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if before.Mode()&os.ModeSymlink != 0 {
		return nil, ErrNotRegular
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	opened, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	after, err := os.Lstat(path)
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	if after.Mode()&os.ModeSymlink != 0 || !os.SameFile(before, opened) || !os.SameFile(opened, after) {
		_ = file.Close()
		return nil, ErrNotRegular
	}
	return file, nil
}
