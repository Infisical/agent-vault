//go:build !darwin || !cgo

package macosprovider

import (
	"context"
	"fmt"
)

func (platformKeychain) CopyMatching(context.Context, KeychainItem) ([]byte, error) {
	return nil, fmt.Errorf("macOS Keychain is unavailable")
}
