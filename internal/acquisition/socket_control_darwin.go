//go:build darwin && cgo

package acquisition

import "golang.org/x/sys/unix"

func configureProviderReceiveSocket(_ int) error { return nil }

func providerCredentialsRequired(_ int) bool { return false }

func inspectProviderControlMessages(messages []unix.SocketControlMessage, _ int) (bool, error) {
	for index := range messages {
		descriptors, _ := unix.ParseUnixRights(&messages[index])
		for _, descriptor := range descriptors {
			closeFD(descriptor)
		}
	}
	return false, ErrFrameMalformed
}
