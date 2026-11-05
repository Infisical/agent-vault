//go:build linux && cgo

package acquisition

import (
	"fmt"

	"golang.org/x/sys/unix"
)

func configureProviderReceiveSocket(fd int) error {
	return unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_PASSCRED, 1)
}

func providerCredentialsRequired(expectedPID int) bool { return expectedPID > 0 }

func inspectProviderControlMessages(messages []unix.SocketControlMessage, expectedPID int) (bool, error) {
	credentialSeen := false
	invalid := false
	for index := range messages {
		message := &messages[index]
		if message.Header.Level == unix.SOL_SOCKET && message.Header.Type == unix.SCM_RIGHTS {
			descriptors, _ := unix.ParseUnixRights(message)
			for _, descriptor := range descriptors {
				closeFD(descriptor)
			}
			invalid = true
			continue
		}
		if message.Header.Level != unix.SOL_SOCKET || message.Header.Type != unix.SCM_CREDENTIALS || credentialSeen {
			invalid = true
			continue
		}
		credentials, err := unix.ParseUnixCredentials(message)
		if err != nil {
			invalid = true
			continue
		}
		if expectedPID > 0 && int(credentials.Pid) != expectedPID {
			invalid = true
			continue
		}
		credentialSeen = true
	}
	if invalid {
		return false, fmt.Errorf("provider control message rejected: %w", ErrFrameMalformed)
	}
	if expectedPID > 0 && !credentialSeen {
		return false, ErrFrameMalformed
	}
	return credentialSeen, nil
}
