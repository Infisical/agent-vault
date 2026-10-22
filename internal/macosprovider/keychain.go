package macosprovider

import (
	"fmt"
	"strings"
)

// KeychainItem names one exact generic-password item. Profiles own these
// selectors; callers never construct them from a proposal.
type KeychainItem struct {
	Service              string
	Account              string
	AccessGroup          string
	AllowUserInteraction bool
}

type platformKeychain struct{}

func validateKeychainItem(item KeychainItem) error {
	for _, value := range []string{item.Service, item.Account, item.AccessGroup} {
		if strings.ContainsAny(value, "\x00\r\n") || len(value) > 1024 {
			return fmt.Errorf("invalid keychain selector")
		}
	}
	if item.Service == "" || item.Account == "" {
		return fmt.Errorf("service and account are required")
	}
	return nil
}
