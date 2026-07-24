package oauth

import (
	"fmt"
	"os"
	"strings"
)

const (
	// GoogleOAuthClientIDEnv and GoogleOAuthClientSecretEnv configure the
	// instance-managed Google OAuth application.
	GoogleOAuthClientIDEnv     = "AGENT_VAULT_OAUTH_GOOGLE_CLIENT_ID"
	GoogleOAuthClientSecretEnv = "AGENT_VAULT_OAUTH_GOOGLE_CLIENT_SECRET"
)

// ManagedProvider is an OAuth application configured by the instance operator.
// Vault users authorize their own accounts, but do not need to create or supply
// an OAuth client.
type ManagedProvider struct {
	ID               string
	AuthorizationURL string
	TokenURL         string
	ClientID         string
	ClientSecret     string
	TokenAuthMethod  string
}

// LoadManagedProvidersFromEnv loads operator-managed OAuth applications.
// A partially configured provider fails closed instead of falling back to
// user-supplied client credentials unexpectedly.
func LoadManagedProvidersFromEnv() ([]ManagedProvider, error) {
	googleClientID := strings.TrimSpace(os.Getenv(GoogleOAuthClientIDEnv))
	googleClientSecret := os.Getenv(GoogleOAuthClientSecretEnv)

	if googleClientID == "" && googleClientSecret == "" {
		return nil, nil
	}
	if googleClientID == "" || googleClientSecret == "" {
		return nil, fmt.Errorf("%s and %s must be set together", GoogleOAuthClientIDEnv, GoogleOAuthClientSecretEnv)
	}

	// Keep the secret in process memory after startup, not in the inherited
	// environment where child processes could read it.
	_ = os.Unsetenv(GoogleOAuthClientSecretEnv)

	return []ManagedProvider{{
		ID:               "google",
		AuthorizationURL: "https://accounts.google.com/o/oauth2/v2/auth?access_type=offline&prompt=consent",
		TokenURL:         "https://oauth2.googleapis.com/token",
		ClientID:         googleClientID,
		ClientSecret:     googleClientSecret,
		TokenAuthMethod:  "client_secret_post",
	}}, nil
}
