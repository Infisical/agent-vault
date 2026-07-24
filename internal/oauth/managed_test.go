package oauth

import (
	"os"
	"strings"
	"testing"
)

func TestLoadManagedProvidersFromEnvDisabled(t *testing.T) {
	t.Setenv(GoogleOAuthClientIDEnv, "")
	t.Setenv(GoogleOAuthClientSecretEnv, "")

	providers, err := LoadManagedProvidersFromEnv()
	if err != nil {
		t.Fatalf("LoadManagedProvidersFromEnv: %v", err)
	}
	if len(providers) != 0 {
		t.Fatalf("providers = %d, want 0", len(providers))
	}
}

func TestLoadManagedProvidersFromEnvGoogle(t *testing.T) {
	t.Setenv(GoogleOAuthClientIDEnv, " google-client-id ")
	t.Setenv(GoogleOAuthClientSecretEnv, "google-client-secret")

	providers, err := LoadManagedProvidersFromEnv()
	if err != nil {
		t.Fatalf("LoadManagedProvidersFromEnv: %v", err)
	}
	if len(providers) != 1 {
		t.Fatalf("providers = %d, want 1", len(providers))
	}

	got := providers[0]
	if got.ID != "google" {
		t.Errorf("ID = %q, want google", got.ID)
	}
	if got.ClientID != "google-client-id" {
		t.Errorf("ClientID = %q, want trimmed client ID", got.ClientID)
	}
	if got.ClientSecret != "google-client-secret" {
		t.Errorf("ClientSecret = %q, want configured secret", got.ClientSecret)
	}
	if !strings.Contains(got.AuthorizationURL, "access_type=offline") || !strings.Contains(got.AuthorizationURL, "prompt=consent") {
		t.Errorf("AuthorizationURL = %q, want offline consent parameters", got.AuthorizationURL)
	}
	if _, ok := os.LookupEnv(GoogleOAuthClientSecretEnv); ok {
		t.Errorf("%s remained in environment", GoogleOAuthClientSecretEnv)
	}
}

func TestLoadManagedProvidersFromEnvRejectsPartialConfig(t *testing.T) {
	tests := []struct {
		name         string
		clientID     string
		clientSecret string
	}{
		{name: "missing secret", clientID: "google-client-id"},
		{name: "missing client ID", clientSecret: "google-client-secret"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(GoogleOAuthClientIDEnv, tt.clientID)
			t.Setenv(GoogleOAuthClientSecretEnv, tt.clientSecret)

			if _, err := LoadManagedProvidersFromEnv(); err == nil {
				t.Fatal("LoadManagedProvidersFromEnv succeeded with partial config")
			}
		})
	}
}
