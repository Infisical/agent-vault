package server

import (
	"testing"

	"github.com/Infisical/agent-vault/internal/oauth"
)

func testManagedGoogleProvider() oauth.ManagedProvider {
	return oauth.ManagedProvider{
		ID:               "google",
		AuthorizationURL: "https://accounts.example.com/authorize",
		TokenURL:         "https://accounts.example.com/token",
		ClientID:         "managed-client-id",
		ClientSecret:     "managed-client-secret",
		TokenAuthMethod:  "client_secret_post",
	}
}

func TestApplyManagedOAuthProvider(t *testing.T) {
	srv := newTestServer()
	srv.SetManagedOAuthProviders([]oauth.ManagedProvider{testManagedGoogleProvider()})

	req := oauthConnectRequest{
		Provider:         "google",
		AuthorizationURL: "https://attacker.example/authorize",
		TokenURL:         "https://attacker.example/token",
		ClientID:         "attacker-client-id",
		ClientSecret:     "attacker-client-secret",
		TokenAuthMethod:  "client_secret_basic",
	}
	if err := srv.applyManagedOAuthProvider(&req); err != nil {
		t.Fatalf("applyManagedOAuthProvider: %v", err)
	}

	provider := testManagedGoogleProvider()
	if req.AuthorizationURL != provider.AuthorizationURL {
		t.Errorf("AuthorizationURL = %q, want %q", req.AuthorizationURL, provider.AuthorizationURL)
	}
	if req.TokenURL != provider.TokenURL {
		t.Errorf("TokenURL = %q, want %q", req.TokenURL, provider.TokenURL)
	}
	if req.ClientID != provider.ClientID {
		t.Errorf("ClientID = %q, want %q", req.ClientID, provider.ClientID)
	}
	if req.ClientSecret != provider.ClientSecret {
		t.Errorf("ClientSecret = %q, want managed secret", req.ClientSecret)
	}
	if req.TokenAuthMethod != provider.TokenAuthMethod {
		t.Errorf("TokenAuthMethod = %q, want %q", req.TokenAuthMethod, provider.TokenAuthMethod)
	}
}

func TestApplyManagedOAuthProviderRejectsUnknownProvider(t *testing.T) {
	srv := newTestServer()
	req := oauthConnectRequest{Provider: "google"}

	if err := srv.applyManagedOAuthProvider(&req); err == nil {
		t.Fatal("applyManagedOAuthProvider succeeded for an unconfigured provider")
	}
}

func TestManagedOAuthProviderForConfig(t *testing.T) {
	srv := newTestServer()
	provider := testManagedGoogleProvider()
	srv.SetManagedOAuthProviders([]oauth.ManagedProvider{provider})

	if got := srv.managedOAuthProviderForConfig(provider.AuthorizationURL, provider.TokenURL, provider.ClientID); got != "google" {
		t.Errorf("managedOAuthProviderForConfig = %q, want google", got)
	}
	if got := srv.managedOAuthProviderForConfig(provider.AuthorizationURL, "https://attacker.example/token", provider.ClientID); got != "" {
		t.Errorf("managedOAuthProviderForConfig = %q for mismatched token URL, want empty", got)
	}
}

func TestManagedOAuthProviderIDsSorted(t *testing.T) {
	srv := newTestServer()
	google := testManagedGoogleProvider()
	github := google
	github.ID = "github"
	srv.SetManagedOAuthProviders([]oauth.ManagedProvider{google, github})

	got := srv.managedOAuthProviderIDs()
	if len(got) != 2 || got[0] != "github" || got[1] != "google" {
		t.Fatalf("managedOAuthProviderIDs = %v, want [github google]", got)
	}
}
