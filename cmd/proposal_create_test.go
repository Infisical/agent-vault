package cmd

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// newAuthFlagCmd returns a cobra.Command with all the auth-related flags
// that proposal_create / service add define, so buildAuthFromFlags has
// something to read from.
func newAuthFlagCmd() *cobra.Command {
	c := &cobra.Command{Use: "test"}
	c.Flags().String("token-key", "", "")
	c.Flags().String("username-key", "", "")
	c.Flags().String("password-key", "", "")
	c.Flags().String("api-key-key", "", "")
	c.Flags().String("api-key-header", "", "")
	c.Flags().String("api-key-prefix", "", "")
	c.Flags().String("oauth-client-id", "", "")
	c.Flags().String("oauth-client-secret-key", "", "")
	c.Flags().String("oauth-refresh-token-key", "", "")
	c.Flags().String("oauth-token-endpoint", "", "")
	c.Flags().StringArray("oauth-scope", nil, "")
	return c
}

func TestBuildAuthFromFlags_Passthrough(t *testing.T) {
	cmd := newAuthFlagCmd()
	auth, err := buildAuthFromFlags(cmd, "passthrough")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if auth.Type != "passthrough" {
		t.Fatalf("type = %q, want passthrough", auth.Type)
	}
	// Every credential field must be empty.
	if auth.Token != "" || auth.Username != "" || auth.Password != "" ||
		auth.Key != "" || auth.Header != "" || auth.Prefix != "" ||
		len(auth.Headers) > 0 {
		t.Fatalf("passthrough auth should have no credential fields, got %+v", auth)
	}
}

func TestBuildAuthFromFlags_PassthroughRejectsCredentialFlags(t *testing.T) {
	cases := []struct {
		flag  string
		value string
	}{
		{"token-key", "FOO"},
		{"username-key", "FOO"},
		{"password-key", "FOO"},
		{"api-key-key", "FOO"},
		{"api-key-header", "X-Foo"},
		{"api-key-prefix", "Bearer "},
		{"oauth-client-id", "client-id"},
		{"oauth-client-secret-key", "CLIENT_SECRET"},
		{"oauth-refresh-token-key", "REFRESH_TOKEN"},
		{"oauth-token-endpoint", "https://oauth2.googleapis.com/token"},
		{"oauth-scope", "repo"},
	}
	for _, tc := range cases {
		t.Run(tc.flag, func(t *testing.T) {
			cmd := newAuthFlagCmd()
			if err := cmd.Flags().Set(tc.flag, tc.value); err != nil {
				t.Fatalf("flag set: %v", err)
			}
			_, err := buildAuthFromFlags(cmd, "passthrough")
			if err == nil {
				t.Fatalf("expected error for --%s on passthrough", tc.flag)
			}
			if !strings.Contains(err.Error(), tc.flag) {
				t.Fatalf("error should mention --%s, got %q", tc.flag, err.Error())
			}
		})
	}
}

func TestBuildAuthFromFlags_OAuth(t *testing.T) {
	cmd := newAuthFlagCmd()
	for flag, value := range map[string]string{
		"oauth-client-id":         "client-id",
		"oauth-client-secret-key": "CLIENT_SECRET",
		"oauth-refresh-token-key": "REFRESH_TOKEN",
		"oauth-token-endpoint":    "https://oauth2.googleapis.com/token",
		"oauth-scope":             "repo",
	} {
		if err := cmd.Flags().Set(flag, value); err != nil {
			t.Fatalf("set --%s: %v", flag, err)
		}
	}

	auth, err := buildAuthFromFlags(cmd, "oauth")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if auth.ClientID != "client-id" || auth.ClientSecretKey != "CLIENT_SECRET" || auth.RefreshTokenKey != "REFRESH_TOKEN" {
		t.Fatalf("unexpected oauth auth: %+v", auth)
	}
	if auth.TokenEndpoint != "https://oauth2.googleapis.com/token" {
		t.Fatalf("TokenEndpoint = %q", auth.TokenEndpoint)
	}
	if len(auth.Scopes) != 1 || auth.Scopes[0] != "repo" {
		t.Fatalf("Scopes = %v", auth.Scopes)
	}
}
