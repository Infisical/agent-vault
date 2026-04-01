// Package oauth provides a provider-agnostic interface for OAuth 2.0 / OIDC
// authentication. Each provider (Google, GitHub, etc.) implements the Provider
// interface and is registered at server startup based on environment variables.
package oauth

import "context"

// Provider defines the interface that all OAuth/OIDC providers must implement.
type Provider interface {
	// Name returns the provider identifier (e.g. "google").
	Name() string

	// DisplayName returns the human-readable name (e.g. "Google").
	DisplayName() string

	// AuthCodeURL builds the authorization URL that the user's browser is
	// redirected to. The state parameter is used for CSRF protection.
	// The codeVerifier is the raw PKCE verifier; the implementation computes
	// the S256 code_challenge from it. The nonce binds the ID token to this
	// specific authorization request, preventing token injection attacks.
	AuthCodeURL(state, codeVerifier, nonce string) string

	// Exchange trades an authorization code for user information. The
	// codeVerifier must match the one used when generating the authorization
	// URL. The nonce must match the one included in the authorization URL.
	// The implementation validates the ID token (signature, issuer,
	// audience, expiry, nonce, email_verified).
	Exchange(ctx context.Context, code, codeVerifier, nonce string) (*UserInfo, error)

	// Enabled returns true if the provider is fully configured and ready.
	Enabled() bool

	// CallbackPath returns the path portion of the callback URL
	// (e.g. "/v1/auth/oauth/google/callback").
	CallbackPath() string
}

// UserInfo is the normalized user information returned by any provider after
// a successful code exchange and ID token validation.
type UserInfo struct {
	ProviderUserID string // unique stable ID from the provider (e.g. "sub" claim)
	Email          string
	Name           string
	AvatarURL      string
	EmailVerified  bool
}
