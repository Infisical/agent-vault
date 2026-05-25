package infisical

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	sdk "github.com/infisical/go-sdk"
)

// secretsFetcher is the slice of the SDK the syncer actually uses. Defining
// it here lets tests fake the SDK without standing up the real client.
type secretsFetcher interface {
	FetchSecrets(ctx context.Context, cfg VaultConfig) ([]Secret, error)
	AuthMethod() AuthMethod
}

// Client wraps the Infisical SDK and provides a narrow fetch surface.
type Client struct {
	sdk    sdk.InfisicalClientInterface
	method AuthMethod
	logger *slog.Logger
}

// NewClient builds and authenticates an Infisical client. Returns
// ErrNotConfigured when INFISICAL_URL is unset (so callers can keep the
// rest of the server alive) or ErrNoAuthMethod when the URL is set but no
// machine-identity env vars are present.
func NewClient(ctx context.Context, logger *slog.Logger) (*Client, error) {
	siteURL := os.Getenv("INFISICAL_URL")
	if siteURL == "" {
		return nil, ErrNotConfigured
	}

	method, err := DetectAuthMethod(os.Getenv, logger)
	if err != nil {
		return nil, err
	}
	if method == "" {
		return nil, ErrNoAuthMethod
	}

	c := sdk.NewInfisicalClient(ctx, sdk.Config{
		SiteUrl:              siteURL,
		AutoTokenRefresh:     true,
		CacheExpiryInSeconds: 0, // disable SDK-side secret caching; we own the cache
	})

	if err := loginWithMethod(c, method); err != nil {
		return nil, fmt.Errorf("infisical login (%s): %w", method, err)
	}

	logger.Info("infisical client ready",
		slog.String("site_url", siteURL),
		slog.String("auth_method", string(method)))

	return &Client{sdk: c, method: method, logger: logger}, nil
}

// AuthMethod returns the detected machine-identity flow this client uses.
func (c *Client) AuthMethod() AuthMethod { return c.method }

// FetchSecrets pulls the secret set for the given vault config. The SDK
// returns values in plaintext; callers are responsible for encrypting
// before persistence and clearing plaintext after use.
//
// Returns an error if the upstream returns two secrets with the same key
// under different paths (common with Recursive=true). Agent Vault's data
// model is flat key-value per vault, so the operator must restructure
// their Infisical layout or use a non-recursive vault. Silent last-write-
// wins would inject a non-deterministic credential.
func (c *Client) FetchSecrets(ctx context.Context, cfg VaultConfig) ([]Secret, error) {
	res, err := c.sdk.Secrets().ListSecrets(sdk.ListSecretsOptions{
		ProjectID:              cfg.ProjectID,
		Environment:            cfg.Environment,
		SecretPath:             cfg.SecretPath,
		Recursive:              cfg.Recursive,
		ExpandSecretReferences: true,
		AttachToProcessEnv:     false,
	})
	if err != nil {
		return nil, err
	}
	raw := make([]rawSecret, len(res.Secrets))
	for i, s := range res.Secrets {
		raw[i] = rawSecret{Key: s.SecretKey, Value: s.SecretValue, Path: s.SecretPath}
	}
	return flattenSecrets(raw)
}

// rawSecret is the subset of SDK fields flattenSecrets needs; defined here
// so the dedup logic is testable without standing up a real SDK client.
type rawSecret struct{ Key, Value, Path string }

// flattenSecrets collapses the SDK's path-scoped secret list into Agent
// Vault's flat key-value form. Returns an error if any key appears under
// two paths (common with Recursive=true). Both paths are named in the
// error so the operator can locate and resolve the conflict.
func flattenSecrets(in []rawSecret) ([]Secret, error) {
	seen := make(map[string]string, len(in))
	out := make([]Secret, 0, len(in))
	for _, s := range in {
		if prev, dup := seen[s.Key]; dup {
			return nil, fmt.Errorf("duplicate secret key %q under both %s and %s; Agent Vault vaults are flat key-value and cannot disambiguate", s.Key, prev, s.Path)
		}
		seen[s.Key] = s.Path
		out = append(out, Secret{Key: s.Key, Value: s.Value})
	}
	return out, nil
}

// loginWithMethod dispatches to the right SDK auth function. Each branch
// passes empty arguments so the SDK reads the env vars directly (matches
// the standard SDK usage pattern documented for each method). The LDAP
// branch reads three env vars manually because the SDK only env-reads
// the identity ID for that method.
func loginWithMethod(c sdk.InfisicalClientInterface, method AuthMethod) error {
	auth := c.Auth()
	switch method {
	case AuthUniversal:
		_, err := auth.UniversalAuthLogin("", "")
		return err
	case AuthKubernetes:
		_, err := auth.KubernetesAuthLogin("", "")
		return err
	case AuthAWSIAM:
		_, err := auth.AwsIamAuthLogin("")
		return err
	case AuthGCPIAM:
		_, err := auth.GcpIamAuthLogin("", "")
		return err
	case AuthGCPIDToken:
		_, err := auth.GcpIdTokenAuthLogin("")
		return err
	case AuthLDAP:
		_, err := auth.LdapAuthLogin(
			os.Getenv("INFISICAL_LDAP_AUTH_IDENTITY_ID"),
			os.Getenv("INFISICAL_LDAP_AUTH_USERNAME"),
			os.Getenv("INFISICAL_LDAP_AUTH_PASSWORD"),
		)
		return err
	default:
		return fmt.Errorf("infisical: unsupported auth method %q", method)
	}
}
