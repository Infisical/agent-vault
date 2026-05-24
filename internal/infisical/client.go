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
func (c *Client) FetchSecrets(ctx context.Context, cfg VaultConfig) ([]Secret, error) {
	secs, err := c.sdk.Secrets().List(sdk.ListSecretsOptions{
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
	out := make([]Secret, 0, len(secs))
	for _, s := range secs {
		out = append(out, Secret{Key: s.SecretKey, Value: s.SecretValue})
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
