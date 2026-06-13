package infisical

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	sdk "github.com/infisical/go-sdk"
)

// SecretsFetcher is the slice of the SDK the syncer actually uses; tests
// substitute their own implementation without standing up the real client.
type SecretsFetcher interface {
	FetchSecrets(ctx context.Context, cfg VaultConfig) ([]Secret, error)
	AuthMethod() AuthMethod
}

// Client wraps the Infisical SDK and provides a narrow fetch surface.
type Client struct {
	sdk    sdk.InfisicalClientInterface
	method AuthMethod
	logger *slog.Logger
}

// NewClient returns ErrNotConfigured when INFISICAL_URL is unset (callers
// keep the server alive) or ErrNoAuthMethod when set but no machine-identity
// env vars are present.
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
		AutoTokenRefresh:     sdk.BoolPtr(true), // v0.8.0 made this a *bool

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

// FetchSecrets honors ctx.Done() by selecting against a goroutine wrapping
// the context-unaware SDK call; on cancel the orphan runs to completion
// (up to the SDK's internal timeout) and sends to the buffered channel.
func (c *Client) FetchSecrets(ctx context.Context, cfg VaultConfig) ([]Secret, error) {
	type result struct {
		secs []Secret
		err  error
	}
	done := make(chan result, 1)
	go func() {
		res, err := c.sdk.Secrets().ListSecrets(sdk.ListSecretsOptions{
			ProjectID:              cfg.ProjectID,
			Environment:            cfg.Environment,
			SecretPath:             cfg.SecretPath,
			ExpandSecretReferences: true,
			AttachToProcessEnv:     false,
		})
		if err != nil {
			done <- result{nil, err}
			return
		}
		out := make([]Secret, len(res.Secrets))
		for i, s := range res.Secrets {
			out[i] = Secret{Key: s.SecretKey, Value: s.SecretValue}
		}
		done <- result{out, nil}
	}()
	select {
	case r := <-done:
		return r.secs, r.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// loginWithMethod dispatches to the SDK. Kubernetes and LDAP read env vars
// manually because the SDK looks up the SA-token path under the wrong key
// (typo) and the LDAP helper only env-reads the identity ID.
func loginWithMethod(c sdk.InfisicalClientInterface, method AuthMethod) error {
	auth := c.Auth()
	switch method {
	case AuthUniversal:
		_, err := auth.UniversalAuthLogin("", "")
		return err
	case AuthKubernetes:
		_, err := auth.KubernetesAuthLogin("", os.Getenv("INFISICAL_KUBERNETES_SERVICE_ACCOUNT_TOKEN_PATH"))
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
