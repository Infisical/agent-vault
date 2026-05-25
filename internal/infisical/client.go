package infisical

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"

	sdk "github.com/infisical/go-sdk"
)

// ErrLayoutConflict marks a flatten failure caused by the upstream secret
// set carrying the same key under more than one path. The wrapped error
// names the conflicting paths and key; all are caller-supplied topology
// (not upstream secrets or URLs), so callers may surface the full message
// in operator responses without the leak risk that motivates scrubbing
// other Infisical errors.
var ErrLayoutConflict = errors.New("infisical: external store layout conflict")

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
// The SDK's ListSecrets is context-unaware (resty has no SetContext or
// SetTimeout configured), so the call runs in a goroutine and we select
// on ctx.Done() to honor the caller's deadline. On cancellation the
// orphan goroutine continues until the SDK gives up (~225s worst case
// on Linux TCP defaults); the result channel is buffered so the orphan
// never blocks on the send. Without this wrap, createExternalVault would
// hold a handler goroutine for the full SDK retry budget even after the
// HTTP client disconnected, and Syncer.refresh goroutines would stay
// in-flight past server shutdown.
//
// Returns ErrLayoutConflict (via flattenSecrets) when two secrets share
// a key across paths (idiomatic for --infisical-recursive=true layouts).
// Agent Vault's data model is flat key-value per vault; silent
// last-write-wins would inject a non-deterministic credential.
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
			Recursive:              cfg.Recursive,
			ExpandSecretReferences: true,
			AttachToProcessEnv:     false,
		})
		if err != nil {
			done <- result{nil, err}
			return
		}
		raw := make([]rawSecret, len(res.Secrets))
		for i, s := range res.Secrets {
			raw[i] = rawSecret{Key: s.SecretKey, Value: s.SecretValue, Path: s.SecretPath}
		}
		out, err := flattenSecrets(raw)
		done <- result{out, err}
	}()
	select {
	case r := <-done:
		return r.secs, r.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
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
			return nil, fmt.Errorf("%w: duplicate secret key %q under both %s and %s; Agent Vault vaults are flat key-value and cannot disambiguate", ErrLayoutConflict, s.Key, prev, s.Path)
		}
		seen[s.Key] = s.Path
		out = append(out, Secret{Key: s.Key, Value: s.Value})
	}
	return out, nil
}

// loginWithMethod dispatches to the right SDK auth function. Most branches
// pass empty arguments so the SDK reads the env vars directly (matches the
// standard SDK usage pattern documented for each method). The Kubernetes
// and LDAP branches read env vars manually: the SDK has a typo that looks
// up the SA-token path under the default-path string instead of the env
// var name, so the operator-supplied path would otherwise be ignored; the
// LDAP helper only env-reads the identity ID.
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
