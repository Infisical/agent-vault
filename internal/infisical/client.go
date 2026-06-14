package infisical

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	sdk "github.com/infisical/go-sdk"
)

// SecretsFetcher is the slice of the SDK the syncer actually uses; tests
// substitute their own implementation without standing up the real client.
type SecretsFetcher interface {
	FetchSecrets(ctx context.Context, cfg VaultConfig) ([]Secret, error)
	AuthMethod() AuthMethod
}

// DynamicSecretInfo is the broker-facing summary of a dynamic-secret config
// discovered at a vault's path. Fields are unknown until a lease is minted.
type DynamicSecretInfo struct {
	Name string
	Type string
}

// DynamicLease is a minted (or renewed) dynamic-secret lease. Fields carries
// the SECRET credential values keyed by their provider field name (username,
// password, …); never log it.
type DynamicLease struct {
	LeaseID  string
	Fields   map[string]string
	ExpireAt time.Time
}

// DynamicFetcher is the slice of the SDK the dynamic-secret resolver uses;
// tests substitute their own implementation. Mirrors SecretsFetcher.
type DynamicFetcher interface {
	ListDynamicSecrets(ctx context.Context, cfg VaultConfig) ([]DynamicSecretInfo, error)
	CreateLease(ctx context.Context, cfg VaultConfig, name string) (DynamicLease, error)
	RenewLease(ctx context.Context, cfg VaultConfig, leaseID string) (expireAt time.Time, err error)
	RevokeLease(ctx context.Context, cfg VaultConfig, leaseID string) error
}

// Client wraps the Infisical SDK and provides a narrow fetch surface.
type Client struct {
	sdk     sdk.InfisicalClientInterface
	method  AuthMethod
	siteURL string
	logger  *slog.Logger

	httpc *http.Client

	// slugCache memoizes project-ID → project-slug lookups (dynamic-secret
	// endpoints key on the slug, but Agent Vault stores the ID). Entries expire
	// after slugCacheTTL so a renamed project slug re-resolves instead of
	// 404ing every dynamic call until restart.
	slugMu    sync.Mutex
	slugCache map[string]slugCacheEntry
}

type slugCacheEntry struct {
	slug      string
	fetchedAt time.Time
}

// slugCacheTTL bounds how long a resolved project slug is reused. Slugs rarely
// change, so this only matters after a rename; an hour keeps the workspace
// lookups negligible while self-healing within a bounded window.
const slugCacheTTL = time.Hour

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
		SiteUrl:          siteURL,
		AutoTokenRefresh: sdk.BoolPtr(true), // v0.8.0 made this a *bool

		CacheExpiryInSeconds: 0, // disable SDK-side secret caching; we own the cache
	})

	if err := loginWithMethod(c, method); err != nil {
		return nil, fmt.Errorf("infisical login (%s): %w", method, err)
	}

	logger.Info("infisical client ready",
		slog.String("site_url", siteURL),
		slog.String("auth_method", string(method)))

	return &Client{
		sdk:       c,
		method:    method,
		siteURL:   strings.TrimRight(siteURL, "/"),
		logger:    logger,
		httpc:     &http.Client{Timeout: 10 * time.Second},
		slugCache: make(map[string]slugCacheEntry),
	}, nil
}

// AuthMethod returns the detected machine-identity flow this client uses.
func (c *Client) AuthMethod() AuthMethod { return c.method }

// FetchSecrets honors ctx.Done() via runSDK; on cancel the orphaned SDK call
// runs to completion (up to the SDK's internal timeout) and is discarded.
func (c *Client) FetchSecrets(ctx context.Context, cfg VaultConfig) ([]Secret, error) {
	return runSDK(ctx, func() ([]Secret, error) {
		res, err := c.sdk.Secrets().ListSecrets(sdk.ListSecretsOptions{
			ProjectID:              cfg.ProjectID,
			Environment:            cfg.Environment,
			SecretPath:             cfg.SecretPath,
			ExpandSecretReferences: true,
			AttachToProcessEnv:     false,
		})
		if err != nil {
			return nil, err
		}
		out := make([]Secret, len(res.Secrets))
		for i, s := range res.Secrets {
			out[i] = Secret{Key: s.SecretKey, Value: s.SecretValue}
		}
		return out, nil
	})
}

// runSDK runs a context-unaware SDK call in a goroutine so ctx.Done() is
// honored; on cancel the orphaned call runs to completion and is discarded.
func runSDK[T any](ctx context.Context, fn func() (T, error)) (T, error) {
	type result struct {
		v   T
		err error
	}
	done := make(chan result, 1)
	go func() {
		v, err := fn()
		done <- result{v, err}
	}()
	select {
	case r := <-done:
		return r.v, r.err
	case <-ctx.Done():
		var zero T
		return zero, ctx.Err()
	}
}

// The dynamic-secret endpoints key on the project slug, not the ID, so each
// translates cfg.ProjectID via projectSlug first.
func (c *Client) ListDynamicSecrets(ctx context.Context, cfg VaultConfig) ([]DynamicSecretInfo, error) {
	slug, err := c.projectSlug(ctx, cfg.ProjectID)
	if err != nil {
		return nil, err
	}
	return runSDK(ctx, func() ([]DynamicSecretInfo, error) {
		res, err := c.sdk.DynamicSecrets().List(sdk.ListDynamicSecretsRootCredentialsOptions{
			ProjectSlug:     slug,
			EnvironmentSlug: cfg.Environment,
			SecretPath:      cfg.SecretPath,
		})
		if err != nil {
			return nil, err
		}
		out := make([]DynamicSecretInfo, len(res))
		for i, ds := range res {
			out[i] = DynamicSecretInfo{Name: ds.Name, Type: ds.Type}
		}
		return out, nil
	})
}

func (c *Client) CreateLease(ctx context.Context, cfg VaultConfig, name string) (DynamicLease, error) {
	slug, err := c.projectSlug(ctx, cfg.ProjectID)
	if err != nil {
		return DynamicLease{}, err
	}
	return runSDK(ctx, func() (DynamicLease, error) {
		// Empty TTL → Infisical uses the dynamic secret's configured DefaultTTL.
		data, _, lease, err := c.sdk.DynamicSecrets().Leases().Create(sdk.CreateDynamicSecretLeaseOptions{
			DynamicSecretName: name,
			ProjectSlug:       slug,
			EnvironmentSlug:   cfg.Environment,
			SecretPath:        cfg.SecretPath,
		})
		if err != nil {
			return DynamicLease{}, err
		}
		return DynamicLease{LeaseID: lease.Id, Fields: stringifyFields(data), ExpireAt: lease.ExpireAt}, nil
	})
}

func (c *Client) RenewLease(ctx context.Context, cfg VaultConfig, leaseID string) (time.Time, error) {
	slug, err := c.projectSlug(ctx, cfg.ProjectID)
	if err != nil {
		return time.Time{}, err
	}
	return runSDK(ctx, func() (time.Time, error) {
		lease, err := c.sdk.DynamicSecrets().Leases().RenewById(sdk.RenewDynamicSecretLeaseOptions{
			LeaseId:         leaseID,
			ProjectSlug:     slug,
			EnvironmentSlug: cfg.Environment,
			SecretPath:      cfg.SecretPath,
		})
		if err != nil {
			return time.Time{}, err
		}
		return lease.ExpireAt, nil
	})
}

func (c *Client) RevokeLease(ctx context.Context, cfg VaultConfig, leaseID string) error {
	slug, err := c.projectSlug(ctx, cfg.ProjectID)
	if err != nil {
		return err
	}
	_, err = runSDK(ctx, func() (struct{}, error) {
		_, err := c.sdk.DynamicSecrets().Leases().DeleteById(sdk.DeleteDynamicSecretLeaseOptions{
			LeaseId:         leaseID,
			ProjectSlug:     slug,
			EnvironmentSlug: cfg.Environment,
			SecretPath:      cfg.SecretPath,
		})
		return struct{}{}, err
	})
	return err
}

// projectSlug resolves a project ID to its slug via GET /api/v1/workspace/{id},
// caching the result for the process. The SDK auto-refreshes the bearer token,
// so GetAccessToken returns a current one.
func (c *Client) projectSlug(ctx context.Context, projectID string) (string, error) {
	c.slugMu.Lock()
	if e, ok := c.slugCache[projectID]; ok && time.Since(e.fetchedAt) < slugCacheTTL {
		c.slugMu.Unlock()
		return e.slug, nil
	}
	c.slugMu.Unlock()

	token := c.sdk.Auth().GetAccessToken()
	if token == "" {
		return "", fmt.Errorf("infisical: no access token available to resolve project slug")
	}
	slug, err := getProjectSlug(ctx, c.httpc, c.siteURL, token, projectID)
	if err != nil {
		return "", err
	}
	c.slugMu.Lock()
	c.slugCache[projectID] = slugCacheEntry{slug: slug, fetchedAt: time.Now()}
	c.slugMu.Unlock()
	return slug, nil
}

// getProjectSlug GETs /api/v1/workspace/{id} and extracts the project slug.
// Free function so the HTTP/parse path is testable without the SDK.
func getProjectSlug(ctx context.Context, httpc *http.Client, siteURL, token, projectID string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, siteURL+"/api/v1/workspace/"+projectID, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := httpc.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("infisical: resolving project slug for %q: status %d", projectID, resp.StatusCode)
	}
	var parsed struct {
		Workspace struct {
			Slug string `json:"slug"`
		} `json:"workspace"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", fmt.Errorf("infisical: parsing project slug response: %w", err)
	}
	if parsed.Workspace.Slug == "" {
		return "", fmt.Errorf("infisical: project %q has no slug in response", projectID)
	}
	return parsed.Workspace.Slug, nil
}

// stringifyFields renders a lease's map[string]any credential payload as
// strings. JSON numbers arrive as float64; render them without a trailing
// ".0" so ports and the like inject cleanly.
func stringifyFields(data map[string]any) map[string]string {
	out := make(map[string]string, len(data))
	for k, v := range data {
		switch t := v.(type) {
		case string:
			out[k] = t
		case float64:
			out[k] = strconv.FormatFloat(t, 'f', -1, 64)
		case bool:
			out[k] = strconv.FormatBool(t)
		case nil:
			out[k] = ""
		default:
			out[k] = fmt.Sprintf("%v", t)
		}
	}
	return out
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
