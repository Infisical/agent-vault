package hashicorp

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"strconv"
	"strings"

	vaultapi "github.com/hashicorp/vault/api"
)

// SecretsFetcher is the slice of the API the syncer actually uses; tests
// substitute their own implementation without standing up a real Vault.
type SecretsFetcher interface {
	FetchSecrets(ctx context.Context, cfg VaultConfig) ([]Secret, error)
	AuthMethod() AuthMethod
}

// Client wraps the HashiCorp Vault API and provides a narrow fetch surface.
type Client struct {
	api    *vaultapi.Client
	method AuthMethod
	logger *slog.Logger
}

// NewClient returns ErrNotConfigured when VAULT_ADDR is unset (callers keep
// the server alive) or ErrNoAuthMethod when set but no auth env vars are
// present. Address, TLS (VAULT_CACERT, VAULT_SKIP_VERIFY), and namespace
// (VAULT_NAMESPACE) are read from the standard Vault environment variables by
// vaultapi.DefaultConfig.
func NewClient(ctx context.Context, logger *slog.Logger) (*Client, error) {
	addr := os.Getenv("VAULT_ADDR")
	if addr == "" {
		return nil, ErrNotConfigured
	}

	method, err := DetectAuthMethod(os.Getenv, logger)
	if err != nil {
		return nil, err
	}
	if method == "" {
		return nil, ErrNoAuthMethod
	}

	cfg := vaultapi.DefaultConfig()
	if cfg.Error != nil {
		return nil, fmt.Errorf("hashicorp config: %w", cfg.Error)
	}
	api, err := vaultapi.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("hashicorp client: %w", err)
	}
	if ns := os.Getenv("VAULT_NAMESPACE"); ns != "" {
		api.SetNamespace(ns)
	}
	// vaultapi.DefaultConfig honors VAULT_SKIP_VERIFY silently. The broker pulls
	// live secrets over this channel, so surface the downgrade as an auditable
	// warning rather than letting a leftover dev setting go unnoticed in prod.
	if skip, _ := strconv.ParseBool(os.Getenv("VAULT_SKIP_VERIFY")); skip {
		logger.Warn("hashicorp vault TLS verification disabled (VAULT_SKIP_VERIFY=true); the broker↔Vault channel is unauthenticated")
	}

	if err := login(ctx, api, method); err != nil {
		return nil, fmt.Errorf("hashicorp login (%s): %w", method, err)
	}

	logger.Info("hashicorp vault client ready",
		slog.String("addr", addr),
		slog.String("auth_method", string(method)))

	return &Client{api: api, method: method, logger: logger}, nil
}

// AuthMethod returns the auth flow this client used.
func (c *Client) AuthMethod() AuthMethod { return c.method }

// FetchSecrets reads the single KV item at cfg.Mount/cfg.SecretPath and flattens
// its key/value pairs into broker-facing Secrets. The API call is
// context-aware, so cancellation propagates directly.
func (c *Client) FetchSecrets(ctx context.Context, cfg VaultConfig) ([]Secret, error) {
	var data map[string]interface{}
	switch cfg.KVVersion {
	case 2:
		sec, err := c.api.KVv2(cfg.Mount).Get(ctx, cfg.SecretPath)
		if err != nil {
			return nil, err
		}
		if sec == nil {
			return nil, fmt.Errorf("no secret at %s/%s", cfg.Mount, cfg.SecretPath)
		}
		data = sec.Data
	case 1:
		sec, err := c.api.KVv1(cfg.Mount).Get(ctx, cfg.SecretPath)
		if err != nil {
			return nil, err
		}
		if sec == nil {
			return nil, fmt.Errorf("no secret at %s/%s", cfg.Mount, cfg.SecretPath)
		}
		data = sec.Data
	default:
		return nil, fmt.Errorf("unsupported kv_version %d", cfg.KVVersion)
	}

	// Sort keys so the snapshot order is deterministic across syncs.
	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	out := make([]Secret, 0, len(keys))
	for _, k := range keys {
		out = append(out, Secret{Key: k, Value: stringValue(data[k])})
	}
	return out, nil
}

// stringValue coerces a KV value to a string. KV values are usually strings;
// scalars are stringified and structured values are JSON-encoded so the broker
// always receives a usable credential rather than a Go-syntax dump.
func stringValue(v interface{}) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case json.Number:
		return t.String()
	case bool:
		return fmt.Sprintf("%t", t)
	case float64:
		// Avoid exponent notation / lossy %v formatting so an injected
		// credential matches the upstream value exactly. (The vault/api client
		// decodes JSON numbers as json.Number above; this is the defensive path.)
		return strconv.FormatFloat(t, 'f', -1, 64)
	case int, int64:
		return fmt.Sprintf("%v", t)
	default:
		if b, err := json.Marshal(t); err == nil {
			return string(b)
		}
		return fmt.Sprintf("%v", t)
	}
}

// login authenticates the API client per the detected method. Token sets the
// token and probes it; AppRole writes the login endpoint and adopts the
// returned client token. Both leave api ready for KV reads.
func login(ctx context.Context, api *vaultapi.Client, method AuthMethod) error {
	switch method {
	case AuthToken:
		api.SetToken(os.Getenv("VAULT_TOKEN"))
		// Token auth has no login round-trip, so an expired or malformed token
		// would otherwise stay silent until the first sync tick. Probe
		// lookup-self once to fail fast at startup (AppRole already fails fast
		// via its login call).
		if _, err := api.Auth().Token().LookupSelfWithContext(ctx); err != nil {
			return fmt.Errorf("token lookup-self: %w", err)
		}
		return nil
	case AuthAppRole:
		// AppRole is commonly mounted at a non-default path on Enterprise/HCP
		// (e.g. auth/prod-approle). VAULT_APPROLE_MOUNT overrides the default.
		mount := strings.Trim(strings.TrimSpace(os.Getenv("VAULT_APPROLE_MOUNT")), "/")
		if mount == "" {
			mount = "approle"
		}
		secret, err := api.Logical().WriteWithContext(ctx, fmt.Sprintf("auth/%s/login", mount), map[string]interface{}{
			"role_id":   os.Getenv("VAULT_ROLE_ID"),
			"secret_id": os.Getenv("VAULT_SECRET_ID"),
		})
		if err != nil {
			return err
		}
		if secret == nil || secret.Auth == nil || secret.Auth.ClientToken == "" {
			return fmt.Errorf("approle login returned no client token")
		}
		api.SetToken(secret.Auth.ClientToken)
		return nil
	default:
		return fmt.Errorf("hashicorp: unsupported auth method %q", method)
	}
}
