package brokercore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"

	"github.com/Infisical/agent-vault/internal/broker"
	"github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/store"
)

// UnmatchedHostPolicy controls what happens when a request's target host
// does not match any configured broker service. PolicyPassthrough is the
// system-wide default; PolicyDeny is the opt-in strict mode.
type UnmatchedHostPolicy string

const (
	PolicyPassthrough UnmatchedHostPolicy = "passthrough"
	PolicyDeny        UnmatchedHostPolicy = "deny"
)

func IsValidUnmatchedHostPolicy(p UnmatchedHostPolicy) bool {
	return p == PolicyPassthrough || p == PolicyDeny
}

// InjectResult is the outcome of matching (host, path) and resolving
// credentials to ready-to-attach HTTP headers.
type InjectResult struct {
	// Headers carries SECRET values — never log. Caller must Set (not
	// Add) so injected values win over client-supplied duplicates.
	// Nil for passthrough services.
	Headers map[string]string

	// MatchedName/Host/Path describe the matched service. Safe to log.
	// Empty under unmatched-host passthrough.
	MatchedName string
	MatchedHost string
	MatchedPath string

	// CredentialKeys are the key names referenced by the matched
	// service. Populated before resolution so credential-missing
	// errors still carry diagnostic context. Safe to log.
	CredentialKeys []string

	// Substitutions are resolved placeholder rewrites; each entry
	// carries a SECRET Value — never log placeholder values.
	Substitutions []ResolvedSubstitution

	// Passthrough is set when no service matched but the unmatched-host
	// policy permitted forwarding.
	Passthrough bool
}

// CredentialProvider resolves a service for (targetHost, targetPath) in
// vaultID and returns the headers to attach. targetPath must be the URL
// path only — no query, no fragment.
type CredentialProvider interface {
	Inject(ctx context.Context, vaultID, targetHost, targetPath string) (*InjectResult, error)
}

// CredentialStore is the minimal store surface used by StoreCredentialProvider.
type CredentialStore interface {
	GetBrokerConfig(ctx context.Context, vaultID string) (*store.BrokerConfig, error)
	GetCredential(ctx context.Context, vaultID, key string) (*store.Credential, error)
	UnmatchedHostPolicy(ctx context.Context, vaultID string) (UnmatchedHostPolicy, error)
}

// StoreCredentialProvider injects credentials using a CredentialStore and a
// 32-byte AES-256-GCM key held in memory for the lifetime of the process.
type StoreCredentialProvider struct {
	Store       CredentialStore
	EncKey      []byte
	OAuthTokens OAuthAccessTokenSource
}

// StoreCredentialProviderOption customizes a StoreCredentialProvider.
type StoreCredentialProviderOption func(*StoreCredentialProvider)

// WithOAuthTokenSource injects the OAuth token source used for oauth auth.
func WithOAuthTokenSource(source OAuthAccessTokenSource) StoreCredentialProviderOption {
	return func(p *StoreCredentialProvider) {
		p.OAuthTokens = source
	}
}

// NewStoreCredentialProvider constructs a provider. encKey must be 32 bytes.
func NewStoreCredentialProvider(s CredentialStore, encKey []byte, opts ...StoreCredentialProviderOption) *StoreCredentialProvider {
	p := &StoreCredentialProvider{Store: s, EncKey: encKey, OAuthTokens: NewOAuthTokenSource()}
	for _, opt := range opts {
		opt(p)
	}
	if p.OAuthTokens == nil {
		p.OAuthTokens = NewOAuthTokenSource()
	}
	return p
}

// Inject matches (targetHost, targetPath) and resolves the matched
// service's auth into HTTP headers. targetHost may include a port —
// stripped before matching. Pass "/" for targetPath when no path is
// meaningful.
func (p *StoreCredentialProvider) Inject(ctx context.Context, vaultID, targetHost, targetPath string) (*InjectResult, error) {
	// A missing row is equivalent to an empty services list — fall
	// through to the unmatched-host policy. Any other error fails closed
	// so a transient store failure can't silently strip enforcement.
	cfg, err := p.Store.GetBrokerConfig(ctx, vaultID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, ErrServiceNotFound
	}

	var services []broker.Service
	if cfg != nil && cfg.ServicesJSON != "" {
		if err := json.Unmarshal([]byte(cfg.ServicesJSON), &services); err != nil {
			return nil, fmt.Errorf("brokercore: parsing broker services: %w", err)
		}
	}
	// MarshalJSON persists Host in joined-inline form; the matcher
	// requires Host without "/", so split before matching.
	for i := range services {
		services[i].Host, services[i].Path = broker.SplitInlineHost(services[i].Host, services[i].Path)
	}
	// Heal legacy unnamed entries so MatchedName (which lands in the
	// request log and the X-Vault-Service header) is never blank for a
	// matched service — the documented `?service=<name>` log filter
	// depends on it.
	broker.AssignSlugNames(services)

	matchHost := targetHost
	if h, _, err := net.SplitHostPort(targetHost); err == nil {
		matchHost = h
	}
	if targetPath == "" {
		targetPath = "/"
	}
	matched, score := broker.MatchService(matchHost, targetPath, services)
	if matched == nil {
		// Fail closed on policy lookup errors so a transient store
		// failure can't silently strip enforcement.
		policy, err := p.Store.UnmatchedHostPolicy(ctx, vaultID)
		if err != nil || policy == PolicyDeny {
			return nil, ErrServiceNotFound
		}
		return &InjectResult{Passthrough: true}, nil
	}
	if !matched.IsEnabled() {
		return nil, ErrServiceDisabled
	}
	slog.Default().Debug("broker matched",
		slog.String("vault", vaultID),
		slog.String("service", matched.Name),
		slog.String("host", matched.Host),
		slog.String("path", matched.Path),
		slog.String("host_tier", score.HostTierName()),
		slog.Int("path_prefix_len", score.PathLiteralLen),
		slog.Int("decl_order", score.DeclOrder),
	)

	// Memoize per-key lookups so a credential shared by auth and a
	// substitution decrypts only once.
	cache := make(map[string]string)
	getCredential := func(key string) (string, error) {
		if v, ok := cache[key]; ok {
			return v, nil
		}
		cred, err := p.Store.GetCredential(ctx, vaultID, key)
		if err != nil || cred == nil {
			return "", fmt.Errorf("credential %q not found", key)
		}
		plaintext, err := crypto.Decrypt(cred.Ciphertext, cred.Nonce, p.EncKey)
		if err != nil {
			return "", fmt.Errorf("failed to decrypt credential %q", key)
		}
		s := string(plaintext)
		cache[key] = s
		return s, nil
	}

	// Capture non-secret metadata up front so a downstream credential-missing
	// error still carries it for diagnostic logging.
	result := &InjectResult{
		MatchedName:    matched.Name,
		MatchedHost:    matched.Host,
		MatchedPath:    matched.Path,
		CredentialKeys: matched.CredentialKeys(),
	}

	// Resolve substitutions before auth so passthrough services (which
	// skip the auth branch) still surface ErrCredentialMissing here.
	// Hold locally and attach only on success — error returns must not
	// expose resolved secret values via result.
	var resolvedSubs []ResolvedSubstitution
	if len(matched.Substitutions) > 0 {
		resolvedSubs = make([]ResolvedSubstitution, 0, len(matched.Substitutions))
		for _, sub := range matched.Substitutions {
			val, err := getCredential(sub.Key)
			if err != nil {
				return result, fmt.Errorf("%w: %v", ErrCredentialMissing, err)
			}
			resolvedSubs = append(resolvedSubs, ResolvedSubstitution{
				Placeholder: sub.Placeholder,
				Value:       val,
				In:          sub.NormalizedIn(),
			})
		}
	}

	if matched.Auth.Type == "passthrough" {
		result.Substitutions = resolvedSubs
		return result, nil
	}

	if matched.Auth.Type == "oauth" {
		clientSecret, err := getCredential(matched.Auth.ClientSecretKey)
		if err != nil {
			return result, fmt.Errorf("%w: %v", ErrCredentialMissing, err)
		}
		refreshToken, err := getCredential(matched.Auth.RefreshTokenKey)
		if err != nil {
			return result, fmt.Errorf("%w: %v", ErrCredentialMissing, err)
		}
		accessToken, err := p.OAuthTokens.Get(ctx, matched.Auth.ClientID, clientSecret, refreshToken, matched.Auth.TokenEndpoint, matched.Auth.Scopes)
		if err != nil {
			if errors.Is(err, ErrOAuthRefreshFailed) {
				return result, fmt.Errorf("%w: %v", ErrOAuthRefreshDenied, err)
			}
			return result, err
		}
		result.Headers = map[string]string{"Authorization": "Bearer " + accessToken}
		result.Substitutions = resolvedSubs
		return result, nil
	}

	headers, err := matched.Auth.Resolve(getCredential)
	if err != nil {
		return result, fmt.Errorf("%w: %v", ErrCredentialMissing, err)
	}

	result.Headers = headers
	result.Substitutions = resolvedSubs
	return result, nil
}
