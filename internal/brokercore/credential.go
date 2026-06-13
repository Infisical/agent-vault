package brokercore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/Infisical/agent-vault/internal/broker"
	"github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/oauth"
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

	// MatchedName/Host/Path/Port describe the matched service. Safe to log.
	// Empty under unmatched-host passthrough.
	MatchedName string
	MatchedHost string
	MatchedPath string
	MatchedPort *int

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
	Inject(ctx context.Context, vaultID, targetHost string, targetPort int, targetPath string) (*InjectResult, error)
}

// CredentialStore is the minimal store surface used by StoreCredentialProvider.
type CredentialStore interface {
	GetBrokerConfig(ctx context.Context, vaultID string) (*store.BrokerConfig, error)
	GetCredential(ctx context.Context, vaultID, key string) (*store.Credential, error)
	UnmatchedHostPolicy(ctx context.Context, vaultID string) (UnmatchedHostPolicy, error)
}

// OAuthStore is the store surface for OAuth token refresh.
// Passed separately to StoreCredentialProvider to keep CredentialStore minimal.
type OAuthStore interface {
	GetCredentialOAuth(ctx context.Context, vaultID, key string) (*store.CredentialOAuth, error)
	UpdateCredentialOAuthTokens(ctx context.Context, vaultID, key string, accessCT, accessNonce, refreshCT, refreshNonce []byte, expiresAt *time.Time) error
	UpdateCredentialOAuthError(ctx context.Context, vaultID, key string, errMsg string) error
}

// StoreCredentialProvider injects credentials using a CredentialStore and a
// 32-byte AES-256-GCM key held in memory for the lifetime of the process.
type StoreCredentialProvider struct {
	Store      CredentialStore
	OAuthStore OAuthStore       // nil = no OAuth refresh
	EncKey     []byte
	Refresher  *oauth.Refresher // nil = no OAuth refresh
}

// NewStoreCredentialProvider constructs a provider. encKey must be 32 bytes.
func NewStoreCredentialProvider(s CredentialStore, encKey []byte) *StoreCredentialProvider {
	return &StoreCredentialProvider{Store: s, EncKey: encKey}
}

// Inject matches (targetHost, targetPath) and resolves the matched
// service's auth into HTTP headers. targetHost may include a port —
// stripped before matching. Pass "/" for targetPath when no path is
// meaningful.
func (p *StoreCredentialProvider) Inject(ctx context.Context, vaultID, targetHost string, targetPort int, targetPath string) (*InjectResult, error) {
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
		services[i].Host, services[i].Path, services[i].Port = broker.SplitInlineHost(services[i].Host, services[i].Path)
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
	matched, score := broker.MatchService(matchHost, targetPort, targetPath, services)
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

		if cred.Type == "oauth" && s == "" {
			return "", fmt.Errorf("%w: credential %q", ErrOAuthNotConnected, key)
		}

		if cred.Type == "oauth" && p.Refresher != nil && p.OAuthStore != nil {
			s, err = p.maybeRefreshOAuth(ctx, vaultID, key, s)
			if err != nil {
				return "", err
			}
		}

		cache[key] = s
		return s, nil
	}

	// Capture non-secret metadata up front so a downstream credential-missing
	// error still carries it for diagnostic logging.
	result := &InjectResult{
		MatchedName:    matched.Name,
		MatchedHost:    matched.Host,
		MatchedPath:    matched.Path,
		MatchedPort:    matched.Port,
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

	headers, err := matched.Auth.Resolve(getCredential)
	if err != nil {
		return result, fmt.Errorf("%w: %v", ErrCredentialMissing, err)
	}

	result.Headers = headers
	result.Substitutions = resolvedSubs
	return result, nil
}

const oauthRefreshBuffer = 5 * time.Minute

func (p *StoreCredentialProvider) maybeRefreshOAuth(ctx context.Context, vaultID, key, currentToken string) (string, error) {
	oauthCfg, err := p.OAuthStore.GetCredentialOAuth(ctx, vaultID, key)
	if err != nil {
		return currentToken, nil
	}

	if oauthCfg.TokenExpiresAt == nil {
		return currentToken, nil
	}
	if time.Until(*oauthCfg.TokenExpiresAt) > oauthRefreshBuffer {
		return currentToken, nil
	}

	if len(oauthCfg.RefreshTokenCT) == 0 {
		return currentToken, nil
	}

	sfKey := vaultID + "|" + key
	result := p.Refresher.Do(sfKey, func() oauth.RefreshResult {
		refreshToken, err := crypto.Decrypt(oauthCfg.RefreshTokenCT, oauthCfg.RefreshTokenNonce, p.EncKey)
		if err != nil {
			return oauth.RefreshResult{Err: fmt.Errorf("%w: decrypt refresh token: %v", ErrOAuthRefreshFailed, err)}
		}

		var clientSecret string
		if len(oauthCfg.ClientSecretCT) > 0 {
			cs, err := crypto.Decrypt(oauthCfg.ClientSecretCT, oauthCfg.ClientSecretNonce, p.EncKey)
			if err != nil {
				return oauth.RefreshResult{Err: fmt.Errorf("%w: decrypt client secret: %v", ErrOAuthRefreshFailed, err)}
			}
			clientSecret = string(cs)
		}

		tok, err := oauth.Refresh(ctx, oauth.RefreshConfig{
			TokenURL:        oauthCfg.TokenURL,
			ClientID:        oauthCfg.ClientID,
			ClientSecret:    clientSecret,
			RefreshToken:    string(refreshToken),
			Scopes:          oauthCfg.Scopes,
			ScopeSeparator:  oauthCfg.ScopeSeparator,
			TokenAuthMethod: oauthCfg.TokenAuthMethod,
		})
		if err != nil {
			_ = p.OAuthStore.UpdateCredentialOAuthError(ctx, vaultID, key, err.Error())
			return oauth.RefreshResult{Err: fmt.Errorf("%w: %v", ErrOAuthRefreshFailed, err)}
		}

		accessCT, accessNonce, err := crypto.Encrypt([]byte(tok.AccessToken), p.EncKey)
		if err != nil {
			return oauth.RefreshResult{Err: fmt.Errorf("%w: encrypt access token: %v", ErrOAuthRefreshFailed, err)}
		}

		var newRefreshCT, newRefreshNonce []byte
		if tok.RefreshToken != "" {
			newRefreshCT, newRefreshNonce, err = crypto.Encrypt([]byte(tok.RefreshToken), p.EncKey)
			if err != nil {
				return oauth.RefreshResult{Err: fmt.Errorf("%w: encrypt refresh token: %v", ErrOAuthRefreshFailed, err)}
			}
		}

		var expiresAt *time.Time
		if !tok.ExpiresAt.IsZero() {
			expiresAt = &tok.ExpiresAt
		}

		if err := p.OAuthStore.UpdateCredentialOAuthTokens(ctx, vaultID, key, accessCT, accessNonce, newRefreshCT, newRefreshNonce, expiresAt); err != nil {
			return oauth.RefreshResult{Err: fmt.Errorf("%w: store tokens: %v", ErrOAuthRefreshFailed, err)}
		}

		return oauth.RefreshResult{AccessToken: tok.AccessToken, Refreshed: true}
	})

	if result.Err != nil {
		return "", result.Err
	}
	if result.Refreshed {
		return result.AccessToken, nil
	}
	return currentToken, nil
}
