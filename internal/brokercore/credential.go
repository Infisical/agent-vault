package brokercore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
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

// InjectResult is the outcome of matching a target host and resolving
// credentials to ready-to-attach HTTP headers.
type InjectResult struct {
	// Headers is the map of header name → value to overlay on the outbound
	// request. Caller must Set (not Add) to ensure injected values win over
	// any client-supplied duplicates. Values are SECRET — never log.
	// Nil for passthrough services.
	Headers map[string]string

	// MatchedHost is the broker service host pattern that matched the
	// target (e.g. "api.github.com"). Safe to log. Empty when the request
	// is forwarded under the unmatched-host passthrough policy.
	MatchedHost string

	// CredentialKeys are the credential key names referenced by the
	// matched service (auth + substitutions). Names only — safe to log.
	// Populated before resolution so credential-missing errors still
	// carry this for diagnostic logging.
	CredentialKeys []string

	// Substitutions are resolved placeholder rewrites the ingress must
	// apply via ApplySubstitutions before forwarding. Each entry carries
	// a SECRET Value — never log; placeholder names are safe.
	Substitutions []ResolvedSubstitution

	// Passthrough is set when no service matched but the vault's
	// unmatched-host policy permitted forwarding. Audited.
	Passthrough bool
}

// CredentialProvider resolves a broker service for targetHost inside vaultID
// and returns the HTTP headers required to authenticate the outbound request.
type CredentialProvider interface {
	Inject(ctx context.Context, vaultID, targetHost string) (*InjectResult, error)
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
	Store  CredentialStore
	EncKey []byte
}

// NewStoreCredentialProvider constructs a provider. encKey must be 32 bytes.
func NewStoreCredentialProvider(s CredentialStore, encKey []byte) *StoreCredentialProvider {
	return &StoreCredentialProvider{Store: s, EncKey: encKey}
}

// Inject matches targetHost against the vault's broker services, resolves
// the matched service's auth config into HTTP headers, and returns them.
//
// targetHost may include a port; the port is stripped before matching so
// services configured as bare hostnames match `api.github.com:443`.
func (p *StoreCredentialProvider) Inject(ctx context.Context, vaultID, targetHost string) (*InjectResult, error) {
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

	matchHost := targetHost
	if h, _, err := net.SplitHostPort(targetHost); err == nil {
		matchHost = h
	}
	matched := broker.MatchHost(matchHost, services)
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
		MatchedHost:    matched.Host,
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
