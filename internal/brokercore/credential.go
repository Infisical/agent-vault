package brokercore

import (
	"context"
	"encoding/json"
	"fmt"
	"net"

	"github.com/Infisical/agent-vault/internal/broker"
	"github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/store"
)

// InjectResult is the outcome of matching a target host and resolving
// credentials to ready-to-attach HTTP headers.
type InjectResult struct {
	// Headers is the map of header name → value to overlay on the outbound
	// request. Caller must Set (not Add) to ensure injected values win over
	// any client-supplied duplicates.
	Headers map[string]string
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
	cfg, err := p.Store.GetBrokerConfig(ctx, vaultID)
	if err != nil || cfg == nil {
		return nil, ErrServiceNotFound
	}

	var services []broker.Service
	if err := json.Unmarshal([]byte(cfg.ServicesJSON), &services); err != nil {
		return nil, fmt.Errorf("brokercore: parsing broker services: %w", err)
	}

	matchHost := targetHost
	if h, _, err := net.SplitHostPort(targetHost); err == nil {
		matchHost = h
	}
	matched := broker.MatchHost(matchHost, services)
	if matched == nil {
		return nil, ErrServiceNotFound
	}

	headers, err := matched.Auth.Resolve(func(key string) (string, error) {
		cred, err := p.Store.GetCredential(ctx, vaultID, key)
		if err != nil || cred == nil {
			return "", fmt.Errorf("credential %q not found", key)
		}
		plaintext, err := crypto.Decrypt(cred.Ciphertext, cred.Nonce, p.EncKey)
		if err != nil {
			return "", fmt.Errorf("failed to decrypt credential %q", key)
		}
		return string(plaintext), nil
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCredentialMissing, err)
	}

	return &InjectResult{Headers: headers}, nil
}
