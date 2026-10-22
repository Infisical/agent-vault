package brokercore

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/Infisical/agent-vault/internal/broker"
	"github.com/Infisical/agent-vault/internal/store"
	"golang.org/x/crypto/hkdf"
)

const (
	hopJWTInfo = "agent-vault hop jwt v1"
	hopTTL     = 30 * time.Second

	PrefixContinuation = "av_cont_"
	PrefixPolicy       = "av_pol_"

	kindContinuation = "cont"
	kindPolicy       = "pol"

	matchVersion = 1
)

// HopBind is the continuation's frozen request identity. Path is the escaped
// path and Query is the raw query, compared byte for byte.
type HopBind struct {
	Method    string `json:"method"`
	Scheme    string `json:"scheme"`
	Authority string `json:"authority"`
	Path      string `json:"path"`
	Query     string `json:"query"`
}

// Matches reports whether the inbound request is the one this bind froze.
func (b HopBind) Matches(method, scheme, authority, escapedPath, rawQuery string) bool {
	return b.Method == method &&
		b.Scheme == scheme &&
		b.Authority == authority &&
		b.Path == escapedPath &&
		b.Query == rawQuery
}

type hopClaims struct {
	Kind          string          `json:"kind"`
	Iat           int64           `json:"iat"`
	Exp           int64           `json:"exp"`
	InvocationID  string          `json:"invocation_id"`
	SourceVaultID string          `json:"source_vault_id"`
	ActorID       string          `json:"actor_id"`
	Bind          *HopBind        `json:"bind,omitempty"`
	Match         json.RawMessage `json:"match,omitempty"`
	PolicyVaultID string          `json:"policy_vault_id,omitempty"`
}

type frozenMatch struct {
	V             int                   `json:"v"`
	Name          string                `json:"name"`
	Host          string                `json:"host"`
	Path          string                `json:"path,omitempty"`
	Port          *int                  `json:"port,omitempty"`
	Auth          broker.Auth           `json:"auth"`
	Substitutions []broker.Substitution `json:"substitutions,omitempty"`
}

// HopMintInput is the material for one filtered request's token pair.
type HopMintInput struct {
	SourceVaultID string
	ActorID       string
	Bind          HopBind
	Service       broker.Service
	PolicyVault   string
}

// HopToken is a verified hop JWT. Frozen is set only for a continuation.
type HopToken struct {
	Kind          string
	InvocationID  string
	SourceVaultID string
	ActorID       string
	PolicyVaultID string
	Bind          HopBind
	Frozen        *broker.Service
	Vault         *store.Vault
}

// VaultLookup is the store surface hop mint and verify need.
type VaultLookup interface {
	GetVault(ctx context.Context, name string) (*store.Vault, error)
	GetVaultByID(ctx context.Context, id string) (*store.Vault, error)
}

// HopMACKey derives the HMAC key from the DEK. Every replica that loaded
// the same DEK derives the same key. The key is not stored.
func HopMACKey(dek []byte) ([]byte, error) {
	if len(dek) == 0 {
		return nil, errors.New("brokercore: hop jwt requires an unlocked DEK")
	}
	r := hkdf.New(sha256.New, dek, nil, []byte(hopJWTInfo))
	key := make([]byte, 32)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, err
	}
	return key, nil
}

// StoreHopMinter mints continuation and policy tokens.
type StoreHopMinter struct {
	Vaults VaultLookup
	DEK    []byte
	Now    func() time.Time
}

// Mint returns the continuation token and, when PolicyVault is set, the
// policy token. Both share one invocation id. The policy token is empty
// when PolicyVault is omitted.
func (m *StoreHopMinter) Mint(ctx context.Context, in HopMintInput) (continuation, policy string, err error) {
	if m == nil || m.Vaults == nil {
		return "", "", fmt.Errorf("%w: hop minter is not configured", ErrFilterMisconfigured)
	}
	key, err := HopMACKey(m.DEK)
	if err != nil {
		return "", "", fmt.Errorf("%w: %v", ErrFilterUnreachable, err)
	}
	now := time.Now()
	if m.Now != nil {
		now = m.Now()
	}
	inv, err := newInvocationID()
	if err != nil {
		return "", "", fmt.Errorf("%w: %v", ErrFilterUnreachable, err)
	}
	matchRaw, err := marshalFrozenMatch(in.Service)
	if err != nil {
		return "", "", fmt.Errorf("%w: %v", ErrFilterMisconfigured, err)
	}
	var policyVaultID string
	if in.PolicyVault != "" {
		v, err := m.Vaults.GetVault(ctx, in.PolicyVault)
		if err != nil || v == nil {
			return "", "", fmt.Errorf("%w: policy vault %q not found", ErrFilterMisconfigured, in.PolicyVault)
		}
		policyVaultID = v.ID
	}
	base := hopClaims{
		Iat:           now.Unix(),
		Exp:           now.Add(hopTTL).Unix(),
		InvocationID:  inv,
		SourceVaultID: in.SourceVaultID,
		ActorID:       in.ActorID,
	}
	contClaims := base
	contClaims.Kind = kindContinuation
	contClaims.Bind = &in.Bind
	contClaims.Match = matchRaw
	continuation, err = signPrefixed(PrefixContinuation, key, contClaims)
	if err != nil {
		return "", "", fmt.Errorf("%w: %v", ErrFilterUnreachable, err)
	}
	if policyVaultID == "" {
		return continuation, "", nil
	}
	polClaims := base
	polClaims.Kind = kindPolicy
	polClaims.PolicyVaultID = policyVaultID
	policy, err = signPrefixed(PrefixPolicy, key, polClaims)
	if err != nil {
		return "", "", fmt.Errorf("%w: %v", ErrFilterUnreachable, err)
	}
	return continuation, policy, nil
}

func marshalFrozenMatch(svc broker.Service) (json.RawMessage, error) {
	body := frozenMatch{
		V:             matchVersion,
		Name:          svc.Name,
		Host:          svc.Host,
		Path:          svc.Path,
		Port:          svc.Port,
		Auth:          svc.Auth,
		Substitutions: svc.Substitutions,
	}
	b, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// ThawMatch decodes a frozen match. An unknown version fails before the
// caller is allowed to read a credential.
func ThawMatch(raw json.RawMessage) (*broker.Service, error) {
	var probe struct {
		V int `json:"v"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return nil, fmt.Errorf("%w: match is not valid JSON", ErrFilterMisconfigured)
	}
	if probe.V != matchVersion {
		return nil, fmt.Errorf("%w: unknown match version %d", ErrFilterMisconfigured, probe.V)
	}
	var body frozenMatch
	if err := json.Unmarshal(raw, &body); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFilterMisconfigured, err)
	}
	return &broker.Service{
		Name:          body.Name,
		Host:          body.Host,
		Path:          body.Path,
		Port:          body.Port,
		Auth:          body.Auth,
		Substitutions: body.Substitutions,
	}, nil
}

// VerifyHopToken checks the prefix, signature, expiry, and kind, then
// loads the vault the token is allowed to act in. It does not look up a
// session. A deleted vault fails closed.
func VerifyHopToken(ctx context.Context, vaults VaultLookup, dek []byte, token string, now time.Time) (*HopToken, error) {
	prefix, raw, ok := splitHopPrefix(token)
	if !ok {
		return nil, ErrInvalidSession
	}
	key, err := HopMACKey(dek)
	if err != nil {
		return nil, ErrInvalidSession
	}
	claims, err := verifyJWT(key, raw, now)
	if err != nil {
		return nil, ErrInvalidSession
	}
	switch prefix {
	case PrefixContinuation:
		if claims.Kind != kindContinuation || claims.Bind == nil || len(claims.Match) == 0 {
			return nil, ErrInvalidSession
		}
	case PrefixPolicy:
		if claims.Kind != kindPolicy || claims.PolicyVaultID == "" {
			return nil, ErrInvalidSession
		}
	default:
		return nil, ErrInvalidSession
	}
	if vaults == nil {
		return nil, ErrVaultNotFound
	}
	vaultID := claims.SourceVaultID
	if prefix == PrefixPolicy {
		vaultID = claims.PolicyVaultID
	}
	v, err := vaults.GetVaultByID(ctx, vaultID)
	if err != nil || v == nil {
		return nil, ErrVaultNotFound
	}
	out := &HopToken{
		Kind:          claims.Kind,
		InvocationID:  claims.InvocationID,
		SourceVaultID: claims.SourceVaultID,
		ActorID:       claims.ActorID,
		PolicyVaultID: claims.PolicyVaultID,
		Vault:         v,
	}
	if claims.Bind != nil {
		out.Bind = *claims.Bind
	}
	if prefix == PrefixContinuation {
		frozen, err := ThawMatch(claims.Match)
		if err != nil {
			return nil, err
		}
		out.Frozen = frozen
	}
	return out, nil
}

func splitHopPrefix(token string) (prefix, jwt string, ok bool) {
	switch {
	case strings.HasPrefix(token, PrefixContinuation):
		return PrefixContinuation, strings.TrimPrefix(token, PrefixContinuation), true
	case strings.HasPrefix(token, PrefixPolicy):
		return PrefixPolicy, strings.TrimPrefix(token, PrefixPolicy), true
	default:
		return "", "", false
	}
}

// IsHopToken reports whether token carries a hop prefix.
func IsHopToken(token string) bool {
	_, _, ok := splitHopPrefix(token)
	return ok
}

func signPrefixed(prefix string, key []byte, claims hopClaims) (string, error) {
	jwt, err := signJWT(key, claims)
	if err != nil {
		return "", err
	}
	return prefix + jwt, nil
}

func signJWT(key []byte, claims hopClaims) (string, error) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	body := base64.RawURLEncoding.EncodeToString(payload)
	unsigned := header + "." + body
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(unsigned))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return unsigned + "." + sig, nil
}

func verifyJWT(key []byte, token string, now time.Time) (*hopClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("jwt segments")
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(parts[0] + "." + parts[1]))
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, err
	}
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return nil, errors.New("bad signature")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var claims hopClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, err
	}
	if claims.Exp == 0 || !now.Before(time.Unix(claims.Exp, 0)) {
		return nil, errors.New("expired")
	}
	return &claims, nil
}

func newInvocationID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
