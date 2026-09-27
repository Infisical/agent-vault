package brokercore

import (
	"context"
	"time"

	"github.com/Infisical/agent-vault/internal/broker"
	"github.com/Infisical/agent-vault/internal/store"
)

// DefaultMaxRequestBytes is the default cap for request bodies forwarded
// on the MITM proxy ingress. Distinct from the generic 1 MB limitBody
// wrapper used on control-plane endpoints.
const DefaultMaxRequestBytes int64 = 1 << 30 // 1 GiB

// MaxMaterializeBytes caps request bodies that must be buffered in RAM
// for body-surface substitutions. Kept small because body substitutions
// target API payloads (JSON, form-encoded), not large file uploads.
const MaxMaterializeBytes int64 = 64 << 20 // 64 MiB

// ProxyScope is the resolved identity + vault context for a proxy request.
// It is produced once per CONNECT on the MITM ingress and carried through
// to credential injection.
//
// HopKind is "cont" or "pol" for a hop JWT. Those tokens are not sessions:
// verify does not look up the actor, and agent revoke does not cut them
// off before exp. Frozen is the continuation's match. Bind is checked
// against the request before any credential read.
type ProxyScope struct {
	AgentID      string // non-empty for agent tokens
	UserID       string // non-empty for user sessions
	HopActorID   string // actor id carried by a hop JWT
	VaultID      string
	VaultName    string
	VaultRole    string
	HopKind      string
	InvocationID string
	Bind         *HopBind
	Frozen       *broker.Service
}

// ActorID returns the non-empty principal ID — UserID for user
// sessions, AgentID for agent tokens. Used as the actor dimension in
// per-scope rate-limit keys.
func (s *ProxyScope) ActorID() string {
	if s.HopActorID != "" {
		return s.HopActorID
	}
	if s.UserID != "" {
		return s.UserID
	}
	return s.AgentID
}

// ContinuationAuthorityMismatch reports whether a continuation token's
// bound authority does not match this CONNECT or forward target. A
// non-continuation scope never mismatches.
func (s *ProxyScope) ContinuationAuthorityMismatch(scheme, authority string) bool {
	if s == nil || s.HopKind != "cont" || s.Bind == nil {
		return s != nil && s.HopKind == "cont"
	}
	return s.Bind.Scheme != scheme || s.Bind.Authority != authority
}

// ContinuationRequestMismatch reports whether the full continuation bind
// fails. Authority is included.
func (s *ProxyScope) ContinuationRequestMismatch(method, scheme, authority, escapedPath, rawQuery string) bool {
	if s == nil || s.HopKind != "cont" || s.Bind == nil {
		return s != nil && s.HopKind == "cont"
	}
	return !s.Bind.Matches(method, scheme, authority, escapedPath, rawQuery)
}

// SessionResolver collapses bearer-token validation and vault selection
// into one call. The MITM ingress passes a vault hint parsed from
// Proxy-Authorization. An empty hint means "infer from session".
type SessionResolver interface {
	ResolveForProxy(ctx context.Context, token, vaultHint string) (*ProxyScope, error)
}

// SessionStore is the minimal store surface used by StoreSessionResolver.
// Kept narrow so tests can supply fakes without stubbing the full store.
type SessionStore interface {
	GetSession(ctx context.Context, rawToken string) (*store.Session, error)
	GetVault(ctx context.Context, name string) (*store.Vault, error)
	GetVaultByID(ctx context.Context, id string) (*store.Vault, error)
	GetVaultRole(ctx context.Context, actorID, vaultID string) (string, error)
	ListActorGrants(ctx context.Context, actorID string) ([]store.VaultGrant, error)
}

// StoreSessionResolver resolves sessions through a SessionStore. Now is
// injectable so tests can control expiry without wall-clock flake.
type StoreSessionResolver struct {
	Store  SessionStore
	Now    func() time.Time
	HopDEK []byte
}

// NewStoreSessionResolver constructs a resolver backed by s. If s is nil
// the returned resolver will panic on use; the constructor is permissive
// to match existing server construction patterns.
func NewStoreSessionResolver(s SessionStore) *StoreSessionResolver {
	return &StoreSessionResolver{Store: s, Now: time.Now}
}

// ResolveForProxy validates token, applies the vault hint, and returns a
// ProxyScope. See the sentinel errors in errors.go for the full taxonomy.
func (r *StoreSessionResolver) ResolveForProxy(ctx context.Context, token, vaultHint string) (*ProxyScope, error) {
	if token == "" {
		return nil, ErrInvalidSession
	}
	if IsHopToken(token) {
		return r.resolveHop(ctx, token)
	}
	sess, err := r.Store.GetSession(ctx, token)
	if err != nil || sess == nil {
		return nil, ErrInvalidSession
	}
	now := r.Now
	if now == nil {
		now = time.Now
	}
	if sess.IsExpired(now()) {
		return nil, ErrInvalidSession
	}

	// Scoped session: vault is baked into the session. A hint must match
	// the session's vault name; never silently retarget.
	if sess.VaultID != "" {
		v, err := r.Store.GetVaultByID(ctx, sess.VaultID)
		if err != nil || v == nil {
			return nil, ErrVaultNotFound
		}
		if vaultHint != "" && vaultHint != v.Name {
			return nil, ErrVaultHintMismatch
		}
		return &ProxyScope{
			UserID:    sess.UserID,
			AgentID:   sess.AgentID,
			VaultID:   v.ID,
			VaultName: v.Name,
			VaultRole: sess.VaultRole,
		}, nil
	}

	// Instance-level agent token: resolve vault from hint, or from the
	// agent's unique grant if any.
	if sess.AgentID == "" {
		return nil, ErrNoVaultContext
	}

	if vaultHint != "" {
		v, err := r.Store.GetVault(ctx, vaultHint)
		if err != nil || v == nil {
			return nil, ErrVaultNotFound
		}
		role, err := r.Store.GetVaultRole(ctx, sess.AgentID, v.ID)
		if err != nil || role == "" {
			return nil, ErrVaultAccessDenied
		}
		return &ProxyScope{
			AgentID:   sess.AgentID,
			VaultID:   v.ID,
			VaultName: v.Name,
			VaultRole: role,
		}, nil
	}

	grants, err := r.Store.ListActorGrants(ctx, sess.AgentID)
	if err != nil {
		return nil, ErrNoVaultContext
	}
	switch len(grants) {
	case 0:
		return nil, ErrNoVaultContext
	case 1:
		g := grants[0]
		return &ProxyScope{
			AgentID:   sess.AgentID,
			VaultID:   g.VaultID,
			VaultName: g.VaultName,
			VaultRole: g.Role,
		}, nil
	default:
		return nil, ErrAgentVaultAmbiguous
	}
}

func (r *StoreSessionResolver) resolveHop(ctx context.Context, token string) (*ProxyScope, error) {
	now := time.Now()
	if r.Now != nil {
		now = r.Now()
	}
	hop, err := VerifyHopToken(ctx, r.Store, r.HopDEK, token, now)
	if err != nil {
		return nil, err
	}
	scope := &ProxyScope{
		HopActorID:   hop.ActorID,
		VaultID:      hop.Vault.ID,
		VaultName:    hop.Vault.Name,
		VaultRole:    "proxy",
		HopKind:      hop.Kind,
		InvocationID: hop.InvocationID,
	}
	if hop.Kind == "cont" {
		scope.Bind = &hop.Bind
		scope.Frozen = hop.Frozen
	}
	return scope, nil
}
