package brokercore

import (
	"context"
	"time"

	"github.com/Infisical/agent-vault/internal/store"
)

// MaxProxyBodyBytes caps forwarded request bodies on both proxy
// ingresses. Distinct from the generic 1 MB limitBody wrapper used
// on control-plane endpoints: proxy bodies are legitimately larger
// (file uploads, bulk API payloads) but must still be bounded to
// protect RAM under the proxy concurrency semaphore.
const MaxProxyBodyBytes = 64 << 20

// ProxyScope is the resolved identity + vault context for a proxy request.
// It is produced once per ingress (per request for /proxy, per CONNECT for
// MITM) and carried through to credential injection.
type ProxyScope struct {
	AgentID   string // non-empty for agent tokens
	UserID    string // non-empty for user sessions
	VaultID   string
	VaultName string
	VaultRole string
}

// ActorID returns the non-empty principal ID — UserID for user
// sessions, AgentID for agent tokens. Used as the actor dimension in
// per-scope rate-limit keys.
func (s *ProxyScope) ActorID() string {
	if s.UserID != "" {
		return s.UserID
	}
	return s.AgentID
}

// SessionResolver collapses bearer-token validation and vault selection into
// one call. Both ingresses use the same resolver; MITM passes a vault hint
// parsed from Proxy-Authorization, /proxy passes r.Header.Get("X-Vault").
// An empty hint means "infer from session".
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
	Store SessionStore
	Now   func() time.Time
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
	sess, err := r.Store.GetSession(ctx, token)
	if err != nil || sess == nil {
		return nil, ErrInvalidSession
	}
	now := r.Now
	if now == nil {
		now = time.Now
	}
	if sess.ExpiresAt != nil && now().After(*sess.ExpiresAt) {
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
