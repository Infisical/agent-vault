package brokercore

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/store"
)

// fakeSessionStore satisfies SessionStore for tests without a real DB.
type fakeSessionStore struct {
	sessions map[string]*store.Session
	vaults   map[string]*store.Vault // keyed by name
	byID     map[string]*store.Vault
	roles    map[string]string // key = actorID+"|"+vaultID → role
	grants   map[string][]store.VaultGrant
}

func newFakeSessionStore() *fakeSessionStore {
	return &fakeSessionStore{
		sessions: map[string]*store.Session{},
		vaults:   map[string]*store.Vault{},
		byID:     map[string]*store.Vault{},
		roles:    map[string]string{},
		grants:   map[string][]store.VaultGrant{},
	}
}

func (f *fakeSessionStore) GetSession(_ context.Context, token string) (*store.Session, error) {
	s, ok := f.sessions[token]
	if !ok {
		return nil, errors.New("not found")
	}
	return s, nil
}
func (f *fakeSessionStore) GetVault(_ context.Context, name string) (*store.Vault, error) {
	v, ok := f.vaults[name]
	if !ok {
		return nil, errors.New("not found")
	}
	return v, nil
}
func (f *fakeSessionStore) GetVaultByID(_ context.Context, id string) (*store.Vault, error) {
	v, ok := f.byID[id]
	if !ok {
		return nil, errors.New("not found")
	}
	return v, nil
}
func (f *fakeSessionStore) GetVaultRole(_ context.Context, actorID, vaultID string) (string, error) {
	r, ok := f.roles[actorID+"|"+vaultID]
	if !ok {
		return "", errors.New("no role")
	}
	return r, nil
}
func (f *fakeSessionStore) ListActorGrants(_ context.Context, actorID string) ([]store.VaultGrant, error) {
	return f.grants[actorID], nil
}

func (f *fakeSessionStore) putVault(id, name string) {
	v := &store.Vault{ID: id, Name: name}
	f.vaults[name] = v
	f.byID[id] = v
}

func TestResolveForProxy_ScopedSession_NoHint(t *testing.T) {
	f := newFakeSessionStore()
	f.putVault("v1", "default")
	f.sessions["tok"] = &store.Session{ID: "tok", UserID: "u1", VaultID: "v1", VaultRole: "admin"}

	r := NewStoreSessionResolver(f)
	scope, err := r.ResolveForProxy(context.Background(), "tok", "")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if scope.VaultID != "v1" || scope.VaultName != "default" || scope.VaultRole != "admin" || scope.UserID != "u1" {
		t.Fatalf("scope = %+v", scope)
	}
}

func TestResolveForProxy_ScopedSession_MatchingHint(t *testing.T) {
	f := newFakeSessionStore()
	f.putVault("v1", "default")
	f.sessions["tok"] = &store.Session{UserID: "u1", VaultID: "v1", VaultRole: "member"}

	r := NewStoreSessionResolver(f)
	scope, err := r.ResolveForProxy(context.Background(), "tok", "default")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if scope.VaultName != "default" {
		t.Fatalf("vault = %q", scope.VaultName)
	}
}

func TestResolveForProxy_ScopedSession_MismatchedHint(t *testing.T) {
	f := newFakeSessionStore()
	f.putVault("v1", "default")
	f.putVault("v2", "prod")
	f.sessions["tok"] = &store.Session{UserID: "u1", VaultID: "v1", VaultRole: "member"}

	r := NewStoreSessionResolver(f)
	_, err := r.ResolveForProxy(context.Background(), "tok", "prod")
	if !errors.Is(err, ErrVaultHintMismatch) {
		t.Fatalf("expected ErrVaultHintMismatch, got %v", err)
	}
}

func TestResolveForProxy_AgentSingleGrant_NoHint(t *testing.T) {
	f := newFakeSessionStore()
	f.putVault("v1", "default")
	f.sessions["tok"] = &store.Session{AgentID: "a1"}
	f.grants["a1"] = []store.VaultGrant{{ActorID: "a1", VaultID: "v1", VaultName: "default", Role: "proxy"}}

	r := NewStoreSessionResolver(f)
	scope, err := r.ResolveForProxy(context.Background(), "tok", "")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if scope.VaultID != "v1" || scope.VaultName != "default" || scope.VaultRole != "proxy" {
		t.Fatalf("scope = %+v", scope)
	}
}

func TestResolveForProxy_AgentWithHint(t *testing.T) {
	f := newFakeSessionStore()
	f.putVault("v1", "default")
	f.putVault("v2", "prod")
	f.sessions["tok"] = &store.Session{AgentID: "a1"}
	f.roles["a1|v2"] = "member"

	r := NewStoreSessionResolver(f)
	scope, err := r.ResolveForProxy(context.Background(), "tok", "prod")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if scope.VaultID != "v2" || scope.VaultRole != "member" {
		t.Fatalf("scope = %+v", scope)
	}
}

func TestResolveForProxy_AgentZeroGrants(t *testing.T) {
	f := newFakeSessionStore()
	f.sessions["tok"] = &store.Session{AgentID: "a1"}

	r := NewStoreSessionResolver(f)
	_, err := r.ResolveForProxy(context.Background(), "tok", "")
	if !errors.Is(err, ErrNoVaultContext) {
		t.Fatalf("expected ErrNoVaultContext, got %v", err)
	}
}

func TestResolveForProxy_AgentMultipleGrantsAmbiguous(t *testing.T) {
	f := newFakeSessionStore()
	f.sessions["tok"] = &store.Session{AgentID: "a1"}
	f.grants["a1"] = []store.VaultGrant{
		{ActorID: "a1", VaultID: "v1", VaultName: "a", Role: "proxy"},
		{ActorID: "a1", VaultID: "v2", VaultName: "b", Role: "proxy"},
	}

	r := NewStoreSessionResolver(f)
	_, err := r.ResolveForProxy(context.Background(), "tok", "")
	if !errors.Is(err, ErrAgentVaultAmbiguous) {
		t.Fatalf("expected ErrAgentVaultAmbiguous, got %v", err)
	}
}

func TestResolveForProxy_AgentHintUnknownVault(t *testing.T) {
	f := newFakeSessionStore()
	f.sessions["tok"] = &store.Session{AgentID: "a1"}

	r := NewStoreSessionResolver(f)
	_, err := r.ResolveForProxy(context.Background(), "tok", "nope")
	if !errors.Is(err, ErrVaultNotFound) {
		t.Fatalf("expected ErrVaultNotFound, got %v", err)
	}
}

func TestResolveForProxy_AgentHintNoAccess(t *testing.T) {
	f := newFakeSessionStore()
	f.putVault("v1", "default")
	f.sessions["tok"] = &store.Session{AgentID: "a1"}

	r := NewStoreSessionResolver(f)
	_, err := r.ResolveForProxy(context.Background(), "tok", "default")
	if !errors.Is(err, ErrVaultAccessDenied) {
		t.Fatalf("expected ErrVaultAccessDenied, got %v", err)
	}
}

func TestResolveForProxy_InvalidToken(t *testing.T) {
	f := newFakeSessionStore()
	r := NewStoreSessionResolver(f)
	_, err := r.ResolveForProxy(context.Background(), "missing", "")
	if !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("expected ErrInvalidSession, got %v", err)
	}
}

func TestResolveForProxy_EmptyToken(t *testing.T) {
	r := NewStoreSessionResolver(newFakeSessionStore())
	_, err := r.ResolveForProxy(context.Background(), "", "")
	if !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("expected ErrInvalidSession, got %v", err)
	}
}

func TestResolveForProxy_ExpiredSession(t *testing.T) {
	f := newFakeSessionStore()
	past := time.Now().Add(-1 * time.Hour)
	f.putVault("v1", "default")
	f.sessions["tok"] = &store.Session{UserID: "u1", VaultID: "v1", VaultRole: "admin", ExpiresAt: &past}

	r := &StoreSessionResolver{Store: f, Now: time.Now}
	_, err := r.ResolveForProxy(context.Background(), "tok", "")
	if !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("expected ErrInvalidSession, got %v", err)
	}
}

func TestResolveForProxy_UserSessionNoVaultNoAgent(t *testing.T) {
	// User login session with no vault scope (global login) is not valid for
	// proxying — treat as no vault context.
	f := newFakeSessionStore()
	f.sessions["tok"] = &store.Session{UserID: "u1"}

	r := NewStoreSessionResolver(f)
	_, err := r.ResolveForProxy(context.Background(), "tok", "")
	if !errors.Is(err, ErrNoVaultContext) {
		t.Fatalf("expected ErrNoVaultContext, got %v", err)
	}
}
