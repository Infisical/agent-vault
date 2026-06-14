package infisical

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/store"
)

// fakeDynFetcher mocks the dynamic-secret SDK surface.
type fakeDynFetcher struct {
	mu          sync.Mutex
	names       []DynamicSecretInfo
	createErr   error
	renewErr    error
	createCalls int32
	renewCalls  int32
	revokeCalls int32
	nextLeaseID int
	leaseTTL    time.Duration
	now         func() time.Time
}

func (f *fakeDynFetcher) ListDynamicSecrets(_ context.Context, _ VaultConfig) ([]DynamicSecretInfo, error) {
	return append([]DynamicSecretInfo(nil), f.names...), nil
}

func (f *fakeDynFetcher) CreateLease(_ context.Context, _ VaultConfig, name string) (DynamicLease, error) {
	atomic.AddInt32(&f.createCalls, 1)
	if f.createErr != nil {
		return DynamicLease{}, f.createErr
	}
	f.mu.Lock()
	f.nextLeaseID++
	id := name + "-lease-" + string(rune('0'+f.nextLeaseID))
	f.mu.Unlock()
	return DynamicLease{
		LeaseID:  id,
		Fields:   map[string]string{"username": "u-" + id, "password": "p-" + id, "port": "5432"},
		ExpireAt: f.now().Add(f.leaseTTL),
	}, nil
}

func (f *fakeDynFetcher) RenewLease(_ context.Context, _ VaultConfig, _ string) (time.Time, error) {
	atomic.AddInt32(&f.renewCalls, 1)
	if f.renewErr != nil {
		return time.Time{}, f.renewErr
	}
	return f.now().Add(f.leaseTTL), nil
}

func (f *fakeDynFetcher) RevokeLease(_ context.Context, _ VaultConfig, _ string) error {
	atomic.AddInt32(&f.revokeCalls, 1)
	return nil
}

// fakeDynStore satisfies DynamicLeaseStore.
type fakeDynStore struct {
	mu     sync.Mutex
	cs     *store.VaultCredentialStore
	leases map[string]store.DynamicSecretLease
}

func newFakeDynStore(cfg VaultConfig) *fakeDynStore {
	cfgJSON, _ := MarshalConfigJSON(cfg)
	return &fakeDynStore{
		cs: &store.VaultCredentialStore{
			VaultID:    "v1",
			Kind:       store.CredentialStoreInfisical,
			ConfigJSON: cfgJSON,
		},
		leases: map[string]store.DynamicSecretLease{},
	}
}

func (f *fakeDynStore) GetVaultCredentialStore(_ context.Context, _ string) (*store.VaultCredentialStore, error) {
	return f.cs, nil
}
func (f *fakeDynStore) InsertDynamicSecretLease(_ context.Context, l store.DynamicSecretLease) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.leases[l.LeaseID] = l
	return nil
}
func (f *fakeDynStore) DeleteDynamicSecretLease(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.leases, id)
	return nil
}
func (f *fakeDynStore) ListDynamicSecretLeases(_ context.Context) ([]store.DynamicSecretLease, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]store.DynamicSecretLease, 0, len(f.leases))
	for _, l := range f.leases {
		out = append(out, l)
	}
	return out, nil
}

func testLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func newTestResolver(t *testing.T) (*DynamicResolver, *fakeDynFetcher, *fakeDynStore, *time.Time) {
	t.Helper()
	cfg := VaultConfig{ProjectID: "proj", Environment: "dev", SecretPath: "/"}
	st := newFakeDynStore(cfg)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := &now
	f := &fakeDynFetcher{
		names:    []DynamicSecretInfo{{Name: "db-postgres"}},
		leaseTTL: time.Hour,
		now:      func() time.Time { return *clock },
	}
	r := NewDynamicResolver(st, f, testLogger())
	r.clock = func() time.Time { return *clock }
	return r, f, st, clock
}

func TestDynamicResolve_MintsAndMaps(t *testing.T) {
	r, f, _, _ := newTestResolver(t)

	val, ok, err := r.Resolve(context.Background(), "v1", "DB_POSTGRES_PASSWORD")
	if err != nil || !ok {
		t.Fatalf("expected ok, got ok=%v err=%v", ok, err)
	}
	if val == "" || val[:2] != "p-" {
		t.Fatalf("unexpected password value %q", val)
	}
	// Numeric field stringified and mapped.
	port, ok, _ := r.Resolve(context.Background(), "v1", "DB_POSTGRES_PORT")
	if !ok || port != "5432" {
		t.Fatalf("expected port 5432, got ok=%v val=%q", ok, port)
	}
	if got := atomic.LoadInt32(&f.createCalls); got != 1 {
		t.Fatalf("expected 1 mint shared across fields, got %d", got)
	}
}

func TestDynamicResolve_UnknownKeyNotDynamic(t *testing.T) {
	r, f, _, _ := newTestResolver(t)
	_, ok, err := r.Resolve(context.Background(), "v1", "STRIPE_KEY")
	if ok || err != nil {
		t.Fatalf("expected not-dynamic (ok=false,err=nil), got ok=%v err=%v", ok, err)
	}
	if atomic.LoadInt32(&f.createCalls) != 0 {
		t.Fatalf("should not mint for a non-dynamic key")
	}
}

func TestDynamicResolve_CacheHit(t *testing.T) {
	r, f, _, _ := newTestResolver(t)
	for i := 0; i < 3; i++ {
		if _, ok, err := r.Resolve(context.Background(), "v1", "DB_POSTGRES_USERNAME"); !ok || err != nil {
			t.Fatalf("resolve %d failed: ok=%v err=%v", i, ok, err)
		}
	}
	if got := atomic.LoadInt32(&f.createCalls); got != 1 {
		t.Fatalf("expected cache reuse (1 mint), got %d", got)
	}
}

func TestDynamicResolve_RenewWithinBuffer(t *testing.T) {
	r, f, _, clock := newTestResolver(t)
	first, _, _ := r.Resolve(context.Background(), "v1", "DB_POSTGRES_PASSWORD")

	// Advance to within the renew buffer of expiry.
	*clock = clock.Add(time.Hour - 30*time.Second)
	second, ok, err := r.Resolve(context.Background(), "v1", "DB_POSTGRES_PASSWORD")
	if !ok || err != nil {
		t.Fatalf("resolve after advance failed: ok=%v err=%v", ok, err)
	}
	if atomic.LoadInt32(&f.renewCalls) != 1 {
		t.Fatalf("expected 1 renew, got %d", f.renewCalls)
	}
	if atomic.LoadInt32(&f.createCalls) != 1 {
		t.Fatalf("renew should not re-mint; got %d mints", f.createCalls)
	}
	if first != second {
		t.Fatalf("renew must preserve credential values: %q != %q", first, second)
	}
}

func TestDynamicResolve_RemintWhenRenewFails(t *testing.T) {
	r, f, _, clock := newTestResolver(t)
	first, _, _ := r.Resolve(context.Background(), "v1", "DB_POSTGRES_PASSWORD")

	f.renewErr = errors.New("renew rejected")
	*clock = clock.Add(time.Hour - 30*time.Second)
	second, ok, err := r.Resolve(context.Background(), "v1", "DB_POSTGRES_PASSWORD")
	if !ok || err != nil {
		t.Fatalf("resolve failed: ok=%v err=%v", ok, err)
	}
	if atomic.LoadInt32(&f.createCalls) != 2 {
		t.Fatalf("expected re-mint (2 mints), got %d", f.createCalls)
	}
	if first == second {
		t.Fatalf("re-mint should rotate values")
	}
	// The replaced lease should have been revoked.
	if atomic.LoadInt32(&f.revokeCalls) != 1 {
		t.Fatalf("expected old lease revoked once, got %d", f.revokeCalls)
	}
}

func TestDynamicResolve_SingleFlight(t *testing.T) {
	r, f, _, _ := newTestResolver(t)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, _ = r.Resolve(context.Background(), "v1", "DB_POSTGRES_PASSWORD")
		}()
	}
	wg.Wait()
	if got := atomic.LoadInt32(&f.createCalls); got != 1 {
		t.Fatalf("expected single-flight to mint once, got %d", got)
	}
}

func TestRevokeVault(t *testing.T) {
	r, f, st, _ := newTestResolver(t)
	if _, ok, _ := r.Resolve(context.Background(), "v1", "DB_POSTGRES_PASSWORD"); !ok {
		t.Fatal("setup resolve failed")
	}
	r.RevokeVault(context.Background(), "v1")
	if atomic.LoadInt32(&f.revokeCalls) != 1 {
		t.Fatalf("expected 1 revoke, got %d", f.revokeCalls)
	}
	if len(st.leases) != 0 {
		t.Fatalf("expected lease rows cleared, got %d", len(st.leases))
	}
	// Next resolve mints fresh.
	if _, ok, _ := r.Resolve(context.Background(), "v1", "DB_POSTGRES_PASSWORD"); !ok {
		t.Fatal("resolve after revoke failed")
	}
	if atomic.LoadInt32(&f.createCalls) != 2 {
		t.Fatalf("expected fresh mint after revoke, got %d", f.createCalls)
	}
}

func TestRevokeVault_RevokesDBOnlyOrphans(t *testing.T) {
	r, f, st, _ := newTestResolver(t)
	// A lease recorded only in the DB (e.g. left by a prior process), never in
	// this process's cache. It must still be revoked, not silently forgotten.
	st.leases["orphan-1"] = store.DynamicSecretLease{
		LeaseID: "orphan-1", VaultID: "v1", DynamicSecretName: "db-postgres",
		ProjectID: "proj", Environment: "dev", SecretPath: "/",
	}
	r.RevokeVault(context.Background(), "v1")
	if atomic.LoadInt32(&f.revokeCalls) != 1 {
		t.Fatalf("expected DB-only orphan revoked once, got %d", f.revokeCalls)
	}
	if _, ok := st.leases["orphan-1"]; ok {
		t.Fatalf("expected orphan row forgotten after revoke")
	}
}

func TestRevokeVaultAsync_EvictsSynchronously(t *testing.T) {
	r, f, _, _ := newTestResolver(t)
	if _, ok, _ := r.Resolve(context.Background(), "v1", "DB_POSTGRES_PASSWORD"); !ok {
		t.Fatal("setup resolve failed")
	}
	// Eviction must happen before RevokeVaultAsync returns, so no stale lease is
	// served: the next resolve re-mints rather than reusing the old cache entry.
	r.RevokeVaultAsync("v1")
	if _, ok, _ := r.Resolve(context.Background(), "v1", "DB_POSTGRES_PASSWORD"); !ok {
		t.Fatal("resolve after async revoke failed")
	}
	if got := atomic.LoadInt32(&f.createCalls); got != 2 {
		t.Fatalf("expected re-mint after eviction (2 mints), got %d", got)
	}
}

func TestSweepOrphans(t *testing.T) {
	r, f, st, _ := newTestResolver(t)
	// Simulate a row left behind by a prior process (not in memory).
	st.leases["orphan-1"] = store.DynamicSecretLease{
		LeaseID: "orphan-1", VaultID: "v1", DynamicSecretName: "db-postgres",
		ProjectID: "proj", Environment: "dev", SecretPath: "/",
	}
	r.SweepOrphans(context.Background())
	if atomic.LoadInt32(&f.revokeCalls) != 1 {
		t.Fatalf("expected orphan revoked once, got %d", f.revokeCalls)
	}
	if _, ok := st.leases["orphan-1"]; ok {
		t.Fatalf("expected orphan row deleted")
	}
}

func TestEnumerate(t *testing.T) {
	r, f, _, _ := newTestResolver(t)
	creds, err := r.Enumerate(context.Background(), "v1")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	// One dynamic secret (db-postgres) with three fields → three credentials.
	got := map[string]string{}
	for _, c := range creds {
		got[c.Key] = c.Value
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 enumerated credentials, got %d (%v)", len(got), got)
	}
	if got["DB_POSTGRES_PORT"] != "5432" || got["DB_POSTGRES_USERNAME"] == "" {
		t.Fatalf("unexpected enumerated values: %v", got)
	}
	// Leasing is shared: Enumerate mints once, a later Resolve reuses it.
	if _, ok, _ := r.Resolve(context.Background(), "v1", "DB_POSTGRES_PASSWORD"); !ok {
		t.Fatal("resolve after enumerate failed")
	}
	if atomic.LoadInt32(&f.createCalls) != 1 {
		t.Fatalf("expected enumerate+resolve to share one lease, got %d mints", f.createCalls)
	}
}

func TestEnumerate_LeaseFailureSurfacesUnavailable(t *testing.T) {
	r, f, _, _ := newTestResolver(t)
	f.createErr = errors.New("You are not allowed to lease on dynamic-secrets")

	creds, err := r.Enumerate(context.Background(), "v1")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(creds) != 1 || !creds[0].Unavailable {
		t.Fatalf("expected one Unavailable entry, got %+v", creds)
	}
	if creds[0].Key != "DB_POSTGRES_*" || creds[0].Value != "" {
		t.Fatalf("unexpected unavailable entry: %+v", creds[0])
	}
}

func TestSanitizeKeyPart(t *testing.T) {
	cases := []struct {
		in    string
		want  string
		valid bool
	}{
		{"db-postgres", "DB_POSTGRES", true},
		{"My Secret", "MY_SECRET", true},
		{"a.b/c", "A_B_C", true},
		{"2fa", "", false}, // leading digit
		{"", "", false},    // empty
	}
	for _, c := range cases {
		got, ok := sanitizeKeyPart(c.in)
		if ok != c.valid || got != c.want {
			t.Errorf("sanitizeKeyPart(%q) = (%q,%v), want (%q,%v)", c.in, got, ok, c.want, c.valid)
		}
	}
}

func TestMatchDynamicKey_LongestPrefix(t *testing.T) {
	names := []DynamicSecretInfo{{Name: "db"}, {Name: "db-replica"}}
	name, suffix, ok := matchDynamicKey("DB_REPLICA_PASSWORD", names)
	if !ok || name != "db-replica" || suffix != "PASSWORD" {
		t.Fatalf("got name=%q suffix=%q ok=%v", name, suffix, ok)
	}
}
