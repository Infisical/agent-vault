package hashicorp

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/store"
)

// fakeFetcher mocks the HashiCorp Vault surface our syncer uses.
type fakeFetcher struct {
	mu       sync.Mutex
	secrets  []Secret
	err      error
	callsLog []VaultConfig
}

func (f *fakeFetcher) FetchSecrets(_ context.Context, cfg VaultConfig) ([]Secret, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.callsLog = append(f.callsLog, cfg)
	if f.err != nil {
		return nil, f.err
	}
	return append([]Secret(nil), f.secrets...), nil
}

func (f *fakeFetcher) AuthMethod() AuthMethod { return AuthToken }

// fakeStore captures the calls the syncer makes against the application store.
type fakeStore struct {
	mu         sync.Mutex
	rows       []store.VaultCredentialStore
	replaceCh  chan map[string][]store.EncryptedKV
	health     map[string]healthRow
	notApplied bool // when true, ReplaceVaultCredentialsForSync reports applied=false
}

type healthRow struct {
	Status string
	Error  string
}

func newFakeStore(rows ...store.VaultCredentialStore) *fakeStore {
	return &fakeStore{
		rows:      rows,
		replaceCh: make(chan map[string][]store.EncryptedKV, 16),
		health:    make(map[string]healthRow),
	}
}

func (f *fakeStore) ListVaultCredentialStores(_ context.Context) ([]store.VaultCredentialStore, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]store.VaultCredentialStore(nil), f.rows...), nil
}

func (f *fakeStore) ReplaceVaultCredentialsForSync(_ context.Context, vaultID, _ string, items []store.EncryptedKV) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.notApplied {
		// Mirror the store gating: the row was disconnected/reconfigured mid-sync,
		// so the snapshot is dropped without writing.
		return false, nil
	}
	f.replaceCh <- map[string][]store.EncryptedKV{vaultID: append([]store.EncryptedKV(nil), items...)}
	return true, nil
}

func (f *fakeStore) UpdateVaultCredentialStoreHealth(_ context.Context, vaultID, status, errMsg string, when time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.health[vaultID] = healthRow{Status: status, Error: errMsg}
	for i := range f.rows {
		if f.rows[i].VaultID == vaultID {
			t := when
			f.rows[i].LastSyncedAt = &t
			f.rows[i].LastSyncStatus = status
		}
	}
	return nil
}

func (f *fakeStore) getHealth(vaultID string) healthRow {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.health[vaultID]
}

func makeDEK(t *testing.T) []byte {
	t.Helper()
	dek := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return dek
}

func hashicorpRow(vaultID string) store.VaultCredentialStore {
	return store.VaultCredentialStore{
		VaultID:             vaultID,
		Kind:                store.CredentialStoreHashicorp,
		ConfigJSON:          `{"mount":"secret","secret_path":"agent-vault/demo","kv_version":2}`,
		PollIntervalSeconds: 60,
	}
}

func TestRefreshOnce_SuccessReplacesCredentials(t *testing.T) {
	dek := makeDEK(t)
	fs := newFakeStore(hashicorpRow("v1"))
	ff := &fakeFetcher{secrets: []Secret{{Key: "ANTHROPIC_API_KEY", Value: "sk-test"}, {Key: "GITHUB_PAT", Value: "ghp_test"}}}
	s := NewSyncer(fs, ff, dek, slog.New(slog.NewTextHandler(io.Discard, nil)))

	if err := s.RefreshOnce(context.Background(), fs.rows[0]); err != nil {
		t.Fatalf("RefreshOnce: %v", err)
	}
	select {
	case got := <-fs.replaceCh:
		if len(got["v1"]) != 2 {
			t.Fatalf("want 2 credentials replaced, got %d", len(got["v1"]))
		}
	default:
		t.Fatal("ReplaceVaultCredentials was not called")
	}
	if h := fs.getHealth("v1"); h.Status != store.SyncStatusOK {
		t.Fatalf("health status: want %q, got %q", store.SyncStatusOK, h.Status)
	}
}

// TestRefreshOnce_NotAppliedDropsSnapshot covers the config-gated write path:
// when the store reports applied=false (vault disconnected or reconfigured mid
// sync), the syncer drops the snapshot without writing and treats it as a
// non-failure — health is NOT marked error, and no credentials are replaced.
func TestRefreshOnce_NotAppliedDropsSnapshot(t *testing.T) {
	dek := makeDEK(t)
	fs := newFakeStore(hashicorpRow("v1"))
	fs.notApplied = true
	ff := &fakeFetcher{secrets: []Secret{{Key: "ANTHROPIC_API_KEY", Value: "sk-test"}}}
	s := NewSyncer(fs, ff, dek, slog.New(slog.NewTextHandler(io.Discard, nil)))

	if err := s.RefreshOnce(context.Background(), fs.rows[0]); err != nil {
		t.Fatalf("RefreshOnce: want nil (drop, not failure), got %v", err)
	}
	select {
	case got := <-fs.replaceCh:
		t.Fatalf("credentials must not be written when applied=false, got %v", got)
	default:
	}
	if h := fs.getHealth("v1"); h.Status != "" {
		t.Fatalf("applied=false must not write health, got %q", h.Status)
	}
}

func TestRefreshOnce_InvalidKeyFailsSync(t *testing.T) {
	dek := makeDEK(t)
	fs := newFakeStore(hashicorpRow("v1"))
	ff := &fakeFetcher{secrets: []Secret{{Key: "lowercase-key", Value: "x"}}}
	s := NewSyncer(fs, ff, dek, slog.New(slog.NewTextHandler(io.Discard, nil)))

	err := s.RefreshOnce(context.Background(), fs.rows[0])
	if !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("want ErrInvalidKey, got %v", err)
	}
	if h := fs.getHealth("v1"); h.Status != store.SyncStatusError {
		t.Fatalf("health status: want %q, got %q", store.SyncStatusError, h.Status)
	}
}

func TestRefreshOnce_RejectsNonHashicorpKind(t *testing.T) {
	dek := makeDEK(t)
	fs := newFakeStore()
	s := NewSyncer(fs, &fakeFetcher{}, dek, slog.New(slog.NewTextHandler(io.Discard, nil)))
	row := store.VaultCredentialStore{VaultID: "v1", Kind: store.CredentialStoreInfisical}
	if err := s.RefreshOnce(context.Background(), row); !errors.Is(err, ErrNotExternal) {
		t.Fatalf("want ErrNotExternal, got %v", err)
	}
}

func TestRefreshOnce_NilFetcherDisabled(t *testing.T) {
	s := NewSyncer(newFakeStore(), nil, makeDEK(t), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := s.RefreshOnce(context.Background(), hashicorpRow("v1")); !errors.Is(err, ErrSyncerDisabled) {
		t.Fatalf("want ErrSyncerDisabled, got %v", err)
	}
}

// TestTick_OnlyProcessesHashicorpRows verifies the syncer ignores rows owned by
// other credential-store kinds (the Infisical syncer owns those).
func TestTick_OnlyProcessesHashicorpRows(t *testing.T) {
	dek := makeDEK(t)
	fs := newFakeStore(
		store.VaultCredentialStore{VaultID: "inf", Kind: store.CredentialStoreInfisical, ConfigJSON: `{}`, PollIntervalSeconds: 60},
		hashicorpRow("hc"),
	)
	ff := &fakeFetcher{secrets: []Secret{{Key: "STRIPE_SECRET_KEY", Value: "sk_live"}}}
	s := NewSyncer(fs, ff, dek, slog.New(slog.NewTextHandler(io.Discard, nil)))

	s.tick(context.Background())
	// Allow the per-vault goroutine to run.
	s.wg.Wait()

	ff.mu.Lock()
	defer ff.mu.Unlock()
	if len(ff.callsLog) != 1 {
		t.Fatalf("want exactly 1 fetch (hashicorp row only), got %d", len(ff.callsLog))
	}
	if ff.callsLog[0].Mount != "secret" {
		t.Fatalf("fetched wrong config: %+v", ff.callsLog[0])
	}
}
