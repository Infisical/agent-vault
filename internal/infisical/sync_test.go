package infisical

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/store"
)

// fakeFetcher mocks the Infisical SDK surface our syncer uses.
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

func (f *fakeFetcher) AuthMethod() AuthMethod { return AuthUniversal }

// fakeStore captures the calls the syncer makes against the application store.
type fakeStore struct {
	mu        sync.Mutex
	rows      []store.VaultCredentialStore
	replaceCh chan map[string][]store.EncryptedKV // capture each ReplaceVaultCredentials per vault
	health    map[string]healthRow
	repErr    error
}

type healthRow struct {
	Status string
	Error  string
	When   time.Time
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
	out := append([]store.VaultCredentialStore(nil), f.rows...)
	return out, nil
}

func (f *fakeStore) ReplaceVaultCredentials(_ context.Context, vaultID string, items []store.EncryptedKV) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.repErr != nil {
		return f.repErr
	}
	f.replaceCh <- map[string][]store.EncryptedKV{vaultID: append([]store.EncryptedKV(nil), items...)}
	return nil
}

func (f *fakeStore) UpdateVaultCredentialStoreHealth(_ context.Context, vaultID, status, errMsg string, when time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.health[vaultID] = healthRow{Status: status, Error: errMsg, When: when}
	// Reflect the update back onto the rows so subsequent ticks see the new last_synced_at.
	for i := range f.rows {
		if f.rows[i].VaultID == vaultID {
			t := when
			f.rows[i].LastSyncedAt = &t
			f.rows[i].LastSyncStatus = status
			f.rows[i].LastSyncError = errMsg
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

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestSyncerRefresh_SuccessReplacesCredentials(t *testing.T) {
	dek := makeDEK(t)
	pastSynced := time.Now().Add(-time.Hour)
	fs := newFakeStore(store.VaultCredentialStore{
		VaultID:             "v1",
		Kind:                KindInfisical,
		ConfigJSON:          `{"project_id":"p","environment":"dev","secret_path":"/"}`,
		PollIntervalSeconds: 60,
		LastSyncedAt:        &pastSynced,
		LastSyncStatus:      "ok",
	})
	ff := &fakeFetcher{secrets: []Secret{
		{Key: "ALPHA", Value: "a"},
		{Key: "BETA", Value: "b"},
	}}
	s := &Syncer{Store: fs, Fetcher: ff, DEK: dek, Logger: discardLogger(), Clock: time.Now, inFlight: map[string]struct{}{}}

	s.refresh(context.Background(), fs.rows[0])

	select {
	case got := <-fs.replaceCh:
		items := got["v1"]
		if len(items) != 2 {
			t.Fatalf("expected 2 items, got %d", len(items))
		}
		// Plaintext must round-trip after decryption.
		for _, it := range items {
			pt, err := crypto.Decrypt(it.Ciphertext, it.Nonce, dek)
			if err != nil {
				t.Fatalf("decrypt %q: %v", it.Key, err)
			}
			switch it.Key {
			case "ALPHA":
				if string(pt) != "a" {
					t.Fatalf("ALPHA: %q", pt)
				}
			case "BETA":
				if string(pt) != "b" {
					t.Fatalf("BETA: %q", pt)
				}
			default:
				t.Fatalf("unexpected key %q", it.Key)
			}
		}
	default:
		t.Fatalf("expected a ReplaceVaultCredentials call")
	}
	if h := fs.getHealth("v1"); h.Status != "ok" || h.Error != "" {
		t.Fatalf("expected ok health, got %+v", h)
	}
}

func TestSyncerRefresh_FailureKeepsStaleAndRecordsError(t *testing.T) {
	dek := makeDEK(t)
	fs := newFakeStore(store.VaultCredentialStore{
		VaultID:             "v1",
		Kind:                KindInfisical,
		ConfigJSON:          `{"project_id":"p","environment":"dev","secret_path":"/"}`,
		PollIntervalSeconds: 60,
	})
	// Upstream error embeds the configured INFISICAL_URL — the kind of detail
	// that should not be reflected to vault members through last_sync_error.
	upstreamErr := "APIError: CallListSecretsV3Raw [GET https://infisical.internal.corp/api/v3/secrets/raw?workspaceId=p] [status-code=404]"
	ff := &fakeFetcher{err: errors.New(upstreamErr)}
	s := &Syncer{Store: fs, Fetcher: ff, DEK: dek, Logger: discardLogger(), Clock: time.Now, inFlight: map[string]struct{}{}}

	s.refresh(context.Background(), fs.rows[0])

	// No Replace call should have been made (serve-stale).
	select {
	case got := <-fs.replaceCh:
		t.Fatalf("expected no Replace on failure, got %+v", got)
	default:
	}
	h := fs.getHealth("v1")
	if h.Status != "error" || h.Error == "" {
		t.Fatalf("expected error health, got %+v", h)
	}
	// The persisted message must be the scrubbed public string, not the
	// raw SDK error — vault members read this via /v1/vaults/{name}/context.
	if h.Error != syncFailedPublicMessage {
		t.Fatalf("expected persisted error to be the scrubbed public message; got %q", h.Error)
	}
	if strings.Contains(h.Error, "infisical.internal.corp") {
		t.Fatalf("upstream URL leaked through last_sync_error: %q", h.Error)
	}
}

func TestSyncerDueAt(t *testing.T) {
	now := time.Now()
	past := now.Add(-2 * time.Minute)
	recent := now.Add(-1 * time.Second)
	s := &Syncer{}

	if !s.dueAt(store.VaultCredentialStore{PollIntervalSeconds: 60, LastSyncedAt: &past}, now) {
		t.Fatalf("past should be due")
	}
	if s.dueAt(store.VaultCredentialStore{PollIntervalSeconds: 60, LastSyncedAt: &recent}, now) {
		t.Fatalf("recent should not be due")
	}
	if !s.dueAt(store.VaultCredentialStore{PollIntervalSeconds: 60}, now) {
		t.Fatalf("nil last_synced_at should be due")
	}
}

func TestEncryptSecrets_RoundTrip(t *testing.T) {
	dek := makeDEK(t)
	items, err := EncryptSecrets([]Secret{{Key: "FOO", Value: "bar"}}, dek)
	if err != nil {
		t.Fatalf("EncryptSecrets: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("expected 1, got %d", len(items))
	}
	pt, err := crypto.Decrypt(items[0].Ciphertext, items[0].Nonce, dek)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(pt) != "bar" {
		t.Fatalf("expected bar, got %q", pt)
	}
}

func TestEncryptSecrets_RejectsEmptyKey(t *testing.T) {
	if _, err := EncryptSecrets([]Secret{{Key: "", Value: "x"}}, makeDEK(t)); err == nil {
		t.Fatalf("expected error for empty key")
	}
}
