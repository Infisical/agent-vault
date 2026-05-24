package infisical

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/store"
)

// SyncerStore is the slice of the application store the syncer needs.
type SyncerStore interface {
	ListVaultCredentialStores(ctx context.Context) ([]store.VaultCredentialStore, error)
	ReplaceVaultCredentials(ctx context.Context, vaultID string, items []store.EncryptedKV) error
	UpdateVaultCredentialStoreHealth(ctx context.Context, vaultID, status, errMsg string, syncedAt time.Time) error
}

// tickInterval is how often the syncer wakes to scan for due vaults.
// Per-vault refresh cadence comes from `poll_interval_seconds` on the
// credential-store row.
const tickInterval = 10 * time.Second

// maxSyncErrorChars caps the length of the human-facing last_sync_error
// message we store. The SDK can return verbose errors and we want a short,
// secret-free string in the DB.
const maxSyncErrorChars = 200

// Syncer pulls Infisical secrets into the local credentials table at each
// vault's configured cadence.
type Syncer struct {
	Store   SyncerStore
	Fetcher secretsFetcher
	DEK     []byte
	Logger  *slog.Logger
	Clock   func() time.Time

	mu     sync.Mutex
	inFlight map[string]struct{}
}

// NewSyncer constructs a syncer; Clock defaults to time.Now if nil.
func NewSyncer(s SyncerStore, c *Client, dek []byte, logger *slog.Logger) *Syncer {
	return &Syncer{
		Store:    s,
		Fetcher:  c,
		DEK:      dek,
		Logger:   logger,
		Clock:    time.Now,
		inFlight: make(map[string]struct{}),
	}
}

// Run loops until ctx is cancelled. Safe to call once per server lifetime.
func (s *Syncer) Run(ctx context.Context) {
	if s.Fetcher == nil {
		s.Logger.Info("infisical syncer disabled (no client)")
		return
	}
	s.Logger.Info("infisical syncer started", slog.Duration("tick", tickInterval))
	ticker := time.NewTicker(tickInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			s.Logger.Info("infisical syncer stopped")
			return
		case <-ticker.C:
			s.tick(ctx)
		}
	}
}

func (s *Syncer) tick(ctx context.Context) {
	stores, err := s.Store.ListVaultCredentialStores(ctx)
	if err != nil {
		s.Logger.Warn("listing credential stores failed", slog.String("err", err.Error()))
		return
	}
	now := s.Clock()
	for _, cs := range stores {
		if cs.Kind != KindInfisical {
			continue
		}
		if !s.dueAt(cs, now) {
			continue
		}
		if !s.markInFlight(cs.VaultID) {
			continue // a previous refresh for this vault is still running
		}
		go func(cs store.VaultCredentialStore) {
			defer s.clearInFlight(cs.VaultID)
			s.refresh(ctx, cs)
		}(cs)
	}
}

// dueAt reports whether the vault is past its poll interval. Vaults with a
// nil last_synced_at are always due (defensive — initial sync runs in the
// create handler, but a manual DB edit could leave one in this state).
func (s *Syncer) dueAt(cs store.VaultCredentialStore, now time.Time) bool {
	if cs.LastSyncedAt == nil {
		return true
	}
	interval := time.Duration(cs.PollIntervalSeconds) * time.Second
	if interval < time.Duration(MinPollIntervalSeconds)*time.Second {
		interval = time.Duration(MinPollIntervalSeconds) * time.Second
	}
	return now.Sub(*cs.LastSyncedAt) >= interval
}

func (s *Syncer) markInFlight(vaultID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, busy := s.inFlight[vaultID]; busy {
		return false
	}
	s.inFlight[vaultID] = struct{}{}
	return true
}

func (s *Syncer) clearInFlight(vaultID string) {
	s.mu.Lock()
	delete(s.inFlight, vaultID)
	s.mu.Unlock()
}

func (s *Syncer) refresh(ctx context.Context, cs store.VaultCredentialStore) {
	cfg, err := ParseConfigJSON(cs.ConfigJSON)
	if err != nil {
		s.recordFailure(ctx, cs.VaultID, fmt.Errorf("bad config_json: %w", err))
		return
	}
	if err := cfg.Validate(); err != nil {
		s.recordFailure(ctx, cs.VaultID, err)
		return
	}

	secs, err := s.Fetcher.FetchSecrets(ctx, cfg)
	if err != nil {
		s.recordFailure(ctx, cs.VaultID, err)
		return
	}

	items, err := EncryptSecrets(secs, s.DEK)
	if err != nil {
		s.recordFailure(ctx, cs.VaultID, err)
		return
	}

	if err := s.Store.ReplaceVaultCredentials(ctx, cs.VaultID, items); err != nil {
		s.recordFailure(ctx, cs.VaultID, err)
		return
	}

	if err := s.Store.UpdateVaultCredentialStoreHealth(ctx, cs.VaultID, StatusOK, "", s.Clock()); err != nil {
		s.Logger.Warn("updating health=ok failed",
			slog.String("vault_id", cs.VaultID),
			slog.String("err", err.Error()))
	}
	s.Logger.Info("infisical sync ok",
		slog.String("vault_id", cs.VaultID),
		slog.Int("keys", len(items)))
}

// EncryptSecrets converts plaintext Infisical secrets into the wire form
// expected by store.ReplaceVaultCredentials. Exported so the vault-create
// handler can reuse it for the initial snapshot.
func EncryptSecrets(secs []Secret, dek []byte) ([]store.EncryptedKV, error) {
	out := make([]store.EncryptedKV, 0, len(secs))
	for _, sec := range secs {
		if sec.Key == "" {
			return nil, errors.New("infisical returned an empty secret key")
		}
		ct, nonce, err := crypto.Encrypt([]byte(sec.Value), dek)
		if err != nil {
			return nil, fmt.Errorf("encrypting %q: %w", sec.Key, err)
		}
		out = append(out, store.EncryptedKV{Key: sec.Key, Ciphertext: ct, Nonce: nonce})
	}
	return out, nil
}

func (s *Syncer) recordFailure(ctx context.Context, vaultID string, err error) {
	msg := truncate(err.Error(), maxSyncErrorChars)
	s.Logger.Warn("infisical sync failed",
		slog.String("vault_id", vaultID),
		slog.String("err", msg))
	if uerr := s.Store.UpdateVaultCredentialStoreHealth(ctx, vaultID, StatusError, msg, s.Clock()); uerr != nil {
		s.Logger.Warn("updating health=error failed",
			slog.String("vault_id", vaultID),
			slog.String("err", uerr.Error()))
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
