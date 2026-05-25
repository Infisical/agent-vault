package infisical

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/Infisical/agent-vault/internal/broker"
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

// syncFailedPublicMessage is persisted to last_sync_error; the real error
// (which can embed INFISICAL_URL + upstream rejection bodies) goes to logs.
const syncFailedPublicMessage = "Infisical sync failed. See server logs for details."

var (
	// ErrSyncerDisabled: no Fetcher (e.g. INFISICAL_URL unset). → 503.
	ErrSyncerDisabled = errors.New("infisical: syncer disabled (no client)")
	// ErrNotExternal: vault is not Infisical-backed. → 400.
	ErrNotExternal = errors.New("infisical: vault has no infisical credential store")
	// ErrSyncInFlight: another refresh is running for this vault. → 409.
	ErrSyncInFlight = errors.New("infisical: sync already in flight for this vault")
)

// Syncer pulls Infisical secrets into the local credentials table at each
// vault's configured cadence.
type Syncer struct {
	Store   SyncerStore
	Fetcher secretsFetcher
	DEK     []byte
	Logger  *slog.Logger
	Clock   func() time.Time

	mu       sync.Mutex
	inFlight map[string]struct{}
	wg       sync.WaitGroup
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

// NewSyncerForTest builds a Syncer wired to an arbitrary fetcher. The
// duck-typed fetcher param lets tests in sibling packages stand up a fake
// without exporting the internal secretsFetcher interface.
func NewSyncerForTest(s SyncerStore, fetcher interface {
	FetchSecrets(context.Context, VaultConfig) ([]Secret, error)
	AuthMethod() AuthMethod
}, dek []byte, logger *slog.Logger) *Syncer {
	return &Syncer{
		Store:    s,
		Fetcher:  fetcher,
		DEK:      dek,
		Logger:   logger,
		Clock:    time.Now,
		inFlight: make(map[string]struct{}),
	}
}

// Run loops until ctx is cancelled, then waits for in-flight refreshes to
// finish. Return implies no goroutine is still reading s.DEK, so the server
// can safely wipe it on shutdown.
func (s *Syncer) Run(ctx context.Context) {
	if s.Fetcher == nil {
		s.Logger.Info("infisical syncer disabled (no client)")
		return
	}
	s.Logger.Info("infisical syncer started", slog.Duration("tick", tickInterval))
	ticker := time.NewTicker(tickInterval)
	defer ticker.Stop()
	defer s.wg.Wait()
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
		s.wg.Add(1)
		go func(cs store.VaultCredentialStore) {
			defer s.wg.Done()
			defer s.clearInFlight(cs.VaultID)
			_ = s.refresh(ctx, cs)
		}(cs)
	}
}

// RefreshOnce runs a single synchronous refresh, reusing the periodic
// syncer's in-flight guard. On failure refresh updates the row's health
// and returns the error so the caller can map it to an HTTP status.
func (s *Syncer) RefreshOnce(ctx context.Context, cs store.VaultCredentialStore) error {
	if s.Fetcher == nil {
		return ErrSyncerDisabled
	}
	if cs.Kind != KindInfisical {
		return ErrNotExternal
	}
	if !s.markInFlight(cs.VaultID) {
		return ErrSyncInFlight
	}
	s.wg.Add(1)
	defer s.wg.Done()
	defer s.clearInFlight(cs.VaultID)
	return s.refresh(ctx, cs)
}

// dueAt reports whether the vault is past its poll interval. Nil
// last_synced_at is always due (defensive against manual DB edits).
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

func (s *Syncer) refresh(ctx context.Context, cs store.VaultCredentialStore) error {
	cfg, err := ParseConfigJSON(cs.ConfigJSON)
	if err != nil {
		err = fmt.Errorf("bad config_json: %w", err)
		s.recordFailure(ctx, cs.VaultID, err)
		return err
	}
	if err := cfg.Validate(); err != nil {
		s.recordFailure(ctx, cs.VaultID, err)
		return err
	}

	secs, err := s.Fetcher.FetchSecrets(ctx, cfg)
	if err != nil {
		s.recordFailure(ctx, cs.VaultID, err)
		return err
	}

	items, err := EncryptSecrets(secs, s.DEK)
	if err != nil {
		s.recordFailure(ctx, cs.VaultID, err)
		return err
	}

	if err := s.Store.ReplaceVaultCredentials(ctx, cs.VaultID, items); err != nil {
		s.recordFailure(ctx, cs.VaultID, err)
		return err
	}

	if err := s.Store.UpdateVaultCredentialStoreHealth(ctx, cs.VaultID, StatusOK, "", s.Clock()); err != nil && !errors.Is(err, sql.ErrNoRows) {
		// sql.ErrNoRows = vault deleted between list and update; treat as skip.
		s.Logger.Warn("updating health=ok failed",
			slog.String("vault_id", cs.VaultID),
			slog.String("err", err.Error()))
	}
	s.Logger.Info("infisical sync ok",
		slog.String("vault_id", cs.VaultID),
		slog.Int("keys", len(items)))
	return nil
}

// ErrInvalidKey marks a sync failure: upstream secret key violates
// broker.CredentialKeyPattern. Surfaced so the operator can rename upstream.
var ErrInvalidKey = errors.New("infisical: upstream secret key does not match required pattern")

// EncryptSecrets encrypts plaintext Infisical secrets for
// store.ReplaceVaultCredentials. Reused by the vault-create handler.
func EncryptSecrets(secs []Secret, dek []byte) ([]store.EncryptedKV, error) {
	out := make([]store.EncryptedKV, 0, len(secs))
	for _, sec := range secs {
		if sec.Key == "" {
			return nil, errors.New("infisical returned an empty secret key")
		}
		if !broker.CredentialKeyPattern.MatchString(sec.Key) {
			return nil, fmt.Errorf("%w: %q (Agent Vault requires UPPER_SNAKE_CASE; rename the secret upstream)", ErrInvalidKey, sec.Key)
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
	// Shutdown cancels ctx mid-fetch; drain quietly without relabeling health.
	if errors.Is(err, context.Canceled) {
		return
	}
	s.Logger.Warn("infisical sync failed",
		slog.String("vault_id", vaultID),
		slog.String("err", err.Error()))
	// ErrInvalidKey is caller-supplied topology; surface verbatim.
	publicMsg := syncFailedPublicMessage
	if errors.Is(err, ErrInvalidKey) {
		publicMsg = err.Error()
	}
	if uerr := s.Store.UpdateVaultCredentialStoreHealth(ctx, vaultID, StatusError, publicMsg, s.Clock()); uerr != nil && !errors.Is(uerr, sql.ErrNoRows) {
		s.Logger.Warn("updating health=error failed",
			slog.String("vault_id", vaultID),
			slog.String("err", uerr.Error()))
	}
}
