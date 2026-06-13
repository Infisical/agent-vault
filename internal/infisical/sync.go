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

type SyncerStore interface {
	ListVaultCredentialStores(ctx context.Context) ([]store.VaultCredentialStore, error)
	ReplaceVaultCredentialsForSync(ctx context.Context, vaultID, configJSON string, items []store.EncryptedKV) (applied bool, err error)
	UpdateVaultCredentialStoreHealth(ctx context.Context, vaultID, status, errMsg string, syncedAt time.Time) error
}

// tickInterval scans for due vaults; per-vault cadence is `poll_interval_seconds`.
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
	store   SyncerStore
	fetcher SecretsFetcher
	dek     []byte
	logger  *slog.Logger
	clock   func() time.Time

	mu       sync.Mutex
	inFlight map[string]struct{}
	wg       sync.WaitGroup
}

// NewSyncer constructs a syncer. A nil fetcher disables the run loop so the
// rest of the server stays up when Infisical isn't configured.
func NewSyncer(s SyncerStore, fetcher SecretsFetcher, dek []byte, logger *slog.Logger) *Syncer {
	return &Syncer{
		store:    s,
		fetcher:  fetcher,
		dek:      dek,
		logger:   logger,
		clock:    time.Now,
		inFlight: make(map[string]struct{}),
	}
}

// Run loops until ctx is cancelled, then waits for in-flight refreshes to
// finish. Return implies no goroutine is still reading s.dek, so the server
// can safely wipe it on shutdown.
func (s *Syncer) Run(ctx context.Context) {
	if s.fetcher == nil {
		s.logger.Info("infisical syncer disabled (no client)")
		return
	}
	s.logger.Info("infisical syncer started", slog.Duration("tick", tickInterval))
	ticker := time.NewTicker(tickInterval)
	defer ticker.Stop()
	defer s.wg.Wait()
	for {
		select {
		case <-ctx.Done():
			s.logger.Info("infisical syncer stopped")
			return
		case <-ticker.C:
			s.tick(ctx)
		}
	}
}

func (s *Syncer) tick(ctx context.Context) {
	stores, err := s.store.ListVaultCredentialStores(ctx)
	if err != nil {
		s.logger.Warn("listing credential stores failed", slog.String("err", err.Error()))
		return
	}
	now := s.clock()
	for _, cs := range stores {
		if cs.Kind != store.CredentialStoreInfisical {
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
	if s.fetcher == nil {
		return ErrSyncerDisabled
	}
	if cs.Kind != store.CredentialStoreInfisical {
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
// last_synced_at is always due. The floor guards against manual DB edits.
func (s *Syncer) dueAt(cs store.VaultCredentialStore, now time.Time) bool {
	if cs.LastSyncedAt == nil {
		return true
	}
	secs := max(cs.PollIntervalSeconds, MinPollIntervalSeconds)
	return now.Sub(*cs.LastSyncedAt) >= time.Duration(secs)*time.Second
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

	secs, err := s.fetcher.FetchSecrets(ctx, cfg)
	if err != nil {
		s.recordFailure(ctx, cs.VaultID, err)
		return err
	}

	items, err := EncryptSecrets(secs, s.dek)
	if err != nil {
		s.recordFailure(ctx, cs.VaultID, err)
		return err
	}

	applied, err := s.store.ReplaceVaultCredentialsForSync(ctx, cs.VaultID, cs.ConfigJSON, items)
	if err != nil {
		s.recordFailure(ctx, cs.VaultID, err)
		return err
	}
	if !applied {
		// Disconnected or reconfigured mid-sync: drop this snapshot so it can't
		// clobber the current credentials. Not a failure.
		s.logger.Info("infisical sync skipped: vault changed mid-sync",
			slog.String("vault_id", cs.VaultID))
		return nil
	}

	// Replace + UpdateHealth are intentionally not in one transaction: a rare
	// failure here leaves fresh credentials with stale last_synced_at, which
	// the next tick reconciles. Credentials are authoritative.
	if err := s.store.UpdateVaultCredentialStoreHealth(ctx, cs.VaultID, store.SyncStatusOK, "", s.clock()); err != nil && !errors.Is(err, sql.ErrNoRows) && !errors.Is(err, context.Canceled) {
		s.logger.Warn("updating health=ok failed",
			slog.String("vault_id", cs.VaultID),
			slog.String("err", err.Error()))
	}
	s.logger.Info("infisical sync ok",
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
	s.logger.Warn("infisical sync failed",
		slog.String("vault_id", vaultID),
		slog.String("err", err.Error()))
	// ErrInvalidKey is caller-supplied topology; surface verbatim.
	publicMsg := syncFailedPublicMessage
	if errors.Is(err, ErrInvalidKey) {
		publicMsg = err.Error()
	}
	// Bumping last_synced_at on failure makes dueAt act as retry backoff.
	if uerr := s.store.UpdateVaultCredentialStoreHealth(ctx, vaultID, store.SyncStatusError, publicMsg, s.clock()); uerr != nil && !errors.Is(uerr, sql.ErrNoRows) && !errors.Is(uerr, context.Canceled) {
		s.logger.Warn("updating health=error failed",
			slog.String("vault_id", vaultID),
			slog.String("err", uerr.Error()))
	}
}
