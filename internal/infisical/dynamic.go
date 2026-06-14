package infisical

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/Infisical/agent-vault/internal/broker"
	"github.com/Infisical/agent-vault/internal/store"
	"golang.org/x/sync/singleflight"
)

const (
	// dynamicNameListTTL bounds how often we list dynamic secrets at a path.
	dynamicNameListTTL = 60 * time.Second
	// dynamicRenewBuffer renews a lease this far ahead of expiry so a value is
	// never served right as it expires.
	dynamicRenewBuffer = 1 * time.Minute
	// dynamicCloseTimeout bounds best-effort revocation during shutdown.
	dynamicCloseTimeout = 5 * time.Second
	// unavailableFieldGlob is the field-name stand-in in the display key of a
	// secret that could not be leased (its real field names are unknown).
	unavailableFieldGlob = "*"
)

// DynamicLeaseStore is the slice of the store the resolver needs: the per-vault
// Infisical config plus lease-metadata bookkeeping.
type DynamicLeaseStore interface {
	GetVaultCredentialStore(ctx context.Context, vaultID string) (*store.VaultCredentialStore, error)
	InsertDynamicSecretLease(ctx context.Context, lease store.DynamicSecretLease) error
	DeleteDynamicSecretLease(ctx context.Context, leaseID string) error
	DeleteDynamicSecretLeasesForVault(ctx context.Context, vaultID string) error
	ListDynamicSecretLeases(ctx context.Context) ([]store.DynamicSecretLease, error)
}

// leaseEntry is a live lease cached in memory. fields are keyed by sanitized
// field name (the suffix of the credential key) and carry SECRET values.
type leaseEntry struct {
	leaseID  string
	name     string
	cfg      VaultConfig
	fields   map[string]string
	expireAt time.Time
}

type nameCacheEntry struct {
	names     []DynamicSecretInfo
	fetchedAt time.Time
}

// DynamicResolver mints, caches, renews, and revokes Infisical dynamic-secret
// leases, exposing each lease field as a credential value named
// <DYNAMIC_SECRET_NAME>_<FIELD> (UPPER_SNAKE_CASE). Leased values live only in
// memory; the store tracks lease IDs so they can be revoked on
// disconnect/shutdown and swept (orphans) on the next startup.
type DynamicResolver struct {
	fetcher DynamicFetcher
	store   DynamicLeaseStore
	logger  *slog.Logger
	clock   func() time.Time
	group   singleflight.Group

	mu     sync.Mutex
	leases map[string]*leaseEntry    // vaultID|name -> live lease
	names  map[string]nameCacheEntry // vaultID -> discovered dynamic secrets
}

// NewDynamicResolver constructs a resolver. A nil fetcher is tolerated and
// makes every Resolve a no-op (ok=false), so callers needn't special-case the
// Infisical-disabled path.
func NewDynamicResolver(s DynamicLeaseStore, fetcher DynamicFetcher, logger *slog.Logger) *DynamicResolver {
	return &DynamicResolver{
		fetcher: fetcher,
		store:   s,
		logger:  logger,
		clock:   time.Now,
		leases:  make(map[string]*leaseEntry),
		names:   make(map[string]nameCacheEntry),
	}
}

// Resolve returns the value for a credential key if it maps to a dynamic-secret
// field in vaultID. ok=false means "not a dynamic credential" (caller keeps its
// own not-found error); a non-nil error is a real failure (bad config, upstream
// down, lease mint failed).
func (r *DynamicResolver) Resolve(ctx context.Context, vaultID, key string) (string, bool, error) {
	cfg, ok, err := r.vaultConfig(ctx, vaultID)
	if err != nil || !ok {
		return "", false, err
	}

	names, err := r.listNames(ctx, vaultID, cfg)
	if err != nil {
		return "", false, err
	}

	name, suffix, ok := matchDynamicKey(key, names)
	if !ok {
		return "", false, nil
	}

	entry, err := r.ensureLease(ctx, vaultID, name, cfg)
	if err != nil {
		return "", false, err
	}
	val, ok := entry.fields[suffix]
	return val, ok, nil
}

// EnumeratedCredential is one concrete leased field exposed as a credential.
// Value is SECRET — never log it. When Unavailable is set the lease could not
// be minted (e.g. the machine identity lacks lease permission), so Value is
// empty and Key is the field prefix; it exists so the secret is still visible.
type EnumeratedCredential struct {
	Key         string
	Value       string
	SecretName  string // the dynamic secret it came from
	SecretType  string // provider type, e.g. "gcp-iam"
	Unavailable bool
}

// Enumerate expands every dynamic secret at the vault's path into its concrete
// <PREFIX>_<FIELD> credentials, MINTING a lease for each (cached and shared with
// Resolve). A secret whose lease fails becomes a single Unavailable entry rather
// than vanishing. Returns (nil, nil) when the vault is not Infisical-backed.
func (r *DynamicResolver) Enumerate(ctx context.Context, vaultID string) ([]EnumeratedCredential, error) {
	cfg, ok, err := r.vaultConfig(ctx, vaultID)
	if err != nil || !ok {
		return nil, err
	}
	names, err := r.listNames(ctx, vaultID, cfg)
	if err != nil {
		return nil, err
	}
	var out []EnumeratedCredential
	for _, ds := range names {
		prefix, ok := sanitizeKeyPart(ds.Name)
		if !ok {
			continue
		}
		entry, err := r.ensureLease(ctx, vaultID, ds.Name, cfg)
		if err != nil {
			r.logger.Warn("leasing dynamic secret for enumeration failed",
				slog.String("vault_id", vaultID), slog.String("name", ds.Name),
				slog.String("err", err.Error()))
			// Display key for an unleasable secret: the field prefix plus a glob,
			// since the concrete field names are only known once a lease mints.
			out = append(out, EnumeratedCredential{
				Key:         prefix + "_" + unavailableFieldGlob,
				SecretName:  ds.Name,
				SecretType:  ds.Type,
				Unavailable: true,
			})
			continue
		}
		for suffix, val := range entry.fields {
			out = append(out, EnumeratedCredential{
				Key:        prefix + "_" + suffix,
				Value:      val,
				SecretName: ds.Name,
				SecretType: ds.Type,
			})
		}
	}
	return out, nil
}

// vaultConfig loads a vault's Infisical config. ok=false (with nil error) means
// the vault is not Infisical-backed or dynamic secrets are disabled.
func (r *DynamicResolver) vaultConfig(ctx context.Context, vaultID string) (VaultConfig, bool, error) {
	if r.fetcher == nil {
		return VaultConfig{}, false, nil
	}
	cs, err := r.store.GetVaultCredentialStore(ctx, vaultID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return VaultConfig{}, false, nil
		}
		return VaultConfig{}, false, err
	}
	if cs == nil || cs.Kind != store.CredentialStoreInfisical {
		return VaultConfig{}, false, nil
	}
	cfg, err := ParseConfigJSON(cs.ConfigJSON)
	if err != nil {
		return VaultConfig{}, false, err
	}
	if err := cfg.Validate(); err != nil {
		return VaultConfig{}, false, err
	}
	return cfg, true, nil
}

// matchDynamicKey finds the dynamic secret whose sanitized name is the longest
// prefix of key (followed by '_'), returning that name and the remaining
// field suffix. Longest-prefix wins so "DB" doesn't shadow "DB_REPLICA".
func matchDynamicKey(key string, names []DynamicSecretInfo) (name, suffix string, ok bool) {
	bestLen := -1
	for _, ds := range names {
		prefix, valid := sanitizeKeyPart(ds.Name)
		if !valid {
			continue
		}
		prefix += "_"
		if strings.HasPrefix(key, prefix) && len(prefix) > bestLen {
			name, suffix, ok = ds.Name, key[len(prefix):], true
			bestLen = len(prefix)
		}
	}
	return name, suffix, ok
}

// sanitizeKeyPart upper-snakes a name/field for use in a credential key,
// returning valid=false when the result can't satisfy CredentialKeyPattern.
func sanitizeKeyPart(s string) (string, bool) {
	r := strings.NewReplacer("-", "_", " ", "_", ".", "_", "/", "_")
	up := strings.ToUpper(r.Replace(strings.TrimSpace(s)))
	if !broker.CredentialKeyPattern.MatchString(up) {
		return "", false
	}
	return up, true
}

func (r *DynamicResolver) listNames(ctx context.Context, vaultID string, cfg VaultConfig) ([]DynamicSecretInfo, error) {
	r.mu.Lock()
	if c, ok := r.names[vaultID]; ok && r.clock().Sub(c.fetchedAt) < dynamicNameListTTL {
		r.mu.Unlock()
		return c.names, nil
	}
	r.mu.Unlock()

	v, err, _ := r.group.Do("names|"+vaultID, func() (interface{}, error) {
		return r.fetcher.ListDynamicSecrets(ctx, cfg)
	})
	if err != nil {
		return nil, err
	}
	names := v.([]DynamicSecretInfo)
	r.mu.Lock()
	r.names[vaultID] = nameCacheEntry{names: names, fetchedAt: r.clock()}
	r.mu.Unlock()
	return names, nil
}

// ensureLease returns a live lease for (vaultID, name), minting or renewing as
// needed. Single-flighted so concurrent requests share one mint.
func (r *DynamicResolver) ensureLease(ctx context.Context, vaultID, name string, cfg VaultConfig) (*leaseEntry, error) {
	cacheKey := vaultID + "|" + name

	r.mu.Lock()
	if e, ok := r.leases[cacheKey]; ok && r.clock().Add(dynamicRenewBuffer).Before(e.expireAt) {
		r.mu.Unlock()
		return e, nil
	}
	r.mu.Unlock()

	v, err, _ := r.group.Do(cacheKey, func() (interface{}, error) {
		// Re-check under the flight: a concurrent caller may have just minted.
		r.mu.Lock()
		existing, hadExisting := r.leases[cacheKey]
		r.mu.Unlock()
		if hadExisting && r.clock().Add(dynamicRenewBuffer).Before(existing.expireAt) {
			return existing, nil
		}

		// Try to extend the current lease (keeps the same credential values).
		if hadExisting {
			expireAt, rerr := r.fetcher.RenewLease(ctx, cfg, existing.leaseID)
			if rerr == nil {
				// Guard the in-place mutation: the fast path reads expireAt under
				// r.mu, so this write must hold it too.
				r.mu.Lock()
				existing.expireAt = expireAt
				r.mu.Unlock()
				r.persistLease(ctx, vaultID, existing)
				return existing, nil
			}
			r.logger.Info("dynamic secret lease renew failed; re-minting",
				slog.String("vault_id", vaultID), slog.String("name", name),
				slog.String("err", rerr.Error()))
		}

		lease, merr := r.fetcher.CreateLease(ctx, cfg, name)
		if merr != nil {
			return nil, merr
		}
		entry := &leaseEntry{
			leaseID:  lease.LeaseID,
			name:     name,
			cfg:      cfg,
			fields:   sanitizeFields(lease.Fields),
			expireAt: lease.ExpireAt,
		}
		r.mu.Lock()
		r.leases[cacheKey] = entry
		r.mu.Unlock()
		r.persistLease(ctx, vaultID, entry)

		// Best-effort revoke the lease we just replaced so it doesn't linger.
		if hadExisting {
			r.revoke(ctx, existing)
		}
		return entry, nil
	})
	if err != nil {
		return nil, err
	}
	return v.(*leaseEntry), nil
}

// sanitizeFields re-keys provider fields by their sanitized credential-key
// suffix, dropping any that can't form a valid key.
func sanitizeFields(fields map[string]string) map[string]string {
	out := make(map[string]string, len(fields))
	for k, v := range fields {
		if up, ok := sanitizeKeyPart(k); ok {
			out[up] = v
		}
	}
	return out
}

func (r *DynamicResolver) persistLease(ctx context.Context, vaultID string, e *leaseEntry) {
	var expire *time.Time
	if !e.expireAt.IsZero() {
		t := e.expireAt
		expire = &t
	}
	if err := r.store.InsertDynamicSecretLease(ctx, store.DynamicSecretLease{
		LeaseID:           e.leaseID,
		VaultID:           vaultID,
		DynamicSecretName: e.name,
		ProjectID:         e.cfg.ProjectID,
		Environment:       e.cfg.Environment,
		SecretPath:        e.cfg.SecretPath,
		ExpireAt:          expire,
	}); err != nil && !errors.Is(err, context.Canceled) {
		r.logger.Warn("persisting dynamic secret lease failed",
			slog.String("vault_id", vaultID), slog.String("err", err.Error()))
	}
}

// revokeUpstream best-effort revokes one lease and logs failures. Returns true
// when the upstream revoke succeeded, so callers can choose whether to also
// forget the persisted row.
func (r *DynamicResolver) revokeUpstream(ctx context.Context, cfg VaultConfig, leaseID string) bool {
	if err := r.fetcher.RevokeLease(ctx, cfg, leaseID); err != nil {
		if !errors.Is(err, context.Canceled) {
			r.logger.Warn("revoking dynamic secret lease failed",
				slog.String("lease_id", leaseID), slog.String("err", err.Error()))
		}
		return false
	}
	return true
}

// revoke best-effort revokes a single lease upstream and forgets its DB row.
func (r *DynamicResolver) revoke(ctx context.Context, e *leaseEntry) {
	r.revokeUpstream(ctx, e.cfg, e.leaseID)
	if err := r.store.DeleteDynamicSecretLease(ctx, e.leaseID); err != nil && !errors.Is(err, context.Canceled) {
		r.logger.Warn("deleting dynamic secret lease row failed",
			slog.String("lease_id", e.leaseID), slog.String("err", err.Error()))
	}
}

// RevokeVault evicts and revokes every cached lease for a vault, called when a
// vault disconnects from or reconfigures its Infisical store. Eviction is
// synchronous; the upstream revoke + row delete follow.
func (r *DynamicResolver) RevokeVault(ctx context.Context, vaultID string) {
	r.revokeEvicted(ctx, vaultID, r.evictVault(vaultID))
}

// RevokeVaultAsync evicts the vault's cached leases synchronously — so no stale
// lease can be served once the caller returns — then revokes them upstream in
// the background, where a slow Infisical can't stall the API response.
func (r *DynamicResolver) RevokeVaultAsync(vaultID string) {
	if r.fetcher == nil {
		return
	}
	victims := r.evictVault(vaultID)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), dynamicCloseTimeout)
		defer cancel()
		r.revokeEvicted(ctx, vaultID, victims)
	}()
}

// evictVault drops a vault's cached leases and discovered names under the lock,
// returning the evicted leases for upstream revocation.
func (r *DynamicResolver) evictVault(vaultID string) []*leaseEntry {
	if r.fetcher == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	var victims []*leaseEntry
	for k, e := range r.leases {
		if strings.HasPrefix(k, vaultID+"|") {
			victims = append(victims, e)
			delete(r.leases, k)
		}
	}
	delete(r.names, vaultID)
	return victims
}

// revokeEvicted revokes already-evicted leases upstream and forgets their rows.
func (r *DynamicResolver) revokeEvicted(ctx context.Context, vaultID string, victims []*leaseEntry) {
	if r.fetcher == nil {
		return
	}
	for _, e := range victims {
		r.revokeUpstream(ctx, e.cfg, e.leaseID)
	}
	if err := r.store.DeleteDynamicSecretLeasesForVault(ctx, vaultID); err != nil && !errors.Is(err, context.Canceled) {
		r.logger.Warn("deleting dynamic secret lease rows failed",
			slog.String("vault_id", vaultID), slog.String("err", err.Error()))
	}
}

// Close best-effort revokes all cached leases on shutdown, bounded by a short
// timeout. Needs only lease IDs + the client, not the encryption key.
func (r *DynamicResolver) Close(ctx context.Context) {
	if r.fetcher == nil {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, dynamicCloseTimeout)
	defer cancel()

	r.mu.Lock()
	victims := make([]*leaseEntry, 0, len(r.leases))
	for _, e := range r.leases {
		victims = append(victims, e)
	}
	r.leases = make(map[string]*leaseEntry)
	r.mu.Unlock()

	for _, e := range victims {
		if r.revokeUpstream(ctx, e.cfg, e.leaseID) {
			_ = r.store.DeleteDynamicSecretLease(ctx, e.leaseID)
		}
	}
}

// SweepOrphans revokes lease rows that survived a restart. After a restart the
// in-memory credential values are gone, so any tracked lease is unusable and is
// revoked + forgotten. Skips IDs already live in this process (created since
// startup). Intended to run in a background goroutine.
func (r *DynamicResolver) SweepOrphans(ctx context.Context) {
	if r.fetcher == nil {
		return
	}
	rows, err := r.store.ListDynamicSecretLeases(ctx)
	if err != nil {
		r.logger.Warn("listing dynamic secret leases for orphan sweep failed",
			slog.String("err", err.Error()))
		return
	}
	live := r.liveLeaseIDs()
	for _, row := range rows {
		if _, ok := live[row.LeaseID]; ok {
			continue // created by this process; not an orphan
		}
		cfg := VaultConfig{ProjectID: row.ProjectID, Environment: row.Environment, SecretPath: row.SecretPath}
		// Drop the row regardless of revoke outcome: the value is unrecoverable
		// and Infisical's TTL is the backstop. Keeping it would retry forever.
		r.revokeUpstream(ctx, cfg, row.LeaseID)
		if err := r.store.DeleteDynamicSecretLease(ctx, row.LeaseID); err != nil && !errors.Is(err, context.Canceled) {
			r.logger.Warn("deleting orphan dynamic secret lease row failed",
				slog.String("lease_id", row.LeaseID), slog.String("err", err.Error()))
		}
	}
}

func (r *DynamicResolver) liveLeaseIDs() map[string]struct{} {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make(map[string]struct{}, len(r.leases))
	for _, e := range r.leases {
		out[e.leaseID] = struct{}{}
	}
	return out
}
