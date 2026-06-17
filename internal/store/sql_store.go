package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	_ "modernc.org/sqlite"
)

// hashSessionToken computes SHA-256 of a raw session token for storage.
// Session tokens are 256-bit random, so a fast hash is sufficient (no KDF needed).
func hashSessionToken(rawToken string) string {
	h := sha256.Sum256([]byte(rawToken))
	return hex.EncodeToString(h[:])
}

// hashToken computes SHA-256 of any token (invite, approval, verification code).
// Used for invite tokens, vault invite tokens, approval tokens, and verification codes.
func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// utcTimePtr converts a *time.Time to UTC, returning nil if the input is nil.
func utcTimePtr(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	u := t.UTC()
	return &u
}



// nullableString returns nil for empty strings, enabling SQL NULL inserts.
func nullableString(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

// newPublicID returns a short, opaque, URL-safe handle (80 random bits as
// 20 hex chars). Used as the {id} path parameter in /v1/auth/sessions/{id}
// so the underlying token hash never appears in logs or URLs.
func newPublicID() string {
	var b [10]byte
	if _, err := io.ReadFull(rand.Reader, b[:]); err != nil {
		panic("crypto/rand: " + err.Error())
	}
	return hex.EncodeToString(b[:])
}

// SQLStore implements Store backed by a SQL database.
// The dialect field abstracts the few differences between SQLite and PostgreSQL.
type SQLStore struct {
	db      *sql.DB
	dialect Dialect
	vaultMu sync.Map // vaultID (string) -> *sync.Mutex (SQLite only)
}

// Open opens (or creates) a SQLite database at dbPath, configures WAL mode
// and sane defaults, and runs any pending schema migrations.
func Open(dbPath string) (*SQLStore, error) {
	// Set restrictive umask before SQLite creates the file to avoid a
	// window where the DB is world-readable (default umask is typically 0022).
	oldUmask := syscall.Umask(0077)

	dsn := dbPath + "?_pragma=journal_mode(wal)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(on)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		syscall.Umask(oldUmask)
		return nil, fmt.Errorf("opening sqlite: %w", err)
	}

	db.SetMaxOpenConns(1)

	if err := db.Ping(); err != nil {
		syscall.Umask(oldUmask)
		_ = db.Close()
		return nil, fmt.Errorf("pinging sqlite: %w", err)
	}

	// Restore original umask now that the file exists.
	syscall.Umask(oldUmask)

	// Ensure permissions are correct even for pre-existing files.
	if err := os.Chmod(dbPath, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "[agent-vault] warning: failed to set database permissions: %v\n", err)
	}

	if err := runGORMMigrations(db, "sqlite"); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("running migrations: %w", err)
	}

	return &SQLStore{db: db, dialect: SQLiteDialect{}}, nil
}

// --- Instance Settings ---

func (s *SQLStore) GetSetting(ctx context.Context, key string) (string, error) {
	var value string
	err := s.db.QueryRowContext(ctx, s.dialect.Rebind(`SELECT value FROM instance_settings WHERE key = ?`), key).Scan(&value)
	if err != nil {
		return "", err
	}
	return value, nil
}

func (s *SQLStore) SetSetting(ctx context.Context, key, value string) error {
	nowVal := s.now()
	_, err := s.db.ExecContext(ctx,
		s.dialect.Rebind(`INSERT INTO instance_settings (key, value, updated_at) VALUES (?, ?, ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = ?`),
		key, value, nowVal, nowVal)
	return err
}

func (s *SQLStore) GetAllSettings(ctx context.Context) (map[string]string, error) {
	rows, err := s.db.QueryContext(ctx, s.dialect.Rebind(`SELECT key, value FROM instance_settings`))
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	settings := make(map[string]string)
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		settings[k] = v
	}
	return settings, rows.Err()
}

func (s *SQLStore) Close() error {
	return s.db.Close()
}

// Ping verifies database connectivity.
func (s *SQLStore) Ping(ctx context.Context) error {
	return s.db.PingContext(ctx)
}

// DialectName returns the name of the underlying SQL dialect.
func (s *SQLStore) DialectName() string {
	return s.dialect.Name()
}

// LockVault acquires an exclusive advisory lock scoped to vaultID.
//
// SQLite path: per-vault in-memory mutex (single-process, same as the old
// server-level vaultServiceMu). Postgres path: pg_advisory_lock on a pinned
// *sql.Conn so the lock survives for the caller's critical section, not just
// a single statement.
func (s *SQLStore) LockVault(ctx context.Context, vaultID string) (func(), error) {
	if s.dialect.Name() == "sqlite" {
		v, _ := s.vaultMu.LoadOrStore(vaultID, &sync.Mutex{})
		mu := v.(*sync.Mutex)
		mu.Lock()
		return mu.Unlock, nil
	}

	// Postgres: advisory lock on a pinned connection.
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return nil, fmt.Errorf("LockVault: acquiring connection: %w", err)
	}

	h := fnv.New64a()
	_, _ = h.Write([]byte(vaultID))
	key := int64(h.Sum64())

	if _, err := conn.ExecContext(ctx, "SELECT pg_advisory_lock($1)", key); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("LockVault: pg_advisory_lock: %w", err)
	}

	return func() {
		// Best-effort unlock; the lock is released on conn close anyway.
		_, _ = conn.ExecContext(context.Background(), "SELECT pg_advisory_unlock($1)", key)
		_ = conn.Close()
	}, nil
}

// now returns the current UTC time formatted for the active dialect.
func (s *SQLStore) now() interface{} {
	return s.dialect.FormatTime(time.Now().UTC())
}

// --- Vault Settings ---

func (s *SQLStore) GetVaultSetting(ctx context.Context, vaultID, key string) (string, error) {
	var value string
	err := s.db.QueryRowContext(ctx,
		s.dialect.Rebind(`SELECT value FROM vault_settings WHERE vault_id = ? AND key = ?`),
		vaultID, key).Scan(&value)
	if err != nil {
		return "", err
	}
	return value, nil
}

func (s *SQLStore) SetVaultSetting(ctx context.Context, vaultID, key, value string) error {
	nowVal := s.now()
	_, err := s.db.ExecContext(ctx,
		s.dialect.Rebind(`INSERT INTO vault_settings (vault_id, key, value, updated_at) VALUES (?, ?, ?, ?)
		 ON CONFLICT(vault_id, key) DO UPDATE SET value = excluded.value, updated_at = ?`),
		vaultID, key, value, nowVal, nowVal)
	return err
}

func (s *SQLStore) DeleteVaultSetting(ctx context.Context, vaultID, key string) error {
	_, err := s.db.ExecContext(ctx,
		s.dialect.Rebind(`DELETE FROM vault_settings WHERE vault_id = ? AND key = ?`),
		vaultID, key)
	return err
}

// --- External Credential Stores ---

// CreateExternalVault atomically commits the vault, default broker config,
// credential-store config, initial encrypted snapshot, and admin grant.
func (s *SQLStore) CreateExternalVault(ctx context.Context, p CreateExternalVaultParams) (*Vault, error) {
	if p.Name == "" || p.Kind == "" || p.ConfigJSON == "" {
		return nil, fmt.Errorf("CreateExternalVault: name, kind, and config required")
	}
	if p.CreatorActorID == "" || p.CreatorActorType == "" {
		return nil, fmt.Errorf("CreateExternalVault: creator actor required")
	}

	vaultID := newUUID()
	bcID := newUUID()
	now := time.Now().UTC()
	nowStr := s.dialect.FormatTime(now)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx,
		s.dialect.Rebind("INSERT INTO vaults (id, name, created_at, updated_at) VALUES (?, ?, ?, ?)"),
		vaultID, p.Name, nowStr, nowStr,
	); err != nil {
		return nil, fmt.Errorf("creating vault: %w", err)
	}

	if _, err := tx.ExecContext(ctx,
		s.dialect.Rebind("INSERT INTO broker_configs (id, vault_id, services_json, created_at, updated_at) VALUES (?, ?, '[]', ?, ?)"),
		bcID, vaultID, nowStr, nowStr,
	); err != nil {
		return nil, fmt.Errorf("creating broker config: %w", err)
	}

	if _, err := tx.ExecContext(ctx,
		s.dialect.Rebind(`INSERT INTO vault_credential_stores
		   (vault_id, kind, config_json, poll_interval_seconds, last_synced_at, last_sync_status, last_sync_error, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, NULL, ?, ?)`),
		vaultID, p.Kind, p.ConfigJSON, p.PollIntervalSeconds, nowStr, SyncStatusOK, nowStr, nowStr,
	); err != nil {
		return nil, fmt.Errorf("creating credential store: %w", err)
	}

	for _, item := range p.Credentials {
		if _, err := tx.ExecContext(ctx,
			s.dialect.Rebind(`INSERT INTO credentials (id, vault_id, key, type, ciphertext, nonce, created_at, updated_at)
			 VALUES (?, ?, ?, 'static', ?, ?, ?, ?)`),
			newUUID(), vaultID, item.Key, item.Ciphertext, item.Nonce, nowStr, nowStr,
		); err != nil {
			return nil, fmt.Errorf("inserting credential %q: %w", item.Key, err)
		}
	}

	if _, err := tx.ExecContext(ctx,
		s.dialect.Rebind(`INSERT INTO vault_grants (actor_id, actor_type, vault_id, role, created_at)
		 VALUES (?, ?, ?, 'admin', ?)`),
		p.CreatorActorID, p.CreatorActorType, vaultID, nowStr,
	); err != nil {
		return nil, fmt.Errorf("granting admin: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit: %w", err)
	}

	return &Vault{ID: vaultID, Name: p.Name, CreatedAt: now, UpdatedAt: now}, nil
}

func (s *SQLStore) GetVaultCredentialStore(ctx context.Context, vaultID string) (*VaultCredentialStore, error) {
	row := s.db.QueryRowContext(ctx,
		s.dialect.Rebind(`SELECT vault_id, kind, config_json, poll_interval_seconds,
		        last_synced_at, last_sync_status, last_sync_error,
		        created_at, updated_at
		   FROM vault_credential_stores WHERE vault_id = ?`),
		vaultID,
	)
	return s.scanVaultCredentialStore(row)
}

// ListVaultCredentialStores returns every external-store row, ordered by
// vault_id for stable iteration.
func (s *SQLStore) ListVaultCredentialStores(ctx context.Context) ([]VaultCredentialStore, error) {
	rows, err := s.db.QueryContext(ctx,
		s.dialect.Rebind(`SELECT vault_id, kind, config_json, poll_interval_seconds,
		        last_synced_at, last_sync_status, last_sync_error,
		        created_at, updated_at
		   FROM vault_credential_stores ORDER BY vault_id`),
	)
	if err != nil {
		return nil, fmt.Errorf("listing credential stores: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []VaultCredentialStore
	for rows.Next() {
		v, err := s.scanVaultCredentialStore(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *v)
	}
	return out, rows.Err()
}

// UpdateVaultCredentialStoreHealth returns sql.ErrNoRows when the row is
// gone (vault deleted mid-sync); callers should treat that as benign.
func (s *SQLStore) UpdateVaultCredentialStoreHealth(ctx context.Context, vaultID, status, errMsg string, syncedAt time.Time) error {
	syncedStr := s.dialect.FormatTime(syncedAt.UTC())
	res, err := s.db.ExecContext(ctx,
		s.dialect.Rebind(`UPDATE vault_credential_stores
		    SET last_synced_at = ?, last_sync_status = ?, last_sync_error = ?, updated_at = ?
		  WHERE vault_id = ?`),
		syncedStr, status, nullableString(errMsg), s.now(), vaultID,
	)
	if err != nil {
		return fmt.Errorf("updating credential store health: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// replaceCredentialsTx wipes and rewrites the vault's static credentials inside
// an existing transaction; empty items just clears them. Shared by the
// standalone replace and the external-store connect path. Non-static (e.g.
// oauth) credentials are deliberately left untouched.
func (s *SQLStore) replaceCredentialsTx(ctx context.Context, tx *sql.Tx, vaultID string, nowStr interface{}, items []EncryptedKV) error {
	if _, err := tx.ExecContext(ctx, s.dialect.Rebind("DELETE FROM credentials WHERE vault_id = ? AND type = 'static'"), vaultID); err != nil {
		return fmt.Errorf("clearing credentials: %w", err)
	}
	if len(items) == 0 {
		return nil
	}
	stmt, err := tx.PrepareContext(ctx, s.dialect.Rebind(
		`INSERT INTO credentials (id, vault_id, key, type, ciphertext, nonce, created_at, updated_at)
		   VALUES (?, ?, ?, 'static', ?, ?, ?, ?)
		   ON CONFLICT(vault_id, key) DO NOTHING`))
	if err != nil {
		return fmt.Errorf("preparing credential insert: %w", err)
	}
	defer func() { _ = stmt.Close() }()
	for _, item := range items {
		if _, err := stmt.ExecContext(ctx,
			newUUID(), vaultID, item.Key, item.Ciphertext, item.Nonce, nowStr, nowStr,
		); err != nil {
			return fmt.Errorf("inserting credential %q: %w", item.Key, err)
		}
	}
	return nil
}

// ReplaceVaultCredentialsForSync is the syncer's write path: it rewrites the
// vault's credentials in one transaction, but only while the external-store row
// still matches the config the snapshot was fetched against. A sync that races
// a disconnect (row gone) or a reconfigure (config_json changed) reports
// applied=false and writes nothing, so a stale snapshot can never clobber the
// credentials a switch just installed. configJSON is the fetched config.
func (s *SQLStore) ReplaceVaultCredentialsForSync(ctx context.Context, vaultID, configJSON string, items []EncryptedKV) (applied bool, err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var dummy int
	switch err := tx.QueryRowContext(ctx,
		s.dialect.Rebind("SELECT 1 FROM vault_credential_stores WHERE vault_id = ? AND config_json = ?"), vaultID, configJSON).Scan(&dummy); {
	case errors.Is(err, sql.ErrNoRows):
		return false, nil // disconnected or reconfigured mid-sync; keep current credentials
	case err != nil:
		return false, fmt.Errorf("checking credential store: %w", err)
	}

	if err := s.replaceCredentialsTx(ctx, tx, vaultID, s.now(), items); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("commit: %w", err)
	}
	return true, nil
}

// SetVaultExternalStore upserts the credential-store row and replaces the
// vault's static credentials in one transaction — the connect path for an
// existing built-in vault. The credential-store health is reset to a fresh
// successful sync (the caller has just probed + fetched the snapshot). Returns
// the resulting row so the caller can render it without a follow-up read.
func (s *SQLStore) SetVaultExternalStore(ctx context.Context, p SetVaultExternalStoreParams) (*VaultCredentialStore, error) {
	if p.VaultID == "" || p.Kind == "" || p.ConfigJSON == "" {
		return nil, fmt.Errorf("SetVaultExternalStore: vault_id, kind, and config required")
	}
	now := time.Now().UTC()
	nowStr := s.dialect.FormatTime(now)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx,
		s.dialect.Rebind(`INSERT INTO vault_credential_stores
		   (vault_id, kind, config_json, poll_interval_seconds, last_synced_at, last_sync_status, last_sync_error, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, NULL, ?, ?)
		 ON CONFLICT(vault_id) DO UPDATE SET
		   kind = excluded.kind,
		   config_json = excluded.config_json,
		   poll_interval_seconds = excluded.poll_interval_seconds,
		   last_synced_at = excluded.last_synced_at,
		   last_sync_status = excluded.last_sync_status,
		   last_sync_error = NULL,
		   updated_at = excluded.updated_at`),
		p.VaultID, p.Kind, p.ConfigJSON, p.PollIntervalSeconds, nowStr, SyncStatusOK, nowStr, nowStr,
	); err != nil {
		return nil, fmt.Errorf("upserting credential store: %w", err)
	}

	if err := s.replaceCredentialsTx(ctx, tx, p.VaultID, nowStr, p.Credentials); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit: %w", err)
	}

	return &VaultCredentialStore{
		VaultID:             p.VaultID,
		Kind:                p.Kind,
		ConfigJSON:          p.ConfigJSON,
		PollIntervalSeconds: p.PollIntervalSeconds,
		LastSyncedAt:        &now,
		LastSyncStatus:      SyncStatusOK,
		UpdatedAt:           now,
	}, nil
}

// DeleteVaultCredentialStore removes the external-store row so the syncer stops
// polling the vault. The vault's credentials are intentionally left untouched —
// the last synced snapshot becomes ordinary built-in credentials. Returns nil
// when no row exists (the vault was already built-in).
func (s *SQLStore) DeleteVaultCredentialStore(ctx context.Context, vaultID string) error {
	if _, err := s.db.ExecContext(ctx,
		s.dialect.Rebind(`DELETE FROM vault_credential_stores WHERE vault_id = ?`), vaultID); err != nil {
		return fmt.Errorf("deleting credential store: %w", err)
	}
	return nil
}

// InsertDynamicSecretLease records an outstanding dynamic-secret lease. The
// lease_id is unique per Infisical, so a re-insert (e.g. after a renew that
// kept the same id) just refreshes expire_at.
func (s *SQLStore) InsertDynamicSecretLease(ctx context.Context, lease DynamicSecretLease) error {
	expire := s.dialect.FormatNullableTime(utcTimePtr(lease.ExpireAt))
	if _, err := s.db.ExecContext(ctx,
		s.dialect.Rebind(`INSERT INTO dynamic_secret_leases
		    (lease_id, vault_id, dynamic_secret_name, project_id, environment, secret_path, expire_at, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(lease_id) DO UPDATE SET expire_at = excluded.expire_at`),
		lease.LeaseID, lease.VaultID, lease.DynamicSecretName, lease.ProjectID,
		lease.Environment, lease.SecretPath, expire, s.now(),
	); err != nil {
		return fmt.Errorf("inserting dynamic secret lease: %w", err)
	}
	return nil
}

// DeleteDynamicSecretLease forgets a single lease row (after a successful
// revoke). Returns nil when the row is already gone.
func (s *SQLStore) DeleteDynamicSecretLease(ctx context.Context, leaseID string) error {
	if _, err := s.db.ExecContext(ctx,
		s.dialect.Rebind(`DELETE FROM dynamic_secret_leases WHERE lease_id = ?`), leaseID); err != nil {
		return fmt.Errorf("deleting dynamic secret lease: %w", err)
	}
	return nil
}

// ListDynamicSecretLeases returns every tracked lease, ordered by vault_id for
// stable iteration. Used by the startup orphan sweep.
func (s *SQLStore) ListDynamicSecretLeases(ctx context.Context) ([]DynamicSecretLease, error) {
	rows, err := s.db.QueryContext(ctx,
		s.dialect.Rebind(`SELECT lease_id, vault_id, dynamic_secret_name, project_id, environment,
		        secret_path, expire_at, created_at
		   FROM dynamic_secret_leases ORDER BY vault_id`))
	if err != nil {
		return nil, fmt.Errorf("listing dynamic secret leases: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []DynamicSecretLease
	for rows.Next() {
		var l DynamicSecretLease
		var expire interface{}
		var createdAt interface{}
		if err := rows.Scan(&l.LeaseID, &l.VaultID, &l.DynamicSecretName, &l.ProjectID,
			&l.Environment, &l.SecretPath, &expire, &createdAt); err != nil {
			return nil, err
		}
		l.ExpireAt, _ = s.dialect.ScanNullableTime(expire)
		l.CreatedAt, _ = s.dialect.ScanTime(createdAt)
		out = append(out, l)
	}
	return out, rows.Err()
}

// rowScanner unifies *sql.Row and *sql.Rows so one scan func serves both.
type rowScanner interface {
	Scan(dest ...interface{}) error
}

func (s *SQLStore) scanVaultCredentialStore(row rowScanner) (*VaultCredentialStore, error) {
	var v VaultCredentialStore
	var lastSyncedAt interface{}
	var lastSyncStatus sql.NullString
	var lastSyncErr sql.NullString
	var createdAt, updatedAt interface{}
	if err := row.Scan(&v.VaultID, &v.Kind, &v.ConfigJSON, &v.PollIntervalSeconds,
		&lastSyncedAt, &lastSyncStatus, &lastSyncErr, &createdAt, &updatedAt); err != nil {
		return nil, err
	}
	v.LastSyncedAt, _ = s.dialect.ScanNullableTime(lastSyncedAt)
	if lastSyncStatus.Valid {
		v.LastSyncStatus = lastSyncStatus.String
	}
	if lastSyncErr.Valid {
		v.LastSyncError = lastSyncErr.String
	}
	v.CreatedAt, _ = s.dialect.ScanTime(createdAt)
	v.UpdatedAt, _ = s.dialect.ScanTime(updatedAt)
	return &v, nil
}

// --- Vaults ---

func (s *SQLStore) CreateVault(ctx context.Context, name string) (*Vault, error) {
	nsID := newUUID()
	bcID := newUUID()
	now := time.Now().UTC()
	nowStr := s.dialect.FormatTime(now)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("beginning transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	_, err = tx.ExecContext(ctx,
		s.dialect.Rebind("INSERT INTO vaults (id, name, created_at, updated_at) VALUES (?, ?, ?, ?)"),
		nsID, name, nowStr, nowStr,
	)
	if err != nil {
		return nil, fmt.Errorf("creating vault: %w", err)
	}

	_, err = tx.ExecContext(ctx,
		s.dialect.Rebind("INSERT INTO broker_configs (id, vault_id, services_json, created_at, updated_at) VALUES (?, ?, '[]', ?, ?)"),
		bcID, nsID, nowStr, nowStr,
	)
	if err != nil {
		return nil, fmt.Errorf("creating default broker config: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("committing vault creation: %w", err)
	}

	return &Vault{ID: nsID, Name: name, CreatedAt: now, UpdatedAt: now}, nil
}

func (s *SQLStore) GetVault(ctx context.Context, name string) (*Vault, error) {
	row := s.db.QueryRowContext(ctx,
		s.dialect.Rebind("SELECT id, name, created_at, updated_at FROM vaults WHERE name = ?"), name,
	)
	return s.scanVault(row)
}

func (s *SQLStore) GetVaultByID(ctx context.Context, id string) (*Vault, error) {
	row := s.db.QueryRowContext(ctx,
		s.dialect.Rebind("SELECT id, name, created_at, updated_at FROM vaults WHERE id = ?"), id,
	)
	return s.scanVault(row)
}

func (s *SQLStore) ListVaults(ctx context.Context) ([]Vault, error) {
	rows, err := s.db.QueryContext(ctx, s.dialect.Rebind("SELECT id, name, created_at, updated_at FROM vaults ORDER BY name"))
	if err != nil {
		return nil, fmt.Errorf("listing vaults: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var vaults []Vault
	for rows.Next() {
		var v Vault
		var createdAt, updatedAt interface{}
		if err := rows.Scan(&v.ID, &v.Name, &createdAt, &updatedAt); err != nil {
			return nil, fmt.Errorf("scanning vault: %w", err)
		}
		v.CreatedAt, _ = s.dialect.ScanTime(createdAt)
		v.UpdatedAt, _ = s.dialect.ScanTime(updatedAt)
		vaults = append(vaults, v)
	}
	return vaults, rows.Err()
}

func (s *SQLStore) DeleteVault(ctx context.Context, name string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Look up vault ID.
	var vaultID string
	if err := tx.QueryRowContext(ctx, s.dialect.Rebind("SELECT id FROM vaults WHERE name = ?"), name).Scan(&vaultID); err != nil {
		if err == sql.ErrNoRows {
			return sql.ErrNoRows
		}
		return fmt.Errorf("looking up vault: %w", err)
	}

	// Delete sessions that reference this vault (FK lacks ON DELETE CASCADE).
	if _, err := tx.ExecContext(ctx, s.dialect.Rebind("DELETE FROM sessions WHERE vault_id = ?"), vaultID); err != nil {
		return fmt.Errorf("deleting vault sessions: %w", err)
	}

	// Delete the vault (cascades to credentials, broker_configs, proposals, agents, etc.).
	if _, err := tx.ExecContext(ctx, s.dialect.Rebind("DELETE FROM vaults WHERE id = ?"), vaultID); err != nil {
		return fmt.Errorf("deleting vault: %w", err)
	}

	return tx.Commit()
}

func (s *SQLStore) RenameVault(ctx context.Context, oldName string, newName string) error {
	nowStr := s.now()

	v, err := s.GetVault(ctx, oldName)
	if err != nil {
		return err
	}

	res, err := s.db.ExecContext(ctx,
		s.dialect.Rebind(`UPDATE vaults SET name = ?, updated_at = ? WHERE id = ?`),
		newName, nowStr, v.ID,
	)
	if err != nil {
		return fmt.Errorf("renaming vault: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// --- Credentials ---

func (s *SQLStore) SetCredential(ctx context.Context, vaultID, key string, ciphertext, nonce []byte) (*Credential, error) {
	id := newUUID()
	now := time.Now().UTC()
	nowStr := s.dialect.FormatTime(now)

	_, err := s.db.ExecContext(ctx,
		s.dialect.Rebind(`INSERT INTO credentials (id, vault_id, key, type, ciphertext, nonce, created_at, updated_at)
		 VALUES (?, ?, ?, 'static', ?, ?, ?, ?)
		 ON CONFLICT(vault_id, key) DO UPDATE SET
		   ciphertext = excluded.ciphertext,
		   nonce = excluded.nonce,
		   updated_at = excluded.updated_at`),
		id, vaultID, key, ciphertext, nonce, nowStr, nowStr,
	)
	if err != nil {
		return nil, fmt.Errorf("setting credential: %w", err)
	}

	return &Credential{
		ID: id, VaultID: vaultID, Key: key, Type: "static",
		Ciphertext: ciphertext, Nonce: nonce,
		CreatedAt: now, UpdatedAt: now,
	}, nil
}

func (s *SQLStore) GetCredential(ctx context.Context, vaultID, key string) (*Credential, error) {
	row := s.db.QueryRowContext(ctx,
		s.dialect.Rebind("SELECT id, vault_id, key, type, ciphertext, nonce, created_at, updated_at FROM credentials WHERE vault_id = ? AND key = ?"),
		vaultID, key,
	)
	return s.scanCredential(row)
}

func (s *SQLStore) ListCredentials(ctx context.Context, vaultID string) ([]Credential, error) {
	rows, err := s.db.QueryContext(ctx,
		s.dialect.Rebind("SELECT id, vault_id, key, type, ciphertext, nonce, created_at, updated_at FROM credentials WHERE vault_id = ? ORDER BY key"),
		vaultID,
	)
	if err != nil {
		return nil, fmt.Errorf("listing credentials: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var creds []Credential
	for rows.Next() {
		var cred Credential
		var createdAt, updatedAt interface{}
		if err := rows.Scan(&cred.ID, &cred.VaultID, &cred.Key, &cred.Type, &cred.Ciphertext, &cred.Nonce, &createdAt, &updatedAt); err != nil {
			return nil, fmt.Errorf("scanning credential: %w", err)
		}
		cred.CreatedAt, _ = s.dialect.ScanTime(createdAt)
		cred.UpdatedAt, _ = s.dialect.ScanTime(updatedAt)
		creds = append(creds, cred)
	}
	return creds, rows.Err()
}

func (s *SQLStore) DeleteCredential(ctx context.Context, vaultID, key string) error {
	res, err := s.db.ExecContext(ctx, s.dialect.Rebind("DELETE FROM credentials WHERE vault_id = ? AND key = ?"), vaultID, key)
	if err != nil {
		return fmt.Errorf("deleting credential: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// --- OAuth Credentials ---

func (s *SQLStore) GetCredentialOAuth(ctx context.Context, vaultID, key string) (*CredentialOAuth, error) {
	var co CredentialOAuth
	var authURL, scopes, scopeSep, tokenAuthMethod sql.NullString
	var tokenExpiresAt, connectedAt, lastRefreshedAt, lastRefreshErrorAt interface{}
	var lastRefreshError sql.NullString
	var createdAt, updatedAt interface{}
	var disablePKCERaw interface{}

	err := s.db.QueryRowContext(ctx,
		s.dialect.Rebind(`SELECT vault_id, credential_key, authorization_url, token_url, client_id,
		   client_secret_ct, client_secret_nonce, scopes, scope_separator, disable_pkce,
		   token_auth_method, refresh_token_ct, refresh_token_nonce, token_expires_at,
		   connected_at, last_refreshed_at, last_refresh_error, last_refresh_error_at,
		   created_at, updated_at
		 FROM credential_oauth WHERE vault_id = ? AND credential_key = ?`),
		vaultID, key,
	).Scan(
		&co.VaultID, &co.CredentialKey, &authURL, &co.TokenURL, &co.ClientID,
		&co.ClientSecretCT, &co.ClientSecretNonce, &scopes, &scopeSep, &disablePKCERaw,
		&tokenAuthMethod, &co.RefreshTokenCT, &co.RefreshTokenNonce, &tokenExpiresAt,
		&connectedAt, &lastRefreshedAt, &lastRefreshError, &lastRefreshErrorAt,
		&createdAt, &updatedAt,
	)
	if err != nil {
		return nil, err
	}

	co.AuthorizationURL = authURL.String
	co.Scopes = scopes.String
	co.ScopeSeparator = scopeSep.String
	if co.ScopeSeparator == "" {
		co.ScopeSeparator = " "
	}
	co.DisablePKCE, _ = s.dialect.ScanBool(disablePKCERaw)
	co.TokenAuthMethod = tokenAuthMethod.String
	if co.TokenAuthMethod == "" {
		co.TokenAuthMethod = "client_secret_post"
	}
	co.TokenExpiresAt, _ = s.dialect.ScanNullableTime(tokenExpiresAt)
	co.ConnectedAt, _ = s.dialect.ScanNullableTime(connectedAt)
	co.LastRefreshedAt, _ = s.dialect.ScanNullableTime(lastRefreshedAt)
	co.LastRefreshError = lastRefreshError.String
	co.LastRefreshErrorAt, _ = s.dialect.ScanNullableTime(lastRefreshErrorAt)
	co.CreatedAt, _ = s.dialect.ScanTime(createdAt)
	co.UpdatedAt, _ = s.dialect.ScanTime(updatedAt)
	return &co, nil
}

func (s *SQLStore) SetCredentialOAuth(ctx context.Context, co *CredentialOAuth) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Ensure parent credentials row exists with type='oauth'.
	_, err = tx.ExecContext(ctx,
		s.dialect.Rebind(`INSERT INTO credentials (id, vault_id, key, type, ciphertext, nonce, created_at, updated_at)
		 VALUES (?, ?, ?, 'oauth', ?, ?, ?, ?)
		 ON CONFLICT(vault_id, key) DO UPDATE SET
		   type = 'oauth',
		   updated_at = excluded.updated_at`),
		newUUID(), co.VaultID, co.CredentialKey, []byte{}, []byte{}, s.now(), s.now(),
	)
	if err != nil {
		return fmt.Errorf("ensuring credential row: %w", err)
	}

	nowStr := s.now()
	disablePKCE := s.dialect.BoolVal(co.DisablePKCE)
	tokenAuthMethod := co.TokenAuthMethod
	if tokenAuthMethod == "" {
		tokenAuthMethod = "client_secret_post"
	}
	scopeSep := co.ScopeSeparator
	if scopeSep == "" {
		scopeSep = " "
	}

	tokenExpiresAt := s.dialect.FormatNullableTime(utcTimePtr(co.TokenExpiresAt))
	connectedAt := s.dialect.FormatNullableTime(utcTimePtr(co.ConnectedAt))
	lastRefreshedAt := s.dialect.FormatNullableTime(utcTimePtr(co.LastRefreshedAt))
	lastRefreshErrorAt := s.dialect.FormatNullableTime(utcTimePtr(co.LastRefreshErrorAt))

	_, err = tx.ExecContext(ctx,
		s.dialect.Rebind(`INSERT INTO credential_oauth (vault_id, credential_key, authorization_url, token_url, client_id,
		   client_secret_ct, client_secret_nonce, scopes, scope_separator, disable_pkce, token_auth_method,
		   refresh_token_ct, refresh_token_nonce, token_expires_at,
		   connected_at, last_refreshed_at, last_refresh_error, last_refresh_error_at,
		   created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(vault_id, credential_key) DO UPDATE SET
		   authorization_url = excluded.authorization_url,
		   token_url = excluded.token_url,
		   client_id = excluded.client_id,
		   client_secret_ct = excluded.client_secret_ct,
		   client_secret_nonce = excluded.client_secret_nonce,
		   scopes = excluded.scopes,
		   scope_separator = excluded.scope_separator,
		   disable_pkce = excluded.disable_pkce,
		   token_auth_method = excluded.token_auth_method,
		   refresh_token_ct = CASE WHEN excluded.token_url = credential_oauth.token_url
		     THEN COALESCE(excluded.refresh_token_ct, credential_oauth.refresh_token_ct)
		     ELSE excluded.refresh_token_ct END,
		   refresh_token_nonce = CASE WHEN excluded.token_url = credential_oauth.token_url
		     THEN COALESCE(excluded.refresh_token_nonce, credential_oauth.refresh_token_nonce)
		     ELSE excluded.refresh_token_nonce END,
		   token_expires_at = CASE WHEN excluded.token_url = credential_oauth.token_url
		     THEN COALESCE(excluded.token_expires_at, credential_oauth.token_expires_at)
		     ELSE excluded.token_expires_at END,
		   connected_at = CASE WHEN excluded.token_url = credential_oauth.token_url
		     THEN COALESCE(excluded.connected_at, credential_oauth.connected_at)
		     ELSE excluded.connected_at END,
		   last_refreshed_at = CASE WHEN excluded.token_url = credential_oauth.token_url
		     THEN COALESCE(excluded.last_refreshed_at, credential_oauth.last_refreshed_at)
		     ELSE excluded.last_refreshed_at END,
		   last_refresh_error = excluded.last_refresh_error,
		   last_refresh_error_at = excluded.last_refresh_error_at,
		   updated_at = excluded.updated_at`),
		co.VaultID, co.CredentialKey, nullableString(co.AuthorizationURL), co.TokenURL, co.ClientID,
		co.ClientSecretCT, co.ClientSecretNonce, nullableString(co.Scopes), scopeSep, disablePKCE, tokenAuthMethod,
		co.RefreshTokenCT, co.RefreshTokenNonce, tokenExpiresAt,
		connectedAt, lastRefreshedAt, nullableString(co.LastRefreshError), lastRefreshErrorAt,
		nowStr, nowStr,
	)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLStore) UpdateCredentialOAuthTokens(ctx context.Context, vaultID, key string, accessCT, accessNonce, refreshCT, refreshNonce []byte, expiresAt *time.Time) error {
	nowStr := s.now()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Update the access token in the credentials table.
	_, err = tx.ExecContext(ctx,
		s.dialect.Rebind(`UPDATE credentials SET ciphertext = ?, nonce = ?, updated_at = ?
		 WHERE vault_id = ? AND key = ?`),
		accessCT, accessNonce, nowStr, vaultID, key,
	)
	if err != nil {
		return fmt.Errorf("updating access token: %w", err)
	}

	// Update refresh state in the companion table.
	expiresAtStr := s.dialect.FormatNullableTime(utcTimePtr(expiresAt))

	if refreshCT != nil {
		_, err = tx.ExecContext(ctx,
			s.dialect.Rebind(`UPDATE credential_oauth SET
			   refresh_token_ct = ?, refresh_token_nonce = ?,
			   token_expires_at = ?, connected_at = COALESCE(connected_at, ?),
			   last_refreshed_at = ?, last_refresh_error = NULL, last_refresh_error_at = NULL,
			   updated_at = ?
			 WHERE vault_id = ? AND credential_key = ?`),
			refreshCT, refreshNonce, expiresAtStr, nowStr, nowStr, nowStr, vaultID, key,
		)
	} else {
		_, err = tx.ExecContext(ctx,
			s.dialect.Rebind(`UPDATE credential_oauth SET
			   token_expires_at = ?, connected_at = COALESCE(connected_at, ?),
			   last_refreshed_at = ?, last_refresh_error = NULL, last_refresh_error_at = NULL,
			   updated_at = ?
			 WHERE vault_id = ? AND credential_key = ?`),
			expiresAtStr, nowStr, nowStr, nowStr, vaultID, key,
		)
	}
	if err != nil {
		return fmt.Errorf("updating oauth refresh state: %w", err)
	}

	return tx.Commit()
}

func (s *SQLStore) UpdateCredentialOAuthError(ctx context.Context, vaultID, key, errMsg string) error {
	nowStr := s.now()
	_, err := s.db.ExecContext(ctx,
		s.dialect.Rebind(`UPDATE credential_oauth SET
		   last_refresh_error = ?, last_refresh_error_at = ?, updated_at = ?
		 WHERE vault_id = ? AND credential_key = ?`),
		errMsg, nowStr, nowStr, vaultID, key,
	)
	return err
}

// --- OAuth States ---

func (s *SQLStore) CreateCredentialOAuthState(ctx context.Context, state *CredentialOAuthState) error {
	_, err := s.db.ExecContext(ctx,
		s.dialect.Rebind(`INSERT INTO credential_oauth_states (id, state_hash, code_verifier, vault_id, credential_key, redirect_url, created_at, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`),
		state.ID, state.StateHash, state.CodeVerifier, state.VaultID, state.CredentialKey,
		nullableString(state.RedirectURL),
		s.dialect.FormatTime(state.CreatedAt.UTC()),
		s.dialect.FormatTime(state.ExpiresAt.UTC()),
	)
	return err
}

func (s *SQLStore) GetCredentialOAuthStateByHash(ctx context.Context, stateHash string) (*CredentialOAuthState, error) {
	var st CredentialOAuthState
	var redirectURL sql.NullString
	var createdAt, expiresAt interface{}
	err := s.db.QueryRowContext(ctx,
		s.dialect.Rebind(`SELECT id, state_hash, code_verifier, vault_id, credential_key, redirect_url, created_at, expires_at
		 FROM credential_oauth_states WHERE state_hash = ?`),
		stateHash,
	).Scan(&st.ID, &st.StateHash, &st.CodeVerifier, &st.VaultID, &st.CredentialKey, &redirectURL, &createdAt, &expiresAt)
	if err != nil {
		return nil, err
	}
	st.RedirectURL = redirectURL.String
	st.CreatedAt, _ = s.dialect.ScanTime(createdAt)
	st.ExpiresAt, _ = s.dialect.ScanTime(expiresAt)
	return &st, nil
}

func (s *SQLStore) DeleteCredentialOAuthState(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, s.dialect.Rebind("DELETE FROM credential_oauth_states WHERE id = ?"), id)
	return err
}

func (s *SQLStore) ExpireCredentialOAuthStates(ctx context.Context, before time.Time) (int, error) {
	res, err := s.db.ExecContext(ctx,
		s.dialect.Rebind("DELETE FROM credential_oauth_states WHERE expires_at < ?"),
		s.dialect.FormatTime(before.UTC()),
	)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// --- Users ---

func (s *SQLStore) CreateUser(ctx context.Context, email string, passwordHash, passwordSalt []byte, role string, kdfTime uint32, kdfMemory uint32, kdfThreads uint8) (*User, error) {
	id := newUUID()
	now := time.Now().UTC()
	nowStr := s.dialect.FormatTime(now)

	_, err := s.db.ExecContext(ctx,
		s.dialect.Rebind("INSERT INTO users (id, email, password_hash, password_salt, role, is_active, kdf_time, kdf_memory, kdf_threads, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"),
		id, email, passwordHash, passwordSalt, role, s.dialect.BoolVal(false), kdfTime, kdfMemory, kdfThreads, nowStr, nowStr,
	)
	if err != nil {
		return nil, fmt.Errorf("creating user: %w", err)
	}

	return &User{
		ID: id, Email: email, PasswordHash: passwordHash, PasswordSalt: passwordSalt,
		KDFTime: kdfTime, KDFMemory: kdfMemory, KDFThreads: kdfThreads,
		Role: role, IsActive: false, CreatedAt: now, UpdatedAt: now,
	}, nil
}

func (s *SQLStore) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	row := s.db.QueryRowContext(ctx,
		s.dialect.Rebind("SELECT id, email, password_hash, password_salt, kdf_time, kdf_memory, kdf_threads, role, is_active, created_at, updated_at FROM users WHERE email = ?"), email,
	)

	var u User
	var createdAt, updatedAt interface{}
	if err := row.Scan(&u.ID, &u.Email, &u.PasswordHash, &u.PasswordSalt, &u.KDFTime, &u.KDFMemory, &u.KDFThreads, &u.Role, &u.IsActive, &createdAt, &updatedAt); err != nil {
		return nil, err
	}
	u.CreatedAt, _ = s.dialect.ScanTime(createdAt)
	u.UpdatedAt, _ = s.dialect.ScanTime(updatedAt)
	return &u, nil
}

func (s *SQLStore) CountUsers(ctx context.Context) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx, s.dialect.Rebind("SELECT COUNT(*) FROM users")).Scan(&count)
	return count, err
}

// RegisterFirstUser atomically checks that no users exist and creates the
// first user as an active owner. Returns ErrNotFirstUser if users already exist.
func (s *SQLStore) RegisterFirstUser(ctx context.Context, email string, passwordHash, passwordSalt []byte, defaultVaultID string, kdfTime uint32, kdfMemory uint32, kdfThreads uint8) (*User, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var count int
	if err := tx.QueryRowContext(ctx, s.dialect.Rebind("SELECT COUNT(*) FROM users")).Scan(&count); err != nil {
		return nil, fmt.Errorf("counting users: %w", err)
	}
	if count > 0 {
		return nil, ErrNotFirstUser
	}

	id := newUUID()
	now := time.Now().UTC()
	nowStr := s.dialect.FormatTime(now)

	_, err = tx.ExecContext(ctx,
		s.dialect.Rebind("INSERT INTO users (id, email, password_hash, password_salt, kdf_time, kdf_memory, kdf_threads, role, is_active, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, 'owner', ?, ?, ?)"),
		id, email, passwordHash, passwordSalt, kdfTime, kdfMemory, kdfThreads, s.dialect.BoolVal(true), nowStr, nowStr,
	)
	if err != nil {
		return nil, fmt.Errorf("creating owner: %w", err)
	}

	if defaultVaultID != "" {
		_, err = tx.ExecContext(ctx,
			s.dialect.Rebind("INSERT INTO vault_grants (actor_id, actor_type, vault_id, role, created_at) VALUES (?, 'user', ?, 'admin', ?) ON CONFLICT(actor_id, vault_id) DO UPDATE SET role = excluded.role"),
			id, defaultVaultID, nowStr,
		)
		if err != nil {
			return nil, fmt.Errorf("granting vault admin: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit: %w", err)
	}

	return &User{
		ID: id, Email: email, PasswordHash: passwordHash, PasswordSalt: passwordSalt,
		KDFTime: kdfTime, KDFMemory: kdfMemory, KDFThreads: kdfThreads,
		Role: "owner", IsActive: true, CreatedAt: now, UpdatedAt: now,
	}, nil
}

func (s *SQLStore) GetUserByID(ctx context.Context, id string) (*User, error) {
	row := s.db.QueryRowContext(ctx,
		s.dialect.Rebind("SELECT id, email, password_hash, password_salt, kdf_time, kdf_memory, kdf_threads, role, is_active, created_at, updated_at FROM users WHERE id = ?"), id,
	)

	var u User
	var createdAt, updatedAt interface{}
	if err := row.Scan(&u.ID, &u.Email, &u.PasswordHash, &u.PasswordSalt, &u.KDFTime, &u.KDFMemory, &u.KDFThreads, &u.Role, &u.IsActive, &createdAt, &updatedAt); err != nil {
		return nil, err
	}
	u.CreatedAt, _ = s.dialect.ScanTime(createdAt)
	u.UpdatedAt, _ = s.dialect.ScanTime(updatedAt)
	return &u, nil
}

func (s *SQLStore) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx,
		s.dialect.Rebind("SELECT id, email, password_hash, password_salt, kdf_time, kdf_memory, kdf_threads, role, is_active, created_at, updated_at FROM users ORDER BY email"),
	)
	if err != nil {
		return nil, fmt.Errorf("listing users: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var users []User
	for rows.Next() {
		var u User
		var createdAt, updatedAt interface{}
		if err := rows.Scan(&u.ID, &u.Email, &u.PasswordHash, &u.PasswordSalt, &u.KDFTime, &u.KDFMemory, &u.KDFThreads, &u.Role, &u.IsActive, &createdAt, &updatedAt); err != nil {
			return nil, fmt.Errorf("scanning user: %w", err)
		}
		u.CreatedAt, _ = s.dialect.ScanTime(createdAt)
		u.UpdatedAt, _ = s.dialect.ScanTime(updatedAt)
		users = append(users, u)
	}
	return users, rows.Err()
}

func (s *SQLStore) UpdateUserPassword(ctx context.Context, userID string, passwordHash, passwordSalt []byte, kdfTime uint32, kdfMemory uint32, kdfThreads uint8) error {
	nowStr := s.now()
	res, err := s.db.ExecContext(ctx,
		s.dialect.Rebind("UPDATE users SET password_hash = ?, password_salt = ?, kdf_time = ?, kdf_memory = ?, kdf_threads = ?, updated_at = ? WHERE id = ?"),
		passwordHash, passwordSalt, kdfTime, kdfMemory, kdfThreads, nowStr, userID,
	)
	if err != nil {
		return fmt.Errorf("updating user password: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *SQLStore) UpdateUserRole(ctx context.Context, userID, role string) error {
	nowStr := s.now()
	res, err := s.db.ExecContext(ctx,
		s.dialect.Rebind("UPDATE users SET role = ?, updated_at = ? WHERE id = ?"),
		role, nowStr, userID,
	)
	if err != nil {
		return fmt.Errorf("updating user role: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *SQLStore) DeleteUser(ctx context.Context, userID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	res, err := tx.ExecContext(ctx, s.dialect.Rebind("DELETE FROM users WHERE id = ?"), userID)
	if err != nil {
		return fmt.Errorf("deleting user: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	// Clean up vault grants (no FK cascade since the unified table uses generic actor_id).
	if _, err := tx.ExecContext(ctx, s.dialect.Rebind("DELETE FROM vault_grants WHERE actor_id = ?"), userID); err != nil {
		return fmt.Errorf("cleaning up vault grants: %w", err)
	}
	// Revoke scoped tokens this user minted on behalf of others. Without
	// this, an orphan token keeps proxying upstream APIs until its TTL
	// expires (up to scopedSessionMaxTTL).
	if _, err := tx.ExecContext(ctx,
		s.dialect.Rebind(`DELETE FROM sessions
		 WHERE created_by_actor_id = ? AND created_by_actor_type = 'user'`),
		userID,
	); err != nil {
		return fmt.Errorf("cleaning up scoped tokens minted by user: %w", err)
	}
	return tx.Commit()
}

func (s *SQLStore) CountOwners(ctx context.Context) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx, s.dialect.Rebind("SELECT COUNT(*) FROM users WHERE role = 'owner'")).Scan(&count)
	return count, err
}

// --- Vault Grants ---

func (s *SQLStore) GrantVaultRole(ctx context.Context, actorID, actorType, vaultID, role string) error {
	nowStr := s.now()
	_, err := s.db.ExecContext(ctx,
		s.dialect.Rebind(`INSERT INTO vault_grants (actor_id, actor_type, vault_id, role, created_at) VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT(actor_id, vault_id) DO UPDATE SET role = excluded.role`),
		actorID, actorType, vaultID, role, nowStr,
	)
	if err != nil {
		return fmt.Errorf("granting vault role: %w", err)
	}
	return nil
}

func (s *SQLStore) RevokeVaultAccess(ctx context.Context, actorID, vaultID string) error {
	res, err := s.db.ExecContext(ctx,
		s.dialect.Rebind("DELETE FROM vault_grants WHERE actor_id = ? AND vault_id = ?"),
		actorID, vaultID,
	)
	if err != nil {
		return fmt.Errorf("revoking vault access: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *SQLStore) ListActorGrants(ctx context.Context, actorID string) ([]VaultGrant, error) {
	rows, err := s.db.QueryContext(ctx,
		s.dialect.Rebind(`SELECT vg.actor_id, vg.actor_type, vg.vault_id, v.name, vg.role, vg.created_at
		 FROM vault_grants vg
		 JOIN vaults v ON v.id = vg.vault_id
		 WHERE vg.actor_id = ? ORDER BY vg.created_at`),
		actorID,
	)
	if err != nil {
		return nil, fmt.Errorf("listing actor grants: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var grants []VaultGrant
	for rows.Next() {
		var g VaultGrant
		var createdAt interface{}
		if err := rows.Scan(&g.ActorID, &g.ActorType, &g.VaultID, &g.VaultName, &g.Role, &createdAt); err != nil {
			return nil, fmt.Errorf("scanning grant: %w", err)
		}
		g.CreatedAt, _ = s.dialect.ScanTime(createdAt)
		grants = append(grants, g)
	}
	return grants, rows.Err()
}

func (s *SQLStore) HasVaultAccess(ctx context.Context, actorID, vaultID string) (bool, error) {
	var exists int
	err := s.db.QueryRowContext(ctx,
		s.dialect.Rebind("SELECT 1 FROM vault_grants WHERE actor_id = ? AND vault_id = ?"),
		actorID, vaultID,
	).Scan(&exists)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("checking vault access: %w", err)
	}
	return true, nil
}

func (s *SQLStore) GetVaultRole(ctx context.Context, actorID, vaultID string) (string, error) {
	var role string
	err := s.db.QueryRowContext(ctx,
		s.dialect.Rebind("SELECT role FROM vault_grants WHERE actor_id = ? AND vault_id = ?"),
		actorID, vaultID,
	).Scan(&role)
	if err != nil {
		return "", err
	}
	return role, nil
}

func (s *SQLStore) CountVaultAdmins(ctx context.Context, vaultID string) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx,
		s.dialect.Rebind("SELECT COUNT(*) FROM vault_grants WHERE vault_id = ? AND role = 'admin'"),
		vaultID,
	).Scan(&count)
	return count, err
}

func (s *SQLStore) ListVaultMembers(ctx context.Context, vaultID string) ([]VaultGrant, error) {
	rows, err := s.db.QueryContext(ctx,
		s.dialect.Rebind(`SELECT vg.actor_id, vg.actor_type, vg.vault_id, v.name, vg.role, vg.created_at
		 FROM vault_grants vg
		 JOIN vaults v ON v.id = vg.vault_id
		 WHERE vg.vault_id = ? ORDER BY vg.created_at`),
		vaultID,
	)
	if err != nil {
		return nil, fmt.Errorf("listing vault members: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var grants []VaultGrant
	for rows.Next() {
		var g VaultGrant
		var createdAt interface{}
		if err := rows.Scan(&g.ActorID, &g.ActorType, &g.VaultID, &g.VaultName, &g.Role, &createdAt); err != nil {
			return nil, fmt.Errorf("scanning grant: %w", err)
		}
		g.CreatedAt, _ = s.dialect.ScanTime(createdAt)
		grants = append(grants, g)
	}
	return grants, rows.Err()
}

func (s *SQLStore) ListVaultMembersByType(ctx context.Context, vaultID, actorType string) ([]VaultGrant, error) {
	rows, err := s.db.QueryContext(ctx,
		s.dialect.Rebind(`SELECT vg.actor_id, vg.actor_type, vg.vault_id, v.name, vg.role, vg.created_at
		 FROM vault_grants vg
		 JOIN vaults v ON v.id = vg.vault_id
		 WHERE vg.vault_id = ? AND vg.actor_type = ? ORDER BY vg.created_at`),
		vaultID, actorType,
	)
	if err != nil {
		return nil, fmt.Errorf("listing vault members by type: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var grants []VaultGrant
	for rows.Next() {
		var g VaultGrant
		var createdAt interface{}
		if err := rows.Scan(&g.ActorID, &g.ActorType, &g.VaultID, &g.VaultName, &g.Role, &createdAt); err != nil {
			return nil, fmt.Errorf("scanning grant: %w", err)
		}
		g.CreatedAt, _ = s.dialect.ScanTime(createdAt)
		grants = append(grants, g)
	}
	return grants, rows.Err()
}

func (s *SQLStore) ActivateUser(ctx context.Context, userID string) error {
	nowStr := s.now()
	res, err := s.db.ExecContext(ctx,
		s.dialect.Rebind("UPDATE users SET is_active = ?, updated_at = ? WHERE id = ?"),
		s.dialect.BoolVal(true), nowStr, userID,
	)
	if err != nil {
		return fmt.Errorf("activating user: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *SQLStore) DeleteUserSessions(ctx context.Context, userID string) error {
	_, err := s.db.ExecContext(ctx, s.dialect.Rebind("DELETE FROM sessions WHERE user_id = ?"), userID)
	if err != nil {
		return fmt.Errorf("deleting user sessions: %w", err)
	}
	return nil
}

// --- Sessions ---

// CreateUserSession persists a user login session with sliding-expiry
// metadata. Both ExpiresAt (absolute cap) and IdleTTL (inactivity window)
// are enforced on read via Session.IsExpired.
func (s *SQLStore) CreateUserSession(ctx context.Context, p CreateUserSessionParams) (*Session, error) {
	if p.UserID == "" {
		return nil, fmt.Errorf("CreateUserSession: UserID is required")
	}
	rawToken := newSessionToken()
	tokenHash := hashSessionToken(rawToken)
	publicID := newPublicID()
	now := time.Now().UTC()

	var idleSecs sql.NullInt64
	if p.IdleTTL > 0 {
		idleSecs = sql.NullInt64{Int64: int64(p.IdleTTL.Seconds()), Valid: true}
	}

	_, err := s.db.ExecContext(ctx,
		s.dialect.Rebind(`INSERT INTO sessions
		   (id, user_id, expires_at, created_at, last_used_at, idle_ttl_seconds,
		    device_label, last_ip, last_user_agent, public_id)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		tokenHash, p.UserID,
		s.dialect.FormatTime(p.ExpiresAt.UTC()),
		s.dialect.FormatTime(now),
		s.dialect.FormatTime(now),
		idleSecs,
		nullableString(p.DeviceLabel),
		nullableString(p.LastIP),
		nullableString(p.LastUserAgent),
		publicID,
	)
	if err != nil {
		return nil, fmt.Errorf("creating session: %w", err)
	}

	exp := p.ExpiresAt.UTC()
	return &Session{
		ID:            rawToken,
		UserID:        p.UserID,
		ExpiresAt:     &exp,
		CreatedAt:     now,
		PublicID:      publicID,
		LastUsedAt:    &now,
		IdleTTL:       p.IdleTTL,
		DeviceLabel:   p.DeviceLabel,
		LastIP:        p.LastIP,
		LastUserAgent: p.LastUserAgent,
	}, nil
}

func (s *SQLStore) CreateScopedSession(ctx context.Context, p CreateScopedSessionParams) (*Session, error) {
	rawToken := newSessionToken()
	tokenHash := hashSessionToken(rawToken)
	publicID := newPublicID()
	now := time.Now().UTC()

	expiresAtVal := s.dialect.FormatNullableTime(utcTimePtr(p.ExpiresAt))

	_, err := s.db.ExecContext(ctx,
		s.dialect.Rebind(`INSERT INTO sessions
		   (id, vault_id, vault_role, expires_at, created_at,
		    public_id, label, created_by_actor_id, created_by_actor_type)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		tokenHash, p.VaultID, p.VaultRole, expiresAtVal, s.dialect.FormatTime(now),
		publicID,
		nullableString(p.Label),
		nullableString(p.CreatedByActorID),
		nullableString(p.CreatedByActorType),
	)
	if err != nil {
		return nil, fmt.Errorf("creating scoped session: %w", err)
	}

	return &Session{
		ID:                 rawToken,
		VaultID:            p.VaultID,
		VaultRole:          p.VaultRole,
		ExpiresAt:          utcTimePtr(p.ExpiresAt),
		CreatedAt:          now,
		PublicID:           publicID,
		Label:              p.Label,
		CreatedByActorID:   p.CreatedByActorID,
		CreatedByActorType: p.CreatedByActorType,
	}, nil
}

// ListScopedSessionsByVault returns active scoped tokens for the vault,
// most recent first. Stale rows past their absolute expiry are filtered
// in SQL; rows with a NULL public_id (legacy scoped rows from before
// migration 044) are excluded so the UI can revoke every row it shows.
func (s *SQLStore) ListScopedSessionsByVault(ctx context.Context, vaultID string) ([]Session, error) {
	if vaultID == "" {
		return nil, fmt.Errorf("ListScopedSessionsByVault: vaultID is required")
	}
	rows, err := s.db.QueryContext(ctx,
		s.dialect.Rebind(`SELECT vault_role, expires_at, created_at, public_id,
		        label, created_by_actor_id, created_by_actor_type
		   FROM sessions
		  WHERE vault_id = ?
		    AND public_id IS NOT NULL
		    AND user_id IS NULL
		    AND agent_id IS NULL
		    AND (expires_at IS NULL OR expires_at > ?)
		  ORDER BY created_at DESC`),
		vaultID, s.now(),
	)
	if err != nil {
		return nil, fmt.Errorf("listing scoped sessions: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []Session
	for rows.Next() {
		var sess Session
		var vaultRole, publicID sql.NullString
		var expiresAt interface{}
		var label, createdByActorID, createdByActorType sql.NullString
		var createdAt interface{}
		if err := rows.Scan(&vaultRole, &expiresAt, &createdAt, &publicID,
			&label, &createdByActorID, &createdByActorType); err != nil {
			return nil, fmt.Errorf("scanning scoped session: %w", err)
		}
		sess.VaultID = vaultID
		sess.VaultRole = vaultRole.String
		sess.PublicID = publicID.String
		sess.Label = label.String
		sess.CreatedByActorID = createdByActorID.String
		sess.CreatedByActorType = createdByActorType.String
		sess.ExpiresAt, _ = s.dialect.ScanNullableTime(expiresAt)
		sess.CreatedAt, _ = s.dialect.ScanTime(createdAt)
		out = append(out, sess)
	}
	return out, rows.Err()
}

// RevokeScopedSession deletes one scoped session by (vaultID, publicID).
// Returns sql.ErrNoRows when no matching row exists. Vault scoping in the
// WHERE clause prevents one vault's admin from revoking another vault's
// token by guessing a public_id.
func (s *SQLStore) RevokeScopedSession(ctx context.Context, vaultID, publicID string) error {
	if vaultID == "" || publicID == "" {
		return sql.ErrNoRows
	}
	res, err := s.db.ExecContext(ctx,
		s.dialect.Rebind("DELETE FROM sessions WHERE vault_id = ? AND public_id = ? AND user_id IS NULL AND agent_id IS NULL"),
		vaultID, publicID,
	)
	if err != nil {
		return fmt.Errorf("revoking scoped session: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *SQLStore) GetSession(ctx context.Context, rawToken string) (*Session, error) {
	tokenHash := hashSessionToken(rawToken)
	row := s.db.QueryRowContext(ctx,
		s.dialect.Rebind(`SELECT id, user_id, vault_id, agent_id, vault_role, expires_at, created_at,
		        last_used_at, idle_ttl_seconds, device_label, last_ip, last_user_agent, public_id,
		        label, created_by_actor_id, created_by_actor_type
		 FROM sessions WHERE id = ?`), tokenHash,
	)

	var sess Session
	var storedID string
	var userID, vaultID, agentID, vaultRole sql.NullString
	var expiresAt, lastUsedAt interface{}
	var deviceLabel, lastIP, lastUserAgent, publicID sql.NullString
	var label, createdByActorID, createdByActorType sql.NullString
	var idleSecs sql.NullInt64
	var createdAt interface{}
	if err := row.Scan(&storedID, &userID, &vaultID, &agentID, &vaultRole, &expiresAt, &createdAt,
		&lastUsedAt, &idleSecs, &deviceLabel, &lastIP, &lastUserAgent, &publicID,
		&label, &createdByActorID, &createdByActorType); err != nil {
		return nil, err
	}
	// Return the raw token as ID (not the hash) so callers can reference it.
	sess.ID = rawToken
	sess.UserID = userID.String
	sess.VaultID = vaultID.String
	sess.AgentID = agentID.String
	sess.VaultRole = vaultRole.String
	sess.ExpiresAt, _ = s.dialect.ScanNullableTime(expiresAt)
	sess.CreatedAt, _ = s.dialect.ScanTime(createdAt)
	sess.LastUsedAt, _ = s.dialect.ScanNullableTime(lastUsedAt)
	if idleSecs.Valid {
		sess.IdleTTL = time.Duration(idleSecs.Int64) * time.Second
	}
	sess.DeviceLabel = deviceLabel.String
	sess.LastIP = lastIP.String
	sess.LastUserAgent = lastUserAgent.String
	sess.PublicID = publicID.String
	sess.Label = label.String
	sess.CreatedByActorID = createdByActorID.String
	sess.CreatedByActorType = createdByActorType.String
	return &sess, nil
}

// TouchInterval is the minimum gap between last_used_at writes for a
// single session. Per-request UPDATEs would serialize SQLite writes during
// a proxy storm; collapsing to one write per minute keeps the idle window
// accurate to within a minute while leaving headroom for concurrent reads.
// Exported so callers (e.g. the server's in-memory touch cache) can stay
// consistent with the store-side throttle.
const TouchInterval = 60 * time.Second

// TouchSession bumps last_used_at on a user session and refreshes
// last_ip + last_user_agent so the auth-sessions view reflects the
// caller's most recent request rather than only the login. Throttled by
// TouchInterval so per-request calls collapse to one write per minute.
// No-op for agent tokens and scoped sessions (rows with user_id IS NULL).
// Empty ip/userAgent leave the existing column value untouched via
// COALESCE — handy when a caller can't determine them.
func (s *SQLStore) TouchSession(ctx context.Context, rawToken, ip, userAgent string) error {
	tokenHash := hashSessionToken(rawToken)
	now := s.dialect.FormatTime(time.Now().UTC())
	cutoff := s.dialect.FormatTime(time.Now().UTC().Add(-TouchInterval))
	_, err := s.db.ExecContext(ctx,
		s.dialect.Rebind(`UPDATE sessions
		    SET last_used_at    = ?,
		        last_ip         = COALESCE(NULLIF(?, ''), last_ip),
		        last_user_agent = COALESCE(NULLIF(?, ''), last_user_agent)
		  WHERE id = ?
		    AND user_id IS NOT NULL
		    AND (last_used_at IS NULL OR last_used_at < ?)`),
		now, ip, userAgent, tokenHash, cutoff,
	)
	if err != nil {
		return fmt.Errorf("touching session: %w", err)
	}
	return nil
}

// ListUserSessions returns active (non-expired) user sessions for userID,
// most recently used first. Idle expiry is enforced at the row level so
// stale rows don't leak into the UI.
func (s *SQLStore) ListUserSessions(ctx context.Context, userID string) ([]Session, error) {
	rows, err := s.db.QueryContext(ctx,
		s.dialect.Rebind(`SELECT id, expires_at, created_at, last_used_at, idle_ttl_seconds,
		        device_label, last_ip, last_user_agent, public_id
		 FROM sessions
		 WHERE user_id = ?
		   AND (expires_at IS NULL OR expires_at > ?)
		 ORDER BY COALESCE(last_used_at, created_at) DESC`),
		userID, s.now(),
	)
	if err != nil {
		return nil, fmt.Errorf("listing user sessions: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []Session
	now := time.Now().UTC()
	for rows.Next() {
		var sess Session
		var hashedID string
		var createdAt interface{}
		var expiresAt, lastUsedAt interface{}
		var deviceLabel, lastIP, lastUserAgent, publicID sql.NullString
		var idleSecs sql.NullInt64
		if err := rows.Scan(&hashedID, &expiresAt, &createdAt, &lastUsedAt, &idleSecs,
			&deviceLabel, &lastIP, &lastUserAgent, &publicID); err != nil {
			return nil, fmt.Errorf("scanning session: %w", err)
		}
		sess.UserID = userID
		// ID is intentionally left empty — the raw token only lives on the
		// client. Callers identify sessions by PublicID.
		sess.PublicID = publicID.String
		sess.DeviceLabel = deviceLabel.String
		sess.LastIP = lastIP.String
		sess.LastUserAgent = lastUserAgent.String
		sess.ExpiresAt, _ = s.dialect.ScanNullableTime(expiresAt)
		sess.CreatedAt, _ = s.dialect.ScanTime(createdAt)
		sess.LastUsedAt, _ = s.dialect.ScanNullableTime(lastUsedAt)
		if idleSecs.Valid {
			sess.IdleTTL = time.Duration(idleSecs.Int64) * time.Second
		}
		// Skip rows past their idle window — same rule as IsExpired.
		if sess.IsExpired(now) {
			continue
		}
		out = append(out, sess)
	}
	return out, rows.Err()
}

// RevokeUserSession deletes a single session by (userID, publicID).
// Returns sql.ErrNoRows if no matching session exists — important so a
// caller can distinguish "already gone" from a successful revoke without
// a separate lookup.
func (s *SQLStore) RevokeUserSession(ctx context.Context, userID, publicID string) error {
	if userID == "" || publicID == "" {
		return sql.ErrNoRows
	}
	res, err := s.db.ExecContext(ctx,
		s.dialect.Rebind("DELETE FROM sessions WHERE user_id = ? AND public_id = ?"),
		userID, publicID,
	)
	if err != nil {
		return fmt.Errorf("revoking session: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *SQLStore) DeleteSession(ctx context.Context, rawToken string) error {
	tokenHash := hashSessionToken(rawToken)
	res, err := s.db.ExecContext(ctx, s.dialect.Rebind("DELETE FROM sessions WHERE id = ?"), tokenHash)
	if err != nil {
		return fmt.Errorf("deleting session: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// --- Master Key ---

func (s *SQLStore) GetMasterKeyRecord(ctx context.Context) (*MasterKeyRecord, error) {
	row := s.db.QueryRowContext(ctx,
		s.dialect.Rebind(`SELECT sentinel, sentinel_nonce, dek_ciphertext, dek_nonce, dek_plaintext,
		        salt, kdf_time, kdf_memory, kdf_threads, created_at
		 FROM master_key WHERE id = 1`),
	)

	var rec MasterKeyRecord
	var createdAt interface{}
	err := row.Scan(
		&rec.Sentinel, &rec.SentinelNonce,
		&rec.DEKCiphertext, &rec.DEKNonce, &rec.DEKPlaintext,
		&rec.Salt, &rec.KDFTime, &rec.KDFMemory, &rec.KDFThreads,
		&createdAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("getting master key record: %w", err)
	}
	rec.CreatedAt, _ = s.dialect.ScanTime(createdAt)
	return &rec, nil
}

func (s *SQLStore) SetMasterKeyRecord(ctx context.Context, record *MasterKeyRecord) error {
	_, err := s.db.ExecContext(ctx,
		s.dialect.Rebind(`INSERT INTO master_key (id, sentinel, sentinel_nonce, dek_ciphertext, dek_nonce, dek_plaintext, salt, kdf_time, kdf_memory, kdf_threads)
		 VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(id) DO NOTHING`),
		record.Sentinel, record.SentinelNonce,
		record.DEKCiphertext, record.DEKNonce, record.DEKPlaintext,
		record.Salt, record.KDFTime, record.KDFMemory, record.KDFThreads,
	)
	if err != nil {
		return fmt.Errorf("setting master key record: %w", err)
	}
	return nil
}

func (s *SQLStore) UpdateMasterKeyRecord(ctx context.Context, record *MasterKeyRecord) error {
	res, err := s.db.ExecContext(ctx,
		s.dialect.Rebind(`UPDATE master_key SET
		    sentinel = ?, sentinel_nonce = ?,
		    dek_ciphertext = ?, dek_nonce = ?, dek_plaintext = ?,
		    salt = ?, kdf_time = ?, kdf_memory = ?, kdf_threads = ?
		 WHERE id = 1`),
		record.Sentinel, record.SentinelNonce,
		record.DEKCiphertext, record.DEKNonce, record.DEKPlaintext,
		record.Salt, record.KDFTime, record.KDFMemory, record.KDFThreads,
	)
	if err != nil {
		return fmt.Errorf("updating master key record: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// --- Broker Configs ---

func (s *SQLStore) SetBrokerConfig(ctx context.Context, vaultID string, servicesJSON string) (*BrokerConfig, error) {
	id := newUUID()
	now := time.Now().UTC()
	nowStr := s.dialect.FormatTime(now)

	_, err := s.db.ExecContext(ctx,
		s.dialect.Rebind(`INSERT INTO broker_configs (id, vault_id, services_json, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT(vault_id) DO UPDATE SET
		   services_json = excluded.services_json,
		   updated_at = excluded.updated_at`),
		id, vaultID, servicesJSON, nowStr, nowStr,
	)
	if err != nil {
		return nil, fmt.Errorf("setting broker config: %w", err)
	}

	return &BrokerConfig{
		ID: id, VaultID: vaultID, ServicesJSON: servicesJSON,
		CreatedAt: now, UpdatedAt: now,
	}, nil
}

func (s *SQLStore) GetBrokerConfig(ctx context.Context, vaultID string) (*BrokerConfig, error) {
	row := s.db.QueryRowContext(ctx,
		s.dialect.Rebind("SELECT id, vault_id, services_json, created_at, updated_at FROM broker_configs WHERE vault_id = ?"),
		vaultID,
	)
	return s.scanBrokerConfig(row)
}

// --- Proposals ---

const approvalTokenTTL = 24 * time.Hour

// newPrefixedToken generates a 256-bit cryptographically random token
// with the given prefix followed by 64 hex characters.
func newPrefixedToken(prefix string) string {
	var b [32]byte
	if _, err := io.ReadFull(rand.Reader, b[:]); err != nil {
		panic("crypto/rand: " + err.Error())
	}
	return prefix + hex.EncodeToString(b[:])
}

func newApprovalToken() string { return newPrefixedToken("av_appr_") }

func (s *SQLStore) CreateProposal(ctx context.Context, vaultID, sessionID, servicesJSON, credentialsJSON, message, userMessage string, credentials map[string]EncryptedCredential) (*Proposal, error) {
	now := time.Now().UTC()
	nowStr := s.dialect.FormatTime(now)
	approvalToken := newApprovalToken()
	tokenExpiresAt := now.Add(approvalTokenTTL)
	tokenExpiresAtStr := s.dialect.FormatTime(tokenExpiresAt)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("beginning transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// For Postgres, lock the vault row so concurrent proposal creations
	// are serialized and cannot compute the same next ID.
	if forUpdate := s.dialect.ForUpdateClause(); forUpdate != "" {
		var dummy int
		_ = tx.QueryRowContext(ctx,
			s.dialect.Rebind("SELECT 1 FROM vaults WHERE id = ? "+forUpdate),
			vaultID,
		).Scan(&dummy)
	}

	// Compute next sequential ID for this vault.
	var nextID int
	err = tx.QueryRowContext(ctx,
		s.dialect.Rebind("SELECT COALESCE(MAX(id), 0) + 1 FROM proposals WHERE vault_id = ?"),
		vaultID,
	).Scan(&nextID)
	if err != nil {
		return nil, fmt.Errorf("computing next proposal id: %w", err)
	}

	_, err = tx.ExecContext(ctx,
		s.dialect.Rebind(`INSERT INTO proposals (id, vault_id, session_id, status, services_json, credentials_json, message, user_message, approval_token_hash, approval_token_expires_at, created_at, updated_at)
		 VALUES (?, ?, ?, 'pending', ?, ?, ?, ?, ?, ?, ?, ?)`),
		nextID, vaultID, sessionID, servicesJSON, credentialsJSON, message, userMessage, hashToken(approvalToken), tokenExpiresAtStr, nowStr, nowStr,
	)
	if err != nil {
		return nil, fmt.Errorf("inserting proposal: %w", err)
	}

	// Store agent-provided encrypted credential values.
	for key, enc := range credentials {
		_, err = tx.ExecContext(ctx,
			s.dialect.Rebind(`INSERT INTO proposal_credentials (vault_id, proposal_id, key, ciphertext, nonce)
			 VALUES (?, ?, ?, ?, ?)`),
			vaultID, nextID, key, enc.Ciphertext, enc.Nonce,
		)
		if err != nil {
			return nil, fmt.Errorf("inserting proposal credential %q: %w", key, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("committing proposal creation: %w", err)
	}

	return &Proposal{
		ID: nextID, VaultID: vaultID, SessionID: sessionID,
		Status: "pending", ServicesJSON: servicesJSON, CredentialsJSON: credentialsJSON,
		Message: message, UserMessage: userMessage,
		ApprovalToken: approvalToken, ApprovalTokenExpiresAt: &tokenExpiresAt,
		CreatedAt: now, UpdatedAt: now,
	}, nil
}

func (s *SQLStore) GetProposal(ctx context.Context, vaultID string, id int) (*Proposal, error) {
	row := s.db.QueryRowContext(ctx,
		s.dialect.Rebind(`SELECT `+proposalColumns+` FROM proposals WHERE vault_id = ? AND id = ?`),
		vaultID, id,
	)
	return s.scanProposal(row)
}

func (s *SQLStore) GetProposalByApprovalToken(ctx context.Context, token string) (*Proposal, error) {
	row := s.db.QueryRowContext(ctx,
		s.dialect.Rebind(`SELECT `+proposalColumns+` FROM proposals WHERE approval_token_hash = ?`),
		hashToken(token),
	)
	return s.scanProposal(row)
}

func (s *SQLStore) ListProposals(ctx context.Context, vaultID, status string) ([]Proposal, error) {
	var rows *sql.Rows
	var err error
	if status != "" {
		rows, err = s.db.QueryContext(ctx,
			s.dialect.Rebind(`SELECT `+proposalColumns+` FROM proposals WHERE vault_id = ? AND status = ? ORDER BY id DESC`),
			vaultID, status,
		)
	} else {
		rows, err = s.db.QueryContext(ctx,
			s.dialect.Rebind(`SELECT `+proposalColumns+` FROM proposals WHERE vault_id = ? ORDER BY id DESC`),
			vaultID,
		)
	}
	if err != nil {
		return nil, fmt.Errorf("listing proposals: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var proposals []Proposal
	for rows.Next() {
		cs, err := s.scanProposalRow(rows)
		if err != nil {
			return nil, err
		}
		proposals = append(proposals, *cs)
	}
	return proposals, rows.Err()
}

func (s *SQLStore) UpdateProposalStatus(ctx context.Context, vaultID string, id int, status, reviewNote string) error {
	nowStr := s.now()
	var reviewedAt interface{}
	if status == "applied" || status == "rejected" {
		reviewedAt = nowStr
	}

	res, err := s.db.ExecContext(ctx,
		s.dialect.Rebind(`UPDATE proposals SET status = ?, review_note = ?, reviewed_at = ?, updated_at = ?
		 WHERE vault_id = ? AND id = ?`),
		status, reviewNote, reviewedAt, nowStr, vaultID, id,
	)
	if err != nil {
		return fmt.Errorf("updating proposal status: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *SQLStore) CountPendingProposals(ctx context.Context, vaultID string) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx,
		s.dialect.Rebind("SELECT COUNT(*) FROM proposals WHERE vault_id = ? AND status = 'pending'"),
		vaultID,
	).Scan(&count)
	return count, err
}

func (s *SQLStore) ExpirePendingProposals(ctx context.Context, before time.Time) (int, error) {
	nowStr := s.now()
	res, err := s.db.ExecContext(ctx,
		s.dialect.Rebind(`UPDATE proposals SET status = 'expired', updated_at = ?
		 WHERE status = 'pending' AND created_at < ?`),
		nowStr, s.dialect.FormatTime(before.UTC()),
	)
	if err != nil {
		return 0, fmt.Errorf("expiring proposals: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

func (s *SQLStore) GetProposalCredentials(ctx context.Context, vaultID string, proposalID int) (map[string]EncryptedCredential, error) {
	rows, err := s.db.QueryContext(ctx,
		s.dialect.Rebind("SELECT key, ciphertext, nonce FROM proposal_credentials WHERE vault_id = ? AND proposal_id = ?"),
		vaultID, proposalID,
	)
	if err != nil {
		return nil, fmt.Errorf("getting proposal credentials: %w", err)
	}
	defer func() { _ = rows.Close() }()

	creds := make(map[string]EncryptedCredential)
	for rows.Next() {
		var key string
		var ct, nonce []byte
		if err := rows.Scan(&key, &ct, &nonce); err != nil {
			return nil, fmt.Errorf("scanning proposal credential: %w", err)
		}
		creds[key] = EncryptedCredential{Ciphertext: ct, Nonce: nonce}
	}
	return creds, rows.Err()
}

func (s *SQLStore) ApplyProposal(ctx context.Context, vaultID string, proposalID int, mergedServicesJSON string, credentials map[string]EncryptedCredential, deleteCredentialKeys []string, oauthConfigs []OAuthCredentialConfig) error {
	nowStr := s.now()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// 1. Update broker config with merged services.
	_, err = tx.ExecContext(ctx,
		s.dialect.Rebind(`UPDATE broker_configs SET services_json = ?, updated_at = ? WHERE vault_id = ?`),
		mergedServicesJSON, nowStr, vaultID,
	)
	if err != nil {
		return fmt.Errorf("updating broker config: %w", err)
	}

	// 2. Upsert each static credential.
	for key, enc := range credentials {
		id := newUUID()
		_, err = tx.ExecContext(ctx,
			s.dialect.Rebind(`INSERT INTO credentials (id, vault_id, key, type, ciphertext, nonce, created_at, updated_at)
			 VALUES (?, ?, ?, 'static', ?, ?, ?, ?)
			 ON CONFLICT(vault_id, key) DO UPDATE SET
			   ciphertext = excluded.ciphertext,
			   nonce = excluded.nonce,
			   updated_at = excluded.updated_at`),
			id, vaultID, key, enc.Ciphertext, enc.Nonce, nowStr, nowStr,
		)
		if err != nil {
			return fmt.Errorf("upserting credential %q: %w", key, err)
		}
	}

	// 2b. Upsert each OAuth credential config.
	for _, oc := range oauthConfigs {
		id := newUUID()
		_, err = tx.ExecContext(ctx,
			s.dialect.Rebind(`INSERT INTO credentials (id, vault_id, key, type, ciphertext, nonce, created_at, updated_at)
			 VALUES (?, ?, ?, 'oauth', ?, ?, ?, ?)
			 ON CONFLICT(vault_id, key) DO UPDATE SET
			   type = 'oauth',
			   updated_at = excluded.updated_at`),
			id, vaultID, oc.Key, []byte{}, []byte{}, nowStr, nowStr,
		)
		if err != nil {
			return fmt.Errorf("upserting oauth credential %q: %w", oc.Key, err)
		}

		disablePKCE := s.dialect.BoolVal(oc.DisablePKCE)
		tokenAuthMethod := oc.TokenAuthMethod
		if tokenAuthMethod == "" {
			tokenAuthMethod = "client_secret_post"
		}
		scopeSep := oc.ScopeSeparator
		if scopeSep == "" {
			scopeSep = " "
		}
		_, err = tx.ExecContext(ctx,
			s.dialect.Rebind(`INSERT INTO credential_oauth (vault_id, credential_key, authorization_url, token_url, client_id,
			   client_secret_ct, client_secret_nonce, scopes, scope_separator, disable_pkce, token_auth_method,
			   created_at, updated_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			 ON CONFLICT(vault_id, credential_key) DO UPDATE SET
			   authorization_url = excluded.authorization_url,
			   token_url = excluded.token_url,
			   client_id = excluded.client_id,
			   client_secret_ct = CASE WHEN excluded.token_url = credential_oauth.token_url
			     THEN COALESCE(excluded.client_secret_ct, credential_oauth.client_secret_ct)
			     ELSE excluded.client_secret_ct END,
			   client_secret_nonce = CASE WHEN excluded.token_url = credential_oauth.token_url
			     THEN COALESCE(excluded.client_secret_nonce, credential_oauth.client_secret_nonce)
			     ELSE excluded.client_secret_nonce END,
			   scopes = excluded.scopes,
			   scope_separator = excluded.scope_separator,
			   disable_pkce = excluded.disable_pkce,
			   token_auth_method = excluded.token_auth_method,
			   refresh_token_ct = CASE WHEN excluded.token_url = credential_oauth.token_url
			     THEN credential_oauth.refresh_token_ct ELSE NULL END,
			   refresh_token_nonce = CASE WHEN excluded.token_url = credential_oauth.token_url
			     THEN credential_oauth.refresh_token_nonce ELSE NULL END,
			   token_expires_at = CASE WHEN excluded.token_url = credential_oauth.token_url
			     THEN credential_oauth.token_expires_at ELSE NULL END,
			   connected_at = CASE WHEN excluded.token_url = credential_oauth.token_url
			     THEN credential_oauth.connected_at ELSE NULL END,
			   updated_at = excluded.updated_at`),
			vaultID, oc.Key, nullableString(oc.AuthorizationURL), oc.TokenURL, oc.ClientID,
			oc.ClientSecretCT, oc.ClientSecretNonce, nullableString(oc.Scopes), scopeSep, disablePKCE, tokenAuthMethod,
			nowStr, nowStr,
		)
		if err != nil {
			return fmt.Errorf("upserting credential_oauth %q: %w", oc.Key, err)
		}
	}

	// 3. Delete credentials marked for removal.
	for _, key := range deleteCredentialKeys {
		_, err = tx.ExecContext(ctx,
			s.dialect.Rebind(`DELETE FROM credentials WHERE vault_id = ? AND key = ?`),
			vaultID, key,
		)
		if err != nil {
			return fmt.Errorf("deleting credential %q: %w", key, err)
		}
	}

	// 4. Mark proposal as applied (status guard prevents double-apply race).
	res, err := tx.ExecContext(ctx,
		s.dialect.Rebind(`UPDATE proposals SET status = 'applied', reviewed_at = ?, updated_at = ?
		 WHERE vault_id = ? AND id = ? AND status = 'pending'`),
		nowStr, nowStr, vaultID, proposalID,
	)
	if err != nil {
		return fmt.Errorf("marking proposal applied: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("proposal already processed (not pending)")
	}

	return tx.Commit()
}

// --- helpers ---

// proposalColumns is the column list used by all proposal SELECT queries.
const proposalColumns = `id, vault_id, session_id, status, services_json, credentials_json,
		message, user_message, review_note, reviewed_at,
		approval_token_expires_at, created_at, updated_at`

func (s *SQLStore) scanProposalFields(cs *Proposal, scan func(dest ...interface{}) error) error {
	var reviewedAtRaw interface{}
	var approvalTokenExpiresAt interface{}
	var createdAt, updatedAt interface{}
	if err := scan(&cs.ID, &cs.VaultID, &cs.SessionID, &cs.Status,
		&cs.ServicesJSON, &cs.CredentialsJSON, &cs.Message, &cs.UserMessage, &cs.ReviewNote,
		&reviewedAtRaw, &approvalTokenExpiresAt,
		&createdAt, &updatedAt); err != nil {
		return err
	}
	if t, err := s.dialect.ScanNullableTime(reviewedAtRaw); err == nil && t != nil {
		s := t.UTC().Format(time.DateTime)
		cs.ReviewedAt = &s
	}
	cs.ApprovalTokenExpiresAt, _ = s.dialect.ScanNullableTime(approvalTokenExpiresAt)
	cs.CreatedAt, _ = s.dialect.ScanTime(createdAt)
	cs.UpdatedAt, _ = s.dialect.ScanTime(updatedAt)
	return nil
}

func (s *SQLStore) scanProposal(row *sql.Row) (*Proposal, error) {
	var cs Proposal
	if err := s.scanProposalFields(&cs, row.Scan); err != nil {
		return nil, err
	}
	return &cs, nil
}

func (s *SQLStore) scanProposalRow(rows *sql.Rows) (*Proposal, error) {
	var cs Proposal
	if err := s.scanProposalFields(&cs, rows.Scan); err != nil {
		return nil, fmt.Errorf("scanning proposal: %w", err)
	}
	return &cs, nil
}

func (s *SQLStore) scanVault(row *sql.Row) (*Vault, error) {
	var v Vault
	var createdAt, updatedAt interface{}
	if err := row.Scan(&v.ID, &v.Name, &createdAt, &updatedAt); err != nil {
		return nil, err
	}
	v.CreatedAt, _ = s.dialect.ScanTime(createdAt)
	v.UpdatedAt, _ = s.dialect.ScanTime(updatedAt)
	return &v, nil
}

func (s *SQLStore) scanCredential(row *sql.Row) (*Credential, error) {
	var cred Credential
	var createdAt, updatedAt interface{}
	if err := row.Scan(&cred.ID, &cred.VaultID, &cred.Key, &cred.Type, &cred.Ciphertext, &cred.Nonce, &createdAt, &updatedAt); err != nil {
		return nil, err
	}
	cred.CreatedAt, _ = s.dialect.ScanTime(createdAt)
	cred.UpdatedAt, _ = s.dialect.ScanTime(updatedAt)
	return &cred, nil
}

func (s *SQLStore) scanBrokerConfig(row *sql.Row) (*BrokerConfig, error) {
	var bc BrokerConfig
	var createdAt, updatedAt interface{}
	if err := row.Scan(&bc.ID, &bc.VaultID, &bc.ServicesJSON, &createdAt, &updatedAt); err != nil {
		return nil, err
	}
	bc.CreatedAt, _ = s.dialect.ScanTime(createdAt)
	bc.UpdatedAt, _ = s.dialect.ScanTime(updatedAt)
	return &bc, nil
}

// --- Vault Invites ---

func newUserInviteToken() string { return newPrefixedToken("av_uinv_") }

func (s *SQLStore) CreateUserInvite(ctx context.Context, email, createdBy, role string, expiresAt time.Time, vaults []UserInviteVault) (*UserInvite, error) {
	now := time.Now().UTC()
	token := newUserInviteToken()
	nowStr := s.dialect.FormatTime(now)
	expiresStr := s.dialect.FormatTime(expiresAt.UTC())
	if role == "" {
		role = "member"
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	inviteID, err := s.dialect.InsertReturningID(ctx, tx,
		`INSERT INTO user_invites (token_hash, email, role, created_by, created_at, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		hashToken(token), email, role, createdBy, nowStr, expiresStr,
	)
	if err != nil {
		return nil, fmt.Errorf("inserting user invite: %w", err)
	}

	for _, v := range vaults {
		_, err := tx.ExecContext(ctx,
			s.dialect.Rebind(`INSERT INTO user_invite_vaults (user_invite_id, vault_id, vault_role)
			 VALUES (?, ?, ?)`),
			inviteID, v.VaultID, v.VaultRole,
		)
		if err != nil {
			return nil, fmt.Errorf("inserting user invite vault: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit: %w", err)
	}

	return &UserInvite{
		ID:        int(inviteID),
		Token:     token,
		Email:     email,
		Role:      role,
		Status:    "pending",
		CreatedBy: createdBy,
		CreatedAt: now,
		ExpiresAt: expiresAt.UTC(),
		Vaults:    vaults,
	}, nil
}

func (s *SQLStore) GetUserInviteByToken(ctx context.Context, token string) (*UserInvite, error) {
	row := s.db.QueryRowContext(ctx,
		s.dialect.Rebind(`SELECT id, email, role, status, created_by, created_at, expires_at, accepted_at
		 FROM user_invites WHERE token_hash = ?`), hashToken(token),
	)
	inv, err := s.scanUserInvite(row)
	if err != nil {
		return nil, err
	}
	vaults, err := s.loadUserInviteVaults(ctx, inv.ID)
	if err != nil {
		return nil, err
	}
	inv.Vaults = vaults
	return inv, nil
}

func (s *SQLStore) GetPendingUserInviteByEmail(ctx context.Context, email string) (*UserInvite, error) {
	nowStr := s.now()
	row := s.db.QueryRowContext(ctx,
		s.dialect.Rebind(`SELECT id, email, role, status, created_by, created_at, expires_at, accepted_at
		 FROM user_invites WHERE email = ? AND status = 'pending' AND expires_at > ?
		 ORDER BY created_at DESC LIMIT 1`), email, nowStr,
	)
	inv, err := s.scanUserInvite(row)
	if err != nil {
		return nil, err
	}
	vaults, err := s.loadUserInviteVaults(ctx, inv.ID)
	if err != nil {
		return nil, err
	}
	inv.Vaults = vaults
	return inv, nil
}

func (s *SQLStore) ListUserInvites(ctx context.Context, status string) ([]UserInvite, error) {
	var rows *sql.Rows
	var err error
	if status != "" {
		rows, err = s.db.QueryContext(ctx,
			s.dialect.Rebind(`SELECT id, email, role, status, created_by, created_at, expires_at, accepted_at
			 FROM user_invites WHERE status = ? ORDER BY created_at DESC`), status,
		)
	} else {
		rows, err = s.db.QueryContext(ctx,
			s.dialect.Rebind(`SELECT id, email, role, status, created_by, created_at, expires_at, accepted_at
			 FROM user_invites ORDER BY created_at DESC`),
		)
	}
	if err != nil {
		return nil, fmt.Errorf("listing user invites: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var invites []UserInvite
	for rows.Next() {
		inv, err := s.scanUserInviteRow(rows)
		if err != nil {
			return nil, err
		}
		invites = append(invites, *inv)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	if err := s.loadUserInviteVaultsBatch(ctx, invites); err != nil {
		return nil, err
	}
	return invites, nil
}

func (s *SQLStore) ListUserInvitesByVault(ctx context.Context, vaultID, status string) ([]UserInvite, error) {
	query := `SELECT ui.id, ui.email, ui.role, ui.status, ui.created_by, ui.created_at, ui.expires_at, ui.accepted_at
		 FROM user_invites ui
		 JOIN user_invite_vaults uiv ON ui.id = uiv.user_invite_id
		 WHERE uiv.vault_id = ?`
	args := []any{vaultID}
	if status != "" {
		query += ` AND ui.status = ?`
		args = append(args, status)
	}
	query += ` ORDER BY ui.created_at DESC`

	rows, err := s.db.QueryContext(ctx, s.dialect.Rebind(query), args...)
	if err != nil {
		return nil, fmt.Errorf("listing user invites by vault: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var invites []UserInvite
	for rows.Next() {
		inv, err := s.scanUserInviteRow(rows)
		if err != nil {
			return nil, err
		}
		invites = append(invites, *inv)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	if err := s.loadUserInviteVaultsBatch(ctx, invites); err != nil {
		return nil, err
	}
	return invites, nil
}

func (s *SQLStore) AcceptUserInvite(ctx context.Context, token string) error {
	nowStr := s.now()

	res, err := s.db.ExecContext(ctx,
		s.dialect.Rebind(`UPDATE user_invites SET status = 'accepted', accepted_at = ?
		 WHERE token_hash = ? AND status = 'pending' AND expires_at > ?`),
		nowStr, hashToken(token), nowStr,
	)
	if err != nil {
		return fmt.Errorf("accepting user invite: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *SQLStore) RevokeUserInvite(ctx context.Context, token string) error {
	res, err := s.db.ExecContext(ctx,
		s.dialect.Rebind(`UPDATE user_invites SET status = 'revoked'
		 WHERE token_hash = ? AND status = 'pending'`),
		hashToken(token),
	)
	if err != nil {
		return fmt.Errorf("revoking user invite: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *SQLStore) UpdateUserInviteVaults(ctx context.Context, token string, vaults []UserInviteVault) error {
	// Look up invite ID by token hash
	var inviteID int
	err := s.db.QueryRowContext(ctx,
		s.dialect.Rebind(`SELECT id FROM user_invites WHERE token_hash = ? AND status = 'pending'`),
		hashToken(token),
	).Scan(&inviteID)
	if err != nil {
		return fmt.Errorf("finding user invite: %w", err)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	_, err = tx.ExecContext(ctx, s.dialect.Rebind(`DELETE FROM user_invite_vaults WHERE user_invite_id = ?`), inviteID)
	if err != nil {
		return fmt.Errorf("clearing user invite vaults: %w", err)
	}

	for _, v := range vaults {
		_, err := tx.ExecContext(ctx,
			s.dialect.Rebind(`INSERT INTO user_invite_vaults (user_invite_id, vault_id, vault_role) VALUES (?, ?, ?)`),
			inviteID, v.VaultID, v.VaultRole,
		)
		if err != nil {
			return fmt.Errorf("inserting user invite vault: %w", err)
		}
	}

	return tx.Commit()
}

func (s *SQLStore) CountPendingUserInvites(ctx context.Context) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx,
		s.dialect.Rebind("SELECT COUNT(*) FROM user_invites WHERE status = 'pending'"),
	).Scan(&count)
	return count, err
}

// loadUserInviteVaults fetches the vault pre-assignments for a user invite.
func (s *SQLStore) loadUserInviteVaults(ctx context.Context, inviteID int) ([]UserInviteVault, error) {
	rows, err := s.db.QueryContext(ctx,
		s.dialect.Rebind(`SELECT uiv.vault_id, v.name, uiv.vault_role
		 FROM user_invite_vaults uiv
		 JOIN vaults v ON v.id = uiv.vault_id
		 WHERE uiv.user_invite_id = ?`), inviteID,
	)
	if err != nil {
		return nil, fmt.Errorf("loading user invite vaults: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var vaults []UserInviteVault
	for rows.Next() {
		var v UserInviteVault
		if err := rows.Scan(&v.VaultID, &v.VaultName, &v.VaultRole); err != nil {
			return nil, err
		}
		vaults = append(vaults, v)
	}
	return vaults, rows.Err()
}

func (s *SQLStore) loadUserInviteVaultsBatch(ctx context.Context, invites []UserInvite) error {
	if len(invites) == 0 {
		return nil
	}

	ids := make([]any, len(invites))
	for i, inv := range invites {
		ids[i] = inv.ID
	}

	query := "SELECT uiv.user_invite_id, uiv.vault_id, v.name, uiv.vault_role FROM user_invite_vaults uiv JOIN vaults v ON v.id = uiv.vault_id WHERE uiv.user_invite_id IN (" + strings.Repeat("?,", len(ids)-1) + "?)" //nolint:gosec // only '?' placeholders
	rows, err := s.db.QueryContext(ctx, s.dialect.Rebind(query), ids...)
	if err != nil {
		return fmt.Errorf("loading user invite vaults batch: %w", err)
	}
	defer func() { _ = rows.Close() }()

	byID := make(map[int][]UserInviteVault, len(invites))
	for rows.Next() {
		var inviteID int
		var v UserInviteVault
		if err := rows.Scan(&inviteID, &v.VaultID, &v.VaultName, &v.VaultRole); err != nil {
			return err
		}
		byID[inviteID] = append(byID[inviteID], v)
	}
	if err := rows.Err(); err != nil {
		return err
	}

	for i := range invites {
		invites[i].Vaults = byID[invites[i].ID]
	}
	return nil
}

func (s *SQLStore) scanUserInvite(row *sql.Row) (*UserInvite, error) {
	var inv UserInvite
	var createdAt, expiresAt interface{}
	var acceptedAt interface{}

	if err := row.Scan(&inv.ID, &inv.Email, &inv.Role, &inv.Status,
		&inv.CreatedBy, &createdAt, &expiresAt, &acceptedAt); err != nil {
		return nil, err
	}

	inv.CreatedAt, _ = s.dialect.ScanTime(createdAt)
	inv.ExpiresAt, _ = s.dialect.ScanTime(expiresAt)
	inv.AcceptedAt, _ = s.dialect.ScanNullableTime(acceptedAt)
	return &inv, nil
}

func (s *SQLStore) scanUserInviteRow(rows *sql.Rows) (*UserInvite, error) {
	var inv UserInvite
	var createdAt, expiresAt interface{}
	var acceptedAt interface{}

	if err := rows.Scan(&inv.ID, &inv.Email, &inv.Role, &inv.Status,
		&inv.CreatedBy, &createdAt, &expiresAt, &acceptedAt); err != nil {
		return nil, err
	}

	inv.CreatedAt, _ = s.dialect.ScanTime(createdAt)
	inv.ExpiresAt, _ = s.dialect.ScanTime(expiresAt)
	inv.AcceptedAt, _ = s.dialect.ScanNullableTime(acceptedAt)
	return &inv, nil
}

// --- Email Verification ---

func (s *SQLStore) CreateEmailVerification(ctx context.Context, email, code string, expiresAt time.Time) (*EmailVerification, error) {
	now := time.Now().UTC()
	id, err := s.dialect.InsertReturningID(ctx, s.db,
		`INSERT INTO email_verifications (email, code_hash, created_at, expires_at)
		 VALUES (?, ?, ?, ?)`,
		email, hashToken(code), s.dialect.FormatTime(now), s.dialect.FormatTime(expiresAt.UTC()),
	)
	if err != nil {
		return nil, fmt.Errorf("creating email verification: %w", err)
	}

	return &EmailVerification{
		ID:        int(id),
		Email:     email,
		Code:      code,
		Status:    "pending",
		CreatedAt: now,
		ExpiresAt: expiresAt.UTC(),
	}, nil
}

func (s *SQLStore) GetPendingEmailVerification(ctx context.Context, email, code string) (*EmailVerification, error) {
	nowStr := s.now()
	var ev EmailVerification
	var createdAt, expiresAt interface{}
	err := s.db.QueryRowContext(ctx,
		s.dialect.Rebind(`SELECT id, email, status, created_at, expires_at
		 FROM email_verifications
		 WHERE email = ? AND code_hash = ? AND status = 'pending' AND expires_at > ?
		 ORDER BY created_at DESC LIMIT 1`), email, hashToken(code), nowStr,
	).Scan(&ev.ID, &ev.Email, &ev.Status, &createdAt, &expiresAt)
	if err != nil {
		return nil, err
	}
	ev.CreatedAt, _ = s.dialect.ScanTime(createdAt)
	ev.ExpiresAt, _ = s.dialect.ScanTime(expiresAt)
	return &ev, nil
}

func (s *SQLStore) MarkEmailVerificationUsed(ctx context.Context, id int) error {
	res, err := s.db.ExecContext(ctx,
		s.dialect.Rebind("UPDATE email_verifications SET status = 'verified' WHERE id = ? AND status = 'pending'"),
		id,
	)
	if err != nil {
		return fmt.Errorf("marking email verification used: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *SQLStore) CountPendingEmailVerifications(ctx context.Context, email string) (int, error) {
	nowStr := s.now()
	var count int
	err := s.db.QueryRowContext(ctx,
		s.dialect.Rebind("SELECT COUNT(*) FROM email_verifications WHERE email = ? AND status = 'pending' AND expires_at > ?"),
		email, nowStr,
	).Scan(&count)
	return count, err
}

// --- Password Resets ---

func (s *SQLStore) CreatePasswordReset(ctx context.Context, email, code string, expiresAt time.Time) (*PasswordReset, error) {
	now := time.Now().UTC()
	id, err := s.dialect.InsertReturningID(ctx, s.db,
		`INSERT INTO password_resets (email, code_hash, created_at, expires_at)
		 VALUES (?, ?, ?, ?)`,
		email, hashToken(code), s.dialect.FormatTime(now), s.dialect.FormatTime(expiresAt.UTC()),
	)
	if err != nil {
		return nil, fmt.Errorf("creating password reset: %w", err)
	}

	return &PasswordReset{
		ID:        int(id),
		Email:     email,
		Code:      code,
		Status:    "pending",
		CreatedAt: now,
		ExpiresAt: expiresAt.UTC(),
	}, nil
}

func (s *SQLStore) GetPendingPasswordReset(ctx context.Context, email, code string) (*PasswordReset, error) {
	nowStr := s.now()
	var pr PasswordReset
	var createdAt, expiresAt interface{}
	err := s.db.QueryRowContext(ctx,
		s.dialect.Rebind(`SELECT id, email, status, created_at, expires_at
		 FROM password_resets
		 WHERE email = ? AND code_hash = ? AND status = 'pending' AND expires_at > ?
		 ORDER BY created_at DESC LIMIT 1`), email, hashToken(code), nowStr,
	).Scan(&pr.ID, &pr.Email, &pr.Status, &createdAt, &expiresAt)
	if err != nil {
		return nil, err
	}
	pr.CreatedAt, _ = s.dialect.ScanTime(createdAt)
	pr.ExpiresAt, _ = s.dialect.ScanTime(expiresAt)
	return &pr, nil
}

func (s *SQLStore) MarkPasswordResetUsed(ctx context.Context, id int) error {
	res, err := s.db.ExecContext(ctx,
		s.dialect.Rebind("UPDATE password_resets SET status = 'used' WHERE id = ? AND status = 'pending'"),
		id,
	)
	if err != nil {
		return fmt.Errorf("marking password reset used: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *SQLStore) CountPendingPasswordResets(ctx context.Context, email string) (int, error) {
	nowStr := s.now()
	var count int
	err := s.db.QueryRowContext(ctx,
		s.dialect.Rebind("SELECT COUNT(*) FROM password_resets WHERE email = ? AND status = 'pending' AND expires_at > ?"),
		email, nowStr,
	).Scan(&count)
	return count, err
}

func (s *SQLStore) ExpirePendingPasswordResets(ctx context.Context, before time.Time) (int, error) {
	res, err := s.db.ExecContext(ctx,
		s.dialect.Rebind("UPDATE password_resets SET status = 'expired' WHERE status = 'pending' AND expires_at < ?"),
		s.dialect.FormatTime(before.UTC()),
	)
	if err != nil {
		return 0, fmt.Errorf("expiring password resets: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// --- Agents ---

func (s *SQLStore) CreateAgent(ctx context.Context, name, createdBy, role string) (*Agent, error) {
	id := newUUID()
	now := time.Now().UTC()
	nowStr := s.dialect.FormatTime(now)

	_, err := s.db.ExecContext(ctx,
		s.dialect.Rebind(`INSERT INTO agents (id, name, role, status, created_by, created_at, updated_at)
		 VALUES (?, ?, ?, 'active', ?, ?, ?)`),
		id, name, role, createdBy, nowStr, nowStr,
	)
	if err != nil {
		return nil, fmt.Errorf("creating agent: %w", err)
	}

	return &Agent{
		ID:        id,
		Name:      name,
		Role:      role,
		Status:    "active",
		CreatedBy: createdBy,
		CreatedAt: now,
		UpdatedAt: now,
	}, nil
}

func (s *SQLStore) CreateAgentWithGrantsAndToken(ctx context.Context, name, createdBy, role string, vaultGrants []AgentVaultGrantSpec, expiresAt *time.Time) (*Agent, *Session, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("beginning transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	agentID := newUUID()
	now := time.Now().UTC()
	nowStr := s.dialect.FormatTime(now)

	_, err = tx.ExecContext(ctx,
		s.dialect.Rebind(`INSERT INTO agents (id, name, role, status, created_by, created_at, updated_at)
		 VALUES (?, ?, ?, 'active', ?, ?, ?)`),
		agentID, name, role, createdBy, nowStr, nowStr,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("creating agent: %w", err)
	}

	grantNow := s.now()
	for _, vg := range vaultGrants {
		_, err = tx.ExecContext(ctx,
			s.dialect.Rebind(`INSERT INTO vault_grants (actor_id, actor_type, vault_id, role, created_at) VALUES (?, 'agent', ?, ?, ?)
			 ON CONFLICT(actor_id, vault_id) DO UPDATE SET role = excluded.role`),
			agentID, vg.VaultID, vg.Role, grantNow,
		)
		if err != nil {
			return nil, nil, fmt.Errorf("granting vault role: %w", err)
		}
	}

	rawToken := newAgentToken()
	tokenHash := hashSessionToken(rawToken)
	expiresAtVal := s.dialect.FormatNullableTime(utcTimePtr(expiresAt))
	_, err = tx.ExecContext(ctx,
		s.dialect.Rebind("INSERT INTO sessions (id, agent_id, expires_at, created_at) VALUES (?, ?, ?, ?)"),
		tokenHash, agentID, expiresAtVal, nowStr,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("creating agent token: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, nil, fmt.Errorf("committing transaction: %w", err)
	}

	ag := &Agent{
		ID:        agentID,
		Name:      name,
		Role:      role,
		Status:    "active",
		CreatedBy: createdBy,
		CreatedAt: now,
		UpdatedAt: now,
	}
	sess := &Session{ID: rawToken, AgentID: agentID, ExpiresAt: utcTimePtr(expiresAt), CreatedAt: now}
	return ag, sess, nil
}

func (s *SQLStore) GetAgentByID(ctx context.Context, id string) (*Agent, error) {
	row := s.db.QueryRowContext(ctx,
		s.dialect.Rebind(`SELECT id, name, role, status, created_by, created_at, updated_at, revoked_at
		 FROM agents WHERE id = ?`), id,
	)
	ag, err := s.scanAgent(row)
	if err != nil {
		return nil, err
	}
	ag.Vaults, err = s.ListActorGrants(ctx, ag.ID)
	if err != nil {
		return nil, err
	}
	return ag, nil
}

func (s *SQLStore) GetAgentByName(ctx context.Context, name string) (*Agent, error) {
	row := s.db.QueryRowContext(ctx,
		s.dialect.Rebind(`SELECT id, name, role, status, created_by, created_at, updated_at, revoked_at
		 FROM agents WHERE name = ?`), name,
	)
	ag, err := s.scanAgent(row)
	if err != nil {
		return nil, err
	}
	ag.Vaults, err = s.ListActorGrants(ctx, ag.ID)
	if err != nil {
		return nil, err
	}
	return ag, nil
}

// ListAgents returns agents that have access to a specific vault via vault_grants.
func (s *SQLStore) ListAgents(ctx context.Context, vaultID string) ([]Agent, error) {
	if vaultID == "" {
		return nil, fmt.Errorf("vaultID is required; use ListAllAgents for cross-vault listing")
	}
	rows, err := s.db.QueryContext(ctx,
		s.dialect.Rebind(`SELECT a.id, a.name, a.role, a.status, a.created_by, a.created_at, a.updated_at, a.revoked_at
		 FROM agents a
		 JOIN vault_grants vg ON vg.actor_id = a.id AND vg.actor_type = 'agent'
		 WHERE vg.vault_id = ? ORDER BY a.name`), vaultID,
	)
	if err != nil {
		return nil, fmt.Errorf("listing agents: %w", err)
	}

	var agents []Agent
	for rows.Next() {
		ag, err := s.scanAgentRow(rows)
		if err != nil {
			_ = rows.Close()
			return nil, err
		}
		agents = append(agents, *ag)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	_ = rows.Close()

	if err := s.batchLoadAgentVaultGrants(ctx, agents); err != nil {
		return nil, err
	}
	return agents, nil
}

// ListAllAgents returns all agents with their vault grants.
func (s *SQLStore) ListAllAgents(ctx context.Context) ([]Agent, error) {
	rows, err := s.db.QueryContext(ctx,
		s.dialect.Rebind(`SELECT id, name, role, status, created_by, created_at, updated_at, revoked_at
		 FROM agents ORDER BY name`),
	)
	if err != nil {
		return nil, fmt.Errorf("listing all agents: %w", err)
	}

	var agents []Agent
	for rows.Next() {
		ag, err := s.scanAgentRow(rows)
		if err != nil {
			_ = rows.Close()
			return nil, err
		}
		agents = append(agents, *ag)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	_ = rows.Close()

	if err := s.batchLoadAgentVaultGrants(ctx, agents); err != nil {
		return nil, err
	}
	return agents, nil
}

func (s *SQLStore) RevokeAgent(ctx context.Context, id string) error {
	nowStr := s.now()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	res, err := tx.ExecContext(ctx,
		s.dialect.Rebind(`UPDATE agents SET status = 'revoked', revoked_at = ?, updated_at = ?
		 WHERE id = ? AND status = 'active'`),
		nowStr, nowStr, id,
	)
	if err != nil {
		return fmt.Errorf("revoking agent: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}

	// Cascade: delete tokens authenticating AS this agent and scoped
	// tokens this agent minted on behalf of others. Without the second
	// branch, a revoked agent's orphan token keeps proxying upstream APIs
	// until its TTL expires (up to scopedSessionMaxTTL).
	_, err = tx.ExecContext(ctx,
		s.dialect.Rebind(`DELETE FROM sessions
		 WHERE agent_id = ?
		    OR (created_by_actor_id = ? AND created_by_actor_type = 'agent')`),
		id, id,
	)
	if err != nil {
		return fmt.Errorf("deleting agent tokens: %w", err)
	}

	return tx.Commit()
}

func (s *SQLStore) DeleteAgent(ctx context.Context, id string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx,
		s.dialect.Rebind(`DELETE FROM sessions
		 WHERE agent_id = ?
		    OR (created_by_actor_id = ? AND created_by_actor_type = 'agent')`),
		id, id); err != nil {
		return fmt.Errorf("deleting agent sessions: %w", err)
	}

	if _, err := tx.ExecContext(ctx,
		s.dialect.Rebind(`DELETE FROM vault_grants WHERE actor_id = ? AND actor_type = 'agent'`), id); err != nil {
		return fmt.Errorf("deleting agent vault grants: %w", err)
	}

	res, err := tx.ExecContext(ctx, s.dialect.Rebind(`DELETE FROM agents WHERE id = ?`), id)
	if err != nil {
		return fmt.Errorf("deleting agent: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}

	return tx.Commit()
}

func (s *SQLStore) RenameAgent(ctx context.Context, id string, newName string) error {
	nowStr := s.now()

	res, err := s.db.ExecContext(ctx,
		s.dialect.Rebind(`UPDATE agents SET name = ?, updated_at = ? WHERE id = ?`),
		newName, nowStr, id,
	)
	if err != nil {
		return fmt.Errorf("renaming agent: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *SQLStore) CountAgentTokens(ctx context.Context, agentID string) (int, error) {
	var count int
	nowStr := s.now()
	err := s.db.QueryRowContext(ctx,
		s.dialect.Rebind("SELECT COUNT(*) FROM sessions WHERE agent_id = ? AND (expires_at IS NULL OR expires_at > ?)"),
		agentID, nowStr,
	).Scan(&count)
	return count, err
}

func (s *SQLStore) GetLatestAgentTokenExpiry(ctx context.Context, agentID string) (*time.Time, error) {
	// Check for non-expiring tokens first — they represent "never expires".
	var hasNonExpiring int
	if err := s.db.QueryRowContext(ctx,
		s.dialect.Rebind("SELECT COUNT(*) FROM sessions WHERE agent_id = ? AND expires_at IS NULL"),
		agentID,
	).Scan(&hasNonExpiring); err != nil {
		return nil, err
	}
	if hasNonExpiring > 0 {
		return nil, nil // nil = never expires
	}

	var expiresAtVal interface{}
	err := s.db.QueryRowContext(ctx,
		s.dialect.Rebind("SELECT MAX(expires_at) FROM sessions WHERE agent_id = ? AND expires_at > ?"),
		agentID, s.now(),
	).Scan(&expiresAtVal)
	if err != nil {
		return nil, err
	}
	result, _ := s.dialect.ScanNullableTime(expiresAtVal)
	if result != nil {
		t := result.UTC()
		return &t, nil
	}
	return nil, nil
}

func (s *SQLStore) DeleteAgentTokens(ctx context.Context, agentID string) error {
	_, err := s.db.ExecContext(ctx, s.dialect.Rebind("DELETE FROM sessions WHERE agent_id = ?"), agentID)
	if err != nil {
		return fmt.Errorf("deleting agent tokens: %w", err)
	}
	return nil
}

func (s *SQLStore) RotateAgentToken(ctx context.Context, agentID string, expiresAt *time.Time) (*Session, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("beginning transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, s.dialect.Rebind("DELETE FROM sessions WHERE agent_id = ?"), agentID); err != nil {
		return nil, fmt.Errorf("deleting agent tokens: %w", err)
	}

	nowStr := s.now()
	if _, err := tx.ExecContext(ctx,
		s.dialect.Rebind(`UPDATE agents SET status = 'active', revoked_at = NULL, updated_at = ? WHERE id = ?`),
		nowStr, agentID,
	); err != nil {
		return nil, fmt.Errorf("reactivating agent: %w", err)
	}

	rawToken := newAgentToken()
	tokenHash := hashSessionToken(rawToken)
	now := time.Now().UTC()

	expiresAtVal := s.dialect.FormatNullableTime(utcTimePtr(expiresAt))

	if _, err := tx.ExecContext(ctx,
		s.dialect.Rebind("INSERT INTO sessions (id, agent_id, expires_at, created_at) VALUES (?, ?, ?, ?)"),
		tokenHash, agentID, expiresAtVal, s.dialect.FormatTime(now),
	); err != nil {
		return nil, fmt.Errorf("creating agent token: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("committing transaction: %w", err)
	}

	return &Session{ID: rawToken, AgentID: agentID, ExpiresAt: utcTimePtr(expiresAt), CreatedAt: now}, nil
}

func (s *SQLStore) CreateAgentToken(ctx context.Context, agentID string, expiresAt *time.Time) (*Session, error) {
	rawToken := newAgentToken()
	tokenHash := hashSessionToken(rawToken)
	now := time.Now().UTC()

	expiresAtVal := s.dialect.FormatNullableTime(utcTimePtr(expiresAt))

	_, err := s.db.ExecContext(ctx,
		s.dialect.Rebind("INSERT INTO sessions (id, agent_id, expires_at, created_at) VALUES (?, ?, ?, ?)"),
		tokenHash, agentID, expiresAtVal, s.dialect.FormatTime(now),
	)
	if err != nil {
		return nil, fmt.Errorf("creating agent token: %w", err)
	}

	return &Session{ID: rawToken, AgentID: agentID, ExpiresAt: utcTimePtr(expiresAt), CreatedAt: now}, nil
}

// scanAgent scans a single agent row from a *sql.Row.
// Expected column order: id, name, status, created_by, created_at, updated_at, revoked_at
func (s *SQLStore) scanAgent(row *sql.Row) (*Agent, error) {
	var ag Agent
	var createdAt, updatedAt interface{}
	var revokedAt interface{}

	if err := row.Scan(&ag.ID, &ag.Name, &ag.Role,
		&ag.Status, &ag.CreatedBy, &createdAt, &updatedAt, &revokedAt); err != nil {
		return nil, err
	}

	ag.CreatedAt, _ = s.dialect.ScanTime(createdAt)
	ag.UpdatedAt, _ = s.dialect.ScanTime(updatedAt)
	ag.RevokedAt, _ = s.dialect.ScanNullableTime(revokedAt)
	return &ag, nil
}

func (s *SQLStore) scanAgentRow(rows *sql.Rows) (*Agent, error) {
	var ag Agent
	var createdAt, updatedAt interface{}
	var revokedAt interface{}

	if err := rows.Scan(&ag.ID, &ag.Name, &ag.Role,
		&ag.Status, &ag.CreatedBy, &createdAt, &updatedAt, &revokedAt); err != nil {
		return nil, err
	}

	ag.CreatedAt, _ = s.dialect.ScanTime(createdAt)
	ag.UpdatedAt, _ = s.dialect.ScanTime(updatedAt)
	ag.RevokedAt, _ = s.dialect.ScanNullableTime(revokedAt)
	return &ag, nil
}

// batchLoadAgentVaultGrants loads vault grants for all agents in a single query.
func (s *SQLStore) batchLoadAgentVaultGrants(ctx context.Context, agents []Agent) error {
	if len(agents) == 0 {
		return nil
	}

	// Build agent ID list and index map.
	idxMap := make(map[string][]int, len(agents))
	args := make([]interface{}, len(agents))
	placeholders := make([]string, len(agents))
	for i, ag := range agents {
		idxMap[ag.ID] = append(idxMap[ag.ID], i)
		args[i] = ag.ID
		placeholders[i] = "?"
	}

	query := `SELECT vg.actor_id, vg.actor_type, vg.vault_id, v.name, vg.role, vg.created_at
		 FROM vault_grants vg
		 JOIN vaults v ON v.id = vg.vault_id
		 WHERE vg.actor_id IN (` + strings.Join(placeholders, ",") + `)` // #nosec G202 -- placeholders are static "?" strings, not user input

	rows, err := s.db.QueryContext(ctx, s.dialect.Rebind(query), args...)
	if err != nil {
		return fmt.Errorf("batch loading agent vault grants: %w", err)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var g VaultGrant
		var createdAt interface{}
		if err := rows.Scan(&g.ActorID, &g.ActorType, &g.VaultID, &g.VaultName, &g.Role, &createdAt); err != nil {
			return err
		}
		g.CreatedAt, _ = s.dialect.ScanTime(createdAt)
		for _, idx := range idxMap[g.ActorID] {
			agents[idx].Vaults = append(agents[idx].Vaults, g)
		}
	}
	return rows.Err()
}

func (s *SQLStore) UpdateAgentRole(ctx context.Context, agentID, role string) error {
	nowStr := s.now()
	res, err := s.db.ExecContext(ctx,
		s.dialect.Rebind("UPDATE agents SET role = ?, updated_at = ? WHERE id = ?"),
		role, nowStr, agentID,
	)
	if err != nil {
		return fmt.Errorf("updating agent role: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *SQLStore) CountAllOwners(ctx context.Context) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx,
		s.dialect.Rebind(`SELECT (SELECT COUNT(*) FROM users WHERE role = 'owner' AND is_active = ?) +
		        (SELECT COUNT(*) FROM agents WHERE role = 'owner' AND status = 'active')`),
		s.dialect.BoolVal(true),
	).Scan(&count)
	return count, err
}

// newUUID generates a v4 UUID using crypto/rand.
func newUUID() string {
	var uuid [16]byte
	if _, err := io.ReadFull(rand.Reader, uuid[:]); err != nil {
		panic("crypto/rand: " + err.Error())
	}
	uuid[6] = (uuid[6] & 0x0f) | 0x40 // version 4
	uuid[8] = (uuid[8] & 0x3f) | 0x80 // variant 2
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:16])
}

func newSessionToken() string { return newPrefixedToken("av_sess_") }
func newAgentToken() string   { return newPrefixedToken("av_agt_") }

// --- CA State ---

func (s *SQLStore) GetCAState(ctx context.Context) (*CAState, error) {
	var cs CAState
	var createdAt, updatedAt interface{}
	err := s.db.QueryRowContext(ctx,
		s.dialect.Rebind(`SELECT root_cert, root_key_ct, root_key_nonce, source, created_at, updated_at
		 FROM ca_state WHERE id = 1`),
	).Scan(&cs.RootCert, &cs.RootKeyCT, &cs.RootKeyNonce, &cs.Source, &createdAt, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	cs.CreatedAt, _ = s.dialect.ScanTime(createdAt)
	cs.UpdatedAt, _ = s.dialect.ScanTime(updatedAt)
	return &cs, nil
}

func (s *SQLStore) SetCAState(ctx context.Context, state *CAState) error {
	nowStr := s.now()
	_, err := s.db.ExecContext(ctx,
		s.dialect.Rebind(`INSERT INTO ca_state (id, root_cert, root_key_ct, root_key_nonce, source, created_at, updated_at)
		 VALUES (1, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(id) DO NOTHING`),
		state.RootCert, state.RootKeyCT, state.RootKeyNonce, state.Source, nowStr, nowStr,
	)
	if err != nil {
		return fmt.Errorf("setting CA state: %w", err)
	}
	return nil
}

// --- Request Logs ---

// InsertRequestLogs persists a batch of request logs inside a single
// transaction. Credential key names are stored as a JSON array.
// Callers are expected to pre-filter out anything secret; the store does
// not validate fields beyond the column types.
func (s *SQLStore) InsertRequestLogs(ctx context.Context, rows []RequestLog) error {
	if len(rows) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("beginning request_logs tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.PrepareContext(ctx, s.dialect.Rebind(`
		INSERT INTO request_logs
		  (vault_id, actor_type, actor_id, ingress, method, host, path,
		   matched_service, credential_keys, status, latency_ms, error_code,
		   auth_scheme, auth_header, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`))
	if err != nil {
		return fmt.Errorf("preparing request_logs insert: %w", err)
	}
	defer func() { _ = stmt.Close() }()

	for _, r := range rows {
		keys := r.CredentialKeys
		if keys == nil {
			keys = []string{}
		}
		keysJSON, err := json.Marshal(keys)
		if err != nil {
			return fmt.Errorf("marshaling credential_keys: %w", err)
		}
		createdAt := r.CreatedAt
		if createdAt.IsZero() {
			createdAt = time.Now()
		}
		if _, err := stmt.ExecContext(ctx,
			r.VaultID, r.ActorType, r.ActorID, r.Ingress, r.Method, r.Host, r.Path,
			r.MatchedService, string(keysJSON), r.Status, r.LatencyMs, r.ErrorCode,
			r.AuthScheme, r.AuthHeader,
			s.dialect.FormatTime(createdAt.UTC()),
		); err != nil {
			return fmt.Errorf("inserting request_log: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("committing request_logs: %w", err)
	}
	return nil
}

// ListRequestLogs returns logs matching opts, newest first. Pagination is
// cursor-based via opts.Before (historical) or opts.After (tailing).
// opts.Limit is used as-is; callers must cap it.
func (s *SQLStore) ListRequestLogs(ctx context.Context, opts ListRequestLogsOpts) ([]RequestLog, error) {
	var (
		where []string
		args  []any
	)
	if opts.VaultID != nil {
		where = append(where, "vault_id = ?")
		args = append(args, *opts.VaultID)
	}
	if opts.Ingress != "" {
		where = append(where, "ingress = ?")
		args = append(args, opts.Ingress)
	}
	if opts.MatchedService != "" {
		where = append(where, "matched_service = ?")
		args = append(args, opts.MatchedService)
	}
	switch opts.StatusBucket {
	case "2xx":
		where = append(where, "status >= 200 AND status < 300")
	case "3xx":
		where = append(where, "status >= 300 AND status < 400")
	case "4xx":
		where = append(where, "status >= 400 AND status < 500")
	case "5xx":
		where = append(where, "status >= 500 AND status < 600")
	case "err":
		where = append(where, "(error_code != '' OR status >= 400)")
	}
	if opts.Before > 0 {
		where = append(where, "id < ?")
		args = append(args, opts.Before)
	}
	if opts.After > 0 {
		where = append(where, "id > ?")
		args = append(args, opts.After)
	}

	limit := opts.Limit
	if limit <= 0 {
		limit = 50
	}

	query := `SELECT id, vault_id, actor_type, actor_id, ingress, method, host, path,
	                 matched_service, credential_keys, status, latency_ms, error_code, created_at
	          FROM request_logs`
	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ") // #nosec G202 -- where entries are static predicate strings; all user input flows through args as ? placeholders
	}
	// Tailing (After > 0) scans ASC so bursts larger than the page are
	// consumed oldest-first — a DESC LIMIT would skip the oldest new
	// rows and silently lose them on the next poll. Historical paging
	// (Before, or no cursor) stays DESC for newest-first display.
	if opts.After > 0 {
		query += " ORDER BY id ASC LIMIT ?"
	} else {
		query += " ORDER BY id DESC LIMIT ?"
	}
	args = append(args, limit)

	rows, err := s.db.QueryContext(ctx, s.dialect.Rebind(query), args...)
	if err != nil {
		return nil, fmt.Errorf("listing request_logs: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []RequestLog
	for rows.Next() {
		var rl RequestLog
		var keysJSON string
		var createdAt interface{}
		if err := rows.Scan(
			&rl.ID, &rl.VaultID, &rl.ActorType, &rl.ActorID, &rl.Ingress,
			&rl.Method, &rl.Host, &rl.Path, &rl.MatchedService, &keysJSON,
			&rl.Status, &rl.LatencyMs, &rl.ErrorCode, &createdAt,
		); err != nil {
			return nil, fmt.Errorf("scanning request_log: %w", err)
		}
		if keysJSON != "" {
			_ = json.Unmarshal([]byte(keysJSON), &rl.CredentialKeys)
		}
		rl.CreatedAt, _ = s.dialect.ScanTime(createdAt)
		out = append(out, rl)
	}
	return out, rows.Err()
}

// ListUnmatchedHosts returns distinct hostnames from request_logs that did
// not match any configured service and resulted in an auth failure (401/403)
// or proxy denial (error_code 'no_match'). Results are ordered by most
// recent failure first. Capped at 500 rows as a defense-in-depth limit.
func (s *SQLStore) ListUnmatchedHosts(ctx context.Context, vaultID string) ([]UnmatchedHost, error) {
	var query string
	if s.dialect.Name() == "postgres" {
		// PostgreSQL does not allow non-aggregated columns with GROUP BY
		// unless they are functionally dependent. Use DISTINCT ON to pick
		// the most recent row per host.
		query = s.dialect.Rebind(`
			SELECT host, request_count, last_seen, auth_scheme, auth_header
			FROM (
				SELECT DISTINCT ON (host)
				       host,
				       COUNT(*) OVER (PARTITION BY host) AS request_count,
				       created_at AS last_seen,
				       auth_scheme,
				       auth_header
				FROM request_logs
				WHERE vault_id = ?
				  AND matched_service = ''
				  AND host != ''
				  AND (error_code = 'no_match' OR status IN (401, 403))
				ORDER BY host, created_at DESC
			) sub
			ORDER BY last_seen DESC, host ASC
			LIMIT 500`)
	} else {
		// SQLite guarantees bare columns come from the MAX row.
		query = s.dialect.Rebind(`
			SELECT host, COUNT(*) AS request_count, MAX(created_at) AS last_seen,
			       auth_scheme, auth_header
			FROM request_logs
			WHERE vault_id = ?
			  AND matched_service = ''
			  AND host != ''
			  AND (error_code = 'no_match' OR status IN (401, 403))
			GROUP BY host
			ORDER BY MAX(created_at) DESC, host ASC
			LIMIT 500`)
	}
	rows, err := s.db.QueryContext(ctx, query, vaultID)
	if err != nil {
		return nil, fmt.Errorf("listing unmatched hosts: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []UnmatchedHost
	for rows.Next() {
		var uh UnmatchedHost
		var lastSeen interface{}
		if err := rows.Scan(&uh.Host, &uh.RequestCount, &lastSeen, &uh.AuthScheme, &uh.AuthHeader); err != nil {
			return nil, fmt.Errorf("scanning unmatched host: %w", err)
		}
		uh.LastSeen, _ = s.dialect.ScanTime(lastSeen)
		out = append(out, uh)
	}
	return out, rows.Err()
}

// DeleteOldRequestLogs deletes rows older than before across all vaults.
// Returns the number of rows affected.
func (s *SQLStore) DeleteOldRequestLogs(ctx context.Context, before time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		s.dialect.Rebind(`DELETE FROM request_logs WHERE created_at < ?`),
		s.dialect.FormatTime(before.UTC()),
	)
	if err != nil {
		return 0, fmt.Errorf("deleting old request_logs: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// TrimRequestLogsToCap keeps at most cap rows for vaultID, deleting the
// oldest beyond that ceiling. Returns rows deleted. Short-circuits when
// the vault is under the cap so steady-state calls do no index-walk work.
func (s *SQLStore) TrimRequestLogsToCap(ctx context.Context, vaultID string, cap int64) (int64, error) {
	if cap <= 0 {
		return 0, nil
	}
	var count int64
	if err := s.db.QueryRowContext(ctx,
		s.dialect.Rebind(`SELECT COUNT(*) FROM request_logs WHERE vault_id = ?`), vaultID,
	).Scan(&count); err != nil {
		return 0, fmt.Errorf("counting request_logs: %w", err)
	}
	if count <= cap {
		return 0, nil
	}
	res, err := s.db.ExecContext(ctx, s.dialect.Rebind(`
		DELETE FROM request_logs
		WHERE vault_id = ?
		  AND id <= (
		    SELECT cutoff_id FROM (
		      SELECT id AS cutoff_id FROM request_logs
		      WHERE vault_id = ?
		      ORDER BY id DESC
		      LIMIT 1 OFFSET ?
		    ) sub
		  )`),
		vaultID, vaultID, cap,
	)
	if err != nil {
		return 0, fmt.Errorf("trimming request_logs: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// VaultIDsWithLogs returns the distinct vault IDs that have at least one
// persisted request log. Used by the retention ticker to scope per-vault
// trimming without iterating every vault.
func (s *SQLStore) VaultIDsWithLogs(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, s.dialect.Rebind(`SELECT DISTINCT vault_id FROM request_logs`))
	if err != nil {
		return nil, fmt.Errorf("listing log vault ids: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}
