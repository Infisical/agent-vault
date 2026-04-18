package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
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

// nowUTC returns the current UTC time formatted as time.DateTime.
func nowUTC() string {
	return time.Now().UTC().Format(time.DateTime)
}

// nullableInt returns nil for zero/negative ints, enabling SQL NULL inserts.
func nullableInt(n int) interface{} {
	if n <= 0 {
		return nil
	}
	return n
}

// SQLiteStore implements Store backed by a SQLite database.
type SQLiteStore struct {
	db *sql.DB
}

// Open opens (or creates) a SQLite database at dbPath, configures WAL mode
// and sane defaults, and runs any pending schema migrations.
func Open(dbPath string) (*SQLiteStore, error) {
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

	if err := migrate(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("running migrations: %w", err)
	}

	return &SQLiteStore{db: db}, nil
}

// --- Instance Settings ---

func (s *SQLiteStore) GetSetting(ctx context.Context, key string) (string, error) {
	var value string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM instance_settings WHERE key = ?`, key).Scan(&value)
	if err != nil {
		return "", err
	}
	return value, nil
}

func (s *SQLiteStore) SetSetting(ctx context.Context, key, value string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO instance_settings (key, value, updated_at) VALUES (?, ?, datetime('now'))
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = datetime('now')`,
		key, value)
	return err
}

func (s *SQLiteStore) GetAllSettings(ctx context.Context) (map[string]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT key, value FROM instance_settings`)
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

func (s *SQLiteStore) Close() error {
	return s.db.Close()
}

// --- Vaults ---

func (s *SQLiteStore) CreateVault(ctx context.Context, name string) (*Vault, error) {
	nsID := newUUID()
	bcID := newUUID()
	now := time.Now().UTC()
	nowStr := now.Format(time.DateTime)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("beginning transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	_, err = tx.ExecContext(ctx,
		"INSERT INTO vaults (id, name, created_at, updated_at) VALUES (?, ?, ?, ?)",
		nsID, name, nowStr, nowStr,
	)
	if err != nil {
		return nil, fmt.Errorf("creating vault: %w", err)
	}

	_, err = tx.ExecContext(ctx,
		"INSERT INTO broker_configs (id, vault_id, services_json, created_at, updated_at) VALUES (?, ?, '[]', ?, ?)",
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

func (s *SQLiteStore) GetVault(ctx context.Context, name string) (*Vault, error) {
	row := s.db.QueryRowContext(ctx,
		"SELECT id, name, created_at, updated_at FROM vaults WHERE name = ?", name,
	)
	return scanVault(row)
}

func (s *SQLiteStore) GetVaultByID(ctx context.Context, id string) (*Vault, error) {
	row := s.db.QueryRowContext(ctx,
		"SELECT id, name, created_at, updated_at FROM vaults WHERE id = ?", id,
	)
	return scanVault(row)
}

func (s *SQLiteStore) ListVaults(ctx context.Context) ([]Vault, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT id, name, created_at, updated_at FROM vaults ORDER BY name")
	if err != nil {
		return nil, fmt.Errorf("listing vaults: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var vaults []Vault
	for rows.Next() {
		var v Vault
		var createdAt, updatedAt string
		if err := rows.Scan(&v.ID, &v.Name, &createdAt, &updatedAt); err != nil {
			return nil, fmt.Errorf("scanning vault: %w", err)
		}
		v.CreatedAt, _ = time.Parse(time.DateTime, createdAt)
		v.UpdatedAt, _ = time.Parse(time.DateTime, updatedAt)
		vaults = append(vaults, v)
	}
	return vaults, rows.Err()
}

func (s *SQLiteStore) DeleteVault(ctx context.Context, name string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Look up vault ID.
	var vaultID string
	if err := tx.QueryRowContext(ctx, "SELECT id FROM vaults WHERE name = ?", name).Scan(&vaultID); err != nil {
		if err == sql.ErrNoRows {
			return sql.ErrNoRows
		}
		return fmt.Errorf("looking up vault: %w", err)
	}

	// Delete sessions that reference this vault (FK lacks ON DELETE CASCADE).
	if _, err := tx.ExecContext(ctx, "DELETE FROM sessions WHERE vault_id = ?", vaultID); err != nil {
		return fmt.Errorf("deleting vault sessions: %w", err)
	}

	// Delete the vault (cascades to credentials, broker_configs, proposals, agents, etc.).
	if _, err := tx.ExecContext(ctx, "DELETE FROM vaults WHERE id = ?", vaultID); err != nil {
		return fmt.Errorf("deleting vault: %w", err)
	}

	return tx.Commit()
}

func (s *SQLiteStore) RenameVault(ctx context.Context, oldName string, newName string) error {
	nowStr := nowUTC()

	v, err := s.GetVault(ctx, oldName)
	if err != nil {
		return err
	}

	res, err := s.db.ExecContext(ctx,
		`UPDATE vaults SET name = ?, updated_at = ? WHERE id = ?`,
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

func (s *SQLiteStore) SetCredential(ctx context.Context, vaultID, key string, ciphertext, nonce []byte) (*Credential, error) {
	id := newUUID()
	now := time.Now().UTC()
	nowStr := now.Format(time.DateTime)

	_, err := s.db.ExecContext(ctx,
		`INSERT INTO credentials (id, vault_id, key, ciphertext, nonce, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(vault_id, key) DO UPDATE SET
		   ciphertext = excluded.ciphertext,
		   nonce = excluded.nonce,
		   updated_at = excluded.updated_at`,
		id, vaultID, key, ciphertext, nonce, nowStr, nowStr,
	)
	if err != nil {
		return nil, fmt.Errorf("setting credential: %w", err)
	}

	return &Credential{
		ID: id, VaultID: vaultID, Key: key,
		Ciphertext: ciphertext, Nonce: nonce,
		CreatedAt: now, UpdatedAt: now,
	}, nil
}

func (s *SQLiteStore) GetCredential(ctx context.Context, vaultID, key string) (*Credential, error) {
	row := s.db.QueryRowContext(ctx,
		"SELECT id, vault_id, key, ciphertext, nonce, created_at, updated_at FROM credentials WHERE vault_id = ? AND key = ?",
		vaultID, key,
	)
	return scanCredential(row)
}

func (s *SQLiteStore) ListCredentials(ctx context.Context, vaultID string) ([]Credential, error) {
	rows, err := s.db.QueryContext(ctx,
		"SELECT id, vault_id, key, ciphertext, nonce, created_at, updated_at FROM credentials WHERE vault_id = ? ORDER BY key",
		vaultID,
	)
	if err != nil {
		return nil, fmt.Errorf("listing credentials: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var creds []Credential
	for rows.Next() {
		var cred Credential
		var createdAt, updatedAt string
		if err := rows.Scan(&cred.ID, &cred.VaultID, &cred.Key, &cred.Ciphertext, &cred.Nonce, &createdAt, &updatedAt); err != nil {
			return nil, fmt.Errorf("scanning credential: %w", err)
		}
		cred.CreatedAt, _ = time.Parse(time.DateTime, createdAt)
		cred.UpdatedAt, _ = time.Parse(time.DateTime, updatedAt)
		creds = append(creds, cred)
	}
	return creds, rows.Err()
}

func (s *SQLiteStore) DeleteCredential(ctx context.Context, vaultID, key string) error {
	res, err := s.db.ExecContext(ctx, "DELETE FROM credentials WHERE vault_id = ? AND key = ?", vaultID, key)
	if err != nil {
		return fmt.Errorf("deleting credential: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// --- Users ---

func (s *SQLiteStore) CreateUser(ctx context.Context, email string, passwordHash, passwordSalt []byte, role string, kdfTime uint32, kdfMemory uint32, kdfThreads uint8) (*User, error) {
	id := newUUID()
	now := time.Now().UTC()
	nowStr := now.Format(time.DateTime)

	_, err := s.db.ExecContext(ctx,
		"INSERT INTO users (id, email, password_hash, password_salt, role, is_active, kdf_time, kdf_memory, kdf_threads, created_at, updated_at) VALUES (?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?)",
		id, email, passwordHash, passwordSalt, role, kdfTime, kdfMemory, kdfThreads, nowStr, nowStr,
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

func (s *SQLiteStore) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	row := s.db.QueryRowContext(ctx,
		"SELECT id, email, password_hash, password_salt, kdf_time, kdf_memory, kdf_threads, role, is_active, created_at, updated_at FROM users WHERE email = ?", email,
	)

	var u User
	var createdAt, updatedAt string
	if err := row.Scan(&u.ID, &u.Email, &u.PasswordHash, &u.PasswordSalt, &u.KDFTime, &u.KDFMemory, &u.KDFThreads, &u.Role, &u.IsActive, &createdAt, &updatedAt); err != nil {
		return nil, err
	}
	u.CreatedAt, _ = time.Parse(time.DateTime, createdAt)
	u.UpdatedAt, _ = time.Parse(time.DateTime, updatedAt)
	return &u, nil
}

func (s *SQLiteStore) CountUsers(ctx context.Context) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM users").Scan(&count)
	return count, err
}

// RegisterFirstUser atomically checks that no users exist and creates the
// first user as an active owner. Returns ErrNotFirstUser if users already exist.
func (s *SQLiteStore) RegisterFirstUser(ctx context.Context, email string, passwordHash, passwordSalt []byte, defaultVaultID string, kdfTime uint32, kdfMemory uint32, kdfThreads uint8) (*User, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var count int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM users").Scan(&count); err != nil {
		return nil, fmt.Errorf("counting users: %w", err)
	}
	if count > 0 {
		return nil, ErrNotFirstUser
	}

	id := newUUID()
	now := time.Now().UTC()
	nowStr := now.Format(time.DateTime)

	_, err = tx.ExecContext(ctx,
		"INSERT INTO users (id, email, password_hash, password_salt, kdf_time, kdf_memory, kdf_threads, role, is_active, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, 'owner', 1, ?, ?)",
		id, email, passwordHash, passwordSalt, kdfTime, kdfMemory, kdfThreads, nowStr, nowStr,
	)
	if err != nil {
		return nil, fmt.Errorf("creating owner: %w", err)
	}

	if defaultVaultID != "" {
		_, err = tx.ExecContext(ctx,
			"INSERT INTO vault_grants (actor_id, actor_type, vault_id, role, created_at) VALUES (?, 'user', ?, 'admin', ?) ON CONFLICT(actor_id, vault_id) DO UPDATE SET role = excluded.role",
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

func (s *SQLiteStore) GetUserByID(ctx context.Context, id string) (*User, error) {
	row := s.db.QueryRowContext(ctx,
		"SELECT id, email, password_hash, password_salt, kdf_time, kdf_memory, kdf_threads, role, is_active, created_at, updated_at FROM users WHERE id = ?", id,
	)

	var u User
	var createdAt, updatedAt string
	if err := row.Scan(&u.ID, &u.Email, &u.PasswordHash, &u.PasswordSalt, &u.KDFTime, &u.KDFMemory, &u.KDFThreads, &u.Role, &u.IsActive, &createdAt, &updatedAt); err != nil {
		return nil, err
	}
	u.CreatedAt, _ = time.Parse(time.DateTime, createdAt)
	u.UpdatedAt, _ = time.Parse(time.DateTime, updatedAt)
	return &u, nil
}

func (s *SQLiteStore) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx,
		"SELECT id, email, password_hash, password_salt, kdf_time, kdf_memory, kdf_threads, role, is_active, created_at, updated_at FROM users ORDER BY email",
	)
	if err != nil {
		return nil, fmt.Errorf("listing users: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var users []User
	for rows.Next() {
		var u User
		var createdAt, updatedAt string
		if err := rows.Scan(&u.ID, &u.Email, &u.PasswordHash, &u.PasswordSalt, &u.KDFTime, &u.KDFMemory, &u.KDFThreads, &u.Role, &u.IsActive, &createdAt, &updatedAt); err != nil {
			return nil, fmt.Errorf("scanning user: %w", err)
		}
		u.CreatedAt, _ = time.Parse(time.DateTime, createdAt)
		u.UpdatedAt, _ = time.Parse(time.DateTime, updatedAt)
		users = append(users, u)
	}
	return users, rows.Err()
}

func (s *SQLiteStore) UpdateUserPassword(ctx context.Context, userID string, passwordHash, passwordSalt []byte, kdfTime uint32, kdfMemory uint32, kdfThreads uint8) error {
	nowStr := nowUTC()
	res, err := s.db.ExecContext(ctx,
		"UPDATE users SET password_hash = ?, password_salt = ?, kdf_time = ?, kdf_memory = ?, kdf_threads = ?, updated_at = ? WHERE id = ?",
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

func (s *SQLiteStore) UpdateUserRole(ctx context.Context, userID, role string) error {
	nowStr := nowUTC()
	res, err := s.db.ExecContext(ctx,
		"UPDATE users SET role = ?, updated_at = ? WHERE id = ?",
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

func (s *SQLiteStore) DeleteUser(ctx context.Context, userID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	res, err := tx.ExecContext(ctx, "DELETE FROM users WHERE id = ?", userID)
	if err != nil {
		return fmt.Errorf("deleting user: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	// Clean up vault grants (no FK cascade since the unified table uses generic actor_id).
	if _, err := tx.ExecContext(ctx, "DELETE FROM vault_grants WHERE actor_id = ?", userID); err != nil {
		return fmt.Errorf("cleaning up vault grants: %w", err)
	}
	return tx.Commit()
}

func (s *SQLiteStore) CountOwners(ctx context.Context) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM users WHERE role = 'owner'").Scan(&count)
	return count, err
}

// --- Vault Grants ---

func (s *SQLiteStore) GrantVaultRole(ctx context.Context, actorID, actorType, vaultID, role string) error {
	nowStr := nowUTC()
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO vault_grants (actor_id, actor_type, vault_id, role, created_at) VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT(actor_id, vault_id) DO UPDATE SET role = excluded.role`,
		actorID, actorType, vaultID, role, nowStr,
	)
	if err != nil {
		return fmt.Errorf("granting vault role: %w", err)
	}
	return nil
}

func (s *SQLiteStore) RevokeVaultAccess(ctx context.Context, actorID, vaultID string) error {
	res, err := s.db.ExecContext(ctx,
		"DELETE FROM vault_grants WHERE actor_id = ? AND vault_id = ?",
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

func (s *SQLiteStore) ListActorGrants(ctx context.Context, actorID string) ([]VaultGrant, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT vg.actor_id, vg.actor_type, vg.vault_id, v.name, vg.role, vg.created_at
		 FROM vault_grants vg
		 JOIN vaults v ON v.id = vg.vault_id
		 WHERE vg.actor_id = ? ORDER BY vg.created_at`,
		actorID,
	)
	if err != nil {
		return nil, fmt.Errorf("listing actor grants: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var grants []VaultGrant
	for rows.Next() {
		var g VaultGrant
		var createdAt string
		if err := rows.Scan(&g.ActorID, &g.ActorType, &g.VaultID, &g.VaultName, &g.Role, &createdAt); err != nil {
			return nil, fmt.Errorf("scanning grant: %w", err)
		}
		g.CreatedAt, _ = time.Parse(time.DateTime, createdAt)
		grants = append(grants, g)
	}
	return grants, rows.Err()
}

func (s *SQLiteStore) HasVaultAccess(ctx context.Context, actorID, vaultID string) (bool, error) {
	var exists int
	err := s.db.QueryRowContext(ctx,
		"SELECT 1 FROM vault_grants WHERE actor_id = ? AND vault_id = ?",
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

func (s *SQLiteStore) GetVaultRole(ctx context.Context, actorID, vaultID string) (string, error) {
	var role string
	err := s.db.QueryRowContext(ctx,
		"SELECT role FROM vault_grants WHERE actor_id = ? AND vault_id = ?",
		actorID, vaultID,
	).Scan(&role)
	if err != nil {
		return "", err
	}
	return role, nil
}

func (s *SQLiteStore) CountVaultAdmins(ctx context.Context, vaultID string) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM vault_grants WHERE vault_id = ? AND role = 'admin'",
		vaultID,
	).Scan(&count)
	return count, err
}

func (s *SQLiteStore) ListVaultMembers(ctx context.Context, vaultID string) ([]VaultGrant, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT vg.actor_id, vg.actor_type, vg.vault_id, v.name, vg.role, vg.created_at
		 FROM vault_grants vg
		 JOIN vaults v ON v.id = vg.vault_id
		 WHERE vg.vault_id = ? ORDER BY vg.created_at`,
		vaultID,
	)
	if err != nil {
		return nil, fmt.Errorf("listing vault members: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var grants []VaultGrant
	for rows.Next() {
		var g VaultGrant
		var createdAt string
		if err := rows.Scan(&g.ActorID, &g.ActorType, &g.VaultID, &g.VaultName, &g.Role, &createdAt); err != nil {
			return nil, fmt.Errorf("scanning grant: %w", err)
		}
		g.CreatedAt, _ = time.Parse(time.DateTime, createdAt)
		grants = append(grants, g)
	}
	return grants, rows.Err()
}

func (s *SQLiteStore) ListVaultMembersByType(ctx context.Context, vaultID, actorType string) ([]VaultGrant, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT vg.actor_id, vg.actor_type, vg.vault_id, v.name, vg.role, vg.created_at
		 FROM vault_grants vg
		 JOIN vaults v ON v.id = vg.vault_id
		 WHERE vg.vault_id = ? AND vg.actor_type = ? ORDER BY vg.created_at`,
		vaultID, actorType,
	)
	if err != nil {
		return nil, fmt.Errorf("listing vault members by type: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var grants []VaultGrant
	for rows.Next() {
		var g VaultGrant
		var createdAt string
		if err := rows.Scan(&g.ActorID, &g.ActorType, &g.VaultID, &g.VaultName, &g.Role, &createdAt); err != nil {
			return nil, fmt.Errorf("scanning grant: %w", err)
		}
		g.CreatedAt, _ = time.Parse(time.DateTime, createdAt)
		grants = append(grants, g)
	}
	return grants, rows.Err()
}

func (s *SQLiteStore) ActivateUser(ctx context.Context, userID string) error {
	nowStr := nowUTC()
	res, err := s.db.ExecContext(ctx,
		"UPDATE users SET is_active = 1, updated_at = ? WHERE id = ?",
		nowStr, userID,
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

func (s *SQLiteStore) DeleteUserSessions(ctx context.Context, userID string) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM sessions WHERE user_id = ?", userID)
	if err != nil {
		return fmt.Errorf("deleting user sessions: %w", err)
	}
	return nil
}

// --- Sessions ---

func (s *SQLiteStore) CreateSession(ctx context.Context, userID string, expiresAt time.Time) (*Session, error) {
	rawToken := newSessionToken()
	tokenHash := hashSessionToken(rawToken)
	now := time.Now().UTC()

	var uid sql.NullString
	if userID != "" {
		uid = sql.NullString{String: userID, Valid: true}
	}

	_, err := s.db.ExecContext(ctx,
		"INSERT INTO sessions (id, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)",
		tokenHash, uid, expiresAt.UTC().Format(time.DateTime), now.Format(time.DateTime),
	)
	if err != nil {
		return nil, fmt.Errorf("creating session: %w", err)
	}

	exp := expiresAt.UTC()
	// Return the raw token as ID so the caller can send it to the client.
	return &Session{ID: rawToken, UserID: userID, ExpiresAt: &exp, CreatedAt: now}, nil
}

func (s *SQLiteStore) CreateScopedSession(ctx context.Context, vaultID, vaultRole string, expiresAt *time.Time) (*Session, error) {
	rawToken := newSessionToken()
	tokenHash := hashSessionToken(rawToken)
	now := time.Now().UTC()

	var expiresAtStr sql.NullString
	if expiresAt != nil {
		expiresAtStr = sql.NullString{String: expiresAt.UTC().Format(time.DateTime), Valid: true}
	}

	_, err := s.db.ExecContext(ctx,
		"INSERT INTO sessions (id, vault_id, vault_role, expires_at, created_at) VALUES (?, ?, ?, ?, ?)",
		tokenHash, vaultID, vaultRole, expiresAtStr, now.Format(time.DateTime),
	)
	if err != nil {
		return nil, fmt.Errorf("creating scoped session: %w", err)
	}

	return &Session{ID: rawToken, VaultID: vaultID, VaultRole: vaultRole, ExpiresAt: utcTimePtr(expiresAt), CreatedAt: now}, nil
}

func (s *SQLiteStore) GetSession(ctx context.Context, rawToken string) (*Session, error) {
	tokenHash := hashSessionToken(rawToken)
	row := s.db.QueryRowContext(ctx,
		"SELECT id, user_id, vault_id, agent_id, vault_role, expires_at, created_at FROM sessions WHERE id = ?", tokenHash,
	)

	var sess Session
	var storedID string
	var userID, vaultID, agentID, vaultRole, expiresAt sql.NullString
	var createdAt string
	if err := row.Scan(&storedID, &userID, &vaultID, &agentID, &vaultRole, &expiresAt, &createdAt); err != nil {
		return nil, err
	}
	// Return the raw token as ID (not the hash) so callers can reference it.
	sess.ID = rawToken
	sess.UserID = userID.String
	sess.VaultID = vaultID.String
	sess.AgentID = agentID.String
	sess.VaultRole = vaultRole.String
	if expiresAt.Valid {
		t, _ := time.Parse(time.DateTime, expiresAt.String)
		sess.ExpiresAt = &t
	}
	sess.CreatedAt, _ = time.Parse(time.DateTime, createdAt)
	return &sess, nil
}

func (s *SQLiteStore) DeleteSession(ctx context.Context, rawToken string) error {
	tokenHash := hashSessionToken(rawToken)
	res, err := s.db.ExecContext(ctx, "DELETE FROM sessions WHERE id = ?", tokenHash)
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

func (s *SQLiteStore) GetMasterKeyRecord(ctx context.Context) (*MasterKeyRecord, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT sentinel, sentinel_nonce, dek_ciphertext, dek_nonce, dek_plaintext,
		        salt, kdf_time, kdf_memory, kdf_threads, created_at
		 FROM master_key WHERE id = 1`,
	)

	var rec MasterKeyRecord
	var createdAt string
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
	rec.CreatedAt, _ = time.Parse(time.DateTime, createdAt)
	return &rec, nil
}

func (s *SQLiteStore) SetMasterKeyRecord(ctx context.Context, record *MasterKeyRecord) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO master_key (id, sentinel, sentinel_nonce, dek_ciphertext, dek_nonce, dek_plaintext, salt, kdf_time, kdf_memory, kdf_threads)
		 VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		record.Sentinel, record.SentinelNonce,
		record.DEKCiphertext, record.DEKNonce, record.DEKPlaintext,
		record.Salt, record.KDFTime, record.KDFMemory, record.KDFThreads,
	)
	if err != nil {
		return fmt.Errorf("setting master key record: %w", err)
	}
	return nil
}

func (s *SQLiteStore) UpdateMasterKeyRecord(ctx context.Context, record *MasterKeyRecord) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE master_key SET
		    sentinel = ?, sentinel_nonce = ?,
		    dek_ciphertext = ?, dek_nonce = ?, dek_plaintext = ?,
		    salt = ?, kdf_time = ?, kdf_memory = ?, kdf_threads = ?
		 WHERE id = 1`,
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

func (s *SQLiteStore) SetBrokerConfig(ctx context.Context, vaultID string, servicesJSON string) (*BrokerConfig, error) {
	id := newUUID()
	now := time.Now().UTC()
	nowStr := now.Format(time.DateTime)

	_, err := s.db.ExecContext(ctx,
		`INSERT INTO broker_configs (id, vault_id, services_json, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT(vault_id) DO UPDATE SET
		   services_json = excluded.services_json,
		   updated_at = excluded.updated_at`,
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

func (s *SQLiteStore) GetBrokerConfig(ctx context.Context, vaultID string) (*BrokerConfig, error) {
	row := s.db.QueryRowContext(ctx,
		"SELECT id, vault_id, services_json, created_at, updated_at FROM broker_configs WHERE vault_id = ?",
		vaultID,
	)
	return scanBrokerConfig(row)
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

func (s *SQLiteStore) CreateProposal(ctx context.Context, vaultID, sessionID, servicesJSON, credentialsJSON, message, userMessage string, credentials map[string]EncryptedCredential) (*Proposal, error) {
	now := time.Now().UTC()
	nowStr := now.Format(time.DateTime)
	approvalToken := newApprovalToken()
	tokenExpiresAt := now.Add(approvalTokenTTL)
	tokenExpiresAtStr := tokenExpiresAt.Format(time.DateTime)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("beginning transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Compute next sequential ID for this vault.
	var nextID int
	err = tx.QueryRowContext(ctx,
		"SELECT COALESCE(MAX(id), 0) + 1 FROM proposals WHERE vault_id = ?",
		vaultID,
	).Scan(&nextID)
	if err != nil {
		return nil, fmt.Errorf("computing next proposal id: %w", err)
	}

	_, err = tx.ExecContext(ctx,
		`INSERT INTO proposals (id, vault_id, session_id, status, services_json, credentials_json, message, user_message, approval_token_hash, approval_token_expires_at, created_at, updated_at)
		 VALUES (?, ?, ?, 'pending', ?, ?, ?, ?, ?, ?, ?, ?)`,
		nextID, vaultID, sessionID, servicesJSON, credentialsJSON, message, userMessage, hashToken(approvalToken), tokenExpiresAtStr, nowStr, nowStr,
	)
	if err != nil {
		return nil, fmt.Errorf("inserting proposal: %w", err)
	}

	// Store agent-provided encrypted credential values.
	for key, enc := range credentials {
		_, err = tx.ExecContext(ctx,
			`INSERT INTO proposal_credentials (vault_id, proposal_id, key, ciphertext, nonce)
			 VALUES (?, ?, ?, ?, ?)`,
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

func (s *SQLiteStore) GetProposal(ctx context.Context, vaultID string, id int) (*Proposal, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT `+proposalColumns+` FROM proposals WHERE vault_id = ? AND id = ?`,
		vaultID, id,
	)
	return scanProposal(row)
}

func (s *SQLiteStore) GetProposalByApprovalToken(ctx context.Context, token string) (*Proposal, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT `+proposalColumns+` FROM proposals WHERE approval_token_hash = ?`,
		hashToken(token),
	)
	return scanProposal(row)
}

func (s *SQLiteStore) ListProposals(ctx context.Context, vaultID, status string) ([]Proposal, error) {
	var rows *sql.Rows
	var err error
	if status != "" {
		rows, err = s.db.QueryContext(ctx,
			`SELECT `+proposalColumns+` FROM proposals WHERE vault_id = ? AND status = ? ORDER BY id DESC`,
			vaultID, status,
		)
	} else {
		rows, err = s.db.QueryContext(ctx,
			`SELECT `+proposalColumns+` FROM proposals WHERE vault_id = ? ORDER BY id DESC`,
			vaultID,
		)
	}
	if err != nil {
		return nil, fmt.Errorf("listing proposals: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var proposals []Proposal
	for rows.Next() {
		cs, err := scanProposalRow(rows)
		if err != nil {
			return nil, err
		}
		proposals = append(proposals, *cs)
	}
	return proposals, rows.Err()
}

func (s *SQLiteStore) UpdateProposalStatus(ctx context.Context, vaultID string, id int, status, reviewNote string) error {
	nowStr := nowUTC()
	var reviewedAt *string
	if status == "applied" || status == "rejected" {
		reviewedAt = &nowStr
	}

	res, err := s.db.ExecContext(ctx,
		`UPDATE proposals SET status = ?, review_note = ?, reviewed_at = ?, updated_at = ?
		 WHERE vault_id = ? AND id = ?`,
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

func (s *SQLiteStore) CountPendingProposals(ctx context.Context, vaultID string) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM proposals WHERE vault_id = ? AND status = 'pending'",
		vaultID,
	).Scan(&count)
	return count, err
}

func (s *SQLiteStore) ExpirePendingProposals(ctx context.Context, before time.Time) (int, error) {
	nowStr := nowUTC()
	res, err := s.db.ExecContext(ctx,
		`UPDATE proposals SET status = 'expired', updated_at = ?
		 WHERE status = 'pending' AND created_at < ?`,
		nowStr, before.UTC().Format(time.DateTime),
	)
	if err != nil {
		return 0, fmt.Errorf("expiring proposals: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

func (s *SQLiteStore) GetProposalCredentials(ctx context.Context, vaultID string, proposalID int) (map[string]EncryptedCredential, error) {
	rows, err := s.db.QueryContext(ctx,
		"SELECT key, ciphertext, nonce FROM proposal_credentials WHERE vault_id = ? AND proposal_id = ?",
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

func (s *SQLiteStore) ApplyProposal(ctx context.Context, vaultID string, proposalID int, mergedServicesJSON string, credentials map[string]EncryptedCredential, deleteCredentialKeys []string) error {
	nowStr := nowUTC()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// 1. Update broker config with merged services.
	_, err = tx.ExecContext(ctx,
		`UPDATE broker_configs SET services_json = ?, updated_at = ? WHERE vault_id = ?`,
		mergedServicesJSON, nowStr, vaultID,
	)
	if err != nil {
		return fmt.Errorf("updating broker config: %w", err)
	}

	// 2. Upsert each credential.
	for key, enc := range credentials {
		id := newUUID()
		_, err = tx.ExecContext(ctx,
			`INSERT INTO credentials (id, vault_id, key, ciphertext, nonce, created_at, updated_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?)
			 ON CONFLICT(vault_id, key) DO UPDATE SET
			   ciphertext = excluded.ciphertext,
			   nonce = excluded.nonce,
			   updated_at = excluded.updated_at`,
			id, vaultID, key, enc.Ciphertext, enc.Nonce, nowStr, nowStr,
		)
		if err != nil {
			return fmt.Errorf("upserting credential %q: %w", key, err)
		}
	}

	// 3. Delete credentials marked for removal.
	for _, key := range deleteCredentialKeys {
		_, err = tx.ExecContext(ctx,
			`DELETE FROM credentials WHERE vault_id = ? AND key = ?`,
			vaultID, key,
		)
		if err != nil {
			return fmt.Errorf("deleting credential %q: %w", key, err)
		}
	}

	// 4. Mark proposal as applied (status guard prevents double-apply race).
	res, err := tx.ExecContext(ctx,
		`UPDATE proposals SET status = 'applied', reviewed_at = ?, updated_at = ?
		 WHERE vault_id = ? AND id = ? AND status = 'pending'`,
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

func scanProposalFields(cs *Proposal, scan func(dest ...interface{}) error) error {
	var reviewedAt sql.NullString
	var approvalTokenExpiresAt sql.NullString
	var createdAt, updatedAt string
	if err := scan(&cs.ID, &cs.VaultID, &cs.SessionID, &cs.Status,
		&cs.ServicesJSON, &cs.CredentialsJSON, &cs.Message, &cs.UserMessage, &cs.ReviewNote,
		&reviewedAt, &approvalTokenExpiresAt,
		&createdAt, &updatedAt); err != nil {
		return err
	}
	if reviewedAt.Valid {
		cs.ReviewedAt = &reviewedAt.String
	}
	if approvalTokenExpiresAt.Valid {
		t, _ := time.Parse(time.DateTime, approvalTokenExpiresAt.String)
		cs.ApprovalTokenExpiresAt = &t
	}
	cs.CreatedAt, _ = time.Parse(time.DateTime, createdAt)
	cs.UpdatedAt, _ = time.Parse(time.DateTime, updatedAt)
	return nil
}

func scanProposal(row *sql.Row) (*Proposal, error) {
	var cs Proposal
	if err := scanProposalFields(&cs, row.Scan); err != nil {
		return nil, err
	}
	return &cs, nil
}

func scanProposalRow(rows *sql.Rows) (*Proposal, error) {
	var cs Proposal
	if err := scanProposalFields(&cs, rows.Scan); err != nil {
		return nil, fmt.Errorf("scanning proposal: %w", err)
	}
	return &cs, nil
}

func scanVault(row *sql.Row) (*Vault, error) {
	var v Vault
	var createdAt, updatedAt string
	if err := row.Scan(&v.ID, &v.Name, &createdAt, &updatedAt); err != nil {
		return nil, err
	}
	v.CreatedAt, _ = time.Parse(time.DateTime, createdAt)
	v.UpdatedAt, _ = time.Parse(time.DateTime, updatedAt)
	return &v, nil
}

func scanCredential(row *sql.Row) (*Credential, error) {
	var cred Credential
	var createdAt, updatedAt string
	if err := row.Scan(&cred.ID, &cred.VaultID, &cred.Key, &cred.Ciphertext, &cred.Nonce, &createdAt, &updatedAt); err != nil {
		return nil, err
	}
	cred.CreatedAt, _ = time.Parse(time.DateTime, createdAt)
	cred.UpdatedAt, _ = time.Parse(time.DateTime, updatedAt)
	return &cred, nil
}

func scanBrokerConfig(row *sql.Row) (*BrokerConfig, error) {
	var bc BrokerConfig
	var createdAt, updatedAt string
	if err := row.Scan(&bc.ID, &bc.VaultID, &bc.ServicesJSON, &createdAt, &updatedAt); err != nil {
		return nil, err
	}
	bc.CreatedAt, _ = time.Parse(time.DateTime, createdAt)
	bc.UpdatedAt, _ = time.Parse(time.DateTime, updatedAt)
	return &bc, nil
}

// --- Invites ---

func newInviteToken() string { return newPrefixedToken("av_inv_") }

func (s *SQLiteStore) CreateAgentInvite(ctx context.Context, agentName, createdBy string, expiresAt time.Time, sessionTTLSeconds int, agentRole string, vaults []AgentInviteVault) (*Invite, error) {
	now := time.Now().UTC()
	token := newInviteToken()
	if agentRole == "" {
		agentRole = "member"
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("beginning transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	res, err := tx.ExecContext(ctx,
		`INSERT INTO invites (token_hash, agent_name, agent_role, status, created_by, created_at, expires_at, session_ttl_seconds)
		 VALUES (?, ?, ?, 'pending', ?, ?, ?, ?)`,
		hashToken(token), agentName, agentRole, createdBy, now.Format(time.DateTime), expiresAt.UTC().Format(time.DateTime), nullableInt(sessionTTLSeconds),
	)
	if err != nil {
		return nil, fmt.Errorf("inserting invite: %w", err)
	}

	inviteID, _ := res.LastInsertId()

	// Insert vault pre-assignments.
	for _, v := range vaults {
		_, err := tx.ExecContext(ctx,
			`INSERT INTO agent_invite_vaults (invite_id, vault_id, vault_role) VALUES (?, ?, ?)`,
			inviteID, v.VaultID, v.VaultRole,
		)
		if err != nil {
			return nil, fmt.Errorf("inserting invite vault: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("committing invite: %w", err)
	}

	return &Invite{
		ID:                int(inviteID),
		Token:             token,
		AgentName:         agentName,
		AgentRole:         agentRole,
		Status:            "pending",
		CreatedBy:         createdBy,
		SessionTTLSeconds: sessionTTLSeconds,
		Vaults:            vaults,
		CreatedAt:         now,
		ExpiresAt:         expiresAt.UTC(),
	}, nil
}

func (s *SQLiteStore) GetInviteByToken(ctx context.Context, token string) (*Invite, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, '' as token, agent_name, agent_id, agent_role, session_ttl_seconds,
		        status, session_id, created_by,
		        created_at, expires_at, redeemed_at, revoked_at
		 FROM invites WHERE token_hash = ?`, hashToken(token),
	)
	inv, err := scanInvite(row)
	if err != nil {
		return nil, err
	}
	inv.Vaults, err = s.loadAgentInviteVaults(ctx, inv.ID)
	if err != nil {
		return nil, err
	}
	return inv, nil
}

func (s *SQLiteStore) ListInvites(ctx context.Context, status string) ([]Invite, error) {
	// Lazily expire pending invites that are past their TTL.
	nowStr := nowUTC()
	_, _ = s.db.ExecContext(ctx,
		`UPDATE invites SET status = 'expired' WHERE status = 'pending' AND expires_at <= ?`,
		nowStr,
	)

	var rows *sql.Rows
	var err error
	if status != "" {
		rows, err = s.db.QueryContext(ctx,
			`SELECT id, '' as token, agent_name, agent_id, agent_role, session_ttl_seconds,
			        status, session_id, created_by,
			        created_at, expires_at, redeemed_at, revoked_at
			 FROM invites WHERE status = ? ORDER BY created_at DESC`,
			status,
		)
	} else {
		rows, err = s.db.QueryContext(ctx,
			`SELECT id, '' as token, agent_name, agent_id, agent_role, session_ttl_seconds,
			        status, session_id, created_by,
			        created_at, expires_at, redeemed_at, revoked_at
			 FROM invites ORDER BY created_at DESC`,
		)
	}
	if err != nil {
		return nil, fmt.Errorf("listing invites: %w", err)
	}

	var invites []Invite
	for rows.Next() {
		inv, err := scanInviteRow(rows)
		if err != nil {
			_ = rows.Close()
			return nil, err
		}
		invites = append(invites, *inv)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	_ = rows.Close()

	// Load vault pre-assignments after closing rows to avoid connection deadlock.
	for i := range invites {
		invites[i].Vaults, _ = s.loadAgentInviteVaults(ctx, invites[i].ID)
	}
	return invites, nil
}

func (s *SQLiteStore) ListInvitesByVault(ctx context.Context, vaultID, status string) ([]Invite, error) {
	// Lazily expire pending invites that are past their TTL.
	nowStr := nowUTC()
	_, _ = s.db.ExecContext(ctx,
		`UPDATE invites SET status = 'expired' WHERE status = 'pending' AND expires_at <= ?`,
		nowStr,
	)

	var rows *sql.Rows
	var err error
	if status != "" {
		rows, err = s.db.QueryContext(ctx,
			`SELECT DISTINCT i.id, '' as token, i.agent_name, i.agent_id, i.agent_role, i.session_ttl_seconds,
			        i.status, i.session_id, i.created_by,
			        i.created_at, i.expires_at, i.redeemed_at, i.revoked_at
			 FROM invites i
			 JOIN agent_invite_vaults aiv ON aiv.invite_id = i.id
			 WHERE aiv.vault_id = ? AND i.status = ? ORDER BY i.created_at DESC`,
			vaultID, status,
		)
	} else {
		rows, err = s.db.QueryContext(ctx,
			`SELECT DISTINCT i.id, '' as token, i.agent_name, i.agent_id, i.agent_role, i.session_ttl_seconds,
			        i.status, i.session_id, i.created_by,
			        i.created_at, i.expires_at, i.redeemed_at, i.revoked_at
			 FROM invites i
			 JOIN agent_invite_vaults aiv ON aiv.invite_id = i.id
			 WHERE aiv.vault_id = ? ORDER BY i.created_at DESC`,
			vaultID,
		)
	}
	if err != nil {
		return nil, fmt.Errorf("listing invites by vault: %w", err)
	}

	var invites []Invite
	for rows.Next() {
		inv, err := scanInviteRow(rows)
		if err != nil {
			_ = rows.Close()
			return nil, err
		}
		invites = append(invites, *inv)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	_ = rows.Close()

	for i := range invites {
		invites[i].Vaults, _ = s.loadAgentInviteVaults(ctx, invites[i].ID)
	}
	return invites, nil
}

func (s *SQLiteStore) RedeemInvite(ctx context.Context, token, sessionID string) error {
	nowStr := nowUTC()

	res, err := s.db.ExecContext(ctx,
		`UPDATE invites SET status = 'redeemed', session_id = ?, redeemed_at = ?
		 WHERE token_hash = ? AND status = 'pending' AND expires_at > ?`,
		sessionID, nowStr, hashToken(token), nowStr,
	)
	if err != nil {
		return fmt.Errorf("redeeming invite: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *SQLiteStore) UpdateInviteSessionID(ctx context.Context, inviteID int, sessionID string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE invites SET session_id = ? WHERE id = ?`,
		sessionID, inviteID,
	)
	return err
}

func (s *SQLiteStore) RevokeInvite(ctx context.Context, token string) error {
	nowStr := nowUTC()

	res, err := s.db.ExecContext(ctx,
		`UPDATE invites SET status = 'revoked', revoked_at = ?
		 WHERE token_hash = ? AND status = 'pending'`,
		nowStr, hashToken(token),
	)
	if err != nil {
		return fmt.Errorf("revoking invite: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *SQLiteStore) GetInviteByID(ctx context.Context, id int) (*Invite, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, '' as token, agent_name, agent_id, agent_role, session_ttl_seconds,
		        status, session_id, created_by,
		        created_at, expires_at, redeemed_at, revoked_at
		 FROM invites WHERE id = ?`, id,
	)
	inv, err := scanInvite(row)
	if err != nil {
		return nil, err
	}
	inv.Vaults, err = s.loadAgentInviteVaults(ctx, inv.ID)
	if err != nil {
		return nil, err
	}
	return inv, nil
}

func (s *SQLiteStore) RevokeInviteByID(ctx context.Context, id int) error {
	nowStr := nowUTC()

	res, err := s.db.ExecContext(ctx,
		`UPDATE invites SET status = 'revoked', revoked_at = ?
		 WHERE id = ? AND status = 'pending'`,
		nowStr, id,
	)
	if err != nil {
		return fmt.Errorf("revoking invite by id: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *SQLiteStore) CountPendingInvites(ctx context.Context) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM invites WHERE status = 'pending'",
	).Scan(&count)
	return count, err
}

func (s *SQLiteStore) HasPendingInviteByAgentName(ctx context.Context, name string) (bool, error) {
	var count int
	err := s.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM invites WHERE status = 'pending' AND agent_name = ?",
		name,
	).Scan(&count)
	return count > 0, err
}

func (s *SQLiteStore) GetPendingInviteByAgentName(ctx context.Context, name string) (*Invite, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, '' as token, agent_name, agent_id, agent_role, session_ttl_seconds,
		        status, session_id, created_by,
		        created_at, expires_at, redeemed_at, revoked_at
		 FROM invites WHERE status = 'pending' AND agent_name = ? LIMIT 1`,
		name,
	)
	if err != nil {
		return nil, err
	}
	if !rows.Next() {
		_ = rows.Close()
		return nil, sql.ErrNoRows
	}
	inv, err := scanInviteRow(rows)
	_ = rows.Close()
	if err != nil {
		return nil, err
	}
	vaults, err := s.loadAgentInviteVaults(ctx, inv.ID)
	if err != nil {
		return nil, err
	}
	inv.Vaults = vaults
	return inv, nil
}

func (s *SQLiteStore) AddAgentInviteVault(ctx context.Context, inviteID int, vaultID, role string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO agent_invite_vaults (invite_id, vault_id, vault_role) VALUES (?, ?, ?)`,
		inviteID, vaultID, role,
	)
	return err
}

func (s *SQLiteStore) RemoveAgentInviteVault(ctx context.Context, inviteID int, vaultID string) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM agent_invite_vaults WHERE invite_id = ? AND vault_id = ?`,
		inviteID, vaultID,
	)
	return err
}

func (s *SQLiteStore) UpdateAgentInviteVaultRole(ctx context.Context, inviteID int, vaultID, role string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE agent_invite_vaults SET vault_role = ? WHERE invite_id = ? AND vault_id = ?`,
		role, inviteID, vaultID,
	)
	return err
}

func (s *SQLiteStore) ExpirePendingInvites(ctx context.Context, before time.Time) (int, error) {
	res, err := s.db.ExecContext(ctx,
		`UPDATE invites SET status = 'expired'
		 WHERE status = 'pending' AND expires_at < ?`,
		before.UTC().Format(time.DateTime),
	)
	if err != nil {
		return 0, fmt.Errorf("expiring invites: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// scanInviteFields populates an Invite from pre-scanned fields.
func scanInviteFields(inv *Invite, agentID, sessionID sql.NullString, createdAt, expiresAt string, redeemedAt, revokedAt sql.NullString, sessionTTL sql.NullInt64) {
	inv.AgentID = agentID.String
	inv.SessionID = sessionID.String
	inv.CreatedAt, _ = time.Parse(time.DateTime, createdAt)
	inv.ExpiresAt, _ = time.Parse(time.DateTime, expiresAt)
	if redeemedAt.Valid {
		t, _ := time.Parse(time.DateTime, redeemedAt.String)
		inv.RedeemedAt = &t
	}
	if revokedAt.Valid {
		t, _ := time.Parse(time.DateTime, revokedAt.String)
		inv.RevokedAt = &t
	}
	if sessionTTL.Valid {
		inv.SessionTTLSeconds = int(sessionTTL.Int64)
	}
}

// scanInvite scans a single invite row from a *sql.Row.
// Expected column order: id, token, agent_name, agent_id, agent_role, session_ttl_seconds,
//
//	status, session_id, created_by, created_at, expires_at, redeemed_at, revoked_at
func scanInvite(row *sql.Row) (*Invite, error) {
	var inv Invite
	var agentID, sessionID sql.NullString
	var createdAt, expiresAt string
	var redeemedAt, revokedAt sql.NullString
	var sessionTTL sql.NullInt64

	if err := row.Scan(&inv.ID, &inv.Token, &inv.AgentName, &agentID, &inv.AgentRole, &sessionTTL,
		&inv.Status, &sessionID, &inv.CreatedBy,
		&createdAt, &expiresAt, &redeemedAt, &revokedAt); err != nil {
		return nil, err
	}

	scanInviteFields(&inv, agentID, sessionID, createdAt, expiresAt, redeemedAt, revokedAt, sessionTTL)
	return &inv, nil
}

// scanInviteRow scans a single invite from a *sql.Rows.
func scanInviteRow(rows *sql.Rows) (*Invite, error) {
	var inv Invite
	var agentID, sessionID sql.NullString
	var createdAt, expiresAt string
	var redeemedAt, revokedAt sql.NullString
	var sessionTTL sql.NullInt64

	if err := rows.Scan(&inv.ID, &inv.Token, &inv.AgentName, &agentID, &inv.AgentRole, &sessionTTL,
		&inv.Status, &sessionID, &inv.CreatedBy,
		&createdAt, &expiresAt, &redeemedAt, &revokedAt); err != nil {
		return nil, err
	}

	scanInviteFields(&inv, agentID, sessionID, createdAt, expiresAt, redeemedAt, revokedAt, sessionTTL)
	return &inv, nil
}

// loadAgentInviteVaults loads the vault pre-assignments for an invite.
func (s *SQLiteStore) loadAgentInviteVaults(ctx context.Context, inviteID int) ([]AgentInviteVault, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT aiv.vault_id, v.name, aiv.vault_role
		 FROM agent_invite_vaults aiv
		 JOIN vaults v ON v.id = aiv.vault_id
		 WHERE aiv.invite_id = ?`, inviteID,
	)
	if err != nil {
		return nil, fmt.Errorf("loading invite vaults: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var vaults []AgentInviteVault
	for rows.Next() {
		var v AgentInviteVault
		if err := rows.Scan(&v.VaultID, &v.VaultName, &v.VaultRole); err != nil {
			return nil, err
		}
		vaults = append(vaults, v)
	}
	return vaults, rows.Err()
}

// --- Vault Invites ---

func newUserInviteToken() string { return newPrefixedToken("av_uinv_") }

func (s *SQLiteStore) CreateUserInvite(ctx context.Context, email, createdBy, role string, expiresAt time.Time, vaults []UserInviteVault) (*UserInvite, error) {
	now := time.Now().UTC()
	token := newUserInviteToken()
	nowStr := now.Format(time.DateTime)
	expiresStr := expiresAt.UTC().Format(time.DateTime)
	if role == "" {
		role = "member"
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	res, err := tx.ExecContext(ctx,
		`INSERT INTO user_invites (token_hash, email, role, created_by, created_at, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		hashToken(token), email, role, createdBy, nowStr, expiresStr,
	)
	if err != nil {
		return nil, fmt.Errorf("inserting user invite: %w", err)
	}

	inviteID, _ := res.LastInsertId()

	for _, v := range vaults {
		_, err := tx.ExecContext(ctx,
			`INSERT INTO user_invite_vaults (user_invite_id, vault_id, vault_role)
			 VALUES (?, ?, ?)`,
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

func (s *SQLiteStore) GetUserInviteByToken(ctx context.Context, token string) (*UserInvite, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, email, role, status, created_by, created_at, expires_at, accepted_at
		 FROM user_invites WHERE token_hash = ?`, hashToken(token),
	)
	inv, err := scanUserInvite(row)
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

func (s *SQLiteStore) GetPendingUserInviteByEmail(ctx context.Context, email string) (*UserInvite, error) {
	nowStr := nowUTC()
	row := s.db.QueryRowContext(ctx,
		`SELECT id, email, role, status, created_by, created_at, expires_at, accepted_at
		 FROM user_invites WHERE email = ? AND status = 'pending' AND expires_at > ?
		 ORDER BY created_at DESC LIMIT 1`, email, nowStr,
	)
	inv, err := scanUserInvite(row)
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

func (s *SQLiteStore) ListUserInvites(ctx context.Context, status string) ([]UserInvite, error) {
	var rows *sql.Rows
	var err error
	if status != "" {
		rows, err = s.db.QueryContext(ctx,
			`SELECT id, email, role, status, created_by, created_at, expires_at, accepted_at
			 FROM user_invites WHERE status = ? ORDER BY created_at DESC`, status,
		)
	} else {
		rows, err = s.db.QueryContext(ctx,
			`SELECT id, email, role, status, created_by, created_at, expires_at, accepted_at
			 FROM user_invites ORDER BY created_at DESC`,
		)
	}
	if err != nil {
		return nil, fmt.Errorf("listing user invites: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var invites []UserInvite
	for rows.Next() {
		inv, err := scanUserInviteRow(rows)
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

func (s *SQLiteStore) ListUserInvitesByVault(ctx context.Context, vaultID, status string) ([]UserInvite, error) {
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

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("listing user invites by vault: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var invites []UserInvite
	for rows.Next() {
		inv, err := scanUserInviteRow(rows)
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

func (s *SQLiteStore) AcceptUserInvite(ctx context.Context, token string) error {
	nowStr := nowUTC()

	res, err := s.db.ExecContext(ctx,
		`UPDATE user_invites SET status = 'accepted', accepted_at = ?
		 WHERE token_hash = ? AND status = 'pending' AND expires_at > ?`,
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

func (s *SQLiteStore) RevokeUserInvite(ctx context.Context, token string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE user_invites SET status = 'revoked'
		 WHERE token_hash = ? AND status = 'pending'`,
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

func (s *SQLiteStore) UpdateUserInviteVaults(ctx context.Context, token string, vaults []UserInviteVault) error {
	// Look up invite ID by token hash
	var inviteID int
	err := s.db.QueryRowContext(ctx,
		`SELECT id FROM user_invites WHERE token_hash = ? AND status = 'pending'`,
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

	_, err = tx.ExecContext(ctx, `DELETE FROM user_invite_vaults WHERE user_invite_id = ?`, inviteID)
	if err != nil {
		return fmt.Errorf("clearing user invite vaults: %w", err)
	}

	for _, v := range vaults {
		_, err := tx.ExecContext(ctx,
			`INSERT INTO user_invite_vaults (user_invite_id, vault_id, vault_role) VALUES (?, ?, ?)`,
			inviteID, v.VaultID, v.VaultRole,
		)
		if err != nil {
			return fmt.Errorf("inserting user invite vault: %w", err)
		}
	}

	return tx.Commit()
}

func (s *SQLiteStore) CountPendingUserInvites(ctx context.Context) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM user_invites WHERE status = 'pending'",
	).Scan(&count)
	return count, err
}

// loadUserInviteVaults fetches the vault pre-assignments for a user invite.
func (s *SQLiteStore) loadUserInviteVaults(ctx context.Context, inviteID int) ([]UserInviteVault, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT uiv.vault_id, v.name, uiv.vault_role
		 FROM user_invite_vaults uiv
		 JOIN vaults v ON v.id = uiv.vault_id
		 WHERE uiv.user_invite_id = ?`, inviteID,
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

func (s *SQLiteStore) loadUserInviteVaultsBatch(ctx context.Context, invites []UserInvite) error {
	if len(invites) == 0 {
		return nil
	}

	ids := make([]any, len(invites))
	for i, inv := range invites {
		ids[i] = inv.ID
	}

	query := "SELECT uiv.user_invite_id, uiv.vault_id, v.name, uiv.vault_role FROM user_invite_vaults uiv JOIN vaults v ON v.id = uiv.vault_id WHERE uiv.user_invite_id IN (" + strings.Repeat("?,", len(ids)-1) + "?)" //nolint:gosec // only '?' placeholders
	rows, err := s.db.QueryContext(ctx, query, ids...)
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

func scanUserInvite(row *sql.Row) (*UserInvite, error) {
	var inv UserInvite
	var createdAt, expiresAt string
	var acceptedAt sql.NullString

	if err := row.Scan(&inv.ID, &inv.Email, &inv.Role, &inv.Status,
		&inv.CreatedBy, &createdAt, &expiresAt, &acceptedAt); err != nil {
		return nil, err
	}

	inv.CreatedAt, _ = time.Parse(time.DateTime, createdAt)
	inv.ExpiresAt, _ = time.Parse(time.DateTime, expiresAt)
	if acceptedAt.Valid {
		t, _ := time.Parse(time.DateTime, acceptedAt.String)
		inv.AcceptedAt = &t
	}
	return &inv, nil
}

func scanUserInviteRow(rows *sql.Rows) (*UserInvite, error) {
	var inv UserInvite
	var createdAt, expiresAt string
	var acceptedAt sql.NullString

	if err := rows.Scan(&inv.ID, &inv.Email, &inv.Role, &inv.Status,
		&inv.CreatedBy, &createdAt, &expiresAt, &acceptedAt); err != nil {
		return nil, err
	}

	inv.CreatedAt, _ = time.Parse(time.DateTime, createdAt)
	inv.ExpiresAt, _ = time.Parse(time.DateTime, expiresAt)
	if acceptedAt.Valid {
		t, _ := time.Parse(time.DateTime, acceptedAt.String)
		inv.AcceptedAt = &t
	}
	return &inv, nil
}

// --- Email Verification ---

func (s *SQLiteStore) CreateEmailVerification(ctx context.Context, email, code string, expiresAt time.Time) (*EmailVerification, error) {
	now := time.Now().UTC()
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO email_verifications (email, code_hash, created_at, expires_at)
		 VALUES (?, ?, ?, ?)`,
		email, hashToken(code), now.Format(time.DateTime), expiresAt.UTC().Format(time.DateTime),
	)
	if err != nil {
		return nil, fmt.Errorf("creating email verification: %w", err)
	}

	id, _ := res.LastInsertId()
	return &EmailVerification{
		ID:        int(id),
		Email:     email,
		Code:      code,
		Status:    "pending",
		CreatedAt: now,
		ExpiresAt: expiresAt.UTC(),
	}, nil
}

func (s *SQLiteStore) GetPendingEmailVerification(ctx context.Context, email, code string) (*EmailVerification, error) {
	nowStr := nowUTC()
	var ev EmailVerification
	var createdAt, expiresAt string
	err := s.db.QueryRowContext(ctx,
		`SELECT id, email, status, created_at, expires_at
		 FROM email_verifications
		 WHERE email = ? AND code_hash = ? AND status = 'pending' AND expires_at > ?
		 ORDER BY created_at DESC LIMIT 1`, email, hashToken(code), nowStr,
	).Scan(&ev.ID, &ev.Email, &ev.Status, &createdAt, &expiresAt)
	if err != nil {
		return nil, err
	}
	ev.CreatedAt, _ = time.Parse(time.DateTime, createdAt)
	ev.ExpiresAt, _ = time.Parse(time.DateTime, expiresAt)
	return &ev, nil
}

func (s *SQLiteStore) MarkEmailVerificationUsed(ctx context.Context, id int) error {
	res, err := s.db.ExecContext(ctx,
		"UPDATE email_verifications SET status = 'verified' WHERE id = ? AND status = 'pending'",
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

func (s *SQLiteStore) CountPendingEmailVerifications(ctx context.Context, email string) (int, error) {
	nowStr := nowUTC()
	var count int
	err := s.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM email_verifications WHERE email = ? AND status = 'pending' AND expires_at > ?",
		email, nowStr,
	).Scan(&count)
	return count, err
}

// --- Password Resets ---

func (s *SQLiteStore) CreatePasswordReset(ctx context.Context, email, code string, expiresAt time.Time) (*PasswordReset, error) {
	now := time.Now().UTC()
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO password_resets (email, code_hash, created_at, expires_at)
		 VALUES (?, ?, ?, ?)`,
		email, hashToken(code), now.Format(time.DateTime), expiresAt.UTC().Format(time.DateTime),
	)
	if err != nil {
		return nil, fmt.Errorf("creating password reset: %w", err)
	}

	id, _ := res.LastInsertId()
	return &PasswordReset{
		ID:        int(id),
		Email:     email,
		Code:      code,
		Status:    "pending",
		CreatedAt: now,
		ExpiresAt: expiresAt.UTC(),
	}, nil
}

func (s *SQLiteStore) GetPendingPasswordReset(ctx context.Context, email, code string) (*PasswordReset, error) {
	nowStr := nowUTC()
	var pr PasswordReset
	var createdAt, expiresAt string
	err := s.db.QueryRowContext(ctx,
		`SELECT id, email, status, created_at, expires_at
		 FROM password_resets
		 WHERE email = ? AND code_hash = ? AND status = 'pending' AND expires_at > ?
		 ORDER BY created_at DESC LIMIT 1`, email, hashToken(code), nowStr,
	).Scan(&pr.ID, &pr.Email, &pr.Status, &createdAt, &expiresAt)
	if err != nil {
		return nil, err
	}
	pr.CreatedAt, _ = time.Parse(time.DateTime, createdAt)
	pr.ExpiresAt, _ = time.Parse(time.DateTime, expiresAt)
	return &pr, nil
}

func (s *SQLiteStore) MarkPasswordResetUsed(ctx context.Context, id int) error {
	res, err := s.db.ExecContext(ctx,
		"UPDATE password_resets SET status = 'used' WHERE id = ? AND status = 'pending'",
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

func (s *SQLiteStore) CountPendingPasswordResets(ctx context.Context, email string) (int, error) {
	nowStr := nowUTC()
	var count int
	err := s.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM password_resets WHERE email = ? AND status = 'pending' AND expires_at > ?",
		email, nowStr,
	).Scan(&count)
	return count, err
}

func (s *SQLiteStore) ExpirePendingPasswordResets(ctx context.Context, before time.Time) (int, error) {
	res, err := s.db.ExecContext(ctx,
		"UPDATE password_resets SET status = 'expired' WHERE status = 'pending' AND expires_at < ?",
		before.UTC().Format(time.DateTime),
	)
	if err != nil {
		return 0, fmt.Errorf("expiring password resets: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// --- OAuth Accounts ---

func (s *SQLiteStore) CreateOAuthAccount(ctx context.Context, userID, provider, providerUserID, email, name, avatarURL string) (*OAuthAccount, error) {
	id := newUUID()
	now := time.Now().UTC()
	nowStr := now.Format(time.DateTime)

	_, err := s.db.ExecContext(ctx,
		`INSERT INTO oauth_accounts (id, user_id, provider, provider_user_id, email, name, avatar_url, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, userID, provider, providerUserID, email, name, avatarURL, nowStr, nowStr,
	)
	if err != nil {
		return nil, fmt.Errorf("creating oauth account: %w", err)
	}

	return &OAuthAccount{
		ID: id, UserID: userID, Provider: provider, ProviderUserID: providerUserID,
		Email: email, Name: name, AvatarURL: avatarURL,
		CreatedAt: now, UpdatedAt: now,
	}, nil
}

func (s *SQLiteStore) GetOAuthAccount(ctx context.Context, provider, providerUserID string) (*OAuthAccount, error) {
	var oa OAuthAccount
	var createdAt, updatedAt string
	var name, avatarURL sql.NullString
	err := s.db.QueryRowContext(ctx,
		`SELECT id, user_id, provider, provider_user_id, email, name, avatar_url, created_at, updated_at
		 FROM oauth_accounts WHERE provider = ? AND provider_user_id = ?`,
		provider, providerUserID,
	).Scan(&oa.ID, &oa.UserID, &oa.Provider, &oa.ProviderUserID, &oa.Email, &name, &avatarURL, &createdAt, &updatedAt)
	if err != nil {
		return nil, err
	}
	oa.Name = name.String
	oa.AvatarURL = avatarURL.String
	oa.CreatedAt, _ = time.Parse(time.DateTime, createdAt)
	oa.UpdatedAt, _ = time.Parse(time.DateTime, updatedAt)
	return &oa, nil
}

func (s *SQLiteStore) GetOAuthAccountByUser(ctx context.Context, userID, provider string) (*OAuthAccount, error) {
	var oa OAuthAccount
	var createdAt, updatedAt string
	var name, avatarURL sql.NullString
	err := s.db.QueryRowContext(ctx,
		`SELECT id, user_id, provider, provider_user_id, email, name, avatar_url, created_at, updated_at
		 FROM oauth_accounts WHERE user_id = ? AND provider = ?`,
		userID, provider,
	).Scan(&oa.ID, &oa.UserID, &oa.Provider, &oa.ProviderUserID, &oa.Email, &name, &avatarURL, &createdAt, &updatedAt)
	if err != nil {
		return nil, err
	}
	oa.Name = name.String
	oa.AvatarURL = avatarURL.String
	oa.CreatedAt, _ = time.Parse(time.DateTime, createdAt)
	oa.UpdatedAt, _ = time.Parse(time.DateTime, updatedAt)
	return &oa, nil
}

func (s *SQLiteStore) ListUserOAuthAccounts(ctx context.Context, userID string) ([]OAuthAccount, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, user_id, provider, provider_user_id, email, name, avatar_url, created_at, updated_at
		 FROM oauth_accounts WHERE user_id = ? ORDER BY provider`,
		userID,
	)
	if err != nil {
		return nil, fmt.Errorf("listing oauth accounts: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var accounts []OAuthAccount
	for rows.Next() {
		var oa OAuthAccount
		var createdAt, updatedAt string
		var name, avatarURL sql.NullString
		if err := rows.Scan(&oa.ID, &oa.UserID, &oa.Provider, &oa.ProviderUserID, &oa.Email, &name, &avatarURL, &createdAt, &updatedAt); err != nil {
			return nil, fmt.Errorf("scanning oauth account: %w", err)
		}
		oa.Name = name.String
		oa.AvatarURL = avatarURL.String
		oa.CreatedAt, _ = time.Parse(time.DateTime, createdAt)
		oa.UpdatedAt, _ = time.Parse(time.DateTime, updatedAt)
		accounts = append(accounts, oa)
	}
	return accounts, rows.Err()
}

func (s *SQLiteStore) DeleteOAuthAccount(ctx context.Context, userID, provider string) error {
	res, err := s.db.ExecContext(ctx,
		"DELETE FROM oauth_accounts WHERE user_id = ? AND provider = ?",
		userID, provider,
	)
	if err != nil {
		return fmt.Errorf("deleting oauth account: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// --- OAuth States ---

func (s *SQLiteStore) CreateOAuthState(ctx context.Context, stateHash, codeVerifier, nonce, redirectURL, mode, userID string, expiresAt time.Time) (*OAuthState, error) {
	id := newUUID()
	now := time.Now().UTC()
	nowStr := now.Format(time.DateTime)

	_, err := s.db.ExecContext(ctx,
		`INSERT INTO oauth_states (id, state_hash, code_verifier, nonce, redirect_url, mode, user_id, created_at, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, stateHash, codeVerifier, nonce, redirectURL, mode, userID, nowStr, expiresAt.UTC().Format(time.DateTime),
	)
	if err != nil {
		return nil, fmt.Errorf("creating oauth state: %w", err)
	}

	return &OAuthState{
		ID: id, StateHash: stateHash, CodeVerifier: codeVerifier, Nonce: nonce,
		RedirectURL: redirectURL, Mode: mode, UserID: userID,
		CreatedAt: now, ExpiresAt: expiresAt.UTC(),
	}, nil
}

func (s *SQLiteStore) GetOAuthStateByHash(ctx context.Context, stateHash string) (*OAuthState, error) {
	var os OAuthState
	var createdAt, expiresAt string
	var nonce, redirectURL, userID sql.NullString
	err := s.db.QueryRowContext(ctx,
		`SELECT id, state_hash, code_verifier, nonce, redirect_url, mode, user_id, created_at, expires_at
		 FROM oauth_states WHERE state_hash = ?`,
		stateHash,
	).Scan(&os.ID, &os.StateHash, &os.CodeVerifier, &nonce, &redirectURL, &os.Mode, &userID, &createdAt, &expiresAt)
	if err != nil {
		return nil, err
	}
	os.Nonce = nonce.String
	os.RedirectURL = redirectURL.String
	os.UserID = userID.String
	os.CreatedAt, _ = time.Parse(time.DateTime, createdAt)
	os.ExpiresAt, _ = time.Parse(time.DateTime, expiresAt)
	return &os, nil
}

func (s *SQLiteStore) DeleteOAuthState(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM oauth_states WHERE id = ?", id)
	return err
}

func (s *SQLiteStore) ExpireOAuthStates(ctx context.Context, before time.Time) (int, error) {
	res, err := s.db.ExecContext(ctx,
		"DELETE FROM oauth_states WHERE expires_at <= ?",
		before.UTC().Format(time.DateTime),
	)
	if err != nil {
		return 0, fmt.Errorf("expiring oauth states: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// --- OAuth User Creation ---

func (s *SQLiteStore) CreateOAuthUser(ctx context.Context, email, role string) (*User, error) {
	id := newUUID()
	now := time.Now().UTC()
	nowStr := now.Format(time.DateTime)

	_, err := s.db.ExecContext(ctx,
		`INSERT INTO users (id, email, password_hash, password_salt, role, is_active, kdf_time, kdf_memory, kdf_threads, created_at, updated_at)
		 VALUES (?, ?, NULL, NULL, ?, 1, 3, 65536, 4, ?, ?)`,
		id, email, role, nowStr, nowStr,
	)
	if err != nil {
		return nil, fmt.Errorf("creating oauth user: %w", err)
	}

	return &User{
		ID: id, Email: email, Role: role, IsActive: true,
		KDFTime: 3, KDFMemory: 65536, KDFThreads: 4,
		CreatedAt: now, UpdatedAt: now,
	}, nil
}

func (s *SQLiteStore) CreateOAuthUserAndAccount(ctx context.Context, email, role, provider, providerUserID, oauthEmail, name, avatarURL string) (*User, *OAuthAccount, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	userID := newUUID()
	oauthAccID := newUUID()
	now := time.Now().UTC()
	nowStr := now.Format(time.DateTime)

	_, err = tx.ExecContext(ctx,
		`INSERT INTO users (id, email, password_hash, password_salt, role, is_active, kdf_time, kdf_memory, kdf_threads, created_at, updated_at)
		 VALUES (?, ?, NULL, NULL, ?, 1, 3, 65536, 4, ?, ?)`,
		userID, email, role, nowStr, nowStr,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("creating oauth user: %w", err)
	}

	_, err = tx.ExecContext(ctx,
		`INSERT INTO oauth_accounts (id, user_id, provider, provider_user_id, email, name, avatar_url, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		oauthAccID, userID, provider, providerUserID, oauthEmail, name, avatarURL, nowStr, nowStr,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("creating oauth account: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, nil, fmt.Errorf("commit: %w", err)
	}

	user := &User{
		ID: userID, Email: email, Role: role, IsActive: true,
		KDFTime: 3, KDFMemory: 65536, KDFThreads: 4,
		CreatedAt: now, UpdatedAt: now,
	}
	oauthAcc := &OAuthAccount{
		ID: oauthAccID, UserID: userID, Provider: provider, ProviderUserID: providerUserID,
		Email: oauthEmail, Name: name, AvatarURL: avatarURL,
		CreatedAt: now, UpdatedAt: now,
	}
	return user, oauthAcc, nil
}

// --- Agents ---

func (s *SQLiteStore) CreateAgent(ctx context.Context, name, createdBy, role string) (*Agent, error) {
	id := newUUID()
	now := time.Now().UTC()
	nowStr := now.Format(time.DateTime)

	_, err := s.db.ExecContext(ctx,
		`INSERT INTO agents (id, name, role, status, created_by, created_at, updated_at)
		 VALUES (?, ?, ?, 'active', ?, ?, ?)`,
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

func (s *SQLiteStore) GetAgentByID(ctx context.Context, id string) (*Agent, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, name, role, status, created_by, created_at, updated_at, revoked_at
		 FROM agents WHERE id = ?`, id,
	)
	ag, err := scanAgent(row)
	if err != nil {
		return nil, err
	}
	ag.Vaults, err = s.ListActorGrants(ctx, ag.ID)
	if err != nil {
		return nil, err
	}
	return ag, nil
}

func (s *SQLiteStore) GetAgentByName(ctx context.Context, name string) (*Agent, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, name, role, status, created_by, created_at, updated_at, revoked_at
		 FROM agents WHERE name = ?`, name,
	)
	ag, err := scanAgent(row)
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
func (s *SQLiteStore) ListAgents(ctx context.Context, vaultID string) ([]Agent, error) {
	if vaultID == "" {
		return nil, fmt.Errorf("vaultID is required; use ListAllAgents for cross-vault listing")
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT a.id, a.name, a.role, a.status, a.created_by, a.created_at, a.updated_at, a.revoked_at
		 FROM agents a
		 JOIN vault_grants vg ON vg.actor_id = a.id AND vg.actor_type = 'agent'
		 WHERE vg.vault_id = ? ORDER BY a.name`, vaultID,
	)
	if err != nil {
		return nil, fmt.Errorf("listing agents: %w", err)
	}

	var agents []Agent
	for rows.Next() {
		ag, err := scanAgentRow(rows)
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
func (s *SQLiteStore) ListAllAgents(ctx context.Context) ([]Agent, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, name, role, status, created_by, created_at, updated_at, revoked_at
		 FROM agents ORDER BY name`,
	)
	if err != nil {
		return nil, fmt.Errorf("listing all agents: %w", err)
	}

	var agents []Agent
	for rows.Next() {
		ag, err := scanAgentRow(rows)
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

func (s *SQLiteStore) RevokeAgent(ctx context.Context, id string) error {
	nowStr := nowUTC()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	res, err := tx.ExecContext(ctx,
		`UPDATE agents SET status = 'revoked', revoked_at = ?, updated_at = ?
		 WHERE id = ? AND status = 'active'`,
		nowStr, nowStr, id,
	)
	if err != nil {
		return fmt.Errorf("revoking agent: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}

	// Cascade: delete all tokens minted for this agent.
	_, err = tx.ExecContext(ctx, "DELETE FROM sessions WHERE agent_id = ?", id)
	if err != nil {
		return fmt.Errorf("deleting agent tokens: %w", err)
	}

	return tx.Commit()
}


func (s *SQLiteStore) RenameAgent(ctx context.Context, id string, newName string) error {
	nowStr := nowUTC()

	res, err := s.db.ExecContext(ctx,
		`UPDATE agents SET name = ?, updated_at = ? WHERE id = ?`,
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

func (s *SQLiteStore) CountAgentTokens(ctx context.Context, agentID string) (int, error) {
	var count int
	nowStr := nowUTC()
	err := s.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM sessions WHERE agent_id = ? AND (expires_at IS NULL OR expires_at > ?)",
		agentID, nowStr,
	).Scan(&count)
	return count, err
}

func (s *SQLiteStore) GetLatestAgentTokenExpiry(ctx context.Context, agentID string) (*time.Time, error) {
	// Check for non-expiring tokens first — they represent "never expires".
	var hasNonExpiring int
	if err := s.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM sessions WHERE agent_id = ? AND expires_at IS NULL",
		agentID,
	).Scan(&hasNonExpiring); err != nil {
		return nil, err
	}
	if hasNonExpiring > 0 {
		return nil, nil // nil = never expires
	}

	var expiresAtStr sql.NullString
	err := s.db.QueryRowContext(ctx,
		"SELECT MAX(expires_at) FROM sessions WHERE agent_id = ? AND expires_at > ?",
		agentID, nowUTC(),
	).Scan(&expiresAtStr)
	if err != nil || !expiresAtStr.Valid {
		return nil, err
	}
	t, err := time.Parse(time.DateTime, expiresAtStr.String)
	if err != nil {
		return nil, err
	}
	t = t.UTC()
	return &t, nil
}

func (s *SQLiteStore) DeleteAgentTokens(ctx context.Context, agentID string) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM sessions WHERE agent_id = ?", agentID)
	if err != nil {
		return fmt.Errorf("deleting agent tokens: %w", err)
	}
	return nil
}

func (s *SQLiteStore) CreateAgentToken(ctx context.Context, agentID string, expiresAt *time.Time) (*Session, error) {
	rawToken := newAgentToken()
	tokenHash := hashSessionToken(rawToken)
	now := time.Now().UTC()

	var expiresAtStr sql.NullString
	if expiresAt != nil {
		expiresAtStr = sql.NullString{String: expiresAt.UTC().Format(time.DateTime), Valid: true}
	}

	_, err := s.db.ExecContext(ctx,
		"INSERT INTO sessions (id, agent_id, expires_at, created_at) VALUES (?, ?, ?, ?)",
		tokenHash, agentID, expiresAtStr, now.Format(time.DateTime),
	)
	if err != nil {
		return nil, fmt.Errorf("creating agent token: %w", err)
	}

	return &Session{ID: rawToken, AgentID: agentID, ExpiresAt: utcTimePtr(expiresAt), CreatedAt: now}, nil
}

func (s *SQLiteStore) CreateRotationInvite(ctx context.Context, agentID, createdBy string, expiresAt time.Time) (*Invite, error) {
	now := time.Now().UTC()
	token := newInviteToken()

	// Use agent's existing name for the invite record.
	var agentName string
	err := s.db.QueryRowContext(ctx, "SELECT name FROM agents WHERE id = ?", agentID).Scan(&agentName)
	if err != nil {
		return nil, fmt.Errorf("looking up agent for rotation: %w", err)
	}

	res, err := s.db.ExecContext(ctx,
		`INSERT INTO invites (token_hash, agent_name, agent_id, status, created_by, created_at, expires_at)
		 VALUES (?, ?, ?, 'pending', ?, ?, ?)`,
		hashToken(token), agentName, agentID, createdBy, now.Format(time.DateTime), expiresAt.UTC().Format(time.DateTime),
	)
	if err != nil {
		return nil, fmt.Errorf("inserting rotation invite: %w", err)
	}

	inviteID, _ := res.LastInsertId()
	return &Invite{
		ID:        int(inviteID),
		Token:     token,
		AgentName: agentName,
		AgentID:   agentID,
		Status:    "pending",
		CreatedBy: createdBy,
		CreatedAt: now,
		ExpiresAt: expiresAt.UTC(),
	}, nil
}

// scanAgent scans a single agent row from a *sql.Row.
// Expected column order: id, name, status, created_by, created_at, updated_at, revoked_at
func scanAgent(row *sql.Row) (*Agent, error) {
	var ag Agent
	var createdAt, updatedAt string
	var revokedAt sql.NullString

	if err := row.Scan(&ag.ID, &ag.Name, &ag.Role,
		&ag.Status, &ag.CreatedBy, &createdAt, &updatedAt, &revokedAt); err != nil {
		return nil, err
	}

	ag.CreatedAt, _ = time.Parse(time.DateTime, createdAt)
	ag.UpdatedAt, _ = time.Parse(time.DateTime, updatedAt)
	if revokedAt.Valid {
		t, _ := time.Parse(time.DateTime, revokedAt.String)
		ag.RevokedAt = &t
	}
	return &ag, nil
}

func scanAgentRow(rows *sql.Rows) (*Agent, error) {
	var ag Agent
	var createdAt, updatedAt string
	var revokedAt sql.NullString

	if err := rows.Scan(&ag.ID, &ag.Name, &ag.Role,
		&ag.Status, &ag.CreatedBy, &createdAt, &updatedAt, &revokedAt); err != nil {
		return nil, err
	}

	ag.CreatedAt, _ = time.Parse(time.DateTime, createdAt)
	ag.UpdatedAt, _ = time.Parse(time.DateTime, updatedAt)
	if revokedAt.Valid {
		t, _ := time.Parse(time.DateTime, revokedAt.String)
		ag.RevokedAt = &t
	}
	return &ag, nil
}


// batchLoadAgentVaultGrants loads vault grants for all agents in a single query.
func (s *SQLiteStore) batchLoadAgentVaultGrants(ctx context.Context, agents []Agent) error {
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

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("batch loading agent vault grants: %w", err)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var g VaultGrant
		var createdAt string
		if err := rows.Scan(&g.ActorID, &g.ActorType, &g.VaultID, &g.VaultName, &g.Role, &createdAt); err != nil {
			return err
		}
		g.CreatedAt, _ = time.Parse(time.DateTime, createdAt)
		for _, idx := range idxMap[g.ActorID] {
			agents[idx].Vaults = append(agents[idx].Vaults, g)
		}
	}
	return rows.Err()
}

func (s *SQLiteStore) UpdateAgentRole(ctx context.Context, agentID, role string) error {
	nowStr := nowUTC()
	res, err := s.db.ExecContext(ctx,
		"UPDATE agents SET role = ?, updated_at = ? WHERE id = ?",
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

func (s *SQLiteStore) CountAllOwners(ctx context.Context) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx,
		`SELECT (SELECT COUNT(*) FROM users WHERE role = 'owner' AND is_active = 1) +
		        (SELECT COUNT(*) FROM agents WHERE role = 'owner' AND status = 'active')`,
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
