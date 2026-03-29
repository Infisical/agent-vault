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

// SQLiteStore implements Store backed by a SQLite database.
type SQLiteStore struct {
	db *sql.DB
}

// Open opens (or creates) a SQLite database at dbPath, configures WAL mode
// and sane defaults, and runs any pending schema migrations.
func Open(dbPath string) (*SQLiteStore, error) {
	dsn := dbPath + "?_pragma=journal_mode(wal)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(on)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("opening sqlite: %w", err)
	}

	db.SetMaxOpenConns(1)

	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("pinging sqlite: %w", err)
	}

	// Restrict database file permissions (SQLite creates with umask default).
	_ = os.Chmod(dbPath, 0600)

	if err := migrate(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("running migrations: %w", err)
	}

	return &SQLiteStore{db: db}, nil
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
		"INSERT INTO broker_configs (id, vault_id, rules_json, created_at, updated_at) VALUES (?, ?, '[]', ?, ?)",
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
	nowStr := time.Now().UTC().Format(time.DateTime)

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
			"INSERT INTO vault_grants (user_id, vault_id, role, created_at) VALUES (?, ?, 'admin', ?) ON CONFLICT(user_id, vault_id) DO UPDATE SET role = excluded.role",
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
	nowStr := time.Now().UTC().Format(time.DateTime)
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
	nowStr := time.Now().UTC().Format(time.DateTime)
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
	res, err := s.db.ExecContext(ctx, "DELETE FROM users WHERE id = ?", userID)
	if err != nil {
		return fmt.Errorf("deleting user: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *SQLiteStore) CountOwners(ctx context.Context) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM users WHERE role = 'owner'").Scan(&count)
	return count, err
}

// --- Vault Grants ---

func (s *SQLiteStore) GrantVaultRole(ctx context.Context, userID, vaultID, role string) error {
	nowStr := time.Now().UTC().Format(time.DateTime)
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO vault_grants (user_id, vault_id, role, created_at) VALUES (?, ?, ?, ?)
		 ON CONFLICT(user_id, vault_id) DO UPDATE SET role = excluded.role`,
		userID, vaultID, role, nowStr,
	)
	if err != nil {
		return fmt.Errorf("granting vault role: %w", err)
	}
	return nil
}

func (s *SQLiteStore) RevokeVaultAccess(ctx context.Context, userID, vaultID string) error {
	res, err := s.db.ExecContext(ctx,
		"DELETE FROM vault_grants WHERE user_id = ? AND vault_id = ?",
		userID, vaultID,
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

func (s *SQLiteStore) ListUserGrants(ctx context.Context, userID string) ([]VaultGrant, error) {
	rows, err := s.db.QueryContext(ctx,
		"SELECT user_id, vault_id, role, created_at FROM vault_grants WHERE user_id = ? ORDER BY created_at",
		userID,
	)
	if err != nil {
		return nil, fmt.Errorf("listing user grants: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var grants []VaultGrant
	for rows.Next() {
		var g VaultGrant
		var createdAt string
		if err := rows.Scan(&g.UserID, &g.VaultID, &g.Role, &createdAt); err != nil {
			return nil, fmt.Errorf("scanning grant: %w", err)
		}
		g.CreatedAt, _ = time.Parse(time.DateTime, createdAt)
		grants = append(grants, g)
	}
	return grants, rows.Err()
}

func (s *SQLiteStore) HasVaultAccess(ctx context.Context, userID, vaultID string) (bool, error) {
	var exists int
	err := s.db.QueryRowContext(ctx,
		"SELECT 1 FROM vault_grants WHERE user_id = ? AND vault_id = ?",
		userID, vaultID,
	).Scan(&exists)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("checking vault access: %w", err)
	}
	return true, nil
}

func (s *SQLiteStore) GetVaultRole(ctx context.Context, userID, vaultID string) (string, error) {
	var role string
	err := s.db.QueryRowContext(ctx,
		"SELECT role FROM vault_grants WHERE user_id = ? AND vault_id = ?",
		userID, vaultID,
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

func (s *SQLiteStore) ListVaultUsers(ctx context.Context, vaultID string) ([]VaultGrant, error) {
	rows, err := s.db.QueryContext(ctx,
		"SELECT user_id, vault_id, role, created_at FROM vault_grants WHERE vault_id = ? ORDER BY created_at",
		vaultID,
	)
	if err != nil {
		return nil, fmt.Errorf("listing vault users: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var grants []VaultGrant
	for rows.Next() {
		var g VaultGrant
		var createdAt string
		if err := rows.Scan(&g.UserID, &g.VaultID, &g.Role, &createdAt); err != nil {
			return nil, fmt.Errorf("scanning grant: %w", err)
		}
		g.CreatedAt, _ = time.Parse(time.DateTime, createdAt)
		grants = append(grants, g)
	}
	return grants, rows.Err()
}

func (s *SQLiteStore) ActivateUser(ctx context.Context, userID string) error {
	nowStr := time.Now().UTC().Format(time.DateTime)
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

	// Return the raw token as ID so the caller can send it to the client.
	return &Session{ID: rawToken, UserID: userID, ExpiresAt: expiresAt.UTC(), CreatedAt: now}, nil
}

func (s *SQLiteStore) CreateScopedSession(ctx context.Context, vaultID, vaultRole string, expiresAt time.Time) (*Session, error) {
	rawToken := newSessionToken()
	tokenHash := hashSessionToken(rawToken)
	now := time.Now().UTC()

	_, err := s.db.ExecContext(ctx,
		"INSERT INTO sessions (id, vault_id, vault_role, expires_at, created_at) VALUES (?, ?, ?, ?, ?)",
		tokenHash, vaultID, vaultRole, expiresAt.UTC().Format(time.DateTime), now.Format(time.DateTime),
	)
	if err != nil {
		return nil, fmt.Errorf("creating scoped session: %w", err)
	}

	return &Session{ID: rawToken, VaultID: vaultID, VaultRole: vaultRole, ExpiresAt: expiresAt.UTC(), CreatedAt: now}, nil
}

func (s *SQLiteStore) GetSession(ctx context.Context, rawToken string) (*Session, error) {
	tokenHash := hashSessionToken(rawToken)
	row := s.db.QueryRowContext(ctx,
		"SELECT id, user_id, vault_id, agent_id, vault_role, expires_at, created_at FROM sessions WHERE id = ?", tokenHash,
	)

	var sess Session
	var storedID string
	var userID, vaultID, agentID, vaultRole sql.NullString
	var expiresAt, createdAt string
	if err := row.Scan(&storedID, &userID, &vaultID, &agentID, &vaultRole, &expiresAt, &createdAt); err != nil {
		return nil, err
	}
	// Return the raw token as ID (not the hash) so callers can reference it.
	sess.ID = rawToken
	sess.UserID = userID.String
	sess.VaultID = vaultID.String
	sess.AgentID = agentID.String
	sess.VaultRole = vaultRole.String
	sess.ExpiresAt, _ = time.Parse(time.DateTime, expiresAt)
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
		"SELECT salt, sentinel, nonce, kdf_time, kdf_memory, kdf_threads, created_at FROM master_key WHERE id = 1",
	)

	var rec MasterKeyRecord
	var createdAt string
	err := row.Scan(&rec.Salt, &rec.Sentinel, &rec.Nonce, &rec.KDFTime, &rec.KDFMemory, &rec.KDFThreads, &createdAt)
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
		"INSERT INTO master_key (id, salt, sentinel, nonce, kdf_time, kdf_memory, kdf_threads) VALUES (1, ?, ?, ?, ?, ?, ?)",
		record.Salt, record.Sentinel, record.Nonce, record.KDFTime, record.KDFMemory, record.KDFThreads,
	)
	if err != nil {
		return fmt.Errorf("setting master key record: %w", err)
	}
	return nil
}

// --- Broker Configs ---

func (s *SQLiteStore) SetBrokerConfig(ctx context.Context, vaultID string, rulesJSON string) (*BrokerConfig, error) {
	id := newUUID()
	now := time.Now().UTC()
	nowStr := now.Format(time.DateTime)

	_, err := s.db.ExecContext(ctx,
		`INSERT INTO broker_configs (id, vault_id, rules_json, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT(vault_id) DO UPDATE SET
		   rules_json = excluded.rules_json,
		   updated_at = excluded.updated_at`,
		id, vaultID, rulesJSON, nowStr, nowStr,
	)
	if err != nil {
		return nil, fmt.Errorf("setting broker config: %w", err)
	}

	return &BrokerConfig{
		ID: id, VaultID: vaultID, RulesJSON: rulesJSON,
		CreatedAt: now, UpdatedAt: now,
	}, nil
}

func (s *SQLiteStore) GetBrokerConfig(ctx context.Context, vaultID string) (*BrokerConfig, error) {
	row := s.db.QueryRowContext(ctx,
		"SELECT id, vault_id, rules_json, created_at, updated_at FROM broker_configs WHERE vault_id = ?",
		vaultID,
	)
	return scanBrokerConfig(row)
}

// --- Proposals ---

const approvalTokenTTL = 24 * time.Hour

func newApprovalToken() string {
	var b [32]byte
	if _, err := io.ReadFull(rand.Reader, b[:]); err != nil {
		panic("crypto/rand: " + err.Error())
	}
	return "av_appr_" + hex.EncodeToString(b[:])
}

func (s *SQLiteStore) CreateProposal(ctx context.Context, vaultID, sessionID, rulesJSON, credentialsJSON, message, userMessage string, credentials map[string]EncryptedCredential) (*Proposal, error) {
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
		`INSERT INTO proposals (id, vault_id, session_id, status, rules_json, credentials_json, message, user_message, approval_token, approval_token_hash, approval_token_expires_at, created_at, updated_at)
		 VALUES (?, ?, ?, 'pending', ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		nextID, vaultID, sessionID, rulesJSON, credentialsJSON, message, userMessage, approvalToken, hashToken(approvalToken), tokenExpiresAtStr, nowStr, nowStr,
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
		Status: "pending", RulesJSON: rulesJSON, CredentialsJSON: credentialsJSON,
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
		`SELECT `+proposalColumns+` FROM proposals WHERE approval_token_hash = ? OR approval_token = ?`,
		hashToken(token), token,
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
	nowStr := time.Now().UTC().Format(time.DateTime)
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
	nowStr := time.Now().UTC().Format(time.DateTime)
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

func (s *SQLiteStore) ApplyProposal(ctx context.Context, vaultID string, proposalID int, mergedRulesJSON string, credentials map[string]EncryptedCredential, deleteCredentialKeys []string) error {
	nowStr := time.Now().UTC().Format(time.DateTime)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// 1. Update broker config with merged rules.
	_, err = tx.ExecContext(ctx,
		`UPDATE broker_configs SET rules_json = ?, updated_at = ? WHERE vault_id = ?`,
		mergedRulesJSON, nowStr, vaultID,
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
const proposalColumns = `id, vault_id, session_id, status, rules_json, credentials_json,
		message, user_message, review_note, reviewed_at,
		approval_token, approval_token_expires_at, created_at, updated_at`

func scanProposalFields(cs *Proposal, scan func(dest ...interface{}) error) error {
	var reviewedAt sql.NullString
	var approvalToken sql.NullString
	var approvalTokenExpiresAt sql.NullString
	var createdAt, updatedAt string
	if err := scan(&cs.ID, &cs.VaultID, &cs.SessionID, &cs.Status,
		&cs.RulesJSON, &cs.CredentialsJSON, &cs.Message, &cs.UserMessage, &cs.ReviewNote,
		&reviewedAt, &approvalToken, &approvalTokenExpiresAt,
		&createdAt, &updatedAt); err != nil {
		return err
	}
	if reviewedAt.Valid {
		cs.ReviewedAt = &reviewedAt.String
	}
	if approvalToken.Valid {
		cs.ApprovalToken = approvalToken.String
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
	if err := row.Scan(&bc.ID, &bc.VaultID, &bc.RulesJSON, &createdAt, &updatedAt); err != nil {
		return nil, err
	}
	bc.CreatedAt, _ = time.Parse(time.DateTime, createdAt)
	bc.UpdatedAt, _ = time.Parse(time.DateTime, updatedAt)
	return &bc, nil
}

// --- Invites ---

// newInviteToken generates a cryptographically random invite token
// with the av_inv_ prefix followed by 64 hex characters (32 random bytes).
func newInviteToken() string {
	var b [32]byte
	if _, err := io.ReadFull(rand.Reader, b[:]); err != nil {
		panic("crypto/rand: " + err.Error())
	}
	return "av_inv_" + hex.EncodeToString(b[:])
}

func (s *SQLiteStore) CreateInvite(ctx context.Context, vaultID, vaultRole, createdBy string, expiresAt time.Time) (*Invite, error) {
	now := time.Now().UTC()
	token := newInviteToken()

	_, err := s.db.ExecContext(ctx,
		`INSERT INTO invites (token, token_hash, vault_id, vault_role, status, created_by, created_at, expires_at)
		 VALUES (?, ?, ?, ?, 'pending', ?, ?, ?)`,
		token, hashToken(token), vaultID, vaultRole, createdBy, now.Format(time.DateTime), expiresAt.UTC().Format(time.DateTime),
	)
	if err != nil {
		return nil, fmt.Errorf("inserting invite: %w", err)
	}

	return &Invite{
		Token:     token,
		VaultID:   vaultID,
		VaultRole: vaultRole,
		Status:    "pending",
		CreatedBy: createdBy,
		CreatedAt: now,
		ExpiresAt: expiresAt.UTC(),
	}, nil
}

func (s *SQLiteStore) GetInviteByToken(ctx context.Context, token string) (*Invite, error) {
	// Look up by hash first, fall back to raw token for pre-migration invites.
	row := s.db.QueryRowContext(ctx,
		`SELECT id, token, vault_id, vault_role, status, session_id, created_by,
		        persistent, agent_name, agent_id,
		        created_at, expires_at, redeemed_at, revoked_at
		 FROM invites WHERE token_hash = ? OR token = ?`, hashToken(token), token,
	)
	return scanInvite(row)
}

func (s *SQLiteStore) ListInvites(ctx context.Context, vaultID, status string) ([]Invite, error) {
	// Lazily expire pending invites that are past their TTL.
	nowStr := time.Now().UTC().Format(time.DateTime)
	_, _ = s.db.ExecContext(ctx,
		`UPDATE invites SET status = 'expired' WHERE vault_id = ? AND status = 'pending' AND expires_at <= ?`,
		vaultID, nowStr,
	)

	var rows *sql.Rows
	var err error
	if status != "" {
		rows, err = s.db.QueryContext(ctx,
			`SELECT id, token, vault_id, vault_role, status, session_id, created_by,
			        persistent, agent_name, agent_id,
			        created_at, expires_at, redeemed_at, revoked_at
			 FROM invites WHERE vault_id = ? AND status = ? ORDER BY created_at DESC`,
			vaultID, status,
		)
	} else {
		rows, err = s.db.QueryContext(ctx,
			`SELECT id, token, vault_id, vault_role, status, session_id, created_by,
			        persistent, agent_name, agent_id,
			        created_at, expires_at, redeemed_at, revoked_at
			 FROM invites WHERE vault_id = ? ORDER BY created_at DESC`,
			vaultID,
		)
	}
	if err != nil {
		return nil, fmt.Errorf("listing invites: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var invites []Invite
	for rows.Next() {
		inv, err := scanInviteRow(rows)
		if err != nil {
			return nil, err
		}
		invites = append(invites, *inv)
	}
	return invites, rows.Err()
}

func (s *SQLiteStore) RedeemInvite(ctx context.Context, token, sessionID string) error {
	nowStr := time.Now().UTC().Format(time.DateTime)

	res, err := s.db.ExecContext(ctx,
		`UPDATE invites SET status = 'redeemed', session_id = ?, redeemed_at = ?
		 WHERE (token_hash = ? OR token = ?) AND status = 'pending' AND expires_at > ?`,
		sessionID, nowStr, hashToken(token), token, nowStr,
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

func (s *SQLiteStore) RevokeInvite(ctx context.Context, token string) error {
	nowStr := time.Now().UTC().Format(time.DateTime)

	res, err := s.db.ExecContext(ctx,
		`UPDATE invites SET status = 'revoked', revoked_at = ?
		 WHERE (token_hash = ? OR token = ?) AND status = 'pending'`,
		nowStr, hashToken(token), token,
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

func (s *SQLiteStore) CountPendingInvites(ctx context.Context, vaultID string) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM invites WHERE vault_id = ? AND status = 'pending'",
		vaultID,
	).Scan(&count)
	return count, err
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
func scanInviteFields(inv *Invite, sessionID, agentName, agentID sql.NullString, persistent int, createdAt, expiresAt string, redeemedAt, revokedAt sql.NullString) {
	inv.SessionID = sessionID.String
	inv.Persistent = persistent != 0
	inv.AgentName = agentName.String
	inv.AgentID = agentID.String
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
}

// scanInvite scans a single invite row from a *sql.Row.
func scanInvite(row *sql.Row) (*Invite, error) {
	var inv Invite
	var sessionID, agentName, agentID sql.NullString
	var persistent int
	var createdAt, expiresAt string
	var redeemedAt, revokedAt sql.NullString

	if err := row.Scan(&inv.ID, &inv.Token, &inv.VaultID, &inv.VaultRole, &inv.Status,
		&sessionID, &inv.CreatedBy, &persistent, &agentName, &agentID,
		&createdAt, &expiresAt, &redeemedAt, &revokedAt); err != nil {
		return nil, err
	}

	scanInviteFields(&inv, sessionID, agentName, agentID, persistent, createdAt, expiresAt, redeemedAt, revokedAt)
	return &inv, nil
}

// scanInviteRow scans a single invite from a *sql.Rows.
func scanInviteRow(rows *sql.Rows) (*Invite, error) {
	var inv Invite
	var sessionID, agentName, agentID sql.NullString
	var persistent int
	var createdAt, expiresAt string
	var redeemedAt, revokedAt sql.NullString

	if err := rows.Scan(&inv.ID, &inv.Token, &inv.VaultID, &inv.VaultRole, &inv.Status,
		&sessionID, &inv.CreatedBy, &persistent, &agentName, &agentID,
		&createdAt, &expiresAt, &redeemedAt, &revokedAt); err != nil {
		return nil, err
	}

	scanInviteFields(&inv, sessionID, agentName, agentID, persistent, createdAt, expiresAt, redeemedAt, revokedAt)
	return &inv, nil
}

// --- Vault Invites ---

func newVaultInviteToken() string {
	var b [32]byte
	if _, err := io.ReadFull(rand.Reader, b[:]); err != nil {
		panic("crypto/rand: " + err.Error())
	}
	return "av_uinv_" + hex.EncodeToString(b[:])
}

func (s *SQLiteStore) CreateVaultInvite(ctx context.Context, email, vaultID, vaultRole, createdBy string, expiresAt time.Time) (*VaultInvite, error) {
	now := time.Now().UTC()
	token := newVaultInviteToken()

	_, err := s.db.ExecContext(ctx,
		`INSERT INTO vault_invites (token, token_hash, email, vault_id, vault_role, created_by, created_at, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		token, hashToken(token), email, vaultID, vaultRole, createdBy, now.Format(time.DateTime), expiresAt.UTC().Format(time.DateTime),
	)
	if err != nil {
		return nil, fmt.Errorf("inserting vault invite: %w", err)
	}

	return &VaultInvite{
		Token:     token,
		Email:     email,
		VaultID:   vaultID,
		VaultRole: vaultRole,
		Status:    "pending",
		CreatedBy: createdBy,
		CreatedAt: now,
		ExpiresAt: expiresAt.UTC(),
	}, nil
}

func (s *SQLiteStore) GetVaultInviteByToken(ctx context.Context, token string) (*VaultInvite, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, token, email, vault_id, vault_role, status, created_by,
		        created_at, expires_at, accepted_at
		 FROM vault_invites WHERE token_hash = ? OR token = ?`, hashToken(token), token,
	)
	return scanVaultInvite(row)
}

func (s *SQLiteStore) GetPendingVaultInviteByEmailAndVault(ctx context.Context, email, vaultID string) (*VaultInvite, error) {
	nowStr := time.Now().UTC().Format(time.DateTime)
	row := s.db.QueryRowContext(ctx,
		`SELECT id, token, email, vault_id, vault_role, status, created_by,
		        created_at, expires_at, accepted_at
		 FROM vault_invites WHERE email = ? AND vault_id = ? AND status = 'pending' AND expires_at > ?
		 ORDER BY created_at DESC LIMIT 1`, email, vaultID, nowStr,
	)
	return scanVaultInvite(row)
}

func (s *SQLiteStore) ListVaultInvites(ctx context.Context, vaultID, status string) ([]VaultInvite, error) {
	var rows *sql.Rows
	var err error
	if status != "" {
		rows, err = s.db.QueryContext(ctx,
			`SELECT id, token, email, vault_id, vault_role, status, created_by,
			        created_at, expires_at, accepted_at
			 FROM vault_invites WHERE vault_id = ? AND status = ? ORDER BY created_at DESC`, vaultID, status,
		)
	} else {
		rows, err = s.db.QueryContext(ctx,
			`SELECT id, token, email, vault_id, vault_role, status, created_by,
			        created_at, expires_at, accepted_at
			 FROM vault_invites WHERE vault_id = ? ORDER BY created_at DESC`, vaultID,
		)
	}
	if err != nil {
		return nil, fmt.Errorf("listing vault invites: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var invites []VaultInvite
	for rows.Next() {
		inv, err := scanVaultInviteRow(rows)
		if err != nil {
			return nil, err
		}
		invites = append(invites, *inv)
	}
	return invites, rows.Err()
}

func (s *SQLiteStore) AcceptVaultInvite(ctx context.Context, token string) error {
	nowStr := time.Now().UTC().Format(time.DateTime)

	res, err := s.db.ExecContext(ctx,
		`UPDATE vault_invites SET status = 'accepted', accepted_at = ?
		 WHERE (token_hash = ? OR token = ?) AND status = 'pending' AND expires_at > ?`,
		nowStr, hashToken(token), token, nowStr,
	)
	if err != nil {
		return fmt.Errorf("accepting vault invite: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *SQLiteStore) RevokeVaultInvite(ctx context.Context, token, vaultID string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE vault_invites SET status = 'revoked'
		 WHERE (token_hash = ? OR token = ?) AND vault_id = ? AND status = 'pending'`,
		hashToken(token), token, vaultID,
	)
	if err != nil {
		return fmt.Errorf("revoking vault invite: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *SQLiteStore) UpdateVaultInviteRole(ctx context.Context, token, vaultID, newRole string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE vault_invites SET vault_role = ?
		 WHERE (token_hash = ? OR token = ?) AND vault_id = ? AND status = 'pending'`,
		newRole, hashToken(token), token, vaultID,
	)
	if err != nil {
		return fmt.Errorf("updating vault invite role: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *SQLiteStore) CountPendingVaultInvites(ctx context.Context, vaultID string) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM vault_invites WHERE vault_id = ? AND status = 'pending'",
		vaultID,
	).Scan(&count)
	return count, err
}

func scanVaultInvite(row *sql.Row) (*VaultInvite, error) {
	var inv VaultInvite
	var createdAt, expiresAt string
	var acceptedAt sql.NullString

	if err := row.Scan(&inv.ID, &inv.Token, &inv.Email, &inv.VaultID, &inv.VaultRole, &inv.Status,
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

func scanVaultInviteRow(rows *sql.Rows) (*VaultInvite, error) {
	var inv VaultInvite
	var createdAt, expiresAt string
	var acceptedAt sql.NullString

	if err := rows.Scan(&inv.ID, &inv.Token, &inv.Email, &inv.VaultID, &inv.VaultRole, &inv.Status,
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
		`INSERT INTO email_verifications (email, code, code_hash, created_at, expires_at)
		 VALUES (?, ?, ?, ?, ?)`,
		email, code, hashToken(code), now.Format(time.DateTime), expiresAt.UTC().Format(time.DateTime),
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
	nowStr := time.Now().UTC().Format(time.DateTime)
	var ev EmailVerification
	var createdAt, expiresAt string
	err := s.db.QueryRowContext(ctx,
		`SELECT id, email, code, status, created_at, expires_at
		 FROM email_verifications
		 WHERE email = ? AND (code_hash = ? OR code = ?) AND status = 'pending' AND expires_at > ?
		 ORDER BY created_at DESC LIMIT 1`, email, hashToken(code), code, nowStr,
	).Scan(&ev.ID, &ev.Email, &ev.Code, &ev.Status, &createdAt, &expiresAt)
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
	nowStr := time.Now().UTC().Format(time.DateTime)
	var count int
	err := s.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM email_verifications WHERE email = ? AND status = 'pending' AND expires_at > ?",
		email, nowStr,
	).Scan(&count)
	return count, err
}

// --- Agents ---

func (s *SQLiteStore) CreateAgent(ctx context.Context, name, vaultID string, tokenHash, tokenSalt []byte, tokenPrefix, vaultRole, createdBy string) (*Agent, error) {
	id := newUUID()
	now := time.Now().UTC()
	nowStr := now.Format(time.DateTime)

	_, err := s.db.ExecContext(ctx,
		`INSERT INTO agents (id, name, vault_id, service_token_hash, service_token_salt, service_token_prefix, vault_role, status, created_by, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?)`,
		id, name, vaultID, tokenHash, tokenSalt, tokenPrefix, vaultRole, createdBy, nowStr, nowStr,
	)
	if err != nil {
		return nil, fmt.Errorf("creating agent: %w", err)
	}

	return &Agent{
		ID:                 id,
		Name:               name,
		VaultID:            vaultID,
		ServiceTokenHash:   tokenHash,
		ServiceTokenSalt:   tokenSalt,
		ServiceTokenPrefix: tokenPrefix,
		VaultRole:          vaultRole,
		Status:             "active",
		CreatedBy:          createdBy,
		CreatedAt:          now,
		UpdatedAt:          now,
	}, nil
}

func (s *SQLiteStore) GetAgentByID(ctx context.Context, id string) (*Agent, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, name, vault_id, service_token_hash, service_token_salt, service_token_prefix,
		        vault_role, status, created_by, created_at, updated_at, revoked_at
		 FROM agents WHERE id = ?`, id,
	)
	return scanAgent(row)
}

func (s *SQLiteStore) GetAgentByName(ctx context.Context, name string) (*Agent, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, name, vault_id, service_token_hash, service_token_salt, service_token_prefix,
		        vault_role, status, created_by, created_at, updated_at, revoked_at
		 FROM agents WHERE name = ?`, name,
	)
	return scanAgent(row)
}

func (s *SQLiteStore) GetAgentByTokenPrefix(ctx context.Context, prefix string) (*Agent, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, name, vault_id, service_token_hash, service_token_salt, service_token_prefix,
		        vault_role, status, created_by, created_at, updated_at, revoked_at
		 FROM agents WHERE service_token_prefix = ? AND status = 'active'`, prefix,
	)
	return scanAgent(row)
}

func (s *SQLiteStore) ListAgents(ctx context.Context, vaultID string) ([]Agent, error) {
	var rows *sql.Rows
	var err error
	if vaultID != "" {
		rows, err = s.db.QueryContext(ctx,
			`SELECT id, name, vault_id, service_token_hash, service_token_salt, service_token_prefix,
			        vault_role, status, created_by, created_at, updated_at, revoked_at
			 FROM agents WHERE vault_id = ? ORDER BY name`, vaultID,
		)
	} else {
		rows, err = s.db.QueryContext(ctx,
			`SELECT id, name, vault_id, service_token_hash, service_token_salt, service_token_prefix,
			        vault_role, status, created_by, created_at, updated_at, revoked_at
			 FROM agents ORDER BY name`,
		)
	}
	if err != nil {
		return nil, fmt.Errorf("listing agents: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var agents []Agent
	for rows.Next() {
		ag, err := scanAgentRow(rows)
		if err != nil {
			return nil, err
		}
		agents = append(agents, *ag)
	}
	return agents, rows.Err()
}

func (s *SQLiteStore) RevokeAgent(ctx context.Context, id string) error {
	nowStr := time.Now().UTC().Format(time.DateTime)

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

	// Cascade: delete all sessions minted by this agent.
	_, err = tx.ExecContext(ctx, "DELETE FROM sessions WHERE agent_id = ?", id)
	if err != nil {
		return fmt.Errorf("deleting agent sessions: %w", err)
	}

	return tx.Commit()
}

func (s *SQLiteStore) UpdateAgentServiceToken(ctx context.Context, id string, tokenHash, tokenSalt []byte, tokenPrefix string) error {
	nowStr := time.Now().UTC().Format(time.DateTime)

	res, err := s.db.ExecContext(ctx,
		`UPDATE agents SET service_token_hash = ?, service_token_salt = ?, service_token_prefix = ?, updated_at = ?
		 WHERE id = ? AND status = 'active'`,
		tokenHash, tokenSalt, tokenPrefix, nowStr, id,
	)
	if err != nil {
		return fmt.Errorf("updating agent service token: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *SQLiteStore) UpdateAgentVaultRole(ctx context.Context, id, role string) error {
	nowStr := time.Now().UTC().Format(time.DateTime)

	res, err := s.db.ExecContext(ctx,
		`UPDATE agents SET vault_role = ?, updated_at = ? WHERE id = ? AND status = 'active'`,
		role, nowStr, id,
	)
	if err != nil {
		return fmt.Errorf("updating agent vault role: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *SQLiteStore) RenameAgent(ctx context.Context, id string, newName string) error {
	nowStr := time.Now().UTC().Format(time.DateTime)

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

func (s *SQLiteStore) CountAgentSessions(ctx context.Context, agentID string) (int, error) {
	var count int
	nowStr := time.Now().UTC().Format(time.DateTime)
	err := s.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM sessions WHERE agent_id = ? AND expires_at > ?",
		agentID, nowStr,
	).Scan(&count)
	return count, err
}

func (s *SQLiteStore) GetLatestAgentSessionExpiry(ctx context.Context, agentID string) (*time.Time, error) {
	var expiresAtStr sql.NullString
	err := s.db.QueryRowContext(ctx,
		"SELECT MAX(expires_at) FROM sessions WHERE agent_id = ? AND expires_at > ?",
		agentID, time.Now().UTC().Format(time.DateTime),
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

func (s *SQLiteStore) DeleteAgentSessions(ctx context.Context, agentID string) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM sessions WHERE agent_id = ?", agentID)
	if err != nil {
		return fmt.Errorf("deleting agent sessions: %w", err)
	}
	return nil
}

func (s *SQLiteStore) CreateAgentSession(ctx context.Context, agentID, vaultID, vaultRole string, expiresAt time.Time) (*Session, error) {
	rawToken := newSessionToken()
	tokenHash := hashSessionToken(rawToken)
	now := time.Now().UTC()

	_, err := s.db.ExecContext(ctx,
		"INSERT INTO sessions (id, vault_id, agent_id, vault_role, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		tokenHash, vaultID, agentID, vaultRole, expiresAt.UTC().Format(time.DateTime), now.Format(time.DateTime),
	)
	if err != nil {
		return nil, fmt.Errorf("creating agent session: %w", err)
	}

	return &Session{ID: rawToken, VaultID: vaultID, AgentID: agentID, VaultRole: vaultRole, ExpiresAt: expiresAt.UTC(), CreatedAt: now}, nil
}

func (s *SQLiteStore) CreatePersistentInvite(ctx context.Context, vaultID, vaultRole, createdBy string, agentName string, expiresAt time.Time) (*Invite, error) {
	now := time.Now().UTC()
	token := newInviteToken()

	var agName sql.NullString
	if agentName != "" {
		agName = sql.NullString{String: agentName, Valid: true}
	}

	_, err := s.db.ExecContext(ctx,
		`INSERT INTO invites (token, token_hash, vault_id, vault_role, status, created_by, persistent, agent_name, created_at, expires_at)
		 VALUES (?, ?, ?, ?, 'pending', ?, 1, ?, ?, ?)`,
		token, hashToken(token), vaultID, vaultRole, createdBy, agName, now.Format(time.DateTime), expiresAt.UTC().Format(time.DateTime),
	)
	if err != nil {
		return nil, fmt.Errorf("inserting persistent invite: %w", err)
	}

	return &Invite{
		Token:      token,
		VaultID:    vaultID,
		VaultRole:  vaultRole,
		Status:     "pending",
		CreatedBy:  createdBy,
		Persistent: true,
		AgentName:  agentName,
		CreatedAt:  now,
		ExpiresAt:  expiresAt.UTC(),
	}, nil
}

func (s *SQLiteStore) CreateRotationInvite(ctx context.Context, agentID, vaultID, createdBy string, expiresAt time.Time) (*Invite, error) {
	now := time.Now().UTC()
	token := newInviteToken()

	_, err := s.db.ExecContext(ctx,
		`INSERT INTO invites (token, token_hash, vault_id, status, created_by, persistent, agent_id, created_at, expires_at)
		 VALUES (?, ?, ?, 'pending', ?, 1, ?, ?, ?)`,
		token, hashToken(token), vaultID, createdBy, agentID, now.Format(time.DateTime), expiresAt.UTC().Format(time.DateTime),
	)
	if err != nil {
		return nil, fmt.Errorf("inserting rotation invite: %w", err)
	}

	return &Invite{
		Token:       token,
		VaultID: vaultID,
		Status:      "pending",
		CreatedBy:   createdBy,
		Persistent:  true,
		AgentID:     agentID,
		CreatedAt:   now,
		ExpiresAt:   expiresAt.UTC(),
	}, nil
}

func scanAgent(row *sql.Row) (*Agent, error) {
	var ag Agent
	var createdAt, updatedAt string
	var revokedAt sql.NullString

	if err := row.Scan(&ag.ID, &ag.Name, &ag.VaultID,
		&ag.ServiceTokenHash, &ag.ServiceTokenSalt, &ag.ServiceTokenPrefix,
		&ag.VaultRole, &ag.Status, &ag.CreatedBy, &createdAt, &updatedAt, &revokedAt); err != nil {
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

	if err := rows.Scan(&ag.ID, &ag.Name, &ag.VaultID,
		&ag.ServiceTokenHash, &ag.ServiceTokenSalt, &ag.ServiceTokenPrefix,
		&ag.VaultRole, &ag.Status, &ag.CreatedBy, &createdAt, &updatedAt, &revokedAt); err != nil {
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

// newSessionToken generates a 256-bit cryptographically random session token
// with an av_sess_ prefix followed by 64 hex characters.
func newSessionToken() string {
	var b [32]byte
	if _, err := io.ReadFull(rand.Reader, b[:]); err != nil {
		panic("crypto/rand: " + err.Error())
	}
	return "av_sess_" + hex.EncodeToString(b[:])
}
