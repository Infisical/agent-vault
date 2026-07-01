package store

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"
)

// TableCount holds the count of rows copied for a single table.
type TableCount struct {
	Table string
	Count int
}

// CountSourceTables returns per-table row counts from the source database
// without copying anything. Useful for --dry-run previews.
func CountSourceTables(src *SQLStore) ([]TableCount, error) {
	tables := []string{
		"instance_settings",
		"master_key",
		"vaults",
		"vault_settings",
		"users",
		"agents",
		"vault_grants",
		"credentials",
		"credential_oauth",
		"credential_oauth_states",
		"broker_configs",
		"sessions",
		"proposals",
		"proposal_credentials",
		"user_invites",
		"user_invite_vaults",
		"email_verifications",
		"password_resets",
		"vault_credential_stores",
		"dynamic_secret_leases",
		"request_logs",
		"ca_state",
	}

	var counts []TableCount
	for _, tbl := range tables {
		var n int
		err := src.db.QueryRow(fmt.Sprintf("SELECT COUNT(*) FROM %s", tbl)).Scan(&n)
		if err != nil {
			// Table may not exist (e.g. ca_state on older SQLite databases).
			n = 0
		}
		counts = append(counts, TableCount{Table: tbl, Count: n})
	}
	return counts, nil
}

// CountDestinationData checks whether the destination database contains any
// user-created data beyond the baseline schema seed (the default vault and
// its broker_config). Returns a non-empty description of what was found,
// or empty string if the destination is clean.
func CountDestinationData(dst *SQLStore) (string, error) {
	checks := []struct {
		label string
		query string
		args  []interface{}
	}{
		{"vaults", dst.dialect.Rebind("SELECT COUNT(*) FROM vaults WHERE id != ?"), []interface{}{"00000000-0000-0000-0000-000000000000"}},
		{"users", "SELECT COUNT(*) FROM users", nil},
		{"agents", "SELECT COUNT(*) FROM agents", nil},
		{"master_key", "SELECT COUNT(*) FROM master_key", nil},
		{"sessions", "SELECT COUNT(*) FROM sessions", nil},
		{"credentials", "SELECT COUNT(*) FROM credentials", nil},
	}
	for _, c := range checks {
		var n int
		var err error
		if c.args != nil {
			err = dst.db.QueryRow(c.query, c.args...).Scan(&n)
		} else {
			err = dst.db.QueryRow(c.query).Scan(&n)
		}
		if err != nil {
			return "", fmt.Errorf("checking %s: %w", c.label, err)
		}
		if n > 0 {
			return fmt.Sprintf("%d %s", n, c.label), nil
		}
	}
	return "", nil
}

// MigrateData copies all data from src (SQLite) to dst (Postgres) in
// foreign-key dependency order. Both stores must already be open and
// fully migrated. The caller should ensure that dst is empty (aside from
// the seeded default vault row).
//
// progressFn is called with (tableName, rowCount) after each table is copied.
func MigrateData(ctx context.Context, src, dst *SQLStore, progressFn func(table string, rows int)) error {
	// Use a single Postgres transaction for the entire copy so we get
	// atomic all-or-nothing semantics. Tables are copied in FK
	// dependency order so referential integrity is maintained.
	tx, err := dst.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("beginning destination transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Copy each table in FK dependency order.
	type copyFunc func(ctx context.Context, src *SQLStore, tx *sql.Tx, dstDialect Dialect) (int, error)

	steps := []struct {
		name string
		fn   copyFunc
	}{
		{"instance_settings", copyInstanceSettings},
		{"master_key", copyMasterKey},
		{"vaults", copyVaults},
		{"vault_settings", copyVaultSettings},
		{"users", copyUsers},
		{"agents", copyAgents},
		{"vault_grants", copyVaultGrants},
		{"credentials", copyCredentials},
		{"credential_oauth", copyCredentialOAuth},
		{"credential_oauth_states", copyCredentialOAuthStates},
		{"broker_configs", copyBrokerConfigs},
		{"sessions", copySessions},
		{"proposals", copyProposals},
		{"proposal_credentials", copyProposalCredentials},
		{"user_invites", copyUserInvites},
		{"user_invite_vaults", copyUserInviteVaults},
		{"email_verifications", copyEmailVerifications},
		{"password_resets", copyPasswordResets},
		{"vault_credential_stores", copyVaultCredentialStores},
		{"dynamic_secret_leases", copyDynamicSecretLeases},
		{"request_logs", copyRequestLogs},
		{"ca_state", copyCAState},
	}

	for _, step := range steps {
		n, err := step.fn(ctx, src, tx, dst.dialect)
		if err != nil {
			return fmt.Errorf("copying %s: %w", step.name, err)
		}
		if progressFn != nil {
			progressFn(step.name, n)
		}
	}

	// Update Postgres sequences for SERIAL columns so new inserts get the
	// correct next value.
	seqUpdates := []struct {
		seq   string
		table string
	}{
		{"email_verifications_id_seq", "email_verifications"},
		{"password_resets_id_seq", "password_resets"},
		{"user_invites_id_seq", "user_invites"},
		{"request_logs_id_seq", "request_logs"},
	}
	for _, su := range seqUpdates {
		var maxID sql.NullInt64
		if err := tx.QueryRowContext(ctx, fmt.Sprintf("SELECT MAX(id) FROM %s", su.table)).Scan(&maxID); err != nil {
			return fmt.Errorf("querying max id for %s: %w", su.table, err)
		}
		if maxID.Valid && maxID.Int64 > 0 {
			_, err := tx.ExecContext(ctx, fmt.Sprintf(
				"SELECT setval('%s', %d)",
				su.seq, maxID.Int64,
			))
			if err != nil {
				return fmt.Errorf("updating sequence %s: %w", su.seq, err)
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("committing migration transaction: %w", err)
	}

	return nil
}

// --- Per-table copy helpers ---

// scanTime reads a timestamp value from a SQLite row and formats it for the
// destination dialect. Returns nil for nil (NULL) source values.
func convertTime(src interface{}, srcDialect, dstDialect Dialect) (interface{}, error) {
	if src == nil {
		return nil, nil
	}
	t, err := srcDialect.ScanTime(src)
	if err != nil {
		return nil, err
	}
	return dstDialect.FormatTime(t), nil
}

// convertBool reads a boolean value from a SQLite row and formats it for the
// destination dialect. Coalesces nil to false (handles nullable SQLite
// INTEGER columns mapped to NOT NULL BOOLEAN in Postgres).
func convertBool(src interface{}, srcDialect, dstDialect Dialect) (interface{}, error) {
	if src == nil {
		return dstDialect.BoolVal(false), nil
	}
	b, err := srcDialect.ScanBool(src)
	if err != nil {
		return nil, err
	}
	return dstDialect.BoolVal(b), nil
}

const defaultVaultID = "00000000-0000-0000-0000-000000000000"

func copyInstanceSettings(ctx context.Context, src *SQLStore, tx *sql.Tx, dstDialect Dialect) (int, error) {
	rows, err := src.db.QueryContext(ctx, "SELECT key, value, updated_at FROM instance_settings")
	if err != nil {
		return 0, err
	}
	defer func() { _ = rows.Close() }()

	n := 0
	for rows.Next() {
		var key, value string
		var updatedAt interface{}
		if err := rows.Scan(&key, &value, &updatedAt); err != nil {
			return n, err
		}
		ts, err := convertTime(updatedAt, src.dialect, dstDialect)
		if err != nil {
			return n, fmt.Errorf("converting updated_at: %w", err)
		}
		_, err = tx.ExecContext(ctx,
			dstDialect.Rebind("INSERT INTO instance_settings (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = EXCLUDED.updated_at"),
			key, value, ts,
		)
		if err != nil {
			return n, err
		}
		n++
	}
	return n, rows.Err()
}

func copyMasterKey(ctx context.Context, src *SQLStore, tx *sql.Tx, dstDialect Dialect) (int, error) {
	rows, err := src.db.QueryContext(ctx,
		"SELECT id, sentinel, sentinel_nonce, dek_ciphertext, dek_nonce, dek_plaintext, salt, kdf_time, kdf_memory, kdf_threads, created_at FROM master_key")
	if err != nil {
		return 0, err
	}
	defer func() { _ = rows.Close() }()

	n := 0
	for rows.Next() {
		var id int
		var sentinel, sentinelNonce, dekCT, dekNonce, dekPlain, salt []byte
		var kdfTime, kdfMemory, kdfThreads interface{}
		var createdAt interface{}
		if err := rows.Scan(&id, &sentinel, &sentinelNonce, &dekCT, &dekNonce, &dekPlain, &salt, &kdfTime, &kdfMemory, &kdfThreads, &createdAt); err != nil {
			return n, err
		}
		ts, err := convertTime(createdAt, src.dialect, dstDialect)
		if err != nil {
			return n, fmt.Errorf("converting created_at: %w", err)
		}
		_, err = tx.ExecContext(ctx,
			dstDialect.Rebind("INSERT INTO master_key (id, sentinel, sentinel_nonce, dek_ciphertext, dek_nonce, dek_plaintext, salt, kdf_time, kdf_memory, kdf_threads, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"),
			id, sentinel, sentinelNonce, dekCT, dekNonce, dekPlain, salt, kdfTime, kdfMemory, kdfThreads, ts,
		)
		if err != nil {
			return n, err
		}
		n++
	}
	return n, rows.Err()
}

func copyVaults(ctx context.Context, src *SQLStore, tx *sql.Tx, dstDialect Dialect) (int, error) {
	rows, err := src.db.QueryContext(ctx, "SELECT id, name, created_at, updated_at FROM vaults")
	if err != nil {
		return 0, err
	}
	defer func() { _ = rows.Close() }()

	n := 0
	for rows.Next() {
		var id, name string
		var createdAt, updatedAt interface{}
		if err := rows.Scan(&id, &name, &createdAt, &updatedAt); err != nil {
			return n, err
		}
		ca, err := convertTime(createdAt, src.dialect, dstDialect)
		if err != nil {
			return n, fmt.Errorf("converting created_at: %w", err)
		}
		ua, err := convertTime(updatedAt, src.dialect, dstDialect)
		if err != nil {
			return n, fmt.Errorf("converting updated_at: %w", err)
		}
		if id == defaultVaultID {
			// The Postgres baseline already seeds this row; update it with
			// the source data so timestamps and name match.
			_, err = tx.ExecContext(ctx,
				dstDialect.Rebind("UPDATE vaults SET name = ?, created_at = ?, updated_at = ? WHERE id = ?"),
				name, ca, ua, id,
			)
		} else {
			_, err = tx.ExecContext(ctx,
				dstDialect.Rebind("INSERT INTO vaults (id, name, created_at, updated_at) VALUES (?, ?, ?, ?)"),
				id, name, ca, ua,
			)
		}
		if err != nil {
			return n, err
		}
		n++
	}
	return n, rows.Err()
}

func copyVaultSettings(ctx context.Context, src *SQLStore, tx *sql.Tx, dstDialect Dialect) (int, error) {
	rows, err := src.db.QueryContext(ctx, "SELECT vault_id, key, value, updated_at FROM vault_settings")
	if err != nil {
		return 0, err
	}
	defer func() { _ = rows.Close() }()

	n := 0
	for rows.Next() {
		var vaultID, key, value string
		var updatedAt interface{}
		if err := rows.Scan(&vaultID, &key, &value, &updatedAt); err != nil {
			return n, err
		}
		ts, err := convertTime(updatedAt, src.dialect, dstDialect)
		if err != nil {
			return n, fmt.Errorf("converting updated_at: %w", err)
		}
		_, err = tx.ExecContext(ctx,
			dstDialect.Rebind("INSERT INTO vault_settings (vault_id, key, value, updated_at) VALUES (?, ?, ?, ?)"),
			vaultID, key, value, ts,
		)
		if err != nil {
			return n, err
		}
		n++
	}
	return n, rows.Err()
}

func copyUsers(ctx context.Context, src *SQLStore, tx *sql.Tx, dstDialect Dialect) (int, error) {
	rows, err := src.db.QueryContext(ctx,
		"SELECT id, email, password_hash, password_salt, role, created_at, updated_at, kdf_time, kdf_memory, kdf_threads, is_active FROM users")
	if err != nil {
		return 0, err
	}
	defer func() { _ = rows.Close() }()

	n := 0
	for rows.Next() {
		var id, email, role string
		var pwHash, pwSalt []byte
		var kdfTime, kdfMemory, kdfThreads int
		var createdAt, updatedAt, isActive interface{}
		if err := rows.Scan(&id, &email, &pwHash, &pwSalt, &role, &createdAt, &updatedAt, &kdfTime, &kdfMemory, &kdfThreads, &isActive); err != nil {
			return n, err
		}
		ca, err := convertTime(createdAt, src.dialect, dstDialect)
		if err != nil {
			return n, fmt.Errorf("converting created_at: %w", err)
		}
		ua, err := convertTime(updatedAt, src.dialect, dstDialect)
		if err != nil {
			return n, fmt.Errorf("converting updated_at: %w", err)
		}
		boolVal, err := convertBool(isActive, src.dialect, dstDialect)
		if err != nil {
			return n, fmt.Errorf("converting is_active: %w", err)
		}
		_, err = tx.ExecContext(ctx,
			dstDialect.Rebind("INSERT INTO users (id, email, password_hash, password_salt, role, created_at, updated_at, kdf_time, kdf_memory, kdf_threads, is_active) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"),
			id, email, pwHash, pwSalt, role, ca, ua, kdfTime, kdfMemory, kdfThreads, boolVal,
		)
		if err != nil {
			return n, err
		}
		n++
	}
	return n, rows.Err()
}

func copyAgents(ctx context.Context, src *SQLStore, tx *sql.Tx, dstDialect Dialect) (int, error) {
	rows, err := src.db.QueryContext(ctx,
		"SELECT id, name, status, created_by, created_at, updated_at, revoked_at, role FROM agents")
	if err != nil {
		return 0, err
	}
	defer func() { _ = rows.Close() }()

	n := 0
	for rows.Next() {
		var id, name, status, createdBy, role string
		var createdAt, updatedAt, revokedAt interface{}
		if err := rows.Scan(&id, &name, &status, &createdBy, &createdAt, &updatedAt, &revokedAt, &role); err != nil {
			return n, err
		}
		ca, err := convertTime(createdAt, src.dialect, dstDialect)
		if err != nil {
			return n, fmt.Errorf("converting created_at: %w", err)
		}
		ua, err := convertTime(updatedAt, src.dialect, dstDialect)
		if err != nil {
			return n, fmt.Errorf("converting updated_at: %w", err)
		}
		ra, err := convertTime(revokedAt, src.dialect, dstDialect)
		if err != nil {
			return n, fmt.Errorf("converting revoked_at: %w", err)
		}
		_, err = tx.ExecContext(ctx,
			dstDialect.Rebind("INSERT INTO agents (id, name, status, created_by, created_at, updated_at, revoked_at, role) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"),
			id, name, status, createdBy, ca, ua, ra, role,
		)
		if err != nil {
			return n, err
		}
		n++
	}
	return n, rows.Err()
}

func copyVaultGrants(ctx context.Context, src *SQLStore, tx *sql.Tx, dstDialect Dialect) (int, error) {
	rows, err := src.db.QueryContext(ctx,
		"SELECT actor_id, actor_type, vault_id, role, created_at FROM vault_grants")
	if err != nil {
		return 0, err
	}
	defer func() { _ = rows.Close() }()

	n := 0
	for rows.Next() {
		var actorID, actorType, vaultID, role string
		var createdAt interface{}
		if err := rows.Scan(&actorID, &actorType, &vaultID, &role, &createdAt); err != nil {
			return n, err
		}
		ca, err := convertTime(createdAt, src.dialect, dstDialect)
		if err != nil {
			return n, fmt.Errorf("converting created_at: %w", err)
		}
		_, err = tx.ExecContext(ctx,
			dstDialect.Rebind("INSERT INTO vault_grants (actor_id, actor_type, vault_id, role, created_at) VALUES (?, ?, ?, ?, ?)"),
			actorID, actorType, vaultID, role, ca,
		)
		if err != nil {
			return n, err
		}
		n++
	}
	return n, rows.Err()
}

func copyCredentials(ctx context.Context, src *SQLStore, tx *sql.Tx, dstDialect Dialect) (int, error) {
	rows, err := src.db.QueryContext(ctx,
		"SELECT id, vault_id, key, type, ciphertext, nonce, created_at, updated_at FROM credentials")
	if err != nil {
		return 0, err
	}
	defer func() { _ = rows.Close() }()

	n := 0
	for rows.Next() {
		var id, vaultID, key, typ string
		var ct, nonce []byte
		var createdAt, updatedAt interface{}
		if err := rows.Scan(&id, &vaultID, &key, &typ, &ct, &nonce, &createdAt, &updatedAt); err != nil {
			return n, err
		}
		ca, err := convertTime(createdAt, src.dialect, dstDialect)
		if err != nil {
			return n, fmt.Errorf("converting created_at: %w", err)
		}
		ua, err := convertTime(updatedAt, src.dialect, dstDialect)
		if err != nil {
			return n, fmt.Errorf("converting updated_at: %w", err)
		}
		_, err = tx.ExecContext(ctx,
			dstDialect.Rebind("INSERT INTO credentials (id, vault_id, key, type, ciphertext, nonce, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"),
			id, vaultID, key, typ, ct, nonce, ca, ua,
		)
		if err != nil {
			return n, err
		}
		n++
	}
	return n, rows.Err()
}

func copyCredentialOAuth(ctx context.Context, src *SQLStore, tx *sql.Tx, dstDialect Dialect) (int, error) {
	rows, err := src.db.QueryContext(ctx,
		`SELECT vault_id, credential_key, authorization_url, token_url, client_id,
		        client_secret_ct, client_secret_nonce, scopes, scope_separator,
		        disable_pkce, token_auth_method,
		        refresh_token_ct, refresh_token_nonce,
		        token_expires_at, connected_at, last_refreshed_at,
		        last_refresh_error, last_refresh_error_at,
		        created_at, updated_at
		 FROM credential_oauth`)
	if err != nil {
		return 0, err
	}
	defer func() { _ = rows.Close() }()

	n := 0
	for rows.Next() {
		var vaultID, credKey string
		var authURL, tokenURL, clientID interface{}
		var clientSecretCT, clientSecretNonce []byte
		var scopes, scopeSep, tokenAuthMethod interface{}
		var disablePkce interface{}
		var refreshCT, refreshNonce []byte
		var tokenExpiresAt, connectedAt, lastRefreshedAt interface{}
		var lastRefreshError interface{}
		var lastRefreshErrorAt interface{}
		var createdAt, updatedAt interface{}

		if err := rows.Scan(
			&vaultID, &credKey, &authURL, &tokenURL, &clientID,
			&clientSecretCT, &clientSecretNonce, &scopes, &scopeSep,
			&disablePkce, &tokenAuthMethod,
			&refreshCT, &refreshNonce,
			&tokenExpiresAt, &connectedAt, &lastRefreshedAt,
			&lastRefreshError, &lastRefreshErrorAt,
			&createdAt, &updatedAt,
		); err != nil {
			return n, err
		}

		ca, err := convertTime(createdAt, src.dialect, dstDialect)
		if err != nil {
			return n, fmt.Errorf("converting created_at: %w", err)
		}
		ua, err := convertTime(updatedAt, src.dialect, dstDialect)
		if err != nil {
			return n, fmt.Errorf("converting updated_at: %w", err)
		}
		tea, err := convertTime(tokenExpiresAt, src.dialect, dstDialect)
		if err != nil {
			return n, fmt.Errorf("converting token_expires_at: %w", err)
		}
		conna, err := convertTime(connectedAt, src.dialect, dstDialect)
		if err != nil {
			return n, fmt.Errorf("converting connected_at: %w", err)
		}
		lra, err := convertTime(lastRefreshedAt, src.dialect, dstDialect)
		if err != nil {
			return n, fmt.Errorf("converting last_refreshed_at: %w", err)
		}
		lrea, err := convertTime(lastRefreshErrorAt, src.dialect, dstDialect)
		if err != nil {
			return n, fmt.Errorf("converting last_refresh_error_at: %w", err)
		}
		boolVal, err := convertBool(disablePkce, src.dialect, dstDialect)
		if err != nil {
			return n, fmt.Errorf("converting disable_pkce: %w", err)
		}

		_, err = tx.ExecContext(ctx,
			dstDialect.Rebind(`INSERT INTO credential_oauth
				(vault_id, credential_key, authorization_url, token_url, client_id,
				 client_secret_ct, client_secret_nonce, scopes, scope_separator,
				 disable_pkce, token_auth_method,
				 refresh_token_ct, refresh_token_nonce,
				 token_expires_at, connected_at, last_refreshed_at,
				 last_refresh_error, last_refresh_error_at,
				 created_at, updated_at)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
			vaultID, credKey, authURL, tokenURL, clientID,
			clientSecretCT, clientSecretNonce, scopes, scopeSep,
			boolVal, tokenAuthMethod,
			refreshCT, refreshNonce,
			tea, conna, lra,
			lastRefreshError, lrea,
			ca, ua,
		)
		if err != nil {
			return n, err
		}
		n++
	}
	return n, rows.Err()
}

func copyCredentialOAuthStates(ctx context.Context, src *SQLStore, tx *sql.Tx, dstDialect Dialect) (int, error) {
	rows, err := src.db.QueryContext(ctx,
		"SELECT id, state_hash, code_verifier, vault_id, credential_key, redirect_url, created_at, expires_at FROM credential_oauth_states")
	if err != nil {
		return 0, err
	}
	defer func() { _ = rows.Close() }()

	n := 0
	for rows.Next() {
		var id, stateHash, codeVerifier, vaultID, credKey string
		var redirectURL interface{}
		var createdAt, expiresAt interface{}
		if err := rows.Scan(&id, &stateHash, &codeVerifier, &vaultID, &credKey, &redirectURL, &createdAt, &expiresAt); err != nil {
			return n, err
		}
		ca, err := convertTime(createdAt, src.dialect, dstDialect)
		if err != nil {
			return n, fmt.Errorf("converting created_at: %w", err)
		}
		ea, err := convertTime(expiresAt, src.dialect, dstDialect)
		if err != nil {
			return n, fmt.Errorf("converting expires_at: %w", err)
		}
		_, err = tx.ExecContext(ctx,
			dstDialect.Rebind("INSERT INTO credential_oauth_states (id, state_hash, code_verifier, vault_id, credential_key, redirect_url, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"),
			id, stateHash, codeVerifier, vaultID, credKey, redirectURL, ca, ea,
		)
		if err != nil {
			return n, err
		}
		n++
	}
	return n, rows.Err()
}

func copyBrokerConfigs(ctx context.Context, src *SQLStore, tx *sql.Tx, dstDialect Dialect) (int, error) {
	rows, err := src.db.QueryContext(ctx,
		"SELECT id, vault_id, services_json, created_at, updated_at FROM broker_configs")
	if err != nil {
		return 0, err
	}
	defer func() { _ = rows.Close() }()

	n := 0
	for rows.Next() {
		var id, vaultID, servicesJSON string
		var createdAt, updatedAt interface{}
		if err := rows.Scan(&id, &vaultID, &servicesJSON, &createdAt, &updatedAt); err != nil {
			return n, err
		}
		ca, err := convertTime(createdAt, src.dialect, dstDialect)
		if err != nil {
			return n, fmt.Errorf("converting created_at: %w", err)
		}
		ua, err := convertTime(updatedAt, src.dialect, dstDialect)
		if err != nil {
			return n, fmt.Errorf("converting updated_at: %w", err)
		}
		if vaultID == defaultVaultID {
			_, err = tx.ExecContext(ctx,
				dstDialect.Rebind("UPDATE broker_configs SET id = ?, services_json = ?, created_at = ?, updated_at = ? WHERE vault_id = ?"),
				id, servicesJSON, ca, ua, vaultID,
			)
		} else {
			_, err = tx.ExecContext(ctx,
				dstDialect.Rebind("INSERT INTO broker_configs (id, vault_id, services_json, created_at, updated_at) VALUES (?, ?, ?, ?, ?)"),
				id, vaultID, servicesJSON, ca, ua,
			)
		}
		if err != nil {
			return n, err
		}
		n++
	}
	return n, rows.Err()
}

func copySessions(ctx context.Context, src *SQLStore, tx *sql.Tx, dstDialect Dialect) (int, error) {
	rows, err := src.db.QueryContext(ctx,
		`SELECT id, expires_at, created_at, vault_id, user_id, agent_id,
		        vault_role, label, last_used_at, idle_ttl_seconds,
		        device_label, last_ip, last_user_agent, public_id,
		        created_by_actor_id, created_by_actor_type
		 FROM sessions`)
	if err != nil {
		return 0, err
	}
	defer func() { _ = rows.Close() }()

	n := 0
	for rows.Next() {
		var id string
		var expiresAt, createdAt interface{}
		var vaultID, userID, agentID interface{}
		var vaultRole, label interface{}
		var lastUsedAt interface{}
		var idleTTL interface{}
		var deviceLabel, lastIP, lastUA, publicID interface{}
		var createdByActorID, createdByActorType interface{}

		if err := rows.Scan(
			&id, &expiresAt, &createdAt, &vaultID, &userID, &agentID,
			&vaultRole, &label, &lastUsedAt, &idleTTL,
			&deviceLabel, &lastIP, &lastUA, &publicID,
			&createdByActorID, &createdByActorType,
		); err != nil {
			return n, err
		}

		ea, err := convertTime(expiresAt, src.dialect, dstDialect)
		if err != nil {
			return n, fmt.Errorf("converting expires_at: %w", err)
		}
		ca, err := convertTime(createdAt, src.dialect, dstDialect)
		if err != nil {
			return n, fmt.Errorf("converting created_at: %w", err)
		}
		lua, err := convertTime(lastUsedAt, src.dialect, dstDialect)
		if err != nil {
			return n, fmt.Errorf("converting last_used_at: %w", err)
		}

		_, err = tx.ExecContext(ctx,
			dstDialect.Rebind(`INSERT INTO sessions
				(id, expires_at, created_at, vault_id, user_id, agent_id,
				 vault_role, label, last_used_at, idle_ttl_seconds,
				 device_label, last_ip, last_user_agent, public_id,
				 created_by_actor_id, created_by_actor_type)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
			id, ea, ca, vaultID, userID, agentID,
			vaultRole, label, lua, idleTTL,
			deviceLabel, lastIP, lastUA, publicID,
			createdByActorID, createdByActorType,
		)
		if err != nil {
			return n, err
		}
		n++
	}
	return n, rows.Err()
}

func copyProposals(ctx context.Context, src *SQLStore, tx *sql.Tx, dstDialect Dialect) (int, error) {
	rows, err := src.db.QueryContext(ctx,
		`SELECT id, vault_id, session_id, status, services_json, credentials_json,
		        message, user_message, review_note, reviewed_at,
		        approval_token_hash, approval_token_expires_at,
		        created_at, updated_at
		 FROM proposals`)
	if err != nil {
		return 0, err
	}
	defer func() { _ = rows.Close() }()

	n := 0
	for rows.Next() {
		var id int
		var vaultID, sessionID, status, servicesJSON, credentialsJSON string
		var message, userMessage, reviewNote string
		var reviewedAt, approvalTokenHash, approvalTokenExpiresAt interface{}
		var createdAt, updatedAt interface{}

		if err := rows.Scan(
			&id, &vaultID, &sessionID, &status, &servicesJSON, &credentialsJSON,
			&message, &userMessage, &reviewNote, &reviewedAt,
			&approvalTokenHash, &approvalTokenExpiresAt,
			&createdAt, &updatedAt,
		); err != nil {
			return n, err
		}

		ra, err := convertTime(reviewedAt, src.dialect, dstDialect)
		if err != nil {
			return n, fmt.Errorf("converting reviewed_at: %w", err)
		}
		atea, err := convertTime(approvalTokenExpiresAt, src.dialect, dstDialect)
		if err != nil {
			return n, fmt.Errorf("converting approval_token_expires_at: %w", err)
		}
		ca, err := convertTime(createdAt, src.dialect, dstDialect)
		if err != nil {
			return n, fmt.Errorf("converting created_at: %w", err)
		}
		ua, err := convertTime(updatedAt, src.dialect, dstDialect)
		if err != nil {
			return n, fmt.Errorf("converting updated_at: %w", err)
		}

		_, err = tx.ExecContext(ctx,
			dstDialect.Rebind(`INSERT INTO proposals
				(id, vault_id, session_id, status, services_json, credentials_json,
				 message, user_message, review_note, reviewed_at,
				 approval_token_hash, approval_token_expires_at,
				 created_at, updated_at)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
			id, vaultID, sessionID, status, servicesJSON, credentialsJSON,
			message, userMessage, reviewNote, ra,
			approvalTokenHash, atea,
			ca, ua,
		)
		if err != nil {
			return n, err
		}
		n++
	}
	return n, rows.Err()
}

func copyProposalCredentials(ctx context.Context, src *SQLStore, tx *sql.Tx, dstDialect Dialect) (int, error) {
	rows, err := src.db.QueryContext(ctx,
		"SELECT vault_id, proposal_id, key, ciphertext, nonce FROM proposal_credentials")
	if err != nil {
		return 0, err
	}
	defer func() { _ = rows.Close() }()

	n := 0
	for rows.Next() {
		var vaultID string
		var proposalID int
		var key string
		var ct, nonce []byte
		if err := rows.Scan(&vaultID, &proposalID, &key, &ct, &nonce); err != nil {
			return n, err
		}
		_, err = tx.ExecContext(ctx,
			dstDialect.Rebind("INSERT INTO proposal_credentials (vault_id, proposal_id, key, ciphertext, nonce) VALUES (?, ?, ?, ?, ?)"),
			vaultID, proposalID, key, ct, nonce,
		)
		if err != nil {
			return n, err
		}
		n++
	}
	return n, rows.Err()
}

func copyUserInvites(ctx context.Context, src *SQLStore, tx *sql.Tx, dstDialect Dialect) (int, error) {
	rows, err := src.db.QueryContext(ctx,
		"SELECT id, token_hash, email, status, created_by, created_at, expires_at, accepted_at, role FROM user_invites")
	if err != nil {
		return 0, err
	}
	defer func() { _ = rows.Close() }()

	n := 0
	for rows.Next() {
		var id int
		var tokenHash, email, status, createdBy, role string
		var createdAt, expiresAt, acceptedAt interface{}
		if err := rows.Scan(&id, &tokenHash, &email, &status, &createdBy, &createdAt, &expiresAt, &acceptedAt, &role); err != nil {
			return n, err
		}
		ca, err := convertTime(createdAt, src.dialect, dstDialect)
		if err != nil {
			return n, fmt.Errorf("converting created_at: %w", err)
		}
		ea, err := convertTime(expiresAt, src.dialect, dstDialect)
		if err != nil {
			return n, fmt.Errorf("converting expires_at: %w", err)
		}
		aa, err := convertTime(acceptedAt, src.dialect, dstDialect)
		if err != nil {
			return n, fmt.Errorf("converting accepted_at: %w", err)
		}
		_, err = tx.ExecContext(ctx,
			dstDialect.Rebind("INSERT INTO user_invites (id, token_hash, email, status, created_by, created_at, expires_at, accepted_at, role) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"),
			id, tokenHash, email, status, createdBy, ca, ea, aa, role,
		)
		if err != nil {
			return n, err
		}
		n++
	}
	return n, rows.Err()
}

func copyUserInviteVaults(ctx context.Context, src *SQLStore, tx *sql.Tx, dstDialect Dialect) (int, error) {
	rows, err := src.db.QueryContext(ctx,
		"SELECT user_invite_id, vault_id, vault_role FROM user_invite_vaults")
	if err != nil {
		return 0, err
	}
	defer func() { _ = rows.Close() }()

	n := 0
	for rows.Next() {
		var inviteID int
		var vaultID, vaultRole string
		if err := rows.Scan(&inviteID, &vaultID, &vaultRole); err != nil {
			return n, err
		}
		_, err = tx.ExecContext(ctx,
			dstDialect.Rebind("INSERT INTO user_invite_vaults (user_invite_id, vault_id, vault_role) VALUES (?, ?, ?)"),
			inviteID, vaultID, vaultRole,
		)
		if err != nil {
			return n, err
		}
		n++
	}
	return n, rows.Err()
}

func copyEmailVerifications(ctx context.Context, src *SQLStore, tx *sql.Tx, dstDialect Dialect) (int, error) {
	rows, err := src.db.QueryContext(ctx,
		"SELECT id, email, code_hash, status, created_at, expires_at FROM email_verifications")
	if err != nil {
		return 0, err
	}
	defer func() { _ = rows.Close() }()

	n := 0
	for rows.Next() {
		var id int
		var email, codeHash, status string
		var createdAt, expiresAt interface{}
		if err := rows.Scan(&id, &email, &codeHash, &status, &createdAt, &expiresAt); err != nil {
			return n, err
		}
		ca, err := convertTime(createdAt, src.dialect, dstDialect)
		if err != nil {
			return n, fmt.Errorf("converting created_at: %w", err)
		}
		ea, err := convertTime(expiresAt, src.dialect, dstDialect)
		if err != nil {
			return n, fmt.Errorf("converting expires_at: %w", err)
		}
		_, err = tx.ExecContext(ctx,
			dstDialect.Rebind("INSERT INTO email_verifications (id, email, code_hash, status, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)"),
			id, email, codeHash, status, ca, ea,
		)
		if err != nil {
			return n, err
		}
		n++
	}
	return n, rows.Err()
}

func copyPasswordResets(ctx context.Context, src *SQLStore, tx *sql.Tx, dstDialect Dialect) (int, error) {
	rows, err := src.db.QueryContext(ctx,
		"SELECT id, email, code_hash, status, created_at, expires_at FROM password_resets")
	if err != nil {
		return 0, err
	}
	defer func() { _ = rows.Close() }()

	n := 0
	for rows.Next() {
		var id int
		var email, codeHash, status string
		var createdAt, expiresAt interface{}
		if err := rows.Scan(&id, &email, &codeHash, &status, &createdAt, &expiresAt); err != nil {
			return n, err
		}
		ca, err := convertTime(createdAt, src.dialect, dstDialect)
		if err != nil {
			return n, fmt.Errorf("converting created_at: %w", err)
		}
		ea, err := convertTime(expiresAt, src.dialect, dstDialect)
		if err != nil {
			return n, fmt.Errorf("converting expires_at: %w", err)
		}
		_, err = tx.ExecContext(ctx,
			dstDialect.Rebind("INSERT INTO password_resets (id, email, code_hash, status, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)"),
			id, email, codeHash, status, ca, ea,
		)
		if err != nil {
			return n, err
		}
		n++
	}
	return n, rows.Err()
}

func copyVaultCredentialStores(ctx context.Context, src *SQLStore, tx *sql.Tx, dstDialect Dialect) (int, error) {
	rows, err := src.db.QueryContext(ctx,
		`SELECT vault_id, kind, config_json, poll_interval_seconds,
		        last_synced_at, last_sync_status, last_sync_error,
		        created_at, updated_at
		 FROM vault_credential_stores`)
	if err != nil {
		return 0, err
	}
	defer func() { _ = rows.Close() }()

	n := 0
	for rows.Next() {
		var vaultID, kind, configJSON string
		var pollInterval int
		var lastSyncedAt, lastSyncStatus, lastSyncError interface{}
		var createdAt, updatedAt interface{}
		if err := rows.Scan(&vaultID, &kind, &configJSON, &pollInterval,
			&lastSyncedAt, &lastSyncStatus, &lastSyncError,
			&createdAt, &updatedAt); err != nil {
			return n, err
		}
		lsa, err := convertTime(lastSyncedAt, src.dialect, dstDialect)
		if err != nil {
			return n, fmt.Errorf("converting last_synced_at: %w", err)
		}
		ca, err := convertTime(createdAt, src.dialect, dstDialect)
		if err != nil {
			return n, fmt.Errorf("converting created_at: %w", err)
		}
		ua, err := convertTime(updatedAt, src.dialect, dstDialect)
		if err != nil {
			return n, fmt.Errorf("converting updated_at: %w", err)
		}
		_, err = tx.ExecContext(ctx,
			dstDialect.Rebind(`INSERT INTO vault_credential_stores
				(vault_id, kind, config_json, poll_interval_seconds,
				 last_synced_at, last_sync_status, last_sync_error,
				 created_at, updated_at)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`),
			vaultID, kind, configJSON, pollInterval,
			lsa, lastSyncStatus, lastSyncError,
			ca, ua,
		)
		if err != nil {
			return n, err
		}
		n++
	}
	return n, rows.Err()
}

func copyDynamicSecretLeases(ctx context.Context, src *SQLStore, tx *sql.Tx, dstDialect Dialect) (int, error) {
	rows, err := src.db.QueryContext(ctx,
		"SELECT lease_id, vault_id, dynamic_secret_name, project_id, environment, secret_path, expire_at, created_at FROM dynamic_secret_leases")
	if err != nil {
		return 0, err
	}
	defer func() { _ = rows.Close() }()

	n := 0
	for rows.Next() {
		var leaseID, vaultID, dsName, projectID, env, secretPath string
		var expireAt, createdAt interface{}
		if err := rows.Scan(&leaseID, &vaultID, &dsName, &projectID, &env, &secretPath, &expireAt, &createdAt); err != nil {
			return n, err
		}
		ea, err := convertTime(expireAt, src.dialect, dstDialect)
		if err != nil {
			return n, fmt.Errorf("converting expire_at: %w", err)
		}
		ca, err := convertTime(createdAt, src.dialect, dstDialect)
		if err != nil {
			return n, fmt.Errorf("converting created_at: %w", err)
		}
		_, err = tx.ExecContext(ctx,
			dstDialect.Rebind("INSERT INTO dynamic_secret_leases (lease_id, vault_id, dynamic_secret_name, project_id, environment, secret_path, expire_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"),
			leaseID, vaultID, dsName, projectID, env, secretPath, ea, ca,
		)
		if err != nil {
			return n, err
		}
		n++
	}
	return n, rows.Err()
}

func copyRequestLogs(ctx context.Context, src *SQLStore, tx *sql.Tx, dstDialect Dialect) (int, error) {
	// Request logs can be large, so we batch in chunks of 1000.
	const batchSize = 1000
	total := 0
	offset := 0

	for {
		rows, err := src.db.QueryContext(ctx,
			fmt.Sprintf("SELECT id, vault_id, actor_type, actor_id, ingress, method, host, path, matched_service, credential_keys, status, latency_ms, error_code, created_at, auth_scheme, auth_header FROM request_logs ORDER BY id LIMIT %d OFFSET %d", batchSize, offset))
		if err != nil {
			return total, err
		}

		batchCount := 0
		for rows.Next() {
			var id int
			var vaultID, actorType, actorID, ingress, method, host, path string
			var matchedService, credKeys string
			var status, latencyMs int
			var errorCode string
			var createdAt interface{}
			var authScheme, authHeader string

			if err := rows.Scan(
				&id, &vaultID, &actorType, &actorID, &ingress, &method, &host, &path,
				&matchedService, &credKeys, &status, &latencyMs, &errorCode,
				&createdAt, &authScheme, &authHeader,
			); err != nil {
				_ = rows.Close()
				return total, err
			}

			ca, err := convertTime(createdAt, src.dialect, dstDialect)
			if err != nil {
				_ = rows.Close()
				return total, fmt.Errorf("converting created_at: %w", err)
			}

			_, err = tx.ExecContext(ctx,
				dstDialect.Rebind(`INSERT INTO request_logs
					(id, vault_id, actor_type, actor_id, ingress, method, host, path,
					 matched_service, credential_keys, status, latency_ms, error_code,
					 created_at, auth_scheme, auth_header)
					VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
				id, vaultID, actorType, actorID, ingress, method, host, path,
				matchedService, credKeys, status, latencyMs, errorCode,
				ca, authScheme, authHeader,
			)
			if err != nil {
				_ = rows.Close()
				return total, err
			}
			batchCount++
		}
		_ = rows.Close()
		if err := rows.Err(); err != nil {
			return total, err
		}

		total += batchCount
		if batchCount < batchSize {
			break
		}
		offset += batchSize
	}

	return total, nil
}

func copyCAState(ctx context.Context, src *SQLStore, tx *sql.Tx, dstDialect Dialect) (int, error) {
	// ca_state may not exist on older SQLite databases.
	rows, err := src.db.QueryContext(ctx,
		"SELECT root_cert, root_key_ct, root_key_nonce, source, created_at, updated_at FROM ca_state WHERE id = 1")
	if err != nil {
		// Table doesn't exist -- not an error, just nothing to copy.
		return 0, nil
	}
	defer func() { _ = rows.Close() }()

	if !rows.Next() {
		return 0, rows.Err()
	}

	var rootCert, rootKeyCT, rootKeyNonce []byte
	var source string
	var createdAt, updatedAt interface{}
	if err := rows.Scan(&rootCert, &rootKeyCT, &rootKeyNonce, &source, &createdAt, &updatedAt); err != nil {
		return 0, err
	}

	ca, err := convertTime(createdAt, src.dialect, dstDialect)
	if err != nil {
		return 0, fmt.Errorf("converting created_at: %w", err)
	}
	ua, err := convertTime(updatedAt, src.dialect, dstDialect)
	if err != nil {
		return 0, fmt.Errorf("converting updated_at: %w", err)
	}

	_, err = tx.ExecContext(ctx,
		dstDialect.Rebind(`INSERT INTO ca_state (id, root_cert, root_key_ct, root_key_nonce, source, created_at, updated_at)
			VALUES (1, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(id) DO UPDATE SET
			  root_cert = EXCLUDED.root_cert,
			  root_key_ct = EXCLUDED.root_key_ct,
			  root_key_nonce = EXCLUDED.root_key_nonce,
			  source = EXCLUDED.source,
			  updated_at = EXCLUDED.updated_at`),
		rootCert, rootKeyCT, rootKeyNonce, source, ca, ua,
	)
	if err != nil {
		return 0, err
	}
	return 1, nil
}

// MigrateCAFromDisk reads the CA certificate and encrypted key from disk
// and inserts them into the destination store's ca_state table.
// Returns (true, nil) if the CA was migrated, (false, nil) if the files
// were not found on disk (not an error), or (false, err) on failure.
func MigrateCAFromDisk(ctx context.Context, dst *SQLStore, caDir string) (bool, error) {
	certPath := caDir + "/ca.crt.pem"
	keyPath := caDir + "/ca.key.enc"

	certPEM, err := readFileIfExists(certPath)
	if err != nil {
		return false, fmt.Errorf("reading %s: %w", certPath, err)
	}
	if certPEM == nil {
		return false, nil // no CA files on disk
	}

	keyJSON, err := readFileIfExists(keyPath)
	if err != nil {
		return false, fmt.Errorf("reading %s: %w", keyPath, err)
	}
	if keyJSON == nil {
		return false, nil
	}

	// Parse the encrypted key JSON: {"nonce":"<base64>","ciphertext":"<base64>"}
	nonce, ct, err := parseEncryptedKeyJSON(keyJSON)
	if err != nil {
		return false, fmt.Errorf("parsing %s: %w", keyPath, err)
	}

	now := time.Now().UTC()
	state := &CAState{
		RootCert:     certPEM,
		RootKeyCT:    ct,
		RootKeyNonce: nonce,
		Source:       "migrated-from-disk",
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if err := dst.SetCAState(ctx, state); err != nil {
		return false, fmt.Errorf("writing CA state: %w", err)
	}
	return true, nil
}

// readFileIfExists reads the named file, returning nil (not an error) when
// the file does not exist.
func readFileIfExists(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	return data, err
}

// encryptedKeyJSON mirrors the on-disk format of ca.key.enc.
type encryptedKeyJSON struct {
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

// parseEncryptedKeyJSON decodes the JSON envelope and base64-decodes the
// nonce and ciphertext fields.
func parseEncryptedKeyJSON(data []byte) (nonce, ciphertext []byte, err error) {
	var ek encryptedKeyJSON
	if err := json.Unmarshal(data, &ek); err != nil {
		return nil, nil, fmt.Errorf("unmarshalling encrypted key: %w", err)
	}
	nonce, err = base64.StdEncoding.DecodeString(ek.Nonce)
	if err != nil {
		return nil, nil, fmt.Errorf("decoding nonce: %w", err)
	}
	ciphertext, err = base64.StdEncoding.DecodeString(ek.Ciphertext)
	if err != nil {
		return nil, nil, fmt.Errorf("decoding ciphertext: %w", err)
	}
	return nonce, ciphertext, nil
}
