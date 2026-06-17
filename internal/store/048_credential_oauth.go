package store

import "gorm.io/gorm"

func init() {
	RegisterGORMMigration(func(db *gorm.DB) error {
		if db.Name() != "sqlite" {
			return nil
		}
		stmts := []string{
			`-- Add credential type discriminator. Existing rows default to 'static'.
ALTER TABLE credentials ADD COLUMN type TEXT NOT NULL DEFAULT 'static'`,
			`-- OAuth configuration and refresh state for OAuth-type credentials.
-- The access token lives in credentials.ciphertext. This table
-- stores everything needed to refresh it and the provider config.
CREATE TABLE credential_oauth (
    vault_id              TEXT NOT NULL,
    credential_key        TEXT NOT NULL,
    authorization_url     TEXT,
    token_url             TEXT NOT NULL,
    client_id             TEXT NOT NULL,
    client_secret_ct      BLOB,
    client_secret_nonce   BLOB,
    scopes                TEXT,
    scope_separator       TEXT DEFAULT ' ',
    disable_pkce          INTEGER DEFAULT 0,
    token_auth_method     TEXT DEFAULT 'client_secret_post',
    refresh_token_ct      BLOB,
    refresh_token_nonce   BLOB,
    token_expires_at      TEXT,
    connected_at          TEXT,
    last_refreshed_at     TEXT,
    last_refresh_error    TEXT,
    last_refresh_error_at TEXT,
    created_at            TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at            TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (vault_id, credential_key),
    FOREIGN KEY (vault_id, credential_key) REFERENCES credentials(vault_id, key) ON DELETE CASCADE
)`,
			`-- CSRF state + PKCE verifier for in-flight OAuth consent redirects.
CREATE TABLE credential_oauth_states (
    id              TEXT PRIMARY KEY,
    state_hash      TEXT NOT NULL UNIQUE,
    code_verifier   TEXT NOT NULL,
    vault_id        TEXT NOT NULL,
    credential_key  TEXT NOT NULL,
    redirect_url    TEXT,
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at      TEXT NOT NULL
)`,
			`CREATE INDEX idx_credential_oauth_states_expires ON credential_oauth_states(expires_at)`,
		}
		for _, stmt := range stmts {
			if err := db.Exec(stmt).Error; err != nil {
				return err
			}
		}
		return nil
	})
}
