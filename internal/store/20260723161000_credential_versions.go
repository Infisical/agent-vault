package store

import "gorm.io/gorm"

// credential_versions archives the value a built-in credential held before
// each overwrite (SetCredential / proposal apply), so operators and agents
// have a rollback path instead of an "oops, it's just gone" outcome. See
// internal/store/credential_history.go for retention (pruned per key, not
// time-based like request_logs — see internal/requestlog/retention.go for
// that pattern) and SQLStore.archiveCredentialVersionTx for where rows are
// written.
func init() {
	RegisterGORMMigration(func(db *gorm.DB) error {
		if db.Migrator().HasTable("credential_versions") {
			return nil
		}

		var stmts []string
		if db.Name() == "postgres" {
			stmts = []string{
				`CREATE TABLE credential_versions (
					id         TEXT PRIMARY KEY,
					vault_id   TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
					key        TEXT NOT NULL,
					version    INTEGER NOT NULL,
					ciphertext BYTEA NOT NULL,
					nonce      BYTEA NOT NULL,
					actor_type TEXT NOT NULL DEFAULT '',
					actor_id   TEXT NOT NULL DEFAULT '',
					created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
					UNIQUE(vault_id, key, version)
				)`,
				`CREATE INDEX idx_credential_versions_vault_key ON credential_versions(vault_id, key)`,
			}
		} else {
			stmts = []string{
				`CREATE TABLE credential_versions (
					id         TEXT PRIMARY KEY,
					vault_id   TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
					key        TEXT NOT NULL,
					version    INTEGER NOT NULL,
					ciphertext BLOB NOT NULL,
					nonce      BLOB NOT NULL,
					actor_type TEXT NOT NULL DEFAULT '',
					actor_id   TEXT NOT NULL DEFAULT '',
					created_at TEXT NOT NULL DEFAULT (datetime('now')),
					UNIQUE(vault_id, key, version)
				)`,
				`CREATE INDEX idx_credential_versions_vault_key ON credential_versions(vault_id, key)`,
			}
		}

		for _, stmt := range stmts {
			if err := db.Exec(stmt).Error; err != nil {
				return err
			}
		}
		return nil
	})
}
