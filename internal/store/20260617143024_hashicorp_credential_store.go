package store

import (
	"strings"

	"gorm.io/gorm"
)

// Widen vault_credential_stores.kind to allow 'hashicorp' alongside 'infisical'.
// Runs after the table exists (migration 047 on SQLite, the Postgres baseline on
// Postgres). SQLite cannot ALTER a CHECK constraint, so the table is rebuilt;
// Postgres alters the named constraint in place. Both branches are idempotent.
func init() {
	RegisterGORMMigration(func(db *gorm.DB) error {
		if db.Name() == "postgres" {
			if err := db.Exec(`ALTER TABLE vault_credential_stores DROP CONSTRAINT IF EXISTS vault_credential_stores_kind_check`).Error; err != nil {
				return err
			}
			return db.Exec(`ALTER TABLE vault_credential_stores ADD CONSTRAINT vault_credential_stores_kind_check CHECK (kind IN ('infisical','hashicorp'))`).Error
		}

		// SQLite: skip if the CHECK already permits hashicorp.
		var ddl string
		if err := db.Raw(`SELECT sql FROM sqlite_master WHERE type='table' AND name='vault_credential_stores'`).Scan(&ddl).Error; err != nil {
			return err
		}
		if strings.Contains(ddl, "hashicorp") {
			return nil
		}
		// Rebuild with the widened CHECK. vault_credential_stores is a leaf table
		// (only it references vaults; nothing references it), so the drop/rename is
		// safe without toggling foreign_keys.
		stmts := []string{
			`CREATE TABLE vault_credential_stores_new (
    vault_id              TEXT PRIMARY KEY REFERENCES vaults(id) ON DELETE CASCADE,
    kind                  TEXT NOT NULL CHECK(kind IN ('infisical','hashicorp')),
    config_json           TEXT NOT NULL,
    poll_interval_seconds INTEGER NOT NULL DEFAULT 60 CHECK(poll_interval_seconds >= 10),
    last_synced_at        TEXT,
    last_sync_status      TEXT CHECK(last_sync_status IS NULL OR last_sync_status IN ('ok','error')),
    last_sync_error       TEXT,
    created_at            TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at            TEXT NOT NULL DEFAULT (datetime('now'))
)`,
			`INSERT INTO vault_credential_stores_new SELECT vault_id, kind, config_json, poll_interval_seconds, last_synced_at, last_sync_status, last_sync_error, created_at, updated_at FROM vault_credential_stores`,
			`DROP TABLE vault_credential_stores`,
			`ALTER TABLE vault_credential_stores_new RENAME TO vault_credential_stores`,
		}
		for _, s := range stmts {
			if err := db.Exec(s).Error; err != nil {
				return err
			}
		}
		return nil
	})
}
