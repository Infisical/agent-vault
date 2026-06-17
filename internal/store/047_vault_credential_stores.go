package store

import "gorm.io/gorm"

func init() {
	RegisterGORMMigration(func(db *gorm.DB) error {
		if db.Name() != "sqlite" {
			return nil
		}
		stmts := []string{
			`-- extend both together when adding a new external store.
CREATE TABLE vault_credential_stores (
    vault_id              TEXT PRIMARY KEY REFERENCES vaults(id) ON DELETE CASCADE,
    kind                  TEXT NOT NULL CHECK(kind IN ('infisical')),
    config_json           TEXT NOT NULL,
    poll_interval_seconds INTEGER NOT NULL DEFAULT 60 CHECK(poll_interval_seconds >= 10),
    last_synced_at        TEXT,
    last_sync_status      TEXT CHECK(last_sync_status IS NULL OR last_sync_status IN ('ok','error')),
    last_sync_error       TEXT,
    created_at            TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at            TEXT NOT NULL DEFAULT (datetime('now'))
)`,
		}
		for _, stmt := range stmts {
			if err := db.Exec(stmt).Error; err != nil {
				return err
			}
		}
		return nil
	})
}
