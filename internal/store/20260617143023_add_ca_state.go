package store

import "gorm.io/gorm"

func init() {
	RegisterGORMMigration(func(db *gorm.DB) error {
		if db.Migrator().HasTable("ca_state") {
			return nil
		}
		if db.Name() == "postgres" {
			return db.Exec(`CREATE TABLE ca_state (
				id             INTEGER PRIMARY KEY DEFAULT 1 CHECK (id = 1),
				root_cert      BYTEA NOT NULL,
				root_key_ct    BYTEA NOT NULL,
				root_key_nonce BYTEA NOT NULL,
				source         TEXT NOT NULL DEFAULT 'auto',
				created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
				updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
			)`).Error
		}
		return db.Exec(`CREATE TABLE ca_state (
			id             INTEGER PRIMARY KEY DEFAULT 1 CHECK (id = 1),
			root_cert      BLOB NOT NULL,
			root_key_ct    BLOB NOT NULL,
			root_key_nonce BLOB NOT NULL,
			source         TEXT NOT NULL DEFAULT 'auto',
			created_at     TEXT NOT NULL DEFAULT (datetime('now')),
			updated_at     TEXT NOT NULL DEFAULT (datetime('now'))
		)`).Error
	})
}
