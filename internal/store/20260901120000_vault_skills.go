package store

import "gorm.io/gorm"

func init() {
	RegisterGORMMigration(func(db *gorm.DB) error {
		if db.Migrator().HasTable("skills") {
			return nil
		}
		// PRIMARY KEY (vault_id, name) does triple duty: it enforces
		// per-vault name uniqueness, indexes the vault_id lookups the
		// list endpoint does (leading column), and gives ON CONFLICT a
		// target that resolves identically on both dialects.
		if db.Name() == "postgres" {
			return db.Exec(`CREATE TABLE skills (
				vault_id    TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
				name        TEXT NOT NULL,
				description TEXT NOT NULL DEFAULT '',
				content     TEXT NOT NULL DEFAULT '',
				created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
				updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
				PRIMARY KEY (vault_id, name)
			)`).Error
		}
		return db.Exec(`CREATE TABLE skills (
			vault_id    TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
			name        TEXT NOT NULL,
			description TEXT NOT NULL DEFAULT '',
			content     TEXT NOT NULL DEFAULT '',
			created_at  TEXT NOT NULL DEFAULT (datetime('now')),
			updated_at  TEXT NOT NULL DEFAULT (datetime('now')),
			PRIMARY KEY (vault_id, name)
		)`).Error
	})
}
