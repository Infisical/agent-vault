package store

import "gorm.io/gorm"

func init() {
	RegisterGORMMigration(func(db *gorm.DB) error {
		if db.Migrator().HasTable("acquisition_handlers") {
			return nil
		}
		timestamp := "TEXT NOT NULL DEFAULT (datetime('now'))"
		enabled := "INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0, 1))"
		if db.Name() == "postgres" {
			timestamp = "TIMESTAMPTZ NOT NULL DEFAULT NOW()"
			enabled = "BOOLEAN NOT NULL DEFAULT FALSE"
		}
		return db.Exec(`CREATE TABLE acquisition_handlers (
			id TEXT PRIMARY KEY,
			generation TEXT NOT NULL,
			kind TEXT NOT NULL,
			executable_path TEXT NOT NULL,
			sha256 TEXT NOT NULL,
			signing_identity TEXT NOT NULL DEFAULT '',
			allowed_keys_json TEXT NOT NULL DEFAULT '[]',
			allowed_vaults_json TEXT NOT NULL DEFAULT '[]',
			allowed_profiles_json TEXT NOT NULL DEFAULT '[]',
			timeout_seconds INTEGER NOT NULL,
			output_limit_bytes INTEGER NOT NULL,
			enabled ` + enabled + `,
			created_at ` + timestamp + `,
			updated_at ` + timestamp + `
		)`).Error
	})
}
