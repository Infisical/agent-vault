package store

import "gorm.io/gorm"

func init() {
	RegisterGORMMigration(func(db *gorm.DB) error {
		if db.Name() != "sqlite" {
			return nil
		}
		stmts := []string{
			`-- Remove per-vault approval policy. Any vault member can now approve changesets.
-- Rebuild table to remove column with CHECK constraint.
-- PRAGMA foreign_keys=OFF prevents DROP TABLE from cascading.

CREATE TABLE vaults_new (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
)`,
			`INSERT INTO vaults_new (id, name, created_at, updated_at)
    SELECT id, name, created_at, updated_at FROM vaults`,
			`DROP TABLE vaults`,
			`ALTER TABLE vaults_new RENAME TO vaults`,
		}
		for _, stmt := range stmts {
			if err := db.Exec(stmt).Error; err != nil {
				return err
			}
		}
		return nil
	})
}
