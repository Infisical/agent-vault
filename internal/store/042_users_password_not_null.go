package store

import "gorm.io/gorm"

func init() {
	RegisterGORMMigration(func(db *gorm.DB) error {
		if db.Name() != "sqlite" {
			return nil
		}
		stmts := []string{
			`-- Restore NOT NULL on users.password_hash and users.password_salt.
-- These were relaxed in migration 022 to support OAuth-only users.
-- OAuth was removed in migration 041, so all users now have a password.
-- SQLite has no ALTER COLUMN, so rebuild the table.


CREATE TABLE users_new (
    id            TEXT PRIMARY KEY,
    email         TEXT NOT NULL UNIQUE,
    password_hash BLOB NOT NULL,
    password_salt BLOB NOT NULL,
    role          TEXT NOT NULL DEFAULT 'owner' CHECK(role IN ('owner', 'member')),
    created_at    TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at    TEXT NOT NULL DEFAULT (datetime('now')),
    kdf_time      INTEGER NOT NULL DEFAULT 3,
    kdf_memory    INTEGER NOT NULL DEFAULT 65536,
    kdf_threads   INTEGER NOT NULL DEFAULT 4,
    is_active     INTEGER NOT NULL DEFAULT 0
)`,
			`INSERT INTO users_new SELECT * FROM users`,
			`DROP TABLE users`,
			`ALTER TABLE users_new RENAME TO users`,
		}
		for _, stmt := range stmts {
			if err := db.Exec(stmt).Error; err != nil {
				return err
			}
		}
		return nil
	})
}
