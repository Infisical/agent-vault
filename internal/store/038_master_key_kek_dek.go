package store

import "gorm.io/gorm"

func init() {
	RegisterGORMMigration(func(db *gorm.DB) error {
		if db.Name() != "sqlite" {
			return nil
		}
		stmts := []string{
			`-- Rebuild master_key for KEK/DEK key-wrapping architecture.
-- Adds DEK storage columns, renames nonce → sentinel_nonce, makes KDF columns nullable.
CREATE TABLE master_key_new (
    id              INTEGER PRIMARY KEY CHECK (id = 1),
    sentinel        BLOB NOT NULL,
    sentinel_nonce  BLOB NOT NULL,
    dek_ciphertext  BLOB,
    dek_nonce       BLOB,
    dek_plaintext   BLOB,
    salt            BLOB,
    kdf_time        INTEGER,
    kdf_memory      INTEGER,
    kdf_threads     INTEGER,
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
)`,
			`INSERT INTO master_key_new (id, sentinel, sentinel_nonce, salt, kdf_time, kdf_memory, kdf_threads, created_at)
SELECT id, sentinel, nonce, salt, kdf_time, kdf_memory, kdf_threads, created_at
FROM master_key`,
			`DROP TABLE master_key`,
			`ALTER TABLE master_key_new RENAME TO master_key`,
		}
		for _, stmt := range stmts {
			if err := db.Exec(stmt).Error; err != nil {
				return err
			}
		}
		return nil
	})
}
