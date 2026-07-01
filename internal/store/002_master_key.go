package store

import "gorm.io/gorm"

func init() {
	RegisterGORMMigration(func(db *gorm.DB) error {
		if db.Name() != "sqlite" {
			return nil
		}
		stmts := []string{
			`CREATE TABLE master_key (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    salt        BLOB NOT NULL,
    sentinel    BLOB NOT NULL,
    nonce       BLOB NOT NULL,
    kdf_time    INTEGER NOT NULL,
    kdf_memory  INTEGER NOT NULL,
    kdf_threads INTEGER NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
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
