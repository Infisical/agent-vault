package store

import "gorm.io/gorm"

func init() {
	RegisterGORMMigration(func(db *gorm.DB) error {
		if db.Name() != "sqlite" {
			return nil
		}
		stmts := []string{
			`ALTER TABLE users ADD COLUMN kdf_time INTEGER NOT NULL DEFAULT 3`,
			`ALTER TABLE users ADD COLUMN kdf_memory INTEGER NOT NULL DEFAULT 65536`,
			`ALTER TABLE users ADD COLUMN kdf_threads INTEGER NOT NULL DEFAULT 4`,
		}
		for _, stmt := range stmts {
			if err := db.Exec(stmt).Error; err != nil {
				return err
			}
		}
		return nil
	})
}
