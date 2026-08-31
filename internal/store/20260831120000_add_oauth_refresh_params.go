package store

import "gorm.io/gorm"

func init() {
	RegisterGORMMigration(func(db *gorm.DB) error {
		if db.Migrator().HasColumn("credential_oauth", "refresh_params") {
			return nil
		}
		return db.Exec(`ALTER TABLE credential_oauth ADD COLUMN refresh_params TEXT NOT NULL DEFAULT '{}'`).Error
	})
}
