package store

import "gorm.io/gorm"

func init() {
	RegisterGORMMigration(func(db *gorm.DB) error {
		if db.Name() != "sqlite" {
			return nil
		}
		stmts := []string{
			`-- Rename rules_json to services_json in broker_configs and proposals tables.
ALTER TABLE broker_configs RENAME COLUMN rules_json TO services_json`,
			`ALTER TABLE proposals RENAME COLUMN rules_json TO services_json`,
		}
		for _, stmt := range stmts {
			if err := db.Exec(stmt).Error; err != nil {
				return err
			}
		}
		return nil
	})
}
