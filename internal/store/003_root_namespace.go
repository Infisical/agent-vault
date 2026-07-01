package store

import "gorm.io/gorm"

func init() {
	RegisterGORMMigration(func(db *gorm.DB) error {
		if db.Name() != "sqlite" {
			return nil
		}
		stmts := []string{
			`INSERT INTO namespaces (id, name, created_at, updated_at)
VALUES ('00000000-0000-0000-0000-000000000000', 'default', datetime('now'), datetime('now'))`,
		}
		for _, stmt := range stmts {
			if err := db.Exec(stmt).Error; err != nil {
				return err
			}
		}
		return nil
	})
}
