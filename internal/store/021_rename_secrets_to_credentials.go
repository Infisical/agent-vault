package store

import "gorm.io/gorm"

func init() {
	RegisterGORMMigration(func(db *gorm.DB) error {
		if db.Name() != "sqlite" {
			return nil
		}
		stmts := []string{
			`-- Rename "secrets" terminology to "credentials" throughout the schema.
ALTER TABLE secrets RENAME TO credentials`,
			`ALTER TABLE proposal_secrets RENAME TO proposal_credentials`,
			`ALTER TABLE proposals RENAME COLUMN secrets_json TO credentials_json`,
		}
		for _, stmt := range stmts {
			if err := db.Exec(stmt).Error; err != nil {
				return err
			}
		}
		return nil
	})
}
