package store

import "gorm.io/gorm"

func init() {
	RegisterGORMMigration(func(db *gorm.DB) error {
		if db.Name() != "sqlite" {
			return nil
		}
		stmts := []string{
			`-- Browser-based changeset approval: add approval token and user-facing message.
ALTER TABLE changesets ADD COLUMN approval_token TEXT`,
			`ALTER TABLE changesets ADD COLUMN approval_token_expires_at TEXT`,
			`ALTER TABLE changesets ADD COLUMN user_message TEXT NOT NULL DEFAULT ''`,
			`CREATE UNIQUE INDEX idx_changesets_approval_token ON changesets(approval_token) WHERE approval_token IS NOT NULL`,
		}
		for _, stmt := range stmts {
			if err := db.Exec(stmt).Error; err != nil {
				return err
			}
		}
		return nil
	})
}
