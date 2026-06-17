package store

import "gorm.io/gorm"

func init() {
	RegisterGORMMigration(func(db *gorm.DB) error {
		if db.Name() != "sqlite" {
			return nil
		}
		stmts := []string{
			`-- Tracking metadata for vault-scoped session tokens so they can be listed
-- and revoked from a UI. created_by_actor_id and _type mirror the actor
-- model from migration 036. The label column already exists from
-- migration 029 and is reused.

ALTER TABLE sessions ADD COLUMN created_by_actor_id TEXT`,
			`ALTER TABLE sessions ADD COLUMN created_by_actor_type TEXT`,
			`CREATE INDEX idx_sessions_vault_id ON sessions(vault_id)`,
		}
		for _, stmt := range stmts {
			if err := db.Exec(stmt).Error; err != nil {
				return err
			}
		}
		return nil
	})
}
