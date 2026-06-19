package store

import "gorm.io/gorm"

func init() {
	RegisterGORMMigration(func(db *gorm.DB) error {
		if db.Name() != "sqlite" {
			return nil
		}
		stmts := []string{
			`-- Remove Google OAuth: delete OAuth-only users and drop OAuth tables.
-- vault_grants.actor_id is polymorphic (holds both user and agent IDs)
-- and has no FK to users, so cascade does not reach it — clean it up
-- explicitly, matching SQLStore.DeleteUser. sessions.user_id and
-- oauth_accounts.user_id do cascade via ON DELETE CASCADE.

DELETE FROM vault_grants
 WHERE actor_type = 'user'
   AND actor_id IN (SELECT id FROM users WHERE password_hash IS NULL)`,
			`DELETE FROM users WHERE password_hash IS NULL`,
			`DROP TABLE IF EXISTS oauth_accounts`,
			`DROP TABLE IF EXISTS oauth_states`,
		}
		for _, stmt := range stmts {
			if err := db.Exec(stmt).Error; err != nil {
				return err
			}
		}
		return nil
	})
}
