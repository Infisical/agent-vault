package store

import "gorm.io/gorm"

func init() {
	RegisterGORMMigration(func(db *gorm.DB) error {
		if db.Name() != "sqlite" {
			return nil
		}
		stmts := []string{
			`-- Tracks outstanding Infisical dynamic-secret leases so they can be revoked on
-- vault disconnect, server shutdown, and (orphans) on the next startup. Holds
-- only lease metadata + the config snapshot needed to call revoke — never the
-- leased credential values, which live in process memory for their TTL only.
CREATE TABLE dynamic_secret_leases (
    lease_id            TEXT PRIMARY KEY,
    vault_id            TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    dynamic_secret_name TEXT NOT NULL,
    project_id          TEXT NOT NULL,
    environment         TEXT NOT NULL,
    secret_path         TEXT NOT NULL,
    expire_at           TEXT,
    created_at          TEXT NOT NULL DEFAULT (datetime('now'))
)`,
			`CREATE INDEX idx_dynamic_secret_leases_vault ON dynamic_secret_leases(vault_id)`,
		}
		for _, stmt := range stmts {
			if err := db.Exec(stmt).Error; err != nil {
				return err
			}
		}
		return nil
	})
}
