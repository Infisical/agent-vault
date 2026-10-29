package store

import "gorm.io/gorm"

func init() {
	RegisterGORMMigration(func(db *gorm.DB) error {
		if !db.Migrator().HasTable("context_bindings") {
			createdAt := "TEXT NOT NULL DEFAULT (datetime('now'))"
			retiredAt := "TEXT"
			if db.Name() == "postgres" {
				createdAt = "TIMESTAMPTZ NOT NULL DEFAULT NOW()"
				retiredAt = "TIMESTAMPTZ"
			}
			result := db.Exec(`CREATE TABLE context_bindings (
				id TEXT PRIMARY KEY,
				origin_type TEXT NOT NULL,
				origin_codex_thread_id TEXT NOT NULL,
				origin_codex_session_id TEXT NOT NULL,
				perplexity_project_id TEXT NOT NULL,
				registered_personal_computer_machine_id TEXT NOT NULL,
				runtime_device_id TEXT NOT NULL,
				workspace_root TEXT NOT NULL DEFAULT '',
				retired_at ` + retiredAt + `,
				created_at ` + createdAt + `,
				updated_at ` + createdAt + `,
				UNIQUE (
					origin_codex_thread_id,
					perplexity_project_id,
					registered_personal_computer_machine_id
				)
			)`)
			if result.Error != nil {
				return result.Error
			}
		}

		if !db.Migrator().HasColumn("proposals", "context_binding_id") {
			return db.Exec(`ALTER TABLE proposals ADD COLUMN context_binding_id TEXT NULL REFERENCES context_bindings(id) ON DELETE RESTRICT`).Error
		}
		return nil
	})
}
