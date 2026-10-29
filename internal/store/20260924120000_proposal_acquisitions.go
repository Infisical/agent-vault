package store

import "gorm.io/gorm"

func init() {
	RegisterGORMMigration(func(db *gorm.DB) error {
		if db.Migrator().HasTable("proposal_acquisitions") {
			return nil
		}
		timestamp := "TEXT"
		requiredTimestamp := "TEXT NOT NULL DEFAULT (datetime('now'))"
		binary := "BLOB"
		if db.Name() == "postgres" {
			timestamp = "TIMESTAMPTZ"
			requiredTimestamp = "TIMESTAMPTZ NOT NULL DEFAULT NOW()"
			binary = "BYTEA"
		}
		if err := db.Exec(`CREATE TABLE proposal_acquisitions (
			id TEXT PRIMARY KEY,
			vault_id TEXT NOT NULL,
			proposal_id INTEGER NOT NULL,
			credential_key TEXT NOT NULL,
			attempt INTEGER NOT NULL,
			handler_id TEXT NOT NULL,
			handler_generation TEXT NOT NULL,
			profile TEXT NOT NULL,
			mode TEXT NOT NULL CHECK (mode IN ('native','guided','oauth','device','server_passthrough')),
			state TEXT NOT NULL CHECK (state IN ('queued','running','awaiting_user','succeeded','failed','cancelled','expired')),
			context_binding_id TEXT NOT NULL REFERENCES context_bindings(id) ON DELETE RESTRICT,
			source TEXT NOT NULL DEFAULT '',
			error_code TEXT NOT NULL DEFAULT '',
			credential_expires_at ` + timestamp + `,
			continuation_ticket_hash ` + binary + `,
			continuation_expires_at ` + timestamp + `,
			continuation_used_at ` + timestamp + `,
			started_at ` + timestamp + `,
			completed_at ` + timestamp + `,
			created_at ` + requiredTimestamp + `,
			updated_at ` + requiredTimestamp + `,
			FOREIGN KEY (vault_id, proposal_id) REFERENCES proposals(vault_id, id) ON DELETE CASCADE,
			UNIQUE (vault_id, proposal_id, credential_key, attempt)
		)`).Error; err != nil {
			return err
		}
		if err := db.Exec(`CREATE UNIQUE INDEX idx_proposal_acquisitions_one_active
			ON proposal_acquisitions(vault_id, proposal_id, credential_key)
			WHERE state IN ('queued','running','awaiting_user')`).Error; err != nil {
			return err
		}
		if err := db.Exec(`CREATE UNIQUE INDEX idx_proposal_acquisitions_continuation
			ON proposal_acquisitions(continuation_ticket_hash)
			WHERE continuation_ticket_hash IS NOT NULL`).Error; err != nil {
			return err
		}
		return db.Exec(`CREATE INDEX idx_proposal_acquisitions_proposal
			ON proposal_acquisitions(vault_id, proposal_id, credential_key, attempt DESC)`).Error
	})
}
