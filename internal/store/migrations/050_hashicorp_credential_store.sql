-- Widen the vault_credential_stores.kind CHECK constraint to allow 'hashicorp'
-- alongside 'infisical'. SQLite cannot ALTER a CHECK constraint in place, so the
-- table is rebuilt with the new constraint. The kind values mirror the
-- CredentialStore constants in internal/store/store.go and must be extended
-- together when adding a new external store.

PRAGMA foreign_keys = OFF;

CREATE TABLE vault_credential_stores_new (
    vault_id              TEXT PRIMARY KEY REFERENCES vaults(id) ON DELETE CASCADE,
    kind                  TEXT NOT NULL CHECK(kind IN ('infisical','hashicorp')),
    config_json           TEXT NOT NULL,
    poll_interval_seconds INTEGER NOT NULL DEFAULT 60 CHECK(poll_interval_seconds >= 10),
    last_synced_at        TEXT,
    last_sync_status      TEXT CHECK(last_sync_status IS NULL OR last_sync_status IN ('ok','error')),
    last_sync_error       TEXT,
    created_at            TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at            TEXT NOT NULL DEFAULT (datetime('now'))
);
INSERT INTO vault_credential_stores_new
SELECT vault_id, kind, config_json, poll_interval_seconds, last_synced_at,
       last_sync_status, last_sync_error, created_at, updated_at
FROM vault_credential_stores;
DROP TABLE vault_credential_stores;
ALTER TABLE vault_credential_stores_new RENAME TO vault_credential_stores;

PRAGMA foreign_keys = ON;
