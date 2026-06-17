CREATE TABLE vault_settings (
    vault_id   TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    key        TEXT NOT NULL,
    value      TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (vault_id, key)
);
