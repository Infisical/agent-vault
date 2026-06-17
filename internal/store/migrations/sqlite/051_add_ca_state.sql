CREATE TABLE IF NOT EXISTS ca_state (
    id             INTEGER PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    root_cert      BLOB NOT NULL,
    root_key_ct    BLOB NOT NULL,
    root_key_nonce BLOB NOT NULL,
    source         TEXT NOT NULL DEFAULT 'auto',
    created_at     TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at     TEXT NOT NULL DEFAULT (datetime('now'))
);
