CREATE TABLE request_logs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    vault_id        TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    actor_type      TEXT NOT NULL DEFAULT '',
    actor_id        TEXT NOT NULL DEFAULT '',
    ingress         TEXT NOT NULL,
    method          TEXT NOT NULL,
    host            TEXT NOT NULL,
    path            TEXT NOT NULL,
    matched_service TEXT NOT NULL DEFAULT '',
    credential_keys TEXT NOT NULL DEFAULT '[]',
    status          INTEGER NOT NULL DEFAULT 0,
    latency_ms      INTEGER NOT NULL DEFAULT 0,
    error_code      TEXT NOT NULL DEFAULT '',
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX idx_request_logs_vault_id_desc ON request_logs(vault_id, id DESC);
CREATE INDEX idx_request_logs_id_desc ON request_logs(id DESC);
