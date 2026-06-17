-- Allow sessions to have no expiry (NULL expires_at = never expires).
-- This supports the unified token model where agents can have non-expiring sessions.

CREATE TABLE sessions_new (
    id         TEXT PRIMARY KEY,
    expires_at TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    vault_id   TEXT REFERENCES vaults(id) ON DELETE CASCADE,
    user_id    TEXT REFERENCES users(id) ON DELETE CASCADE,
    agent_id   TEXT REFERENCES agents(id),
    vault_role TEXT NOT NULL DEFAULT 'proxy' CHECK(vault_role IN ('proxy', 'member', 'admin')),
    label      TEXT
);

INSERT INTO sessions_new (id, expires_at, created_at, vault_id, user_id, agent_id, vault_role, label)
    SELECT id, expires_at, created_at, vault_id, user_id, agent_id, vault_role, label
    FROM sessions;

DROP TABLE sessions;
ALTER TABLE sessions_new RENAME TO sessions;
CREATE INDEX idx_sessions_agent_id ON sessions(agent_id);
