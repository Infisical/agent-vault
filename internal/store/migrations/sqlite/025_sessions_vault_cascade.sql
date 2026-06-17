-- Recreate sessions table to add ON DELETE CASCADE on vault_id FK.
-- SQLite does not support ALTER CONSTRAINT, so we must recreate the table.

CREATE TABLE sessions_new (
    id         TEXT PRIMARY KEY,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    vault_id   TEXT REFERENCES vaults(id) ON DELETE CASCADE,
    user_id    TEXT REFERENCES users(id),
    agent_id   TEXT REFERENCES agents(id),
    vault_role TEXT NOT NULL DEFAULT 'consumer' CHECK(vault_role IN ('consumer', 'member', 'admin'))
);

INSERT INTO sessions_new (id, expires_at, created_at, vault_id, user_id, agent_id, vault_role)
    SELECT id, expires_at, created_at, vault_id, user_id, agent_id, vault_role FROM sessions;

DROP TABLE sessions;
ALTER TABLE sessions_new RENAME TO sessions;

CREATE INDEX idx_sessions_agent_id ON sessions(agent_id);
