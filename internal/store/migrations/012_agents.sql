-- Persistent agent identity: named agents with long-lived service tokens.

CREATE TABLE agents (
    id                   TEXT PRIMARY KEY,
    name                 TEXT NOT NULL UNIQUE,
    namespace_id         TEXT NOT NULL REFERENCES namespaces(id) ON DELETE CASCADE,
    service_token_hash   BLOB NOT NULL,
    service_token_salt   BLOB NOT NULL,
    service_token_prefix TEXT NOT NULL,
    status               TEXT NOT NULL DEFAULT 'active'
                         CHECK(status IN ('active','revoked')),
    created_by           TEXT NOT NULL,
    created_at           TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at           TEXT NOT NULL DEFAULT (datetime('now')),
    revoked_at           TEXT
);

CREATE UNIQUE INDEX idx_agents_name ON agents(name);
CREATE INDEX idx_agents_namespace ON agents(namespace_id);
CREATE INDEX idx_agents_token_prefix ON agents(service_token_prefix);

-- Extend invites for persistent agent invites and rotation invites.
ALTER TABLE invites ADD COLUMN persistent INTEGER NOT NULL DEFAULT 0;
ALTER TABLE invites ADD COLUMN agent_name TEXT;
ALTER TABLE invites ADD COLUMN agent_id TEXT REFERENCES agents(id);

-- Extend sessions with agent_id for audit trail.
ALTER TABLE sessions ADD COLUMN agent_id TEXT REFERENCES agents(id);
CREATE INDEX idx_sessions_agent_id ON sessions(agent_id);
