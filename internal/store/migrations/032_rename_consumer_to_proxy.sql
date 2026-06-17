-- Rename vault-level role "consumer" to "proxy" across all tables.

-- 1. Agents: recreate with updated CHECK constraint.
CREATE TABLE agents_new (
    id                   TEXT PRIMARY KEY,
    name                 TEXT NOT NULL UNIQUE,
    vault_id             TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    service_token_hash   BLOB NOT NULL,
    service_token_salt   BLOB NOT NULL,
    service_token_prefix TEXT NOT NULL,
    status               TEXT NOT NULL DEFAULT 'active'
                         CHECK(status IN ('active','revoked')),
    vault_role           TEXT NOT NULL DEFAULT 'proxy'
                         CHECK(vault_role IN ('proxy', 'member', 'admin')),
    created_by           TEXT NOT NULL,
    created_at           TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at           TEXT NOT NULL DEFAULT (datetime('now')),
    revoked_at           TEXT
);

INSERT INTO agents_new (id, name, vault_id, service_token_hash, service_token_salt, service_token_prefix, status, vault_role, created_by, created_at, updated_at, revoked_at)
    SELECT id, name, vault_id, service_token_hash, service_token_salt, service_token_prefix, status,
           CASE vault_role WHEN 'consumer' THEN 'proxy' ELSE vault_role END,
           created_by, created_at, updated_at, revoked_at
    FROM agents;

DROP TABLE agents;
ALTER TABLE agents_new RENAME TO agents;
CREATE UNIQUE INDEX idx_agents_name ON agents(name);
CREATE INDEX idx_agents_vault ON agents(vault_id);
CREATE INDEX idx_agents_token_prefix ON agents(service_token_prefix);

-- 2. Invites: recreate with updated CHECK constraint.
CREATE TABLE invites_new (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash    TEXT,
    vault_id      TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    vault_role    TEXT NOT NULL DEFAULT 'proxy'
                  CHECK(vault_role IN ('proxy', 'member', 'admin')),
    status        TEXT NOT NULL DEFAULT 'pending'
                  CHECK(status IN ('pending','redeemed','expired','revoked')),
    session_id    TEXT,
    created_by    TEXT NOT NULL,
    persistent    INTEGER NOT NULL DEFAULT 0,
    agent_name    TEXT,
    agent_id      TEXT REFERENCES agents(id),
    session_ttl_seconds INTEGER,
    session_label TEXT,
    created_at    TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at    TEXT NOT NULL,
    redeemed_at   TEXT,
    revoked_at    TEXT
);

INSERT INTO invites_new (id, token_hash, vault_id, vault_role, status, session_id, created_by, persistent, agent_name, agent_id, session_ttl_seconds, session_label, created_at, expires_at, redeemed_at, revoked_at)
    SELECT id, token_hash, vault_id,
           CASE vault_role WHEN 'consumer' THEN 'proxy' ELSE vault_role END,
           status, session_id, created_by, persistent, agent_name, agent_id, session_ttl_seconds, session_label, created_at, expires_at, redeemed_at, revoked_at
    FROM invites;

DROP TABLE invites;
ALTER TABLE invites_new RENAME TO invites;
CREATE INDEX idx_invites_token_hash ON invites(token_hash);
CREATE INDEX idx_invites_vault_status ON invites(vault_id, status);

-- 3. Sessions: recreate with updated CHECK constraint.
CREATE TABLE sessions_new (
    id         TEXT PRIMARY KEY,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    vault_id   TEXT REFERENCES vaults(id) ON DELETE CASCADE,
    user_id    TEXT REFERENCES users(id) ON DELETE CASCADE,
    agent_id   TEXT REFERENCES agents(id),
    vault_role TEXT NOT NULL DEFAULT 'proxy' CHECK(vault_role IN ('proxy', 'member', 'admin')),
    label      TEXT
);

INSERT INTO sessions_new (id, expires_at, created_at, vault_id, user_id, agent_id, vault_role, label)
    SELECT id, expires_at, created_at, vault_id, user_id, agent_id,
           CASE vault_role WHEN 'consumer' THEN 'proxy' ELSE vault_role END,
           label
    FROM sessions;

DROP TABLE sessions;
ALTER TABLE sessions_new RENAME TO sessions;
CREATE INDEX idx_sessions_agent_id ON sessions(agent_id);
