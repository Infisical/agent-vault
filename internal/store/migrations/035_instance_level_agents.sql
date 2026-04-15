-- Move agents from vault-scoped to instance-level entities.
-- Agents now have multi-vault access via agent_vault_grants (like vault_grants for users).
-- Agent invites support vault pre-assignments via agent_invite_vaults (like user_invite_vaults).

PRAGMA foreign_keys = OFF;

-- 1. Create agent_vault_grants table (parallels vault_grants for users).
CREATE TABLE agent_vault_grants (
    agent_id   TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    vault_id   TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    vault_role TEXT NOT NULL DEFAULT 'proxy'
               CHECK(vault_role IN ('proxy', 'member', 'admin')),
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (agent_id, vault_id)
);
CREATE INDEX idx_agent_vault_grants_vault ON agent_vault_grants(vault_id);

-- 2. Migrate existing agent-vault relationships to grants.
INSERT INTO agent_vault_grants (agent_id, vault_id, vault_role, created_at)
SELECT id, vault_id, vault_role, created_at FROM agents WHERE vault_id IS NOT NULL;

-- 3. Rebuild agents table: remove vault_id, vault_role, and legacy service_token_* columns.
--    Instance-level agents authenticate via session tokens, not service tokens.
CREATE TABLE agents_new (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL UNIQUE,
    status     TEXT NOT NULL DEFAULT 'active'
               CHECK(status IN ('active','revoked')),
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    revoked_at TEXT
);

INSERT INTO agents_new (id, name, status, created_by, created_at, updated_at, revoked_at)
SELECT id, name, status, created_by, created_at, updated_at, revoked_at
FROM agents;

DROP TABLE agents;
ALTER TABLE agents_new RENAME TO agents;
CREATE UNIQUE INDEX idx_agents_name ON agents(name);

-- 4. Create agent_invite_vaults table (parallels user_invite_vaults).
CREATE TABLE agent_invite_vaults (
    invite_id  INTEGER NOT NULL REFERENCES invites(id) ON DELETE CASCADE,
    vault_id   TEXT    NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    vault_role TEXT    NOT NULL DEFAULT 'proxy'
               CHECK(vault_role IN ('proxy', 'member', 'admin')),
    PRIMARY KEY (invite_id, vault_id)
);
CREATE INDEX idx_agent_invite_vaults_vault ON agent_invite_vaults(vault_id);

-- 5. Migrate existing invite vault assignments to agent_invite_vaults.
INSERT INTO agent_invite_vaults (invite_id, vault_id, vault_role)
SELECT id, vault_id, vault_role FROM invites WHERE vault_id IS NOT NULL;

-- 6. Rebuild invites table: remove vault_id, vault_role, persistent.
--    All invites are now named (agent_name required). Vault context is in agent_invite_vaults.
CREATE TABLE invites_new (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    token               TEXT,
    token_hash          TEXT,
    agent_name          TEXT NOT NULL,
    agent_id            TEXT REFERENCES agents(id),
    session_ttl_seconds INTEGER,
    session_label       TEXT,
    status              TEXT NOT NULL DEFAULT 'pending'
                        CHECK(status IN ('pending','redeemed','expired','revoked')),
    session_id          TEXT,
    created_by          TEXT NOT NULL,
    created_at          TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at          TEXT NOT NULL,
    redeemed_at         TEXT,
    revoked_at          TEXT
);

INSERT INTO invites_new (id, token_hash, agent_name, agent_id, session_ttl_seconds, session_label, status, session_id, created_by, created_at, expires_at, redeemed_at, revoked_at)
SELECT id, token_hash, COALESCE(agent_name, 'unnamed-' || id), agent_id, session_ttl_seconds, session_label, status, session_id, created_by, created_at, expires_at, redeemed_at, revoked_at
FROM invites;

DROP TABLE invites;
ALTER TABLE invites_new RENAME TO invites;
CREATE INDEX idx_invites_token_hash ON invites(token_hash);
CREATE INDEX idx_invites_status ON invites(status);

-- 7. Rebuild sessions table to allow NULL vault_id for instance-level agent sessions.
--    User scoped sessions still have vault_id set. Agent sessions have vault_id = NULL.
CREATE TABLE sessions_new (
    id         TEXT PRIMARY KEY,
    expires_at TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    vault_id   TEXT REFERENCES vaults(id) ON DELETE CASCADE,
    user_id    TEXT REFERENCES users(id) ON DELETE CASCADE,
    agent_id   TEXT REFERENCES agents(id) ON DELETE CASCADE,
    vault_role TEXT CHECK(vault_role IN ('proxy', 'member', 'admin')),
    label      TEXT
);

INSERT INTO sessions_new (id, expires_at, created_at, vault_id, user_id, agent_id, vault_role, label)
SELECT id, expires_at, created_at, vault_id, user_id, agent_id, vault_role, label
FROM sessions;

-- For existing agent sessions, clear vault_id (they become instance-level).
UPDATE sessions_new SET vault_id = NULL, vault_role = NULL WHERE agent_id IS NOT NULL AND agent_id != '';

DROP TABLE sessions;
ALTER TABLE sessions_new RENAME TO sessions;
CREATE INDEX idx_sessions_agent_id ON sessions(agent_id);

PRAGMA foreign_keys = ON;
