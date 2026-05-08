-- Collapse the two-tier role system (instance + vault) into a single
-- instance-level role with three values: owner, admin, agent.
--
-- Existing-data mapping for agents (only place data changes role).
--   * agents.role='owner' is unchanged.
--   * agents.role='admin' stays admin if the agent has at least one
--     vault_grants row with role IN (admin, member). Otherwise it
--     downgrades to 'agent' (proxy-only or no grants).
--
-- Owners' vault_grants rows are dropped — owners now auto-access every
-- vault. Users keep role='admin' or 'owner' as before. The vault_grants
-- table loses its role column. Sessions and invite junction tables are
-- rebuilt to drop their per-vault role columns.

PRAGMA foreign_keys = OFF;

-- 1. Collapse agent instance roles using highest-wins mapping.
--    Done before relaxing the CHECK constraint so the staging values
--    (still 'owner' or 'admin') validate against the existing schema.
UPDATE agents
   SET role = 'agent'
 WHERE role = 'admin'
   AND id NOT IN (
       SELECT actor_id
         FROM vault_grants
        WHERE actor_type = 'agent'
          AND role IN ('admin', 'member')
   );

-- Owners auto-access every vault now -> drop their grants.
DELETE FROM vault_grants WHERE actor_id IN (
    SELECT id FROM users  WHERE role = 'owner'
    UNION
    SELECT id FROM agents WHERE role = 'owner'
);

-- 2. agents.role: relax CHECK to allow 'agent'.
CREATE TABLE agents_new (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL UNIQUE,
    status     TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','revoked')),
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    revoked_at TEXT,
    role       TEXT NOT NULL DEFAULT 'agent' CHECK(role IN ('owner', 'admin', 'agent'))
);
INSERT INTO agents_new (id, name, status, created_by, created_at, updated_at, revoked_at, role)
SELECT id, name, status, created_by, created_at, updated_at, revoked_at, role
FROM agents;
DROP TABLE agents;
ALTER TABLE agents_new RENAME TO agents;
CREATE UNIQUE INDEX idx_agents_name ON agents(name);

-- 3. invites.agent_role: relax CHECK to allow 'agent'.
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
    revoked_at          TEXT,
    agent_role          TEXT NOT NULL DEFAULT 'agent' CHECK(agent_role IN ('owner', 'admin', 'agent'))
);
INSERT INTO invites_new (id, token, token_hash, agent_name, agent_id, session_ttl_seconds, session_label, status, session_id, created_by, created_at, expires_at, redeemed_at, revoked_at, agent_role)
SELECT id, token, token_hash, agent_name, agent_id, session_ttl_seconds, session_label, status, session_id, created_by, created_at, expires_at, redeemed_at, revoked_at, agent_role
FROM invites;
DROP TABLE invites;
ALTER TABLE invites_new RENAME TO invites;
CREATE INDEX idx_invites_token_hash ON invites(token_hash);
CREATE INDEX idx_invites_status ON invites(status);

-- 4. vault_grants: drop the role column.
CREATE TABLE vault_grants_new (
    actor_id   TEXT NOT NULL,
    actor_type TEXT NOT NULL CHECK(actor_type IN ('user', 'agent')),
    vault_id   TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (actor_id, vault_id)
);
INSERT INTO vault_grants_new (actor_id, actor_type, vault_id, created_at)
SELECT actor_id, actor_type, vault_id, created_at FROM vault_grants;
DROP TABLE vault_grants;
ALTER TABLE vault_grants_new RENAME TO vault_grants;
CREATE INDEX idx_vault_grants_vault ON vault_grants(vault_id);
CREATE INDEX idx_vault_grants_actor ON vault_grants(actor_id);
CREATE INDEX idx_vault_grants_type  ON vault_grants(actor_type);

-- 5. user_invite_vaults: drop vault_role.
CREATE TABLE user_invite_vaults_new (
    user_invite_id  INTEGER NOT NULL REFERENCES user_invites(id) ON DELETE CASCADE,
    vault_id        TEXT    NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    PRIMARY KEY (user_invite_id, vault_id)
);
INSERT INTO user_invite_vaults_new (user_invite_id, vault_id)
SELECT user_invite_id, vault_id FROM user_invite_vaults;
DROP TABLE user_invite_vaults;
ALTER TABLE user_invite_vaults_new RENAME TO user_invite_vaults;
CREATE INDEX idx_user_invite_vaults_vault ON user_invite_vaults(vault_id);

-- 6. agent_invite_vaults: drop vault_role.
CREATE TABLE agent_invite_vaults_new (
    invite_id  INTEGER NOT NULL REFERENCES invites(id) ON DELETE CASCADE,
    vault_id   TEXT    NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    PRIMARY KEY (invite_id, vault_id)
);
INSERT INTO agent_invite_vaults_new (invite_id, vault_id)
SELECT invite_id, vault_id FROM agent_invite_vaults;
DROP TABLE agent_invite_vaults;
ALTER TABLE agent_invite_vaults_new RENAME TO agent_invite_vaults;
CREATE INDEX idx_agent_invite_vaults_vault ON agent_invite_vaults(vault_id);

-- 7. sessions: drop the vault_role column. Scoped sessions still bind to a
--    single vault (vault_id) but no longer carry a role. Effective power
--    is derived from the actor's instance role.
CREATE TABLE sessions_new (
    id               TEXT PRIMARY KEY,
    expires_at       TEXT,
    created_at       TEXT NOT NULL DEFAULT (datetime('now')),
    vault_id         TEXT REFERENCES vaults(id) ON DELETE CASCADE,
    user_id          TEXT REFERENCES users(id) ON DELETE CASCADE,
    agent_id         TEXT REFERENCES agents(id),
    label            TEXT,
    last_used_at     TEXT,
    idle_ttl_seconds INTEGER,
    device_label     TEXT,
    last_ip          TEXT,
    last_user_agent  TEXT,
    public_id        TEXT
);
INSERT INTO sessions_new (id, expires_at, created_at, vault_id, user_id, agent_id, label, last_used_at, idle_ttl_seconds, device_label, last_ip, last_user_agent, public_id)
SELECT id, expires_at, created_at, vault_id, user_id, agent_id, label, last_used_at, idle_ttl_seconds, device_label, last_ip, last_user_agent, public_id
FROM sessions;
DROP TABLE sessions;
ALTER TABLE sessions_new RENAME TO sessions;
CREATE INDEX        idx_sessions_agent_id  ON sessions(agent_id);
CREATE INDEX        idx_sessions_user_id   ON sessions(user_id);
CREATE UNIQUE INDEX idx_sessions_public_id ON sessions(public_id);

PRAGMA foreign_keys = ON;
