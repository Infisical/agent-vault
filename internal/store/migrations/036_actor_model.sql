-- Unify the permission model: agents become first-class actors with instance-level roles.
-- Merge vault_grants + agent_vault_grants into a single vault_grants table.

PRAGMA foreign_keys = OFF;

-- 1. Add instance-level role to agents (owner/member, like users).
ALTER TABLE agents ADD COLUMN role TEXT NOT NULL DEFAULT 'member' CHECK(role IN ('owner', 'member'));

-- 2. Add instance-level role to agent invites.
ALTER TABLE invites ADD COLUMN agent_role TEXT NOT NULL DEFAULT 'member' CHECK(agent_role IN ('owner', 'member'));

-- 3. Create unified vault_grants table with actor_id + actor_type.
CREATE TABLE vault_grants_new (
    actor_id   TEXT NOT NULL,
    actor_type TEXT NOT NULL CHECK(actor_type IN ('user', 'agent')),
    vault_id   TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    role       TEXT NOT NULL DEFAULT 'member' CHECK(role IN ('proxy', 'member', 'admin')),
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (actor_id, vault_id)
);

-- Migrate existing user vault grants.
INSERT INTO vault_grants_new (actor_id, actor_type, vault_id, role, created_at)
SELECT user_id, 'user', vault_id, role, created_at FROM vault_grants;

-- Migrate existing agent vault grants.
INSERT INTO vault_grants_new (actor_id, actor_type, vault_id, role, created_at)
SELECT agent_id, 'agent', vault_id, vault_role, created_at FROM agent_vault_grants;

-- Drop old tables.
DROP TABLE vault_grants;
DROP TABLE agent_vault_grants;
ALTER TABLE vault_grants_new RENAME TO vault_grants;

-- Recreate indexes.
CREATE INDEX idx_vault_grants_vault ON vault_grants(vault_id);
CREATE INDEX idx_vault_grants_actor ON vault_grants(actor_id);
CREATE INDEX idx_vault_grants_type  ON vault_grants(actor_type);

PRAGMA foreign_keys = ON;
