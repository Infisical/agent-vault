-- Agent vault role: consumer (proxy/discover/changesets), member (+secrets/policy/approve), admin (+invite users/agents with any role)
ALTER TABLE agents ADD COLUMN vault_role TEXT NOT NULL DEFAULT 'consumer'
    CHECK(vault_role IN ('consumer', 'member', 'admin'));

-- Invite vault role (applies to both temporary and persistent invites)
ALTER TABLE invites ADD COLUMN vault_role TEXT NOT NULL DEFAULT 'consumer'
    CHECK(vault_role IN ('consumer', 'member', 'admin'));

-- Session vault role (for temporary invite sessions that have no agent record, and cached for agent sessions)
ALTER TABLE sessions ADD COLUMN vault_role TEXT NOT NULL DEFAULT 'consumer'
    CHECK(vault_role IN ('consumer', 'member', 'admin'));
