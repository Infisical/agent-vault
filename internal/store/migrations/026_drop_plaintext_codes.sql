-- Security hardening: drop plaintext token/code columns, add user_id cascade.
-- Only hashed columns are needed for lookups.

-- 1. Email verifications: drop plaintext code column.
-- Expire any legacy rows without a hash (pre-migration 019).
UPDATE email_verifications SET status = 'expired'
    WHERE code_hash IS NULL AND status = 'pending';

CREATE TABLE email_verifications_new (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    email      TEXT    NOT NULL,
    code_hash  TEXT    NOT NULL,
    status     TEXT    NOT NULL DEFAULT 'pending'
               CHECK(status IN ('pending', 'verified', 'expired')),
    created_at TEXT    NOT NULL DEFAULT (datetime('now')),
    expires_at TEXT    NOT NULL
);

INSERT INTO email_verifications_new (id, email, code_hash, status, created_at, expires_at)
    SELECT id, email, COALESCE(code_hash, ''), status, created_at, expires_at
    FROM email_verifications;

DROP TABLE email_verifications;
ALTER TABLE email_verifications_new RENAME TO email_verifications;
CREATE INDEX idx_email_verifications_email ON email_verifications(email, status);
CREATE INDEX idx_email_verifications_code_hash ON email_verifications(code_hash);

-- 2. Invites: drop plaintext token column, keep token_hash.
-- Expire any legacy rows without a hash.
UPDATE invites SET status = 'expired'
    WHERE token_hash IS NULL AND status = 'pending';

CREATE TABLE invites_new (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash    TEXT,
    vault_id      TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    vault_role    TEXT NOT NULL DEFAULT 'consumer'
                  CHECK(vault_role IN ('consumer', 'member', 'admin')),
    status        TEXT NOT NULL DEFAULT 'pending'
                  CHECK(status IN ('pending','redeemed','expired','revoked')),
    session_id    TEXT,
    created_by    TEXT NOT NULL,
    persistent    INTEGER NOT NULL DEFAULT 0,
    agent_name    TEXT,
    agent_id      TEXT REFERENCES agents(id),
    created_at    TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at    TEXT NOT NULL,
    redeemed_at   TEXT,
    revoked_at    TEXT
);

INSERT INTO invites_new (id, token_hash, vault_id, vault_role, status, session_id, created_by, persistent, agent_name, agent_id, created_at, expires_at, redeemed_at, revoked_at)
    SELECT id, token_hash, vault_id, vault_role, status, session_id, created_by, persistent, agent_name, agent_id, created_at, expires_at, redeemed_at, revoked_at
    FROM invites;

DROP TABLE invites;
ALTER TABLE invites_new RENAME TO invites;
CREATE INDEX idx_invites_token_hash ON invites(token_hash);
CREATE INDEX idx_invites_vault_status ON invites(vault_id, status);

-- 3. Vault invites: drop plaintext token column, keep token_hash.
UPDATE vault_invites SET status = 'expired'
    WHERE token_hash IS NULL AND status = 'pending';

CREATE TABLE vault_invites_new (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash  TEXT,
    email       TEXT    NOT NULL,
    vault_id    TEXT    NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    vault_role  TEXT    NOT NULL DEFAULT 'member'
                CHECK(vault_role IN ('admin', 'member')),
    status      TEXT    NOT NULL DEFAULT 'pending'
                CHECK(status IN ('pending','accepted','expired','revoked')),
    created_by  TEXT    NOT NULL,
    created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
    expires_at  TEXT    NOT NULL,
    accepted_at TEXT
);

INSERT INTO vault_invites_new (id, token_hash, email, vault_id, vault_role, status, created_by, created_at, expires_at, accepted_at)
    SELECT id, token_hash, email, vault_id, vault_role, status, created_by, created_at, expires_at, accepted_at
    FROM vault_invites;

DROP TABLE vault_invites;
ALTER TABLE vault_invites_new RENAME TO vault_invites;
CREATE INDEX idx_vault_invites_token_hash ON vault_invites(token_hash);
CREATE INDEX idx_vault_invites_email_status ON vault_invites(email, status);
CREATE INDEX idx_vault_invites_vault_status ON vault_invites(vault_id, status);

-- 4. Proposals: drop plaintext approval_token column, keep approval_token_hash.
CREATE TABLE proposals_new (
    id            INTEGER NOT NULL,
    vault_id      TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    session_id    TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'pending'
                  CHECK(status IN ('pending','applied','rejected','expired')),
    rules_json    TEXT NOT NULL DEFAULT '[]',
    credentials_json TEXT NOT NULL DEFAULT '[]',
    message       TEXT NOT NULL DEFAULT '',
    user_message  TEXT NOT NULL DEFAULT '',
    review_note   TEXT NOT NULL DEFAULT '',
    reviewed_at   TEXT,
    approval_token_hash TEXT,
    approval_token_expires_at TEXT,
    created_at    TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at    TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (vault_id, id)
);

INSERT INTO proposals_new (id, vault_id, session_id, status, rules_json, credentials_json, message, user_message, review_note, reviewed_at, approval_token_hash, approval_token_expires_at, created_at, updated_at)
    SELECT id, vault_id, session_id, status, rules_json, credentials_json, message, user_message, review_note, reviewed_at, approval_token_hash, approval_token_expires_at, created_at, updated_at
    FROM proposals;

DROP TABLE proposals;
ALTER TABLE proposals_new RENAME TO proposals;
CREATE INDEX idx_proposals_vault_status ON proposals(vault_id, status);
CREATE INDEX idx_proposals_approval_token_hash ON proposals(approval_token_hash);

-- Sessions user_id CASCADE is handled by migration 028.
