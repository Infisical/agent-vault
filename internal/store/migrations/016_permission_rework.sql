-- Add vault-level role to grants (admin or member).
ALTER TABLE vault_grants ADD COLUMN role TEXT NOT NULL DEFAULT 'member'
    CHECK(role IN ('admin', 'member'));

-- Add is_active flag to users (for email verification gating).
ALTER TABLE users ADD COLUMN is_active INTEGER NOT NULL DEFAULT 1;

-- Email verification codes for self-signup.
CREATE TABLE email_verifications (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    email      TEXT    NOT NULL,
    code       TEXT    NOT NULL,
    status     TEXT    NOT NULL DEFAULT 'pending'
               CHECK(status IN ('pending', 'verified', 'expired')),
    created_at TEXT    NOT NULL DEFAULT (datetime('now')),
    expires_at TEXT    NOT NULL
);
CREATE INDEX idx_email_verifications_email ON email_verifications(email, status);

-- Replace user_invites (multi-vault JSON) with vault_invites (single vault + role).
DROP TABLE IF EXISTS user_invites;

CREATE TABLE vault_invites (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    token       TEXT    NOT NULL UNIQUE,
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
CREATE INDEX idx_vault_invites_email_status ON vault_invites(email, status);
CREATE INDEX idx_vault_invites_token ON vault_invites(token);
CREATE INDEX idx_vault_invites_vault_status ON vault_invites(vault_id, status);
