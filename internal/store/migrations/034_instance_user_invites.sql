-- Replace vault-scoped user invites with instance-level user invites.
-- Invites now bring users into the instance, with optional vault pre-assignment.

DROP TABLE IF EXISTS vault_invites;

CREATE TABLE user_invites (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash  TEXT    NOT NULL UNIQUE,
    email       TEXT    NOT NULL,
    status      TEXT    NOT NULL DEFAULT 'pending'
                CHECK(status IN ('pending','accepted','expired','revoked')),
    created_by  TEXT    NOT NULL,
    created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
    expires_at  TEXT    NOT NULL,
    accepted_at TEXT
);
CREATE INDEX idx_user_invites_token_hash ON user_invites(token_hash);
CREATE INDEX idx_user_invites_email_status ON user_invites(email, status);

CREATE TABLE user_invite_vaults (
    user_invite_id  INTEGER NOT NULL REFERENCES user_invites(id) ON DELETE CASCADE,
    vault_id        TEXT    NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    vault_role      TEXT    NOT NULL DEFAULT 'member'
                    CHECK(vault_role IN ('admin', 'member')),
    PRIMARY KEY (user_invite_id, vault_id)
);
CREATE INDEX idx_user_invite_vaults_vault ON user_invite_vaults(vault_id);
