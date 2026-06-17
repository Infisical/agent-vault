-- Make password fields nullable for OAuth-only users.
-- SQLite does not support ALTER COLUMN, so rebuild the table.
PRAGMA foreign_keys = OFF;

CREATE TABLE users_new (
    id            TEXT PRIMARY KEY,
    email         TEXT NOT NULL UNIQUE,
    password_hash BLOB,
    password_salt BLOB,
    role          TEXT NOT NULL DEFAULT 'owner' CHECK(role IN ('owner', 'member')),
    created_at    TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at    TEXT NOT NULL DEFAULT (datetime('now')),
    kdf_time      INTEGER NOT NULL DEFAULT 3,
    kdf_memory    INTEGER NOT NULL DEFAULT 65536,
    kdf_threads   INTEGER NOT NULL DEFAULT 4,
    is_active     INTEGER NOT NULL DEFAULT 0
);
INSERT INTO users_new SELECT * FROM users;
DROP TABLE users;
ALTER TABLE users_new RENAME TO users;

PRAGMA foreign_keys = ON;

-- OAuth identity linking: maps provider identities to local users.
CREATE TABLE oauth_accounts (
    id               TEXT PRIMARY KEY,
    user_id          TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider         TEXT NOT NULL,
    provider_user_id TEXT NOT NULL,
    email            TEXT NOT NULL,
    name             TEXT,
    avatar_url       TEXT,
    created_at       TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at       TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(provider, provider_user_id),
    UNIQUE(user_id, provider)
);
CREATE INDEX idx_oauth_accounts_user_id ON oauth_accounts(user_id);

-- CSRF state + PKCE verifier for OAuth flows.
CREATE TABLE oauth_states (
    id            TEXT PRIMARY KEY,
    state_hash    TEXT NOT NULL UNIQUE,
    code_verifier TEXT NOT NULL,
    redirect_url  TEXT,
    mode          TEXT NOT NULL DEFAULT 'login',
    user_id       TEXT,
    created_at    TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at    TEXT NOT NULL
);
