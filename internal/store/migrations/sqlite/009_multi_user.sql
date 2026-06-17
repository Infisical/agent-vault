-- Recreate users table with widened role CHECK to allow 'member' role.
-- SQLite does not support ALTER COLUMN, so we must recreate the table.
CREATE TABLE users_new (
    id            TEXT PRIMARY KEY,
    email         TEXT NOT NULL UNIQUE,
    password_hash BLOB NOT NULL,
    password_salt BLOB NOT NULL,
    role          TEXT NOT NULL DEFAULT 'owner' CHECK(role IN ('owner', 'member')),
    created_at    TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at    TEXT NOT NULL DEFAULT (datetime('now'))
);
INSERT INTO users_new SELECT * FROM users;
DROP TABLE users;
ALTER TABLE users_new RENAME TO users;

-- Namespace grants: flat user<->namespace join table.
CREATE TABLE namespace_grants (
    user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    namespace_id TEXT NOT NULL REFERENCES namespaces(id) ON DELETE CASCADE,
    created_at   TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (user_id, namespace_id)
);

-- Approval policy on namespaces (default: any member can approve changesets).
ALTER TABLE namespaces ADD COLUMN approval_policy TEXT NOT NULL DEFAULT 'any-member' CHECK(approval_policy IN ('any-member', 'owner-only'));
