CREATE TABLE users (
    id            TEXT PRIMARY KEY,
    email         TEXT NOT NULL UNIQUE,
    password_hash BLOB NOT NULL,
    password_salt BLOB NOT NULL,
    role          TEXT NOT NULL DEFAULT 'owner' CHECK(role IN ('owner')),
    created_at    TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

ALTER TABLE sessions ADD COLUMN user_id TEXT REFERENCES users(id);
