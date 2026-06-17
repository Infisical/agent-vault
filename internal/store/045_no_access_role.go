package store

import "gorm.io/gorm"

func init() {
	RegisterGORMMigration(func(db *gorm.DB) error {
		if db.Name() != "sqlite" {
			return nil
		}
		stmts := []string{
			`-- Widen instance-role CHECK constraints to allow 'no-access'.
-- SQLite cannot ALTER a CHECK constraint in place, so each affected table
-- is rebuilt with the new constraint.


-- 1. users.role
CREATE TABLE users_new (
    id            TEXT PRIMARY KEY,
    email         TEXT NOT NULL UNIQUE,
    password_hash BLOB NOT NULL,
    password_salt BLOB NOT NULL,
    role          TEXT NOT NULL DEFAULT 'owner' CHECK(role IN ('owner', 'member', 'no-access')),
    created_at    TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at    TEXT NOT NULL DEFAULT (datetime('now')),
    kdf_time      INTEGER NOT NULL DEFAULT 3,
    kdf_memory    INTEGER NOT NULL DEFAULT 65536,
    kdf_threads   INTEGER NOT NULL DEFAULT 4,
    is_active     INTEGER NOT NULL DEFAULT 0
)`,
			`INSERT INTO users_new SELECT * FROM users`,
			`DROP TABLE users`,
			`ALTER TABLE users_new RENAME TO users`,
			`-- 2. agents.role
CREATE TABLE agents_new (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL UNIQUE,
    status     TEXT NOT NULL DEFAULT 'active'
               CHECK(status IN ('active','revoked')),
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    revoked_at TEXT,
    role       TEXT NOT NULL DEFAULT 'member' CHECK(role IN ('owner', 'member', 'no-access'))
)`,
			`INSERT INTO agents_new (id, name, status, created_by, created_at, updated_at, revoked_at, role)
SELECT id, name, status, created_by, created_at, updated_at, revoked_at, role
FROM agents`,
			`DROP TABLE agents`,
			`ALTER TABLE agents_new RENAME TO agents`,
			`CREATE UNIQUE INDEX idx_agents_name ON agents(name)`,
			`-- 3. invites.agent_role
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
    agent_role          TEXT NOT NULL DEFAULT 'member' CHECK(agent_role IN ('owner', 'member', 'no-access'))
)`,
			`INSERT INTO invites_new (id, token, token_hash, agent_name, agent_id, session_ttl_seconds, session_label, status, session_id, created_by, created_at, expires_at, redeemed_at, revoked_at, agent_role)
SELECT id, token, token_hash, agent_name, agent_id, session_ttl_seconds, session_label, status, session_id, created_by, created_at, expires_at, redeemed_at, revoked_at, agent_role
FROM invites`,
			`DROP TABLE invites`,
			`ALTER TABLE invites_new RENAME TO invites`,
			`CREATE INDEX idx_invites_token_hash ON invites(token_hash)`,
			`CREATE INDEX idx_invites_status ON invites(status)`,
			`-- 4. user_invites.role
CREATE TABLE user_invites_new (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash  TEXT    NOT NULL UNIQUE,
    email       TEXT    NOT NULL,
    status      TEXT    NOT NULL DEFAULT 'pending'
                CHECK(status IN ('pending','accepted','expired','revoked')),
    created_by  TEXT    NOT NULL,
    created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
    expires_at  TEXT    NOT NULL,
    accepted_at TEXT,
    role        TEXT    NOT NULL DEFAULT 'member' CHECK(role IN ('owner', 'member', 'no-access'))
)`,
			`INSERT INTO user_invites_new (id, token_hash, email, status, created_by, created_at, expires_at, accepted_at, role)
SELECT id, token_hash, email, status, created_by, created_at, expires_at, accepted_at, role
FROM user_invites`,
			`DROP TABLE user_invites`,
			`ALTER TABLE user_invites_new RENAME TO user_invites`,
			`CREATE INDEX idx_user_invites_token_hash ON user_invites(token_hash)`,
			`CREATE INDEX idx_user_invites_email_status ON user_invites(email, status)`,
		}
		for _, stmt := range stmts {
			if err := db.Exec(stmt).Error; err != nil {
				return err
			}
		}
		return nil
	})
}
