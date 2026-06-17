-- Long-lived user sessions: GitHub-CLI-style "log in once, stay logged in".
-- Adds an idle-TTL window plus per-session metadata for a self-service
-- "active sessions" UI. Agent tokens and scoped sessions leave the new
-- columns NULL and behave exactly as before.
--
-- Backward compatibility: pre-existing user sessions keep working through
-- their original (24h) expires_at — IsExpired skips the idle check when
-- idle_ttl_seconds is NULL, and the absolute expiry is unchanged. Users
-- pick up the long-lived behavior on their next login.

ALTER TABLE sessions ADD COLUMN last_used_at     TEXT;
ALTER TABLE sessions ADD COLUMN idle_ttl_seconds INTEGER;
ALTER TABLE sessions ADD COLUMN device_label     TEXT;
ALTER TABLE sessions ADD COLUMN last_ip          TEXT;
ALTER TABLE sessions ADD COLUMN last_user_agent  TEXT;
ALTER TABLE sessions ADD COLUMN public_id        TEXT;

CREATE INDEX        idx_sessions_user_id   ON sessions(user_id);
CREATE UNIQUE INDEX idx_sessions_public_id ON sessions(public_id);

-- Backfill public_id for pre-existing user sessions so they appear in
-- /v1/auth/sessions and can be revoked. randomblob(10) → 80 bits, matches
-- newPublicID() in sqlite.go. Scoped and agent rows keep public_id NULL
-- (SQLite UNIQUE indexes allow multiple NULLs).
UPDATE sessions
   SET public_id = lower(hex(randomblob(10)))
 WHERE user_id IS NOT NULL
   AND public_id IS NULL;
