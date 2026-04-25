-- Long-lived user sessions: GitHub-CLI-style "log in once, stay logged in".
-- Adds an idle-TTL window plus per-session metadata for a self-service
-- "active sessions" UI. Agent tokens and scoped sessions leave the new
-- columns NULL and behave exactly as before.
--
-- Pre-existing user sessions are wiped on upgrade — instances re-login once.

ALTER TABLE sessions ADD COLUMN last_used_at     TEXT;
ALTER TABLE sessions ADD COLUMN idle_ttl_seconds INTEGER;
ALTER TABLE sessions ADD COLUMN device_label     TEXT;
ALTER TABLE sessions ADD COLUMN last_ip          TEXT;
ALTER TABLE sessions ADD COLUMN last_user_agent  TEXT;
ALTER TABLE sessions ADD COLUMN public_id        TEXT;

CREATE INDEX        idx_sessions_user_id   ON sessions(user_id);
CREATE UNIQUE INDEX idx_sessions_public_id ON sessions(public_id);

DELETE FROM sessions WHERE user_id IS NOT NULL;
