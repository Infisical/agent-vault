CREATE TABLE invites (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    token         TEXT NOT NULL UNIQUE,
    namespace_id  TEXT NOT NULL REFERENCES namespaces(id) ON DELETE CASCADE,
    status        TEXT NOT NULL DEFAULT 'pending'
                  CHECK(status IN ('pending','redeemed','expired','revoked')),
    session_id    TEXT,
    created_by    TEXT NOT NULL,
    created_at    TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at    TEXT NOT NULL,
    redeemed_at   TEXT,
    revoked_at    TEXT
);

CREATE INDEX idx_invites_token ON invites(token);
CREATE INDEX idx_invites_namespace_status ON invites(namespace_id, status);
