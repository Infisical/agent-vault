CREATE TABLE user_invites (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    token           TEXT    NOT NULL UNIQUE,
    email           TEXT    NOT NULL,
    namespaces_json TEXT    NOT NULL DEFAULT '[]',
    status          TEXT    NOT NULL DEFAULT 'pending'
                    CHECK(status IN ('pending','accepted','expired','revoked')),
    created_by      TEXT    NOT NULL,
    created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    expires_at      TEXT    NOT NULL,
    accepted_at     TEXT
);

CREATE INDEX idx_user_invites_email_status ON user_invites(email, status);
CREATE INDEX idx_user_invites_token ON user_invites(token);
