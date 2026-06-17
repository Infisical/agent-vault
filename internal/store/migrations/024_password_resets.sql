CREATE TABLE password_resets (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    email      TEXT    NOT NULL,
    code_hash  TEXT    NOT NULL,
    status     TEXT    NOT NULL DEFAULT 'pending'
               CHECK(status IN ('pending', 'used', 'expired')),
    created_at TEXT    NOT NULL DEFAULT (datetime('now')),
    expires_at TEXT    NOT NULL
);
CREATE INDEX idx_password_resets_email ON password_resets(email, status);
CREATE INDEX idx_password_resets_code_hash ON password_resets(code_hash);
