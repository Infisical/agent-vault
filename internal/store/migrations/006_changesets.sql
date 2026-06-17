CREATE TABLE changesets (
    id            INTEGER NOT NULL,
    namespace_id  TEXT NOT NULL REFERENCES namespaces(id) ON DELETE CASCADE,
    session_id    TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'pending'
                  CHECK(status IN ('pending','applied','rejected','expired')),
    rules_json    TEXT NOT NULL DEFAULT '[]',
    secrets_json  TEXT NOT NULL DEFAULT '[]',
    message       TEXT NOT NULL DEFAULT '',
    review_note   TEXT NOT NULL DEFAULT '',
    reviewed_at   TEXT,
    created_at    TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at    TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (namespace_id, id)
);

CREATE TABLE changeset_secrets (
    namespace_id  TEXT NOT NULL,
    changeset_id  INTEGER NOT NULL,
    key           TEXT NOT NULL,
    ciphertext    BLOB NOT NULL,
    nonce         BLOB NOT NULL,
    FOREIGN KEY (namespace_id, changeset_id) REFERENCES changesets(namespace_id, id) ON DELETE CASCADE,
    PRIMARY KEY (namespace_id, changeset_id, key)
);

CREATE INDEX idx_changesets_ns_status ON changesets(namespace_id, status);
