CREATE TABLE master_key (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    salt        BLOB NOT NULL,
    sentinel    BLOB NOT NULL,
    nonce       BLOB NOT NULL,
    kdf_time    INTEGER NOT NULL,
    kdf_memory  INTEGER NOT NULL,
    kdf_threads INTEGER NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
