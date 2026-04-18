CREATE TABLE master_key (
    id              INTEGER PRIMARY KEY CHECK (id = 1),
    sentinel        BLOB NOT NULL,
    sentinel_nonce  BLOB NOT NULL,
    dek_ciphertext  BLOB,          -- wrapped DEK (non-NULL when password-protected)
    dek_nonce       BLOB,          -- GCM nonce for DEK wrapping
    dek_plaintext   BLOB,          -- unwrapped DEK (non-NULL in passwordless mode)
    salt            BLOB,          -- KDF salt (non-NULL when password-protected)
    kdf_time        INTEGER,
    kdf_memory      INTEGER,
    kdf_threads     INTEGER,
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);
