-- Remove per-vault approval policy. Any vault member can now approve changesets.
-- Rebuild table to remove column with CHECK constraint.
-- PRAGMA foreign_keys=OFF prevents DROP TABLE from cascading.
PRAGMA foreign_keys = OFF;

CREATE TABLE vaults_new (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

INSERT INTO vaults_new (id, name, created_at, updated_at)
    SELECT id, name, created_at, updated_at FROM vaults;

DROP TABLE vaults;

ALTER TABLE vaults_new RENAME TO vaults;

PRAGMA foreign_keys = ON;
