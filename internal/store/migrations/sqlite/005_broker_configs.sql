CREATE TABLE broker_configs (
    id           TEXT PRIMARY KEY,
    namespace_id TEXT NOT NULL UNIQUE REFERENCES namespaces(id) ON DELETE CASCADE,
    rules_json   TEXT NOT NULL DEFAULT '[]',
    created_at   TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at   TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Backfill existing namespaces with empty broker configs
INSERT INTO broker_configs (id, namespace_id, rules_json, created_at, updated_at)
SELECT lower(hex(randomblob(4)) || '-' || hex(randomblob(2)) || '-4' ||
       substr(hex(randomblob(2)),2) || '-' || substr('89ab', abs(random()) % 4 + 1, 1) ||
       substr(hex(randomblob(2)),2) || '-' || hex(randomblob(6))),
       id, '[]', datetime('now'), datetime('now')
FROM namespaces;
