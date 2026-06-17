ALTER TABLE sessions ADD COLUMN namespace_id TEXT REFERENCES namespaces(id);
