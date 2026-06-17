ALTER TABLE request_logs ADD COLUMN auth_scheme TEXT NOT NULL DEFAULT '';
ALTER TABLE request_logs ADD COLUMN auth_header TEXT NOT NULL DEFAULT '';
