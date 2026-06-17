-- Rename "secrets" terminology to "credentials" throughout the schema.
ALTER TABLE secrets RENAME TO credentials;
ALTER TABLE proposal_secrets RENAME TO proposal_credentials;
ALTER TABLE proposals RENAME COLUMN secrets_json TO credentials_json;
