-- Rename "namespace" terminology to "vault" throughout the schema.
ALTER TABLE namespaces RENAME TO vaults;
ALTER TABLE namespace_grants RENAME TO vault_grants;
ALTER TABLE vault_grants RENAME COLUMN namespace_id TO vault_id;

ALTER TABLE secrets RENAME COLUMN namespace_id TO vault_id;
ALTER TABLE sessions RENAME COLUMN namespace_id TO vault_id;
ALTER TABLE broker_configs RENAME COLUMN namespace_id TO vault_id;
ALTER TABLE changesets RENAME COLUMN namespace_id TO vault_id;
ALTER TABLE changeset_secrets RENAME COLUMN namespace_id TO vault_id;
ALTER TABLE invites RENAME COLUMN namespace_id TO vault_id;
ALTER TABLE agents RENAME COLUMN namespace_id TO vault_id;
ALTER TABLE user_invites RENAME COLUMN namespaces_json TO vaults_json;

DROP INDEX IF EXISTS idx_invites_namespace_status;
CREATE INDEX idx_invites_vault_status ON invites(vault_id, status);

DROP INDEX IF EXISTS idx_agents_namespace;
CREATE INDEX idx_agents_vault ON agents(vault_id);
