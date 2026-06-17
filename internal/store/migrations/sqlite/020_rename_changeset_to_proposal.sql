-- Rename "changeset" terminology to "proposal" throughout the schema.
ALTER TABLE changesets RENAME TO proposals;
ALTER TABLE changeset_secrets RENAME TO proposal_secrets;
ALTER TABLE proposal_secrets RENAME COLUMN changeset_id TO proposal_id;

-- Recreate indexes with new names.
DROP INDEX IF EXISTS idx_changesets_ns_status;
CREATE INDEX idx_proposals_vault_status ON proposals(vault_id, status);

DROP INDEX IF EXISTS idx_changesets_approval_token;
CREATE UNIQUE INDEX idx_proposals_approval_token ON proposals(approval_token) WHERE approval_token IS NOT NULL;

DROP INDEX IF EXISTS idx_changesets_approval_token_hash;
CREATE INDEX idx_proposals_approval_token_hash ON proposals(approval_token_hash);
