-- Security hardening: hash tokens, add unique constraint on token prefix.

-- Add token_hash columns for invite tokens.
-- New lookups use token_hash. Raw token column kept for backwards compatibility.
ALTER TABLE invites ADD COLUMN token_hash TEXT;
ALTER TABLE vault_invites ADD COLUMN token_hash TEXT;
ALTER TABLE changesets ADD COLUMN approval_token_hash TEXT;

-- Add hashed column for email verification codes.
ALTER TABLE email_verifications ADD COLUMN code_hash TEXT;

-- Make service_token_prefix unique to prevent silent wrong-agent matches on collision.
DROP INDEX IF EXISTS idx_agents_token_prefix;
CREATE UNIQUE INDEX idx_agents_token_prefix ON agents(service_token_prefix);

-- Add index on token_hash columns for fast lookups.
CREATE INDEX idx_invites_token_hash ON invites(token_hash);
CREATE INDEX idx_vault_invites_token_hash ON vault_invites(token_hash);
CREATE INDEX idx_changesets_approval_token_hash ON changesets(approval_token_hash);
CREATE INDEX idx_email_verifications_code_hash ON email_verifications(code_hash);
