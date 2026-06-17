-- Browser-based changeset approval: add approval token and user-facing message.
ALTER TABLE changesets ADD COLUMN approval_token TEXT;
ALTER TABLE changesets ADD COLUMN approval_token_expires_at TEXT;
ALTER TABLE changesets ADD COLUMN user_message TEXT NOT NULL DEFAULT '';
CREATE UNIQUE INDEX idx_changesets_approval_token ON changesets(approval_token) WHERE approval_token IS NOT NULL;
