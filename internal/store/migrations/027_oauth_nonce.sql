-- Add OIDC nonce column to oauth_states for ID token binding.
-- Prevents token injection attacks where a valid ID token from one session
-- is replayed into another.
ALTER TABLE oauth_states ADD COLUMN nonce TEXT;
