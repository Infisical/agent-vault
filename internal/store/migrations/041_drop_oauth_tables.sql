-- Remove Google OAuth: delete OAuth-only users and drop OAuth tables.
-- Cascading FK deletes clean up vault_members / sessions / agents / etc.
-- for users that authenticated only via OAuth (password_hash IS NULL).

DELETE FROM users WHERE password_hash IS NULL;

DROP TABLE IF EXISTS oauth_accounts;
DROP TABLE IF EXISTS oauth_states;
