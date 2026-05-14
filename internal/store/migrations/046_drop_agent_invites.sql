-- Drop the agent invites tables.
-- Agent provisioning now happens directly via POST /v1/agents and rotation
-- via POST /v1/agents/{name}/rotate. The invite ceremony is gone.
-- User invites live in user_invites/user_invite_vaults and are untouched.

DROP TABLE IF EXISTS agent_invite_vaults;
DROP TABLE IF EXISTS invites;
