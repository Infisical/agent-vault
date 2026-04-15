ALTER TABLE user_invites ADD COLUMN role TEXT NOT NULL DEFAULT 'member' CHECK(role IN ('owner', 'member'));
