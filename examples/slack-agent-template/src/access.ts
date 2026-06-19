const RAW = process.env.AGENT_ALLOWLIST ?? "";

const ALLOWED = new Set(
  RAW.split(/[\s,]+/)
    .map((email) => email.trim().toLowerCase())
    .filter(Boolean),
);

/** True when AGENT_ALLOWLIST was set with at least one email. */
export function allowlistConfigured(): boolean {
  return ALLOWED.size > 0;
}

/**
 * Whether the given email is on the optional Slack allowlist.
 * When no allowlist is configured, the template allows all Slack users.
 */
export function isAllowedEmail(email: string | undefined | null): boolean {
  if (!allowlistConfigured()) return true;
  if (!email) return false;
  return ALLOWED.has(email.trim().toLowerCase());
}
