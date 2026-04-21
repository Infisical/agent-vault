import { useState, useEffect, useRef, type FormEvent } from "react";
import { useRouteContext } from "@tanstack/react-router";
import { apiFetch } from "../../lib/api";
import Button from "../../components/Button";
import Input from "../../components/Input";
import type { AuthContext } from "../../router";

type RateLimitTier = {
  rate?: number;
  burst?: number;
  window?: string;
  max?: number;
  concurrency?: number;
  source: "env" | "override" | "default";
};

type RateLimitState = {
  profile: string;
  locked: boolean;
  off: boolean;
  tiers: Record<string, RateLimitTier>;
};

const TIER_ORDER = ["GLOBAL", "AUTH", "PROXY", "AUTHED"];

const TIER_LABELS: Record<string, string> = {
  AUTH: "Auth (unauthenticated)",
  PROXY: "Proxy ingress",
  AUTHED: "Authenticated endpoints",
  GLOBAL: "Server-wide (global)",
};

const TIER_TOOLTIPS: Record<string, string> = {
  AUTH: "Every unauthenticated endpoint: login, register, forgot/reset password, email verification, OAuth login/callback, invite redemption, approval-token lookups. Keyed on client IP (and additionally on email for login; rejected when either bucket is exhausted).",
  PROXY: "/proxy/* and the MITM forward path, keyed on (agent, vault). Token bucket smooths sustained traffic; a per-scope concurrency semaphore bounds in-flight upstream calls. Both ingresses share one budget so switching doesn't bypass the limit.",
  AUTHED: "Everything behind requireAuth — CRUD, reads, admin, proposals, /discover. One bucket per actor. Defaults accommodate the heaviest legitimate agent workload; tighten only if abuse is observed.",
  GLOBAL: "Server-wide backstop: Rate + Burst drive a requests-per-second ceiling; Concurrency caps total in-flight requests. Outermost safety net — sheds load before per-tier limits engage.",
};

// toCleanedOverrides drops empty/NaN fields from the override map so
// the wire payload only carries values the owner actually set.
function toCleanedOverrides(
  overrides: Record<string, Partial<RateLimitTier>>,
): Record<string, Partial<RateLimitTier>> {
  const out: Record<string, Partial<RateLimitTier>> = {};
  for (const [tier, ov] of Object.entries(overrides)) {
    const trimmed: Partial<RateLimitTier> = {};
    if (ov.rate !== undefined && ov.rate !== null && !Number.isNaN(ov.rate)) trimmed.rate = Number(ov.rate);
    if (ov.burst !== undefined && ov.burst !== null && !Number.isNaN(ov.burst)) trimmed.burst = Number(ov.burst);
    if (ov.max !== undefined && ov.max !== null && !Number.isNaN(ov.max)) trimmed.max = Number(ov.max);
    if (ov.concurrency !== undefined && ov.concurrency !== null && !Number.isNaN(ov.concurrency)) trimmed.concurrency = Number(ov.concurrency);
    if (ov.window) trimmed.window = ov.window;
    if (Object.keys(trimmed).length > 0) out[tier] = trimmed;
  }
  return out;
}

function TierLabel({ name, label }: { name: string; label: string }) {
  const description = TIER_TOOLTIPS[name];
  return (
    <span className="relative group inline-block">
      <span
        tabIndex={0}
        title={description}
        className="border-b border-dotted border-text-dim cursor-help focus:outline-none focus:border-text-muted"
      >
        {label}
      </span>
      {description && (
        <span
          role="tooltip"
          className="pointer-events-none absolute left-0 top-full mt-1.5 z-20 w-72 px-3 py-2 rounded-md bg-surface-raised border border-border text-xs text-text-muted leading-snug shadow-lg opacity-0 group-hover:opacity-100 group-focus-within:opacity-100 transition-opacity duration-100"
        >
          {description}
        </span>
      )}
    </span>
  );
}

export default function InstanceSettingsTab() {
  const { auth } = useRouteContext({ from: "/_auth" }) as { auth: AuthContext };

  const [inviteOnly, setInviteOnly] = useState(false);
  const [domains, setDomains] = useState<string[]>([]);
  const [inputValue, setInputValue] = useState("");
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");

  const [smtpConfigured, setSmtpConfigured] = useState(false);
  const [testEmailTo, setTestEmailTo] = useState("");
  const [testEmailSending, setTestEmailSending] = useState(false);
  const [testEmailError, setTestEmailError] = useState("");
  const [testEmailSuccess, setTestEmailSuccess] = useState("");

  const [rateLimit, setRateLimit] = useState<RateLimitState | null>(null);
  const [rlProfile, setRlProfile] = useState("default");
  const [rlAdvanced, setRlAdvanced] = useState(false);
  const [rlOverrides, setRlOverrides] = useState<Record<string, Partial<RateLimitTier>>>({});
  const [rlSaving, setRlSaving] = useState(false);
  const [rlError, setRlError] = useState("");
  // Set by save/reset so the preview effect's next run skips its POST —
  // the save response already carries the fresh effective config.
  const skipNextPreview = useRef(false);
  const [rlSuccess, setRlSuccess] = useState("");

  useEffect(() => {
    apiFetch("/v1/admin/settings")
      .then((r) => r.json())
      .then((data) => {
        setInviteOnly(data.invite_only ?? false);
        setDomains(data.allowed_email_domains || []);
        setSmtpConfigured(data.smtp_configured ?? false);
        if (data.rate_limit) {
          setRateLimit(data.rate_limit as RateLimitState);
          setRlProfile(data.rate_limit.profile || "default");
        }
        setLoading(false);
      })
      .catch(() => setLoading(false));
  }, []);

  // Live preview: whenever profile or overrides change, ask the server
  // what the effective config would be and reflect it in the table.
  // Debounced so typing into a numeric field doesn't spam.
  useEffect(() => {
    if (!rateLimit || rateLimit.locked) return;
    if (skipNextPreview.current) {
      skipNextPreview.current = false;
      return;
    }
    const cleaned = toCleanedOverrides(rlOverrides);
    const controller = new AbortController();
    const id = setTimeout(async () => {
      try {
        const resp = await apiFetch("/v1/admin/settings/rate-limit/preview", {
          method: "POST",
          body: JSON.stringify({ profile: rlProfile, overrides: cleaned }),
          signal: controller.signal,
        });
        if (!resp.ok) return;
        const data = (await resp.json()) as RateLimitState;
        setRateLimit((prev) => (prev ? { ...data, locked: prev.locked } : data));
      } catch {
        // AbortController cancellation or network — ignore.
      }
    }, 150);
    return () => {
      controller.abort();
      clearTimeout(id);
    };
    // rateLimit excluded: preview *updates* rateLimit; re-running would loop.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [rlProfile, rlOverrides]);

  function addDomain(e: FormEvent) {
    e.preventDefault();
    const domain = inputValue.trim().toLowerCase();
    if (!domain) return;
    if (!domain.includes(".") || domain.includes("@") || domain.includes(" ")) {
      setError(`Invalid domain: "${domain}"`);
      return;
    }
    if (domains.includes(domain)) {
      setError(`"${domain}" is already in the list`);
      return;
    }
    setDomains([...domains, domain]);
    setInputValue("");
    setError("");
    setSuccess("");
  }

  function removeDomain(domain: string) {
    setDomains(domains.filter((d) => d !== domain));
    setSuccess("");
  }

  async function handleSendTestEmail() {
    setTestEmailSending(true);
    setTestEmailError("");
    setTestEmailSuccess("");
    try {
      const to = testEmailTo.trim();
      const resp = await apiFetch("/v1/admin/email/test", {
        method: "POST",
        ...(to ? { body: JSON.stringify({ to }) } : {}),
      });
      const data = await resp.json();
      if (resp.ok) {
        setTestEmailSuccess(`Test email sent to ${data.to}`);
      } else {
        setTestEmailError(data.error || "Failed to send test email.");
      }
    } catch {
      setTestEmailError("Network error.");
    } finally {
      setTestEmailSending(false);
    }
  }

  async function handleSave() {
    setSaving(true);
    setError("");
    setSuccess("");

    try {
      const resp = await apiFetch("/v1/admin/settings", {
        method: "PUT",
        body: JSON.stringify({ invite_only: inviteOnly, allowed_email_domains: domains }),
      });
      const data = await resp.json();

      if (resp.ok) {
        setInviteOnly(data.invite_only ?? false);
        setDomains(data.allowed_email_domains || []);
        setSuccess("Settings saved.");
      } else {
        setError(data.error || "Failed to save settings.");
      }
    } catch {
      setError("Network error.");
    } finally {
      setSaving(false);
    }
  }

  async function handleSaveRateLimit() {
    setRlSaving(true);
    setRlError("");
    setRlSuccess("");
    try {
      const resp = await apiFetch("/v1/admin/settings", {
        method: "PUT",
        body: JSON.stringify({
          rate_limit: { profile: rlProfile, overrides: toCleanedOverrides(rlOverrides) },
        }),
      });
      const data = await resp.json();
      if (resp.ok) {
        skipNextPreview.current = true;
        setRateLimit(data.rate_limit as RateLimitState);
        setRlOverrides({});
        setRlSuccess("Rate-limit settings saved.");
      } else {
        setRlError(data.error || "Failed to save rate-limit settings.");
      }
    } catch {
      setRlError("Network error.");
    } finally {
      setRlSaving(false);
    }
  }

  async function handleResetRateLimit() {
    setRlSaving(true);
    setRlError("");
    setRlSuccess("");
    try {
      const resp = await apiFetch("/v1/admin/settings", {
        method: "PUT",
        body: JSON.stringify({ rate_limit: { profile: "default" } }),
      });
      const data = await resp.json();
      if (resp.ok) {
        skipNextPreview.current = true;
        setRateLimit(data.rate_limit as RateLimitState);
        setRlProfile("default");
        setRlOverrides({});
        setRlSuccess("Rate-limit settings reset to defaults.");
      } else {
        setRlError(data.error || "Failed to reset rate-limit settings.");
      }
    } catch {
      setRlError("Network error.");
    } finally {
      setRlSaving(false);
    }
  }

  function setOverride(tier: string, field: keyof RateLimitTier, value: string) {
    setRlOverrides((prev) => {
      const next = { ...prev };
      const cur: Partial<RateLimitTier> = { ...(next[tier] || {}) };
      if (value === "") {
        delete (cur as Record<string, unknown>)[field];
      } else if (field === "window") {
        cur.window = value;
      } else {
        (cur as Record<string, unknown>)[field] = Number(value);
      }
      if (Object.keys(cur).length === 0) {
        delete next[tier];
      } else {
        next[tier] = cur;
      }
      return next;
    });
  }

  if (loading) {
    return (
      <div className="p-8 w-full max-w-[960px]">
        <p className="text-sm text-text-muted">Loading settings...</p>
      </div>
    );
  }

  return (
    <div className="p-8 w-full max-w-[960px]">
      <div className="mb-6">
        <h2 className="text-[22px] font-semibold text-text tracking-tight mb-1">
          Instance Settings
        </h2>
        <p className="text-sm text-text-muted">
          Configure instance-wide settings.
        </p>
      </div>

      <section className="mb-8">
        <div className="border border-border rounded-xl bg-surface p-5">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-sm font-semibold text-text mb-1">
                Invite-Only Registration
              </h3>
              <p className="text-sm text-text-muted">
                When enabled, new users can only join through vault invites.
                Self-registration and OAuth signup are disabled.
              </p>
            </div>
            <button
              type="button"
              role="switch"
              aria-checked={inviteOnly}
              onClick={() => { setInviteOnly(!inviteOnly); setSuccess(""); }}
              className={`relative inline-flex h-6 w-11 flex-shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none focus:ring-2 focus:ring-primary focus:ring-offset-2 ${
                inviteOnly ? "bg-primary" : "bg-border"
              }`}
            >
              <span
                className={`pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out ${
                  inviteOnly ? "translate-x-5" : "translate-x-0"
                }`}
              />
            </button>
          </div>
        </div>
      </section>

      <section className="mb-8">
        <div className="border border-border rounded-xl bg-surface p-5">
          <h3 className="text-sm font-semibold text-text mb-1">
            Allowed Email Domains
          </h3>
          <p className="text-sm text-text-muted mb-4">
            Restrict signups to specific email domains. When set, only users
            with email addresses from these domains can register (via email/password
            or Google OAuth). Leave empty to allow all domains.
          </p>

          <form onSubmit={addDomain} className="flex gap-2 mb-4 max-w-md">
            <div className="flex-1">
              <Input
                placeholder="example.com"
                value={inputValue}
                onChange={(e) => {
                  setInputValue(e.target.value);
                  setError("");
                }}
              />
            </div>
            <Button type="submit" variant="secondary">
              Add
            </Button>
          </form>

          {domains.length > 0 ? (
            <div className="flex flex-wrap gap-2 mb-4">
              {domains.map((domain) => (
                <span
                  key={domain}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-bg border border-border rounded-lg text-sm text-text"
                >
                  @{domain}
                  <button
                    type="button"
                    onClick={() => removeDomain(domain)}
                    className="text-text-dim hover:text-danger transition-colors"
                    aria-label={`Remove ${domain}`}
                  >
                    <svg
                      className="w-3.5 h-3.5"
                      viewBox="0 0 24 24"
                      fill="none"
                      stroke="currentColor"
                      strokeWidth="2"
                      strokeLinecap="round"
                      strokeLinejoin="round"
                    >
                      <line x1="18" y1="6" x2="6" y2="18" />
                      <line x1="6" y1="6" x2="18" y2="18" />
                    </svg>
                  </button>
                </span>
              ))}
            </div>
          ) : (
            <p className="text-sm text-text-dim mb-4">
              No domain restrictions. All email domains can sign up.
            </p>
          )}

          {error && (
            <div className="bg-danger-bg border border-danger/20 rounded-lg p-3 text-sm text-danger mb-4">
              {error}
            </div>
          )}
          {success && (
            <div className="bg-success-bg border border-success/20 rounded-lg p-3 text-sm text-success mb-4">
              {success}
            </div>
          )}

          <Button onClick={handleSave} loading={saving}>
            Save Changes
          </Button>
        </div>
      </section>

      {rateLimit && (
        <section className="mb-8">
          <div className="border border-border rounded-xl bg-surface p-5">
            <div className="flex items-center justify-between mb-1">
              <h3 className="text-sm font-semibold text-text">Rate Limiting</h3>
              {rateLimit.locked && (
                <span className="text-[11px] uppercase tracking-wider text-warning bg-warning-bg border border-warning/30 rounded px-2 py-0.5">
                  Pinned by env
                </span>
              )}
            </div>
            <p className="text-sm text-text-muted mb-4">
              Tiered limits protect auth, proxy, authed CRUD, and global in-flight.
              Pick a profile; expand Advanced for per-tier overrides.
              {rateLimit.locked && (
                <> Fields are read-only because <code className="text-text-muted">AGENT_VAULT_RATELIMIT_LOCK=true</code> is set.</>
              )}
            </p>

            <div className="flex items-center gap-3 mb-4">
              <label className="text-sm text-text-muted" htmlFor="rl-profile">Profile</label>
              <select
                id="rl-profile"
                className="h-9 px-3 rounded-lg border border-border bg-bg text-sm text-text disabled:opacity-60"
                value={rlProfile}
                disabled={rateLimit.locked}
                onChange={(e) => { setRlProfile(e.target.value); setRlSuccess(""); }}
              >
                <option value="default">default</option>
                <option value="strict">strict (≈ half the defaults)</option>
                <option value="loose">loose (≈ 2× the defaults)</option>
                <option value="off">off (disable all limits)</option>
              </select>
            </div>

            <button
              type="button"
              onClick={() => setRlAdvanced((v) => !v)}
              className="text-xs text-text-muted hover:text-text underline decoration-dotted underline-offset-2 mb-3"
            >
              {rlAdvanced ? "Hide advanced" : "Show advanced (per-tier overrides)"}
            </button>

            {rlAdvanced && (
              <div className="border border-border rounded-lg mb-4">
                <table className="w-full text-sm">
                  <thead className="bg-bg text-text-muted">
                    <tr>
                      <th className="text-left px-3 py-2 font-medium">Tier</th>
                      <th className="text-left px-3 py-2 font-medium">Rate</th>
                      <th className="text-left px-3 py-2 font-medium">Burst</th>
                      <th className="text-left px-3 py-2 font-medium">Window</th>
                      <th className="text-left px-3 py-2 font-medium">Max</th>
                      <th className="text-left px-3 py-2 font-medium">Concurrency</th>
                      <th className="text-left px-3 py-2 font-medium">Source</th>
                    </tr>
                  </thead>
                  <tbody>
                    {TIER_ORDER.map((name) => {
                      const tier = rateLimit.tiers[name];
                      if (!tier) return null;
                      const ov = rlOverrides[name] || {};
                      const locked = rateLimit.locked || tier.source === "env";
                      return (
                        <tr key={name} className="border-t border-border">
                          <td className="px-3 py-2 text-text">
                            <TierLabel name={name} label={TIER_LABELS[name] || name} />
                          </td>
                          <td className="px-3 py-2">
                            <input
                              type="number" step="0.1" min={0} disabled={locked}
                              className="w-20 h-7 px-2 rounded border border-border bg-bg text-text disabled:opacity-60"
                              placeholder={tier.rate !== undefined ? String(tier.rate) : "—"}
                              value={ov.rate ?? ""}
                              onChange={(e) => setOverride(name, "rate", e.target.value)}
                            />
                          </td>
                          <td className="px-3 py-2">
                            <input
                              type="number" min={0} disabled={locked}
                              className="w-20 h-7 px-2 rounded border border-border bg-bg text-text disabled:opacity-60"
                              placeholder={tier.burst !== undefined ? String(tier.burst) : "—"}
                              value={ov.burst ?? ""}
                              onChange={(e) => setOverride(name, "burst", e.target.value)}
                            />
                          </td>
                          <td className="px-3 py-2">
                            <input
                              type="text" disabled={locked}
                              className="w-24 h-7 px-2 rounded border border-border bg-bg text-text disabled:opacity-60"
                              placeholder={tier.window || "—"}
                              value={ov.window ?? ""}
                              onChange={(e) => setOverride(name, "window", e.target.value)}
                            />
                          </td>
                          <td className="px-3 py-2">
                            <input
                              type="number" min={0} disabled={locked}
                              className="w-20 h-7 px-2 rounded border border-border bg-bg text-text disabled:opacity-60"
                              placeholder={tier.max !== undefined ? String(tier.max) : "—"}
                              value={ov.max ?? ""}
                              onChange={(e) => setOverride(name, "max", e.target.value)}
                            />
                          </td>
                          <td className="px-3 py-2">
                            <input
                              type="number" min={0} disabled={locked}
                              className="w-20 h-7 px-2 rounded border border-border bg-bg text-text disabled:opacity-60"
                              placeholder={tier.concurrency !== undefined ? String(tier.concurrency) : "—"}
                              value={ov.concurrency ?? ""}
                              onChange={(e) => setOverride(name, "concurrency", e.target.value)}
                            />
                          </td>
                          <td className="px-3 py-2 text-text-dim">
                            <span className={`text-[11px] uppercase tracking-wider ${
                              tier.source === "env" ? "text-warning" :
                              tier.source === "override" ? "text-primary" : "text-text-dim"
                            }`}>{tier.source}</span>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}

            {rlError && (
              <div className="bg-danger-bg border border-danger/20 rounded-lg p-3 text-sm text-danger mb-3">
                {rlError}
              </div>
            )}
            {rlSuccess && (
              <div className="bg-success-bg border border-success/20 rounded-lg p-3 text-sm text-success mb-3">
                {rlSuccess}
              </div>
            )}

            <div className="flex gap-2">
              <Button onClick={handleSaveRateLimit} loading={rlSaving} disabled={rateLimit.locked}>
                Save Rate Limits
              </Button>
              <Button onClick={handleResetRateLimit} variant="secondary" disabled={rateLimit.locked || rlSaving}>
                Reset to defaults
              </Button>
            </div>
          </div>
        </section>
      )}

      <section className="mb-8">
        <div className="border border-border rounded-xl bg-surface p-5">
          <h3 className="text-sm font-semibold text-text mb-1">
            Test Email
          </h3>
          <p className="text-sm text-text-muted mb-4">
            Send a test email to verify your SMTP configuration is working.
          </p>

          {!smtpConfigured ? (
            <p className="text-sm text-text-dim">
              SMTP is not configured. Set the <code className="text-text-muted">AGENT_VAULT_SMTP_*</code> environment variables to enable email sending.
            </p>
          ) : (
            <>
              <div className="flex gap-2 mb-4 max-w-md">
                <div className="flex-1">
                  <Input
                    type="email"
                    placeholder={auth.email}
                    value={testEmailTo}
                    onChange={(e) => {
                      setTestEmailTo(e.target.value);
                      setTestEmailError("");
                      setTestEmailSuccess("");
                    }}
                  />
                </div>
                <Button
                  onClick={handleSendTestEmail}
                  loading={testEmailSending}
                  variant="secondary"
                >
                  Send
                </Button>
              </div>

              {testEmailError && (
                <div className="bg-danger-bg border border-danger/20 rounded-lg p-3 text-sm text-danger">
                  {testEmailError}
                </div>
              )}
              {testEmailSuccess && (
                <div className="bg-success-bg border border-success/20 rounded-lg p-3 text-sm text-success">
                  {testEmailSuccess}
                </div>
              )}
            </>
          )}
        </div>
      </section>
    </div>
  );
}
