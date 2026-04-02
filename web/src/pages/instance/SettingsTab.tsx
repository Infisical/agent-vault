import { useState, useEffect, type FormEvent } from "react";
import { useRouteContext } from "@tanstack/react-router";
import { apiFetch } from "../../lib/api";
import Button from "../../components/Button";
import Input from "../../components/Input";
import type { AuthContext } from "../../router";

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

  useEffect(() => {
    apiFetch("/v1/admin/settings")
      .then((r) => r.json())
      .then((data) => {
        setInviteOnly(data.invite_only ?? false);
        setDomains(data.allowed_email_domains || []);
        setSmtpConfigured(data.smtp_configured ?? false);
        setLoading(false);
      })
      .catch(() => setLoading(false));
  }, []);

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
