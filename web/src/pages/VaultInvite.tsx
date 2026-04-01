import { useState, useRef, type FormEvent } from "react";
import { Link, useLoaderData } from "@tanstack/react-router";
import Navbar from "../components/Navbar";
import Button from "../components/Button";
import { ErrorBanner } from "../components/shared";
import { DomainNotice } from "../components/DomainNotice";
import { apiFetch } from "../lib/api";
import { OAuthSection } from "../components/GoogleButton";

interface VaultInviteData {
  token?: string;
  email?: string;
  vault_name?: string;
  vault_role?: string;
  needs_account?: boolean;
  error?: boolean;
  error_title?: string;
  error_message?: string;
}

export default function VaultInvite() {
  const invite = useLoaderData({ from: "/vault-invite/$token" }) as VaultInviteData | null;

  return (
    <div className="min-h-screen w-full flex flex-col bg-bg">
      <Navbar />
      <div className="flex-1 flex items-center justify-center p-6">
        <div className="flex flex-col items-center w-full">
          {!invite || invite.error ? (
            invite?.error_title === "Already Accepted" ? (
              <AlreadyAccepted />
            ) : (
              <div className="bg-surface rounded-2xl w-full max-w-[480px] p-10 shadow-[0_1px_3px_rgba(0,0,0,0.08),0_8px_24px_rgba(0,0,0,0.04)]">
                <ErrorSection
                  title={invite?.error_title ?? "Invite Unavailable"}
                  message={invite?.error_message ?? "This invite link is no longer valid. Please ask your vault administrator for a new invitation."}
                />
              </div>
            )
          ) : (
            <div className="bg-surface rounded-2xl w-full max-w-[480px] p-10 shadow-[0_1px_3px_rgba(0,0,0,0.08),0_8px_24px_rgba(0,0,0,0.04)]">
              {invite.needs_account ? (
                <NewUserForm
                  token={invite.token!}
                  email={invite.email!}
                  vaultName={invite.vault_name!}
                  vaultRole={invite.vault_role!}
                />
              ) : (
                <ExistingUserForm
                  token={invite.token!}
                  email={invite.email!}
                  vaultName={invite.vault_name!}
                  vaultRole={invite.vault_role!}
                />
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function AlreadyAccepted() {
  return (
    <>
      <div className="bg-surface rounded-2xl w-full max-w-[480px] p-10 shadow-[0_1px_3px_rgba(0,0,0,0.08),0_8px_24px_rgba(0,0,0,0.04)]">
        <div className="flex flex-col items-center text-center">
          <div className="w-16 h-16 rounded-2xl bg-primary/10 flex items-center justify-center mb-6">
            <svg className="w-8 h-8 text-primary" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
              <circle cx="12" cy="12" r="10" />
              <line x1="12" y1="8" x2="12" y2="12" />
              <line x1="12" y1="16" x2="12.01" y2="16" />
            </svg>
          </div>
          <h2 className="text-2xl font-semibold text-text mb-2">Already Accepted</h2>
          <p className="text-text-muted text-[15px] mb-8">
            This invitation has already been accepted. You can log in to access your vault.
          </p>
          <Link
            to="/login"
            className="w-full py-3.5 px-4 bg-primary text-primary-text rounded-lg text-[15px] font-semibold transition-colors flex items-center justify-center gap-2 hover:bg-primary-hover no-underline"
          >
            Log in to your account
            <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <line x1="5" y1="12" x2="19" y2="12" />
              <polyline points="12 5 19 12 12 19" />
            </svg>
          </Link>
        </div>
      </div>
    </>
  );
}

function ErrorSection({ title, message }: { title: string; message: string }) {
  return (
    <div className="flex flex-col bg-danger-bg border border-danger/20 rounded-lg p-4 text-sm leading-normal text-danger">
      <div className="font-semibold mb-1 flex items-center gap-2">
        <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <circle cx="12" cy="12" r="10" />
          <line x1="15" y1="9" x2="9" y2="15" />
          <line x1="9" y1="9" x2="15" y2="15" />
        </svg>
        <span>{title}</span>
      </div>
      <div className="text-text-muted">{message}</div>
    </div>
  );
}

function InviteDetails({ vaultName, vaultRole }: { vaultName: string; vaultRole: string }) {
  return (
    <div className="bg-bg border border-border rounded-lg p-4 mb-6">
      <div className="flex items-center justify-between">
        <div>
          <div className="text-xs font-semibold text-text-muted uppercase tracking-wider mb-1">Vault</div>
          <div className="text-sm text-text font-medium">{vaultName}</div>
        </div>
        <div className="text-right">
          <div className="text-xs font-semibold text-text-muted uppercase tracking-wider mb-1">Role</div>
          <span className="inline-block px-2.5 py-0.5 bg-primary/10 text-primary text-xs font-semibold rounded-full capitalize">
            {vaultRole}
          </span>
        </div>
      </div>
    </div>
  );
}

function ExistingUserForm({
  token,
  email,
  vaultName,
  vaultRole,
}: {
  token: string;
  email: string;
  vaultName: string;
  vaultRole: string;
}) {
  const [view, setView] = useState<"confirm" | "success">("confirm");
  const [formError, setFormError] = useState("");
  const [submitting, setSubmitting] = useState(false);

  async function handleAccept() {
    setFormError("");
    setSubmitting(true);

    try {
      const resp = await apiFetch(`/v1/vault-invites/${token}/accept`, {
        method: "POST",
        body: JSON.stringify({}),
      });
      const data = await resp.json();

      if (resp.ok) {
        setView("success");
      } else {
        setFormError(data.error || "Something went wrong. Please try again.");
        setSubmitting(false);
      }
    } catch {
      setFormError("Network error. Please check your connection and try again.");
      setSubmitting(false);
    }
  }

  if (view === "success") {
    return (
      <div className="flex flex-col items-center text-center">
        <div className="w-16 h-16 rounded-2xl bg-primary/10 flex items-center justify-center mb-6">
          <svg className="w-8 h-8 text-primary" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" />
            <polyline points="22 4 12 14.01 9 11.01" />
          </svg>
        </div>
        <h2 className="text-2xl font-semibold text-text mb-2">Invite Accepted</h2>
        <p className="text-text-muted text-[15px] mb-8">
          You now have <strong className="text-text">{vaultRole}</strong> access to vault <strong className="text-text">{vaultName}</strong>.
        </p>
        <a
          href="/login"
          className="w-full py-3.5 px-4 bg-primary text-primary-text rounded-lg text-[15px] font-semibold transition-colors flex items-center justify-center gap-2 hover:bg-primary-hover no-underline"
        >
          Log In
          <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <line x1="5" y1="12" x2="19" y2="12" />
            <polyline points="12 5 19 12 12 19" />
          </svg>
        </a>
      </div>
    );
  }

  return (
    <>
      <h2 className="text-[28px] font-semibold mb-2 tracking-tight text-text">
        Accept Vault Invitation
      </h2>
      <p className="text-text-muted text-[15px] mb-6">
        You've been invited to join a vault as <strong className="text-text">{email}</strong>.
      </p>

      <InviteDetails vaultName={vaultName} vaultRole={vaultRole} />

      {formError && <ErrorBanner message={formError} className="mb-4" />}

      <Button
        type="button"
        onClick={handleAccept}
        loading={submitting}
        className="w-full py-3.5 px-4 bg-primary text-primary-text border-none rounded-lg text-[15px] font-semibold cursor-pointer transition-colors flex items-center justify-center gap-2 hover:bg-primary-hover disabled:opacity-50 disabled:cursor-not-allowed"
      >
        {submitting ? "Accepting\u2026" : "Accept Invitation"}
      </Button>
    </>
  );
}

function NewUserForm({
  token,
  email,
  vaultName,
  vaultRole,
}: {
  token: string;
  email: string;
  vaultName: string;
  vaultRole: string;
}) {
  const [view, setView] = useState<"form" | "success">("form");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [passwordError, setPasswordError] = useState("");
  const [confirmError, setConfirmError] = useState("");
  const [formError, setFormError] = useState("");
  const [submitting, setSubmitting] = useState(false);

  const passwordRef = useRef<HTMLInputElement>(null);
  const confirmRef = useRef<HTMLInputElement>(null);

  function clearErrors() {
    setPasswordError("");
    setConfirmError("");
    setFormError("");
  }

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    clearErrors();

    if (password.length < 8) {
      setPasswordError("Password must be at least 8 characters.");
      passwordRef.current?.focus();
      return;
    }

    if (password !== confirm) {
      setConfirmError("Passwords do not match.");
      confirmRef.current?.focus();
      return;
    }

    setSubmitting(true);

    try {
      const resp = await apiFetch(`/v1/vault-invites/${token}/accept`, {
        method: "POST",
        body: JSON.stringify({ password }),
      });
      const data = await resp.json();

      if (resp.ok) {
        setView("success");
      } else {
        setFormError(data.error || "Something went wrong. Please try again.");
        setSubmitting(false);
      }
    } catch {
      setFormError("Network error. Please check your connection and try again.");
      setSubmitting(false);
    }
  }

  if (view === "success") {
    return (
      <div className="flex flex-col items-center text-center">
        <div className="w-16 h-16 rounded-2xl bg-primary/10 flex items-center justify-center mb-6">
          <svg className="w-8 h-8 text-primary" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" />
            <polyline points="22 4 12 14.01 9 11.01" />
          </svg>
        </div>
        <h2 className="text-2xl font-semibold text-text mb-2">Account Created</h2>
        <p className="text-text-muted text-[15px] mb-8">
          Your account is ready with <strong className="text-text">{vaultRole}</strong> access to vault <strong className="text-text">{vaultName}</strong>.
        </p>
        <a
          href="/login"
          className="w-full py-3.5 px-4 bg-primary text-primary-text rounded-lg text-[15px] font-semibold transition-colors flex items-center justify-center gap-2 hover:bg-primary-hover no-underline"
        >
          Log In
          <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <line x1="5" y1="12" x2="19" y2="12" />
            <polyline points="12 5 19 12 12 19" />
          </svg>
        </a>
      </div>
    );
  }

  return (
    <>
      <h2 className="text-[28px] font-semibold mb-2 tracking-tight text-text">
        Accept Vault Invitation
      </h2>
      <p className="text-text-muted text-[15px] mb-6">
        Create an account to join vault <strong className="text-text">{vaultName}</strong> as <strong className="text-text">{vaultRole}</strong>.
      </p>

      <InviteDetails vaultName={vaultName} vaultRole={vaultRole} />

      <DomainNotice className="mb-4" />

      <OAuthSection redirect={`/vault-invite/${token}`} />

      <form onSubmit={handleSubmit} autoComplete="off">
        <div className="mb-6">
          <label className="block text-xs font-semibold mb-2 text-text-muted uppercase tracking-wider">
            Email
          </label>
          <input
            type="email"
            value={email}
            disabled
            className="w-full px-4 py-3 bg-bg border border-border rounded-lg text-text text-sm outline-none cursor-not-allowed"
          />
        </div>

        <div className="mb-6">
          <label htmlFor="password" className="block text-xs font-semibold mb-2 text-text-muted uppercase tracking-wider">
            Create Password
          </label>
          <div className="relative">
            <input
              ref={passwordRef}
              type="password"
              id="password"
              placeholder="At least 8 characters"
              required
              minLength={8}
              autoComplete="new-password"
              className={`w-full px-4 py-3 pr-10 bg-surface border rounded-lg text-text text-sm outline-none transition-colors ${
                passwordError
                  ? "border-danger shadow-[0_0_0_3px_var(--color-danger-bg)]"
                  : "border-border focus:border-border-focus focus:shadow-[0_0_0_3px_var(--color-primary-ring)]"
              }`}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
            <div className="absolute right-3 top-1/2 -translate-y-1/2 text-text-dim">
              <svg className="w-[18px] h-[18px]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
                <path d="M7 11V7a5 5 0 0 1 10 0v4" />
              </svg>
            </div>
          </div>
          {passwordError && <div className="text-sm text-danger mt-1">{passwordError}</div>}
        </div>

        <div className="mb-6">
          <label htmlFor="confirm-password" className="block text-xs font-semibold mb-2 text-text-muted uppercase tracking-wider">
            Confirm Password
          </label>
          <div className="relative">
            <input
              ref={confirmRef}
              type="password"
              id="confirm-password"
              placeholder="Repeat your password"
              required
              minLength={8}
              autoComplete="new-password"
              className={`w-full px-4 py-3 pr-10 bg-surface border rounded-lg text-text text-sm outline-none transition-colors ${
                confirmError
                  ? "border-danger shadow-[0_0_0_3px_var(--color-danger-bg)]"
                  : "border-border focus:border-border-focus focus:shadow-[0_0_0_3px_var(--color-primary-ring)]"
              }`}
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
            />
            <div className="absolute right-3 top-1/2 -translate-y-1/2 text-text-dim">
              <svg className="w-[18px] h-[18px]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                <polyline points="9 12 12 15 16 10" />
              </svg>
            </div>
          </div>
          {confirmError && <div className="text-sm text-danger mt-1">{confirmError}</div>}
        </div>

        {formError && <ErrorBanner message={formError} className="mb-4" />}

        <Button
          type="submit"
          loading={submitting}
          className="w-full py-3.5 px-4 bg-primary text-primary-text border-none rounded-lg text-[15px] font-semibold cursor-pointer transition-colors mt-2 flex items-center justify-center gap-2 hover:bg-primary-hover disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {submitting ? "Creating account\u2026" : "Accept Invite & Create Account"}
        </Button>
      </form>
    </>
  );
}

