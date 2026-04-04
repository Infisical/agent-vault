import { useState, useRef, type FormEvent } from "react";
import { useLoaderData } from "@tanstack/react-router";
import { apiFetch } from "../lib/api";
import Navbar from "../components/Navbar";
import Button from "../components/Button";
import Input from "../components/Input";
import FormField from "../components/FormField";
import ProposalPreview, { type ProposalData } from "../components/ProposalPreview";
import { ErrorBanner } from "../components/shared";

interface ApprovalData extends ProposalData {
  error?: boolean;
  error_title?: string;
  error_message?: string;
  authenticated?: boolean;
  user_email?: string;
  token?: string;
}

export default function ProposalApprove() {
  const approval = useLoaderData({ from: "/approve/$id" }) as ApprovalData | null;

  return (
    <div className="min-h-screen w-full flex flex-col bg-bg">
      <Navbar />
      <div className="flex-1 flex items-center justify-center p-6">
        <div className="flex flex-col items-center w-full">
          {!approval || approval.error ? (
            <div className="bg-surface rounded-2xl w-full max-w-[560px] p-10 shadow-[0_1px_3px_rgba(0,0,0,0.08),0_8px_24px_rgba(0,0,0,0.04)]">
              <ErrorSection
                title={approval?.error_title ?? "Unavailable"}
                message={approval?.error_message ?? "This approval link is no longer valid."}
              />
            </div>
          ) : !approval.authenticated ? (
            <UnauthenticatedView data={approval} />
          ) : (
            <ApprovalForm data={approval} />
          )}
        </div>
      </div>
    </div>
  );
}

function ErrorSection({ title, message }: { title: string; message: string }) {
  return (
    <div className="flex flex-col items-center text-center">
      <div className="w-16 h-16 rounded-2xl bg-danger/10 flex items-center justify-center mb-6">
        <svg className="w-8 h-8 text-danger" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <circle cx="12" cy="12" r="10" />
          <line x1="15" y1="9" x2="9" y2="15" />
          <line x1="9" y1="9" x2="15" y2="15" />
        </svg>
      </div>
      <h2 className="text-2xl font-semibold text-text mb-2">{title}</h2>
      <p className="text-text-muted text-[15px]">{message}</p>
    </div>
  );
}

function UnauthenticatedView({ data }: { data: ApprovalData }) {
  return (
    <div className="bg-surface rounded-2xl w-full max-w-[560px] p-10 shadow-[0_1px_3px_rgba(0,0,0,0.08),0_8px_24px_rgba(0,0,0,0.04)]">
      <ProposalPreview data={data} />

      <div className="border-t border-border mt-6 pt-6">
        <p className="text-sm text-text-muted mb-4">
          Log in to approve this request.
        </p>
        <InlineLoginForm />
      </div>
    </div>
  );
}

function InlineLoginForm() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [formError, setFormError] = useState("");
  const [submitting, setSubmitting] = useState(false);

  const emailRef = useRef<HTMLInputElement>(null);
  const passwordRef = useRef<HTMLInputElement>(null);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setFormError("");

    if (!email.trim()) {
      emailRef.current?.focus();
      return;
    }
    if (!password) {
      passwordRef.current?.focus();
      return;
    }

    setSubmitting(true);

    try {
      const resp = await apiFetch("/v1/auth/login", {
        method: "POST",
        body: JSON.stringify({ email: email.trim(), password }),
      });
      const data = await resp.json();

      if (resp.ok) {
        window.location.reload();
      } else {
        setFormError(data.error || "Invalid email or password.");
        setSubmitting(false);
      }
    } catch {
      setFormError("Network error. Please check your connection and try again.");
      setSubmitting(false);
    }
  }

  return (
    <form onSubmit={handleSubmit} autoComplete="on">
      <div className="mb-4">
        <FormField label="Email">
          <Input
            ref={emailRef}
            type="email"
            placeholder="name@company.com"
            required
            autoComplete="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
          />
        </FormField>
      </div>

      <div className="mb-4">
        <FormField label="Password">
          <Input
            ref={passwordRef}
            type="password"
            placeholder="&#8226;&#8226;&#8226;&#8226;&#8226;&#8226;&#8226;&#8226;&#8226;&#8226;&#8226;&#8226;"
            required
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </FormField>
      </div>

      {formError && <ErrorBanner message={formError} className="mb-4" />}

      <Button
        type="submit"
        loading={submitting}
        className="w-full py-3 px-4 bg-primary text-primary-text border-none rounded-lg text-sm font-semibold cursor-pointer transition-colors flex items-center justify-center gap-2 hover:bg-primary-hover disabled:opacity-50 disabled:cursor-not-allowed"
      >
        Log in
      </Button>
    </form>
  );
}

function ApprovalForm({ data }: { data: ApprovalData }) {
  const [view, setView] = useState<"form" | "success" | "rejected">("form");
  const [credentialValues, setCredentialValues] = useState<Record<string, string>>({});
  const [formError, setFormError] = useState("");
  const [submitting, setSubmitting] = useState(false);

  const setCredentials = (data.credentials ?? []).filter(
    (s) => s.action === "set" && !s.has_value
  );
  const allFilled = setCredentials.every((s) => (credentialValues[s.key] ?? "").trim() !== "");

  function updateCredential(key: string, value: string) {
    setCredentialValues((prev) => ({ ...prev, [key]: value }));
  }

  async function handleApprove(e: FormEvent) {
    e.preventDefault();
    setFormError("");
    setSubmitting(true);

    const credentials: Record<string, string> = {};
    for (const s of setCredentials) {
      credentials[s.key] = (credentialValues[s.key] ?? "").trim();
    }

    try {
      const resp = await apiFetch(
        `/v1/admin/proposals/${data.proposal_id}/approve`,
        {
          method: "POST",
          body: JSON.stringify({
            vault: data.vault,
            credentials,
          }),
        }
      );
      const result = await resp.json();

      if (resp.ok) {
        setView("success");
      } else {
        setFormError(result.error || "Something went wrong. Check your values and try again.");
        setSubmitting(false);
      }
    } catch {
      setFormError("Network error. Please check your connection and try again.");
      setSubmitting(false);
    }
  }

  async function handleReject() {
    setFormError("");
    setSubmitting(true);

    try {
      const resp = await apiFetch(
        `/v1/admin/proposals/${data.proposal_id}/reject`,
        {
          method: "POST",
          body: JSON.stringify({
            vault: data.vault,
            reason: "Rejected via browser approval page",
          }),
        }
      );

      if (resp.ok) {
        setView("rejected");
      } else {
        const result = await resp.json();
        setFormError(result.error || "Failed to reject. Please try again.");
        setSubmitting(false);
      }
    } catch {
      setFormError("Network error. Please check your connection and try again.");
      setSubmitting(false);
    }
  }

  if (view === "success") {
    return (
      <div className="bg-surface rounded-2xl w-full max-w-[560px] p-10 shadow-[0_1px_3px_rgba(0,0,0,0.08),0_8px_24px_rgba(0,0,0,0.04)]">
        <div className="flex flex-col items-center text-center">
          <div className="w-16 h-16 rounded-2xl bg-success/10 flex items-center justify-center mb-6">
            <svg className="w-8 h-8 text-success" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
              <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" />
              <polyline points="22 4 12 14.01 9 11.01" />
            </svg>
          </div>
          <h2 className="text-2xl font-semibold text-text mb-2">Connected</h2>
          <p className="text-text-muted text-[15px] mb-6">
            Access has been granted. You can close this tab and return to your agent.
          </p>
        </div>
      </div>
    );
  }

  if (view === "rejected") {
    return (
      <div className="bg-surface rounded-2xl w-full max-w-[560px] p-10 shadow-[0_1px_3px_rgba(0,0,0,0.08),0_8px_24px_rgba(0,0,0,0.04)]">
        <div className="flex flex-col items-center text-center">
          <div className="w-16 h-16 rounded-2xl bg-text-muted/10 flex items-center justify-center mb-6">
            <svg className="w-8 h-8 text-text-muted" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <circle cx="12" cy="12" r="10" />
              <line x1="15" y1="9" x2="9" y2="15" />
              <line x1="9" y1="9" x2="15" y2="15" />
            </svg>
          </div>
          <h2 className="text-2xl font-semibold text-text mb-2">Denied</h2>
          <p className="text-text-muted text-[15px] mb-6">
            The request has been rejected. You can close this tab.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="bg-surface rounded-2xl w-full max-w-[560px] p-10 shadow-[0_1px_3px_rgba(0,0,0,0.08),0_8px_24px_rgba(0,0,0,0.04)]">
      <ProposalPreview data={data} />

      <form onSubmit={handleApprove} className="mt-6 border-t border-border pt-6">
        {setCredentials.length > 0 && (
          <div className="space-y-5 mb-6">
            {setCredentials.map((cred) => (
              <FormField
                key={cred.key}
                label={cred.description || cred.key}
                helperText={
                  (cred.obtain || cred.obtain_instructions) ? (
                    <span>
                      {cred.obtain ? (
                        <a
                          href={cred.obtain.startsWith("http") ? cred.obtain : `https://${cred.obtain}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-primary hover:underline"
                        >
                          Get it here
                        </a>
                      ) : null}
                      {cred.obtain && cred.obtain_instructions ? " — " : ""}
                      {cred.obtain_instructions}
                    </span>
                  ) : undefined
                }
              >
                <Input
                  type="password"
                  placeholder={`Paste your ${cred.description || cred.key}`}
                  required
                  autoComplete="off"
                  value={credentialValues[cred.key] ?? ""}
                  onChange={(e) => updateCredential(cred.key, e.target.value)}
                />
              </FormField>
            ))}
          </div>
        )}

        {formError && <ErrorBanner message={formError} className="mb-4" />}

        <div className="flex gap-3">
          <Button
            type="submit"
            disabled={!allFilled}
            loading={submitting}
            className="flex-1 py-3 px-4 bg-primary text-primary-text border-none rounded-lg text-[15px] font-semibold cursor-pointer transition-colors flex items-center justify-center gap-2 hover:bg-primary-hover disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <polyline points="20 6 9 17 4 12" />
            </svg>
            Allow
          </Button>
          <Button
            type="button"
            variant="secondary"
            onClick={handleReject}
            disabled={submitting}
            className="py-3 px-5 bg-bg border border-border text-text rounded-lg text-[15px] font-semibold cursor-pointer transition-colors hover:bg-border/50 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            Deny
          </Button>
        </div>

        <p className="text-xs text-text-muted mt-4 text-left leading-relaxed">
          This gives the agent permission to make requests to{" "}
          {(data.services ?? [])
            .filter((r) => r.action === "set")
            .map((r) => r.host)
            .join(", ")}{" "}
          on your behalf. You can revoke access anytime.
        </p>
      </form>
    </div>
  );
}
