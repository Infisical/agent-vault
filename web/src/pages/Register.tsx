import { useState, useRef, type FormEvent } from "react";
import { Link, useLoaderData, useNavigate } from "@tanstack/react-router";
import { apiFetch } from "../lib/api";
import Navbar from "../components/Navbar";
import Button from "../components/Button";
import { ErrorBanner } from "../components/shared";
import { OAuthSection } from "../components/GoogleButton";
import { DomainNotice } from "../components/DomainNotice";

export default function Register() {
  const data = useLoaderData({ from: "/register" }) as { needs_first_user?: boolean; invite_only?: boolean } | undefined;
  const isFirstUser = data?.needs_first_user ?? false;
  const isInviteOnly = !isFirstUser && (data?.invite_only ?? false);

  return (
    <div className="min-h-screen w-full flex flex-col bg-bg">
      <Navbar />
      <div className="flex-1 flex items-center justify-center p-6">
        <div className="flex flex-col items-center w-full">
          <div className="bg-surface rounded-2xl w-full max-w-[480px] p-10 shadow-[0_1px_3px_rgba(0,0,0,0.08),0_8px_24px_rgba(0,0,0,0.04)]">
            {isInviteOnly ? <InviteOnlyNotice /> : <RegisterForm isFirstUser={isFirstUser} />}
          </div>

          {!isFirstUser && (
            <p className="text-sm text-text-muted mt-6 text-center">
              Already have an account?{" "}
              <Link to="/login" className="text-primary font-medium hover:underline">
                Log in
              </Link>
            </p>
          )}
        </div>
      </div>
    </div>
  );
}

function InviteOnlyNotice() {
  return (
    <div className="flex flex-col items-center text-center">
      <div className="w-16 h-16 rounded-2xl bg-primary/10 flex items-center justify-center mb-6">
        <svg className="w-8 h-8 text-primary" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
          <path d="M7 11V7a5 5 0 0 1 10 0v4" />
        </svg>
      </div>
      <h2 className="text-2xl font-semibold text-text mb-2">Invite Only</h2>
      <p className="text-text-muted text-[15px] mb-8">
        This instance is invite-only. To create an account, ask an administrator for an invite.
      </p>
      <Link
        to="/login"
        className="w-full py-3.5 px-4 bg-primary text-primary-text rounded-lg text-[15px] font-semibold transition-colors flex items-center justify-center gap-2 hover:bg-primary-hover no-underline"
      >
        Log In
        <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <line x1="5" y1="12" x2="19" y2="12" />
          <polyline points="12 5 19 12 12 19" />
        </svg>
      </Link>
    </div>
  );
}

function RegisterForm({ isFirstUser }: { isFirstUser: boolean }) {
  const navigate = useNavigate();
  const [step, setStep] = useState<"register" | "verify" | "done">("register");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [code, setCode] = useState("");
  const [formError, setFormError] = useState("");
  const [passwordError, setPasswordError] = useState("");
  const [confirmError, setConfirmError] = useState("");
  const [submitting, setSubmitting] = useState("");
  const [successMessage, setSuccessMessage] = useState("");
  const [emailSent, setEmailSent] = useState(false);

  const emailRef = useRef<HTMLInputElement>(null);
  const passwordRef = useRef<HTMLInputElement>(null);
  const confirmRef = useRef<HTMLInputElement>(null);
  const codeRef = useRef<HTMLInputElement>(null);

  function clearErrors() {
    setFormError("");
    setPasswordError("");
    setConfirmError("");
  }

  async function handleRegister(e: FormEvent) {
    e.preventDefault();
    clearErrors();

    if (!email.trim()) {
      emailRef.current?.focus();
      return;
    }
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

    setSubmitting("register");

    try {
      const resp = await apiFetch("/v1/auth/register", {
        method: "POST",
        body: JSON.stringify({ email: email.trim(), password }),
      });
      const data = await resp.json();

      if (!resp.ok) {
        setFormError(data.error || "Registration failed.");
        setSubmitting("");
        return;
      }

      if (data.requires_verification) {
        setEmailSent(!!data.email_sent);
        setStep("verify");
        setSubmitting("");
      } else if (data.authenticated) {
        navigate({ to: "/vaults" });
      } else {
        setSuccessMessage(data.message || "Account created successfully.");
        setStep("done");
        setSubmitting("");
      }
    } catch {
      setFormError("Network error. Please check your connection and try again.");
      setSubmitting("");
    }
  }

  async function handleVerify(e: FormEvent) {
    e.preventDefault();
    clearErrors();

    if (!code.trim()) {
      codeRef.current?.focus();
      return;
    }

    setSubmitting("verify");

    try {
      const resp = await apiFetch("/v1/auth/verify", {
        method: "POST",
        body: JSON.stringify({ email: email.trim(), code: code.trim() }),
      });
      const data = await resp.json();

      if (!resp.ok) {
        setFormError(data.error || "Verification failed.");
        setSubmitting("");
        return;
      }

      if (data.authenticated) {
        navigate({ to: "/vaults" });
      } else {
        setSuccessMessage(data.message || "Account verified.");
        setStep("done");
        setSubmitting("");
      }
    } catch {
      setFormError("Network error. Please check your connection and try again.");
      setSubmitting("");
    }
  }

  if (step === "done") {
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
          {successMessage || "Your account is ready."} You can now log in.
        </p>
        <Link
          to="/login"
          className="w-full py-3.5 px-4 bg-primary text-primary-text rounded-lg text-[15px] font-semibold transition-colors flex items-center justify-center gap-2 hover:bg-primary-hover no-underline"
        >
          Log In
          <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <line x1="5" y1="12" x2="19" y2="12" />
            <polyline points="12 5 19 12 12 19" />
          </svg>
        </Link>
      </div>
    );
  }

  if (step === "verify") {
    return (
      <>
        <h2 className="text-[28px] font-semibold mb-2 tracking-tight text-text">
          Verify Your Email
        </h2>
        <p className="text-text-muted text-[15px] mb-8">
          {emailSent
            ? <>We sent a 6-digit code to <strong className="text-text">{email}</strong>. Enter it below to activate your account.</>
            : <>Ask your Agent Vault instance owner for the 6-digit verification code, then enter it below to activate your account.</>
          }
        </p>

        <form onSubmit={handleVerify}>
          <div className="mb-6">
            <label htmlFor="code" className="block text-xs font-semibold mb-2 text-text-muted uppercase tracking-wider">
              Verification Code
            </label>
            <input
              ref={codeRef}
              type="text"
              id="code"
              placeholder="000000"
              required
              maxLength={6}
              autoComplete="one-time-code"
              className="w-full px-4 py-3 bg-surface border border-border rounded-lg text-text text-sm outline-none transition-colors focus:border-border-focus focus:shadow-[0_0_0_3px_var(--color-primary-ring)] text-center tracking-[0.3em] text-lg font-mono"
              value={code}
              onChange={(e) => setCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
            />
          </div>

          {formError && <ErrorBanner message={formError} className="mb-4" />}

          <Button
            type="submit"
            loading={submitting === "verify"}
            className="w-full py-3.5 px-4 bg-primary text-primary-text border-none rounded-lg text-[15px] font-semibold cursor-pointer transition-colors mt-2 flex items-center justify-center gap-2 hover:bg-primary-hover disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {submitting === "verify" ? "Verifying\u2026" : "Verify & Activate"}
          </Button>
        </form>
      </>
    );
  }

  return (
    <>
      <h2 className="text-[28px] font-semibold mb-2 tracking-tight text-text">
        {isFirstUser ? "Create Owner Account" : "Create Account"}
      </h2>
      <p className="text-text-muted text-[15px] mb-8">
        {isFirstUser
          ? "Set up the first account to initialize your Agent Vault instance."
          : "Sign up for an account to access your team's Agent Vault instance."}
      </p>

      {!isFirstUser && <DomainNotice className="mb-6" />}

      {!isFirstUser && <OAuthSection />}

      <form onSubmit={handleRegister} autoComplete="off">
        <div className="mb-6">
          <label htmlFor="email" className="block text-xs font-semibold mb-2 text-text-muted uppercase tracking-wider">
            Email
          </label>
          <input
            ref={emailRef}
            type="email"
            id="email"
            placeholder="name@company.com"
            required
            autoComplete="email"
            className="w-full px-4 py-3 bg-surface border border-border rounded-lg text-text text-sm outline-none transition-colors focus:border-border-focus focus:shadow-[0_0_0_3px_var(--color-primary-ring)]"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
          />
        </div>

        <div className="mb-6">
          <label htmlFor="password" className="block text-xs font-semibold mb-2 text-text-muted uppercase tracking-wider">
            Password
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

        {formError && (
          <div className="bg-danger-bg border border-danger/20 rounded-lg p-4 text-sm text-danger mb-4">
            {formError}
          </div>
        )}

        <Button
          type="submit"
          loading={submitting === "register"}
          className="w-full py-3.5 px-4 bg-primary text-primary-text border-none rounded-lg text-[15px] font-semibold cursor-pointer transition-colors mt-2 flex items-center justify-center gap-2 hover:bg-primary-hover disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {submitting === "register" ? "Creating account\u2026" : (
            <>
              {isFirstUser ? "Create Owner Account" : "Create Account"}
              <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <line x1="5" y1="12" x2="19" y2="12" />
                <polyline points="12 5 19 12 12 19" />
              </svg>
            </>
          )}
        </Button>
      </form>
    </>
  );
}

