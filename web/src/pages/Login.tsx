import { useState, useEffect, useRef, type FormEvent } from "react";
import { Link, useNavigate } from "@tanstack/react-router";
import Navbar from "../components/Navbar";
import Button from "../components/Button";
import Input from "../components/Input";
import FormField from "../components/FormField";
import { ErrorBanner } from "../components/shared";
import { apiFetch } from "../lib/api";
import { OAuthSection } from "../components/GoogleButton";
import { DomainNotice } from "../components/DomainNotice";

export default function Login() {
  const [inviteOnly, setInviteOnly] = useState(false);

  useEffect(() => {
    apiFetch("/v1/status")
      .then((r) => r.json())
      .then((data) => {
        if (data.invite_only) setInviteOnly(true);
      })
      .catch(() => {});
  }, []);

  return (
    <div className="min-h-screen w-full flex flex-col bg-bg">
      <Navbar />
      <div className="flex-1 flex items-center justify-center p-6">
        <div className="flex flex-col items-center w-full">
          <div className="bg-surface rounded-2xl w-full max-w-[480px] p-10 shadow-[0_1px_3px_rgba(0,0,0,0.08),0_8px_24px_rgba(0,0,0,0.04)]">
            <LoginForm />
          </div>

          {!inviteOnly && (
            <p className="text-sm text-text-muted mt-6 text-center">
              Don't have an account?{" "}
              <Link to="/register" className="text-primary font-medium hover:underline">
                Register
              </Link>
            </p>
          )}
        </div>
      </div>
    </div>
  );
}

function LoginForm() {
  const navigate = useNavigate();
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
        navigate({ to: "/vaults" });
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
    <>
      <h2 className="text-[28px] font-semibold mb-2 tracking-tight text-text">
        Log In
      </h2>
      <p className="text-text-muted text-[15px] mb-8">
        Access your team's Agent Vault instance.
      </p>

      <DomainNotice className="mb-6" />

      <OAuthSection />

      <form onSubmit={handleSubmit} autoComplete="on">
        <div className="mb-6">
          <FormField label="Email">
            <Input
              ref={emailRef}
              type="email"
              id="email"
              placeholder="name@company.com"
              required
              autoComplete="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
            />
          </FormField>
        </div>

        <div className="mb-6">
          <FormField label="Password">
            <Input
              ref={passwordRef}
              type="password"
              id="password"
              placeholder="&#8226;&#8226;&#8226;&#8226;&#8226;&#8226;&#8226;&#8226;&#8226;&#8226;&#8226;&#8226;"
              required
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </FormField>
          <div className="text-right mt-2">
            <Link to="/forgot-password" className="text-sm text-primary font-medium hover:underline">
              Forgot password?
            </Link>
          </div>
        </div>

        {formError && <ErrorBanner message={formError} className="mb-4" />}

        <Button
          type="submit"
          disabled={submitting}
          loading={submitting}
          className="w-full py-3.5 px-4 bg-primary text-primary-text border-none rounded-lg text-[15px] font-semibold cursor-pointer transition-colors mt-2 flex items-center justify-center gap-2 hover:bg-primary-hover disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {submitting ? "Logging in\u2026" : (
            <>
              Log In
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

