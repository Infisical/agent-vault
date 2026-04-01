import { useState, useEffect } from "react";
import { apiFetch } from "../lib/api";

interface OAuthProvider {
  name: string;
  display_name: string;
}

export function useOAuthProviders() {
  const [providers, setProviders] = useState<OAuthProvider[]>([]);

  useEffect(() => {
    apiFetch("/v1/auth/oauth/providers")
      .then((r) => r.json())
      .then((data) => setProviders(data.providers || []))
      .catch(() => {});
  }, []);

  return providers;
}

export function GoogleLoginButton({ redirect }: { redirect?: string }) {
  const url = redirect
    ? `/v1/auth/oauth/google/login?redirect=${encodeURIComponent(redirect)}`
    : "/v1/auth/oauth/google/login";

  return (
    <a
      href={url}
      className="w-full py-3 px-4 bg-surface border border-border rounded-lg text-[15px] font-medium text-text cursor-pointer transition-colors flex items-center justify-center gap-3 hover:bg-bg no-underline"
    >
      <GoogleIcon />
      Continue with Google
    </a>
  );
}

export function OAuthDivider() {
  return (
    <div className="flex items-center gap-3 my-6">
      <div className="flex-1 h-px bg-border" />
      <span className="text-xs text-text-dim font-medium uppercase tracking-wider">or</span>
      <div className="flex-1 h-px bg-border" />
    </div>
  );
}

export function OAuthSection({ redirect }: { redirect?: string }) {
  const providers = useOAuthProviders();
  if (!providers.some((p) => p.name === "google")) return null;

  return (
    <>
      <GoogleLoginButton redirect={redirect} />
      <OAuthDivider />
    </>
  );
}

function GoogleIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 18 18" fill="none">
      <path
        d="M17.64 9.2c0-.637-.057-1.251-.164-1.84H9v3.481h4.844a4.14 4.14 0 0 1-1.796 2.716v2.259h2.908c1.702-1.567 2.684-3.875 2.684-6.615Z"
        fill="#4285F4"
      />
      <path
        d="M9 18c2.43 0 4.467-.806 5.956-2.18l-2.908-2.259c-.806.54-1.837.86-3.048.86-2.344 0-4.328-1.584-5.036-3.711H.957v2.332A8.997 8.997 0 0 0 9 18Z"
        fill="#34A853"
      />
      <path
        d="M3.964 10.71A5.41 5.41 0 0 1 3.682 9c0-.593.102-1.17.282-1.71V4.958H.957A8.997 8.997 0 0 0 0 9c0 1.452.348 2.827.957 4.042l3.007-2.332Z"
        fill="#FBBC05"
      />
      <path
        d="M9 3.58c1.321 0 2.508.454 3.44 1.345l2.582-2.58C13.463.891 11.426 0 9 0A8.997 8.997 0 0 0 .957 4.958L3.964 7.29C4.672 5.163 6.656 3.58 9 3.58Z"
        fill="#EA4335"
      />
    </svg>
  );
}
