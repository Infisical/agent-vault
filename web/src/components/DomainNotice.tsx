import { useState, useEffect } from "react";
import { apiFetch } from "../lib/api";

export function DomainNotice({ className = "" }: { className?: string }) {
  const [domains, setDomains] = useState<string[]>([]);
  const [inviteOnly, setInviteOnly] = useState(false);

  useEffect(() => {
    apiFetch("/v1/status")
      .then((r) => r.json())
      .then((data) => {
        if (data.invite_only) {
          setInviteOnly(true);
        } else if (data.allowed_email_domains?.length) {
          setDomains(data.allowed_email_domains);
        }
      })
      .catch(() => {});
  }, []);

  if (!inviteOnly && domains.length === 0) return null;

  const label = inviteOnly
    ? "This instance is invite-only"
    : domains.length === 1
      ? `Signups restricted to @${domains[0]}`
      : `Signups restricted to: ${domains.map((d) => `@${d}`).join(", ")}`;

  return (
    <div
      className={`flex items-center gap-2 px-3 py-2 bg-bg border border-border rounded-lg text-xs text-text-muted ${className}`}
    >
      <svg
        className="w-3.5 h-3.5 flex-shrink-0"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
      >
        <circle cx="12" cy="12" r="10" />
        <line x1="12" y1="16" x2="12" y2="12" />
        <line x1="12" y1="8" x2="12.01" y2="8" />
      </svg>
      {label}
    </div>
  );
}
