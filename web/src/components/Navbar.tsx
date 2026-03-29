import { useState, useEffect, useRef } from "react";
import { Link, useNavigate } from "@tanstack/react-router";

interface NavbarProps {
  email?: string;
  vaultName?: string;
  isOwner?: boolean;
}

export default function Navbar({ email, vaultName, isOwner }: NavbarProps) {
  return (
    <nav className="flex items-center justify-between px-6 py-4 bg-surface border-b border-border">
      <div className="flex items-center gap-2">
        <Link to="/vaults" className="font-sans text-base font-semibold text-text tracking-tight hover:text-text no-underline">
          Agent Vault
        </Link>
        {vaultName && (
          <>
            <span className="text-text-dim text-base">/</span>
            <span className="font-sans text-base font-semibold text-text tracking-tight">
              {vaultName}
            </span>
          </>
        )}
      </div>
      <div className="flex items-center gap-3">
        <div className="relative group">
          <a href="https://docs.agent-vault.dev" target="_blank" rel="noopener noreferrer" className="w-8 h-8 rounded-full flex items-center justify-center text-text-muted hover:bg-bg transition-colors">
            <svg className="w-[18px] h-[18px]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M2 3h6a4 4 0 0 1 4 4v14a3 3 0 0 0-3-3H2z" />
              <path d="M22 3h-6a4 4 0 0 0-4 4v14a3 3 0 0 1 3-3h7z" />
            </svg>
          </a>
          <span className="pointer-events-none absolute left-1/2 -translate-x-1/2 top-full mt-2 px-2.5 py-1 text-xs font-medium text-text bg-surface border border-border rounded-md shadow-[0_4px_16px_rgba(0,0,0,0.1)] opacity-0 group-hover:opacity-100 transition-opacity whitespace-nowrap">
            Docs
          </span>
        </div>
        <div className="relative group">
          <a href="https://github.com/Infisical/agent-vault" target="_blank" rel="noopener noreferrer" className="w-8 h-8 rounded-full flex items-center justify-center text-text-muted hover:bg-bg transition-colors">
            <svg className="w-[18px] h-[18px]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <circle cx="12" cy="12" r="10" />
              <line x1="12" y1="16" x2="12" y2="12" />
              <line x1="12" y1="8" x2="12.01" y2="8" />
            </svg>
          </a>
          <span className="pointer-events-none absolute left-1/2 -translate-x-1/2 top-full mt-2 px-2.5 py-1 text-xs font-medium text-text bg-surface border border-border rounded-md shadow-[0_4px_16px_rgba(0,0,0,0.1)] opacity-0 group-hover:opacity-100 transition-opacity whitespace-nowrap">
            GitHub
          </span>
        </div>
        {email && <UserMenu email={email} isOwner={isOwner} />}
      </div>
    </nav>
  );
}

function UserMenu({ email, isOwner }: { email: string; isOwner?: boolean }) {
  const navigate = useNavigate();
  const [open, setOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    function handleClick(e: MouseEvent) {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) {
        setOpen(false);
      }
    }
    document.addEventListener("mousedown", handleClick);
    return () => document.removeEventListener("mousedown", handleClick);
  }, []);

  async function handleLogout() {
    await fetch("/v1/auth/logout", { method: "POST" });
    navigate({ to: "/login" });
  }

  return (
    <div className="relative" ref={menuRef}>
      <button
        onClick={() => setOpen((o) => !o)}
        className="flex items-center gap-1.5 text-sm text-text-muted hover:text-text transition-colors ml-1"
      >
        <span>{email}</span>
        <svg
          className={`w-3.5 h-3.5 transition-transform ${open ? "rotate-180" : ""}`}
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
        >
          <polyline points="6 9 12 15 18 9" />
        </svg>
      </button>
      {open && (
        <div className="absolute right-0 top-full mt-2 w-48 bg-surface border border-border rounded-lg shadow-[0_4px_16px_rgba(0,0,0,0.1)] py-1 z-50">
          <Link
            to="/account"
            className="block w-full text-left px-4 py-2.5 text-sm text-text-muted hover:bg-bg hover:text-text transition-colors no-underline"
            onClick={() => setOpen(false)}
          >
            Manage account
          </Link>
          {isOwner && (
            <Link
              to="/manage"
              className="block w-full text-left px-4 py-2.5 text-sm text-text-muted hover:bg-bg hover:text-text transition-colors no-underline"
              onClick={() => setOpen(false)}
            >
              Manage instance
            </Link>
          )}
          <button
            onClick={handleLogout}
            className="w-full text-left px-4 py-2.5 text-sm text-text-muted hover:bg-bg hover:text-text transition-colors"
          >
            Log out
          </button>
        </div>
      )}
    </div>
  );
}
