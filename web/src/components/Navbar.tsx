import { useState, useEffect, useRef } from "react";
import { Link, useNavigate } from "@tanstack/react-router";
import { MOBILE_NAV_ID } from "./ResponsiveSidebar";

interface NavbarProps {
  email?: string;
  vaultName?: string;
  isOwner?: boolean;
  /** When set, a menu button is shown below md to open the sidebar drawer. */
  onMenuClick?: () => void;
  menuOpen?: boolean;
}

export default function Navbar({ email, vaultName, isOwner, onMenuClick, menuOpen }: NavbarProps) {
  return (
    <nav className="flex items-center justify-between gap-2 px-3 sm:px-6 py-2 sm:py-4 pt-[max(0.5rem,env(safe-area-inset-top))] sm:pt-4 bg-surface border-b border-border">
      <div className="flex items-center gap-2 min-w-0">
        {onMenuClick && (
          <button
            type="button"
            onClick={onMenuClick}
            aria-label="Open navigation"
            aria-expanded={menuOpen ?? false}
            aria-controls={MOBILE_NAV_ID}
            className="md:hidden -ml-1 w-11 h-11 flex-shrink-0 flex items-center justify-center rounded-full text-text-muted hover:text-text hover:bg-bg transition-colors"
          >
            <svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <line x1="4" y1="6" x2="20" y2="6" />
              <line x1="4" y1="12" x2="20" y2="12" />
              <line x1="4" y1="18" x2="20" y2="18" />
            </svg>
          </button>
        )}
        <Link to="/" className="font-sans text-base font-semibold text-text tracking-tight hover:text-text no-underline whitespace-nowrap">
          Agent Vault
        </Link>
        {vaultName && (
          <>
            <span className="text-text-dim text-base">/</span>
            <span className="font-sans text-base font-semibold text-text tracking-tight truncate min-w-0">
              {vaultName}
            </span>
          </>
        )}
      </div>
      <div className="flex items-center gap-3 flex-shrink-0">
        <div className={`relative group ${email ? "hidden sm:block" : ""}`}>
          <a href="https://docs.agent-vault.dev" target="_blank" rel="noopener noreferrer" aria-label="Docs" className="w-8 h-8 rounded-full flex items-center justify-center text-text-muted hover:bg-bg transition-colors">
            <svg className="w-[18px] h-[18px]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M2 3h6a4 4 0 0 1 4 4v14a3 3 0 0 0-3-3H2z" />
              <path d="M22 3h-6a4 4 0 0 0-4 4v14a3 3 0 0 1 3-3h7z" />
            </svg>
          </a>
          <span className="pointer-events-none absolute left-1/2 -translate-x-1/2 top-full mt-2 px-2.5 py-1 text-xs font-medium text-text bg-surface border border-border rounded-md shadow-[0_4px_16px_rgba(0,0,0,0.1)] opacity-0 group-hover:opacity-100 transition-opacity whitespace-nowrap">
            Docs
          </span>
        </div>
        <div className={`relative group ${email ? "hidden sm:block" : ""}`}>
          <a href="https://github.com/Infisical/agent-vault" target="_blank" rel="noopener noreferrer" aria-label="GitHub" className="w-8 h-8 rounded-full flex items-center justify-center text-text-muted hover:bg-bg transition-colors">
            <svg className="w-[18px] h-[18px]" viewBox="0 0 24 24" fill="currentColor">
              <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0 0 24 12c0-6.63-5.37-12-12-12z" />
            </svg>
          </a>
          <span className="pointer-events-none absolute left-1/2 -translate-x-1/2 top-full mt-2 px-2.5 py-1 text-xs font-medium text-text bg-surface border border-border rounded-md shadow-[0_4px_16px_rgba(0,0,0,0.1)] opacity-0 group-hover:opacity-100 transition-opacity whitespace-nowrap">
            GitHub
          </span>
        </div>
        <div className={`relative group ${email ? "hidden sm:block" : ""}`}>
          <a href="https://infisical.com/slack" target="_blank" rel="noopener noreferrer" aria-label="Community" className="w-8 h-8 rounded-full flex items-center justify-center text-text-muted hover:bg-bg transition-colors">
            <svg className="w-[18px] h-[18px]" viewBox="0 0 24 24" fill="currentColor">
              <path d="M5.042 15.165a2.528 2.528 0 0 1-2.52 2.523A2.528 2.528 0 0 1 0 15.165a2.527 2.527 0 0 1 2.522-2.52h2.52v2.52zm1.271 0a2.527 2.527 0 0 1 2.521-2.52 2.527 2.527 0 0 1 2.521 2.52v6.313A2.528 2.528 0 0 1 8.834 24a2.528 2.528 0 0 1-2.521-2.522v-6.313zM8.834 5.042a2.528 2.528 0 0 1-2.521-2.52A2.528 2.528 0 0 1 8.834 0a2.528 2.528 0 0 1 2.521 2.522v2.52H8.834zm0 1.271a2.528 2.528 0 0 1 2.521 2.521 2.528 2.528 0 0 1-2.521 2.521H2.522A2.528 2.528 0 0 1 0 8.834a2.528 2.528 0 0 1 2.522-2.521h6.312zm10.122 2.521a2.528 2.528 0 0 1 2.522-2.521A2.528 2.528 0 0 1 24 8.834a2.528 2.528 0 0 1-2.522 2.521h-2.522V8.834zm-1.268 0a2.528 2.528 0 0 1-2.523 2.521 2.527 2.527 0 0 1-2.52-2.521V2.522A2.527 2.527 0 0 1 15.165 0a2.528 2.528 0 0 1 2.523 2.522v6.312zm-2.523 10.122a2.528 2.528 0 0 1 2.523 2.522A2.528 2.528 0 0 1 15.165 24a2.527 2.527 0 0 1-2.52-2.522v-2.522h2.52zm0-1.268a2.527 2.527 0 0 1-2.52-2.523 2.526 2.526 0 0 1 2.52-2.52h6.313A2.527 2.527 0 0 1 24 15.165a2.528 2.528 0 0 1-2.522 2.523h-6.313z" />
            </svg>
          </a>
          <span className="pointer-events-none absolute left-1/2 -translate-x-1/2 top-full mt-2 px-2.5 py-1 text-xs font-medium text-text bg-surface border border-border rounded-md shadow-[0_4px_16px_rgba(0,0,0,0.1)] opacity-0 group-hover:opacity-100 transition-opacity whitespace-nowrap">
            Community
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
        aria-haspopup="menu"
        aria-expanded={open}
        aria-label={`Account menu for ${email}`}
        className="flex items-center gap-1.5 min-h-11 sm:min-h-0 px-2 sm:px-0 text-sm text-text-muted hover:text-text transition-colors ml-1"
      >
        <svg className="w-5 h-5 sm:hidden" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
          <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" />
          <circle cx="12" cy="7" r="4" />
        </svg>
        <span className="hidden sm:inline">{email}</span>
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
        <div className="absolute right-0 top-full mt-2 w-56 sm:w-48 bg-surface border border-border rounded-lg shadow-[0_4px_16px_rgba(0,0,0,0.1)] py-1 z-50">
          <div className="sm:hidden px-4 py-2.5 text-xs text-text-dim break-all border-b border-border">{email}</div>
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
          {[
            { href: "https://docs.agent-vault.dev", label: "Docs" },
            { href: "https://github.com/Infisical/agent-vault", label: "GitHub" },
            { href: "https://infisical.com/slack", label: "Community" },
          ].map((link) => (
            <a
              key={link.href}
              href={link.href}
              target="_blank"
              rel="noopener noreferrer"
              className="sm:hidden block w-full text-left px-4 py-2.5 text-sm text-text-muted hover:bg-bg hover:text-text transition-colors no-underline"
              onClick={() => setOpen(false)}
            >
              {link.label}
            </a>
          ))}
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
