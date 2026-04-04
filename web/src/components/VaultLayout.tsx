import { type ReactNode, useEffect, useRef, useState } from "react";
import { Link, Outlet, useLocation, useNavigate, useRouteContext } from "@tanstack/react-router";
import type { AuthContext, VaultContext } from "../router";
import Navbar from "./Navbar";

type VaultTab = "proposals" | "services" | "credentials" | "users" | "agents" | "settings";

interface NavItem {
  id: VaultTab;
  label: string;
  icon: ReactNode;
  badge?: number;
}

export default function VaultLayout() {
  const { auth } = useRouteContext({ from: "/_auth" }) as { auth: AuthContext };
  const vaultContext = useRouteContext({ from: "/_auth/vaults/$name" }) as VaultContext;
  const location = useLocation();
  const navigate = useNavigate();
  const [isExiting, setIsExiting] = useState(false);
  const sidebarRef = useRef<HTMLElement>(null);
  const [pendingCount, setPendingCount] = useState(0);

  useEffect(() => {
    async function fetchPendingCount() {
      try {
        const resp = await fetch(
          `/v1/admin/proposals?vault=${encodeURIComponent(vaultContext.vault_name)}&status=pending`
        );
        if (resp.ok) {
          const data = await resp.json();
          setPendingCount((data.proposals ?? []).length);
        }
      } catch {
        // ignore
      }
    }
    fetchPendingCount();
    const interval = setInterval(fetchPendingCount, 30_000);
    return () => clearInterval(interval);
  }, [vaultContext.vault_name]);

  // Derive active tab from current URL path
  const pathSegments = location.pathname.split("/");
  const lastSegment = pathSegments[pathSegments.length - 1] as VaultTab;
  const activeTab: VaultTab = ["proposals", "services", "credentials", "users", "agents", "settings"].includes(lastSegment)
    ? lastSegment
    : "services";

  const mainNav: NavItem[] = [
    {
      id: "services",
      label: "Services",
      icon: (
        <svg className="w-[18px] h-[18px]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
        </svg>
      ),
    },
    {
      id: "proposals",
      label: "Proposals",
      badge: pendingCount > 0 ? pendingCount : undefined,
      icon: (
        <svg className="w-[18px] h-[18px]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z" />
        </svg>
      ),
    },
    {
      id: "credentials",
      label: "Credentials",
      icon: (
        <svg className="w-[18px] h-[18px]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
          <path d="M7 11V7a5 5 0 0 1 10 0v4" />
        </svg>
      ),
    },
  ];

  const memberNav: NavItem[] = [
    {
      id: "users",
      label: "Users",
      icon: (
        <svg className="w-[18px] h-[18px]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" />
          <circle cx="12" cy="7" r="4" />
        </svg>
      ),
    },
  ];

  memberNav.push({
    id: "agents",
    label: "Agents",
    icon: (
      <svg className="w-[18px] h-[18px]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <rect x="4" y="4" width="16" height="16" rx="2" ry="2" />
        <rect x="9" y="9" width="6" height="6" />
        <line x1="9" y1="1" x2="9" y2="4" />
        <line x1="15" y1="1" x2="15" y2="4" />
        <line x1="9" y1="20" x2="9" y2="23" />
        <line x1="15" y1="20" x2="15" y2="23" />
        <line x1="20" y1="9" x2="23" y2="9" />
        <line x1="20" y1="14" x2="23" y2="14" />
        <line x1="1" y1="9" x2="4" y2="9" />
        <line x1="1" y1="14" x2="4" y2="14" />
      </svg>
    ),
  });

  return (
    <div className="min-h-screen w-full flex flex-col bg-bg">
      <Navbar email={auth.email} vaultName={vaultContext.vault_name} isOwner={auth.is_owner} />
      <div className="flex flex-1">
        {/* Sidebar */}
        <aside
          ref={sidebarRef}
          className={`w-[220px] flex-shrink-0 border-r border-border bg-surface flex flex-col ${isExiting ? "animate-sidebar-out" : "animate-sidebar-in"}`}
        >
          <div className="px-4 pt-5 pb-3">
            <a
              href="/vaults"
              onClick={(e) => {
                e.preventDefault();
                if (isExiting) return;
                setIsExiting(true);
                const aside = sidebarRef.current;
                if (aside) {
                  aside.addEventListener("animationend", () => navigate({ to: "/vaults" }), { once: true });
                } else {
                  navigate({ to: "/vaults" });
                }
              }}
              className="flex items-center gap-1.5 text-xs text-text-muted hover:text-text transition-colors"
            >
              <svg className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <polyline points="15 18 9 12 15 6" />
              </svg>
              All vaults
            </a>
          </div>

          <nav className="flex-1 px-3 pb-4 flex flex-col">
            <ul className="space-y-0.5">
              {mainNav.map((item) => (
                <SidebarItem
                  key={item.id}
                  item={item}
                  active={activeTab === item.id}
                  vaultName={vaultContext.vault_name}
                />
              ))}
            </ul>

            <div className="mt-6 mb-2 px-3">
              <span className="text-[11px] font-semibold text-text-dim uppercase tracking-wider">
                Members
              </span>
            </div>
            <ul className="space-y-0.5">
              {memberNav.map((item) => (
                <SidebarItem
                  key={item.id}
                  item={item}
                  active={activeTab === item.id}
                  vaultName={vaultContext.vault_name}
                />
              ))}
            </ul>

            <div className="mt-auto pt-4">
              <ul className="space-y-0.5">
                <SidebarItem
                  item={{
                    id: "settings",
                    label: "Settings",
                    icon: (
                      <svg className="w-[18px] h-[18px]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <circle cx="12" cy="12" r="3" />
                        <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z" />
                      </svg>
                    ),
                  }}
                  active={activeTab === "settings"}
                  vaultName={vaultContext.vault_name}
                />
              </ul>
            </div>
          </nav>
        </aside>

        {/* Content */}
        <main className="flex-1 min-w-0 flex justify-center">
          <Outlet />
        </main>
      </div>
    </div>
  );
}

function SidebarItem({
  item,
  active,
  vaultName,
}: {
  item: NavItem;
  active: boolean;
  vaultName: string;
}) {
  const tabPath = `/vaults/${encodeURIComponent(vaultName)}/${item.id}`;
  return (
    <li>
      <Link
        to={tabPath}
        className={`w-full flex items-center gap-3 px-3 py-2 rounded-lg text-sm transition-colors no-underline ${
          active
            ? "bg-bg/50 text-text font-semibold"
            : "text-text-muted hover:bg-bg/50 hover:text-text"
        }`}
      >
        <span className={active ? "text-text" : "text-text-dim"}>{item.icon}</span>
        <span className="flex-1 text-left">{item.label}</span>
        {item.badge !== undefined && (
          <span className="inline-flex items-center justify-center min-w-[20px] h-5 px-1.5 rounded-full text-xs font-semibold bg-warning-bg text-warning border border-warning/20">
            {item.badge}
          </span>
        )}
      </Link>
    </li>
  );
}
