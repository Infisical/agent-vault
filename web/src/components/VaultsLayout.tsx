import { type ReactNode } from "react";
import { Link, Outlet, useLocation, useRouteContext } from "@tanstack/react-router";
import type { AuthContext } from "../router";
import Navbar from "./Navbar";

type HomeTab = "vaults" | "users" | "agents";

interface NavItem {
  id: HomeTab;
  label: string;
  icon: ReactNode;
}

const navItems: NavItem[] = [
  {
    id: "vaults",
    label: "Vaults",
    icon: (
      <svg className="w-[18px] h-[18px]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <rect x="3" y="3" width="18" height="18" rx="2" ry="2" />
        <rect x="7" y="7" width="3" height="9" />
        <rect x="14" y="7" width="3" height="9" />
      </svg>
    ),
  },
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
  {
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
  },
];

export default function VaultsLayout() {
  const { auth } = useRouteContext({ from: "/_auth" }) as { auth: AuthContext };
  const location = useLocation();

  const activeTab: HomeTab = location.pathname === "/vaults/users" ? "users" : location.pathname === "/vaults/agents" ? "agents" : "vaults";

  return (
    <div className="min-h-screen w-full flex flex-col bg-bg">
      <Navbar email={auth.email} isOwner={auth.is_owner} />
      <div className="flex flex-1">
        {/* Sidebar */}
        <aside className="w-[220px] flex-shrink-0 border-r border-border bg-surface flex flex-col animate-sidebar-in">
          <nav className="flex-1 px-3 pt-5 pb-4">
            <ul className="space-y-0.5">
              {navItems.map((item) => (
                <li key={item.id}>
                  <Link
                    to={item.id === "vaults" ? "/vaults" : item.id === "users" ? "/vaults/users" : "/vaults/agents"}
                    className={`w-full flex items-center gap-3 px-3 py-2 rounded-lg text-sm transition-colors no-underline ${
                      activeTab === item.id
                        ? "bg-bg/50 text-text font-semibold"
                        : "text-text-muted hover:bg-bg/50 hover:text-text"
                    }`}
                  >
                    <span className={activeTab === item.id ? "text-text" : "text-text-dim"}>{item.icon}</span>
                    <span className="flex-1 text-left">{item.label}</span>
                  </Link>
                </li>
              ))}
            </ul>
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
