import { type ReactNode, useRef, useState } from "react";
import { Link, Outlet, useLocation, useNavigate, useRouteContext } from "@tanstack/react-router";
import type { AuthContext } from "../router";
import Navbar from "./Navbar";

type InstanceTab = "agents" | "settings";

interface NavItem {
  id: InstanceTab;
  label: string;
  icon: ReactNode;
}

export default function InstanceLayout() {
  const { auth } = useRouteContext({ from: "/_auth" }) as { auth: AuthContext };
  const location = useLocation();
  const navigate = useNavigate();
  const [isExiting, setIsExiting] = useState(false);
  const sidebarRef = useRef<HTMLElement>(null);

  const pathSegments = location.pathname.split("/");
  const lastSegment = pathSegments[pathSegments.length - 1] as InstanceTab;
  const activeTab: InstanceTab = ["agents", "settings"].includes(lastSegment)
    ? (lastSegment as InstanceTab)
    : "agents";

  const navItems: NavItem[] = [
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
    {
      id: "settings",
      label: "Settings",
      icon: (
        <svg className="w-[18px] h-[18px]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <circle cx="12" cy="12" r="3" />
          <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z" />
        </svg>
      ),
    },
  ];

  return (
    <div className="min-h-screen w-full flex flex-col bg-bg">
      <Navbar email={auth.email} isOwner={auth.is_owner} />
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

          <nav className="flex-1 px-3 pb-4">
            <ul className="space-y-0.5">
              {navItems.map((item) => (
                <li key={item.id}>
                  <Link
                    to={`/manage/${item.id}`}
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
