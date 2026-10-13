import { type ReactNode, type Ref, useEffect, useRef } from "react";
import { useLocation } from "@tanstack/react-router";

export const MOBILE_NAV_ID = "mobile-nav-drawer";

interface ResponsiveSidebarProps {
  /** Whether the mobile drawer is open. Ignored from md up. */
  open: boolean;
  onClose: () => void;
  /** Classes for the desktop sidebar (width, border, animation). */
  className: string;
  asideRef?: Ref<HTMLElement>;
  children: ReactNode;
}

/**
 * Renders the layout sidebar as a fixed column from md up, and as an
 * off-canvas drawer below md that is toggled from the Navbar menu button.
 * The desktop markup and behaviour are unchanged.
 */
export default function ResponsiveSidebar({
  open,
  onClose,
  className,
  asideRef,
  children,
}: ResponsiveSidebarProps) {
  const location = useLocation();
  const panelRef = useRef<HTMLDivElement>(null);
  const onCloseRef = useRef(onClose);
  onCloseRef.current = onClose;

  // Close the drawer after navigating to another page.
  useEffect(() => {
    onCloseRef.current();
  }, [location.pathname]);

  useEffect(() => {
    if (!open) return;
    const previouslyFocused = document.activeElement as HTMLElement | null;
    const prevOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";

    function handleKey(e: KeyboardEvent) {
      if (e.key === "Escape") onCloseRef.current();
    }
    function handleResize() {
      if (window.matchMedia("(min-width: 48rem)").matches) onCloseRef.current();
    }
    document.addEventListener("keydown", handleKey);
    window.addEventListener("resize", handleResize);

    const firstFocusable = panelRef.current?.querySelector<HTMLElement>("a[href], button");
    firstFocusable?.focus();

    return () => {
      document.body.style.overflow = prevOverflow;
      document.removeEventListener("keydown", handleKey);
      window.removeEventListener("resize", handleResize);
      previouslyFocused?.focus?.();
    };
  }, [open]);

  return (
    <>
      <aside ref={asideRef} className={`hidden md:flex ${className}`}>
        {children}
      </aside>

      {open && (
        <div className="fixed inset-0 z-50 md:hidden">
          <div className="absolute inset-0 bg-black/50" onClick={onClose} aria-hidden="true" />
          <div
            ref={panelRef}
            id={MOBILE_NAV_ID}
            role="dialog"
            aria-modal="true"
            aria-label="Navigation"
            className="absolute left-0 top-0 h-full w-[280px] max-w-[85vw] bg-surface border-r border-border flex flex-col overflow-y-auto animate-sidebar-in pt-[env(safe-area-inset-top)] pb-[env(safe-area-inset-bottom)] pl-[env(safe-area-inset-left)]"
          >
            <div className="flex justify-end px-3 pt-3">
              <button
                type="button"
                onClick={onClose}
                aria-label="Close navigation"
                className="w-11 h-11 flex items-center justify-center rounded-full text-text-muted hover:text-text hover:bg-bg transition-colors"
              >
                <svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <line x1="18" y1="6" x2="6" y2="18" />
                  <line x1="6" y1="6" x2="18" y2="18" />
                </svg>
              </button>
            </div>
            <div className="flex-1 flex flex-col">{children}</div>
          </div>
        </div>
      )}
    </>
  );
}
