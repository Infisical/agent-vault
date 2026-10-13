import { type ReactNode, type Ref, useEffect, useRef } from "react";
import { useLocation } from "@tanstack/react-router";
import { lockBodyScroll } from "../lib/scrollLock";
import { OVERLAY_OPEN_EVENT } from "../lib/overlayOpen";

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
  const drawerRootRef = useRef<HTMLDivElement>(null);
  const onCloseRef = useRef(onClose);
  onCloseRef.current = onClose;

  // Close the drawer after navigating to another page.
  useEffect(() => {
    onCloseRef.current();
  }, [location.pathname]);

  // Close when a Sheet or Modal opens so the overlay is not trapped under
  // inert main (sheets/modals render from page content inside main).
  useEffect(() => {
    if (!open) return;
    function onOverlayOpen() {
      onCloseRef.current();
    }
    window.addEventListener(OVERLAY_OPEN_EVENT, onOverlayOpen);
    return () => window.removeEventListener(OVERLAY_OPEN_EVENT, onOverlayOpen);
  }, [open]);

  useEffect(() => {
    if (!open) return;
    const previouslyFocused = document.activeElement as HTMLElement | null;
    const unlockScroll = lockBodyScroll();

    // Make everything outside the drawer unavailable while it is open, so
    // neither Tab nor assistive tech can reach controls behind the backdrop.
    const drawerRoot = drawerRootRef.current;
    const inerted: HTMLElement[] = [];
    let node: HTMLElement | null = drawerRoot;
    while (node && node.parentElement && node !== document.body) {
      for (const sibling of Array.from(node.parentElement.children)) {
        if (sibling !== node && sibling instanceof HTMLElement && !sibling.inert) {
          sibling.inert = true;
          inerted.push(sibling);
        }
      }
      node = node.parentElement;
    }

    function handleKey(e: KeyboardEvent) {
      if (e.key === "Escape") {
        onCloseRef.current();
        return;
      }
      if (e.key !== "Tab" || !panelRef.current) return;
      // Keep Tab focus cycling inside the drawer.
      const focusables = Array.from(
        panelRef.current.querySelectorAll<HTMLElement>(
          'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'
        )
      );
      if (focusables.length === 0) return;
      const first = focusables[0];
      const last = focusables[focusables.length - 1];
      const active = document.activeElement;
      if (e.shiftKey && (active === first || !panelRef.current.contains(active))) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && (active === last || !panelRef.current.contains(active))) {
        e.preventDefault();
        first.focus();
      }
    }
    function handleResize() {
      if (window.matchMedia("(min-width: 48rem)").matches) onCloseRef.current();
    }
    document.addEventListener("keydown", handleKey);
    window.addEventListener("resize", handleResize);

    const firstFocusable = panelRef.current?.querySelector<HTMLElement>("a[href], button");
    firstFocusable?.focus();

    return () => {
      unlockScroll();
      for (const el of inerted) el.inert = false;
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
        <div ref={drawerRootRef} className="fixed inset-0 z-50 md:hidden">
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
