import { type ReactNode, useCallback, useEffect, useLayoutEffect, useRef, useState } from "react";

const MARGIN = 8;
const GAP = 6;

/**
 * Hover and focus tooltip rendered with fixed positioning, so it is not
 * clipped by scrollable parents (such as a table that scrolls sideways) and
 * is clamped to stay inside the viewport on narrow screens.
 */
export default function Tooltip({
  trigger,
  children,
  className = "",
}: {
  trigger: ReactNode;
  children: ReactNode;
  /** Classes for the wrapper around the trigger. */
  className?: string;
}) {
  const anchorRef = useRef<HTMLSpanElement>(null);
  const tipRef = useRef<HTMLSpanElement>(null);
  const [open, setOpen] = useState(false);
  const [pos, setPos] = useState<{ top: number; left: number } | null>(null);

  const place = useCallback(() => {
    const anchor = anchorRef.current;
    const tip = tipRef.current;
    if (!anchor || !tip) return;
    const a = anchor.getBoundingClientRect();
    const width = tip.offsetWidth;
    const maxLeft = window.innerWidth - width - MARGIN;
    setPos({ top: a.bottom + GAP, left: Math.max(MARGIN, Math.min(a.left, maxLeft)) });
  }, []);

  useLayoutEffect(() => {
    if (open) place();
    else setPos(null);
  }, [open, place]);

  useEffect(() => {
    if (!open) return;
    const close = () => setOpen(false);
    window.addEventListener("scroll", close, true);
    window.addEventListener("resize", close);
    return () => {
      window.removeEventListener("scroll", close, true);
      window.removeEventListener("resize", close);
    };
  }, [open]);

  return (
    <span
      ref={anchorRef}
      className={`relative ${className}`}
      onMouseEnter={() => setOpen(true)}
      onMouseLeave={() => setOpen(false)}
      onFocus={() => setOpen(true)}
      onBlur={() => setOpen(false)}
    >
      {trigger}
      {open && (
        <span
          ref={tipRef}
          role="tooltip"
          style={{ position: "fixed", top: pos?.top ?? 0, left: pos?.left ?? 0, visibility: pos ? "visible" : "hidden" }}
          className="pointer-events-none z-[60] w-72 max-w-[calc(100vw-1rem)] px-3 py-2 rounded-md bg-surface-raised border border-border text-xs text-text-muted leading-snug shadow-lg normal-case tracking-normal font-normal"
        >
          {children}
        </span>
      )}
    </span>
  );
}
