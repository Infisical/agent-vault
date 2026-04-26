import { useEffect, type ReactNode } from "react";

interface SheetProps {
  open: boolean;
  onClose: () => void;
  eyebrow?: string;
  title: string;
  /** Rendered between the header and the scrollable body. Stays pinned. */
  headerExtra?: ReactNode;
  children: ReactNode;
  footer?: ReactNode;
  /** Tailwind max-width class. Defaults to `max-w-[520px]`. */
  widthClass?: string;
}

export default function Sheet({
  open,
  onClose,
  eyebrow,
  title,
  headerExtra,
  children,
  footer,
  widthClass = "max-w-[520px]",
}: SheetProps) {
  useEffect(() => {
    if (!open) return;
    function handleKey(e: KeyboardEvent) {
      if (e.key === "Escape") onClose();
    }
    document.addEventListener("keydown", handleKey);
    return () => document.removeEventListener("keydown", handleKey);
  }, [open, onClose]);

  useEffect(() => {
    if (!open) return;
    const prev = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      document.body.style.overflow = prev;
    };
  }, [open]);

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50" onClick={onClose}>
      <div className="absolute inset-0 bg-black/40" />
      <div
        className={`absolute right-0 top-0 h-full w-full ${widthClass} bg-surface shadow-[0_0_48px_rgba(0,0,0,0.4)] flex flex-col`}
        onClick={(e) => e.stopPropagation()}
        role="dialog"
        aria-modal="true"
        aria-label={title}
      >
        <div className="px-6 pt-5 pb-4 border-b border-border">
          <div className="flex items-start justify-between gap-4">
            <div className="min-w-0">
              {eyebrow && (
                <div className="text-[11px] font-mono uppercase tracking-[0.18em] text-text-muted mb-1">
                  {eyebrow}
                </div>
              )}
              <h2 className="text-lg font-semibold text-text truncate">{title}</h2>
            </div>
            <button
              onClick={onClose}
              aria-label="Close"
              className="-mr-2 -mt-1 w-8 h-8 flex-shrink-0 flex items-center justify-center rounded-full text-text-dim hover:text-text hover:bg-bg transition-colors"
            >
              <svg
                className="w-4 h-4"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
              >
                <line x1="18" y1="6" x2="6" y2="18" />
                <line x1="6" y1="6" x2="18" y2="18" />
              </svg>
            </button>
          </div>
          {headerExtra && <div className="mt-4">{headerExtra}</div>}
        </div>

        <div className="flex-1 overflow-y-auto px-6 py-5">{children}</div>

        {footer && (
          <div className="px-6 py-4 border-t border-border flex items-center justify-end gap-3">
            {footer}
          </div>
        )}
      </div>
    </div>
  );
}
