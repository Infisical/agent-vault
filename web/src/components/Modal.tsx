import { useEffect, type ReactNode } from "react";
import { createPortal } from "react-dom";
import { lockBodyScroll } from "../lib/scrollLock";
import { notifyOverlayOpen } from "../lib/overlayOpen";

interface ModalProps {
  open: boolean;
  onClose: () => void;
  title: string;
  description?: string;
  children: ReactNode;
  footer?: ReactNode;
}

export default function Modal({ open, onClose, title, description, children, footer }: ModalProps) {
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
    return lockBodyScroll();
  }, [open]);

  // Close the mobile nav (and clear inert on main) so a delayed modal is usable.
  useEffect(() => {
    if (open) notifyOverlayOpen();
  }, [open]);

  if (!open) return null;

  return createPortal(
    <div
      className="fixed inset-0 z-50 flex items-stretch sm:items-center justify-center"
      onClick={onClose}
    >
      {/* Backdrop */}
      <div className="absolute inset-0 bg-black/40" />

      {/* Card */}
      <div
        className="relative w-full sm:max-w-[560px] h-full sm:h-auto sm:max-h-[90vh] sm:mx-4 bg-surface sm:rounded-2xl shadow-[0_8px_32px_rgba(0,0,0,0.12)] flex flex-col pt-[env(safe-area-inset-top)] pb-[env(safe-area-inset-bottom)] sm:pt-0 sm:pb-0"
        onClick={(e) => e.stopPropagation()}
        role="dialog"
        aria-modal="true"
        aria-label={title}
      >
        {/* Header */}
        <div className="px-4 sm:px-6 pt-4 sm:pt-6 pb-0 flex-shrink-0">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-semibold text-text min-w-0 break-words">{title}</h2>
            <button
              onClick={onClose}
              aria-label="Close"
              className="-mr-2 sm:mr-0 w-11 h-11 sm:w-8 sm:h-8 flex-shrink-0 flex items-center justify-center rounded-full text-text-dim hover:text-text hover:bg-bg transition-colors"
            >
              <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <line x1="18" y1="6" x2="6" y2="18" />
                <line x1="6" y1="6" x2="18" y2="18" />
              </svg>
            </button>
          </div>
          {description && (
            <>
              <p className="text-sm text-text-muted mt-1">{description}</p>
              <div className="border-b border-border mt-4" />
            </>
          )}
        </div>

        {/* Body */}
        <div className="px-4 sm:px-6 py-5 overflow-y-auto flex-1 min-h-0" style={{ scrollbarWidth: "thin", scrollbarColor: "var(--color-border) transparent" }}>{children}</div>

        {/* Footer */}
        {footer && (
          <div className="px-4 sm:px-6 py-4 flex flex-wrap items-center justify-end gap-3 flex-shrink-0 border-t border-border">
            {footer}
          </div>
        )}
      </div>
    </div>,
    document.body
  );
}
