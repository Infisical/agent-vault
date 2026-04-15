import { useState, useEffect, useRef } from "react";
import { createPortal } from "react-dom";

export interface DropdownMenuItem {
  label: string;
  onClick: () => void | Promise<void>;
  variant?: "danger";
}

interface DropdownMenuProps {
  items: DropdownMenuItem[];
  /** Width of the dropdown in pixels. Defaults to 128. */
  width?: number;
}

export default function DropdownMenu({ items, width = 128 }: DropdownMenuProps) {
  const [open, setOpen] = useState(false);
  const btnRef = useRef<HTMLButtonElement>(null);
  const menuRef = useRef<HTMLDivElement>(null);
  const [pos, setPos] = useState({ top: 0, left: 0 });

  useEffect(() => {
    if (!open) return;
    function handleClick(e: MouseEvent) {
      if (
        menuRef.current &&
        !menuRef.current.contains(e.target as Node) &&
        btnRef.current &&
        !btnRef.current.contains(e.target as Node)
      ) {
        setOpen(false);
      }
    }
    document.addEventListener("mousedown", handleClick);
    return () => document.removeEventListener("mousedown", handleClick);
  }, [open]);

  function toggle() {
    if (!open && btnRef.current) {
      const rect = btnRef.current.getBoundingClientRect();
      setPos({ top: rect.bottom + 4, left: rect.right - width });
    }
    setOpen((v) => !v);
  }

  if (items.length === 0) return null;

  return (
    <>
      <button
        ref={btnRef}
        onClick={toggle}
        className="w-8 h-8 flex items-center justify-center rounded-lg text-text-dim hover:text-text hover:bg-bg transition-colors"
      >
        <svg className="w-4 h-4" viewBox="0 0 24 24" fill="currentColor">
          <circle cx="12" cy="5" r="1.5" />
          <circle cx="12" cy="12" r="1.5" />
          <circle cx="12" cy="19" r="1.5" />
        </svg>
      </button>
      {open &&
        createPortal(
          <div
            ref={menuRef}
            className="fixed z-50 bg-surface border border-border rounded-lg shadow-[0_4px_16px_rgba(0,0,0,0.12)] py-1"
            style={{ top: pos.top, left: pos.left, width }}
          >
            {items.map((item) => (
              <button
                key={item.label}
                onClick={async () => {
                  setOpen(false);
                  await item.onClick();
                }}
                className={`w-full text-left px-4 py-2.5 text-sm transition-colors ${
                  item.variant === "danger"
                    ? "text-danger hover:bg-danger-bg"
                    : "text-text hover:bg-bg"
                }`}
              >
                {item.label}
              </button>
            ))}
          </div>,
          document.body
        )}
    </>
  );
}
