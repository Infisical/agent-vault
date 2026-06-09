import { useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";

export interface ComboboxOption {
  id: string;
  label: string;
  sublabel?: string;
  /** Pinned options always render at the end of the list, exempt from filtering. */
  pinned?: boolean;
}

interface ComboboxProps {
  value: string;
  /** Called on free typing, like a normal Input. */
  onChange: (text: string) => void;
  options: ComboboxOption[];
  /** Called when an option is explicitly picked from the list. */
  onSelect: (id: string) => void;
  placeholder?: string;
}

/**
 * A text input with a suggestion popover. Typing filters the options;
 * text that matches nothing behaves exactly like a plain Input.
 */
export default function Combobox({ value, onChange, options, onSelect, placeholder }: ComboboxProps) {
  const [open, setOpen] = useState(false);
  const [highlighted, setHighlighted] = useState(0);
  const [typing, setTyping] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const wrapperRef = useRef<HTMLDivElement>(null);
  const listRef = useRef<HTMLDivElement>(null);
  const [pos, setPos] = useState({ top: 0, left: 0, width: 0 });

  const query = value.trim().toLowerCase();
  const matches = typing
    ? options.filter((o) => !o.pinned && (!query || o.label.toLowerCase().includes(query) || o.sublabel?.toLowerCase().includes(query)))
    : options.filter((o) => !o.pinned);
  const filtered = [...matches, ...options.filter((o) => o.pinned)];

  useEffect(() => {
    if (!open) return;
    function handleClick(e: MouseEvent) {
      if (
        listRef.current &&
        !listRef.current.contains(e.target as Node) &&
        wrapperRef.current &&
        !wrapperRef.current.contains(e.target as Node)
      ) {
        setOpen(false);
      }
    }
    document.addEventListener("mousedown", handleClick);
    return () => document.removeEventListener("mousedown", handleClick);
  }, [open]);

  function show() {
    if (inputRef.current) {
      const rect = inputRef.current.getBoundingClientRect();
      setPos({ top: rect.bottom + 4, left: rect.left, width: rect.width });
    }
    setHighlighted(0);
    setOpen(true);
  }

  function select(id: string) {
    setOpen(false);
    setTyping(false);
    onSelect(id);
  }

  function handleKeyDown(e: React.KeyboardEvent) {
    if (!open || filtered.length === 0) return;
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setHighlighted((h) => (h + 1) % filtered.length);
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setHighlighted((h) => (h - 1 + filtered.length) % filtered.length);
    } else if (e.key === "Enter") {
      e.preventDefault();
      select(filtered[Math.min(highlighted, filtered.length - 1)].id);
    } else if (e.key === "Escape") {
      e.stopPropagation();
      setOpen(false);
    }
  }

  return (
    <div ref={wrapperRef} className="relative">
      <input
        ref={inputRef}
        value={value}
        placeholder={placeholder}
        onChange={(e) => {
          onChange(e.target.value);
          setHighlighted(0);
          setTyping(true);
          show();
        }}
        onFocus={() => { setTyping(false); show(); }}
        onKeyDown={handleKeyDown}
        role="combobox"
        aria-expanded={open && filtered.length > 0}
        autoComplete="off"
        className="w-full px-4 py-3 pr-10 bg-surface-raised border border-border rounded-lg text-text text-sm outline-none transition-colors focus:border-border-focus focus:shadow-[0_0_0_3px_var(--color-primary-ring)]"
      />
      <button
        type="button"
        tabIndex={-1}
        aria-label="Show suggestions"
        // mousedown so the toggle wins over the input's focus/outside-click handling
        onMouseDown={(e) => {
          e.preventDefault();
          setTyping(false);
          if (open) {
            setOpen(false);
          } else {
            inputRef.current?.focus();
            show();
          }
        }}
        className="absolute right-3 top-1/2 -translate-y-1/2 w-4 h-4 text-text-muted hover:text-text transition-colors"
      >
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <polyline points="6 9 12 15 18 9" />
        </svg>
      </button>
      {open && filtered.length > 0 &&
        createPortal(
          <div
            ref={listRef}
            className="fixed z-50 bg-surface border border-border rounded-lg shadow-[0_4px_16px_rgba(0,0,0,0.12)] py-1 max-h-64 overflow-y-auto"
            style={{ top: pos.top, left: pos.left, width: pos.width, scrollbarWidth: "thin", scrollbarColor: "var(--color-border) var(--color-surface)" }}
          >
            {filtered.map((option, i) => (
              <button
                key={option.id}
                type="button"
                // mousedown so selection wins over the input's blur/outside-click handling
                onMouseDown={(e) => {
                  e.preventDefault();
                  select(option.id);
                }}
                onMouseEnter={() => setHighlighted(i)}
                className={`w-full text-left px-4 py-2.5 transition-colors ${i === highlighted ? "bg-bg" : ""} ${option.pinned && i > 0 ? "border-t border-border" : ""}`}
              >
                <span className="block text-sm text-text">{option.label}</span>
                {option.sublabel && <span className="block text-xs text-text-dim truncate">{option.sublabel}</span>}
              </button>
            ))}
          </div>,
          document.body
        )}
    </div>
  );
}
