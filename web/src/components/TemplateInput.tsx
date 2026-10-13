import { useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";

interface TemplateInputProps {
  value: string;
  onChange: (text: string) => void;
  /** Credential keys suggested while the caret sits inside a {{ … placeholder. */
  suggestions: string[];
  placeholder?: string;
  /** Called on Enter when the suggestion popover is closed. */
  onEnter?: () => void;
}

/**
 * Finds the unclosed {{ token the caret is inside, if any: the last "{{"
 * before the caret with no closing brace between it and the caret.
 */
function openToken(value: string, caret: number): { start: number; partial: string } | null {
  const before = value.slice(0, caret);
  const start = before.lastIndexOf("{{");
  if (start === -1) return null;
  const inner = before.slice(start + 2);
  if (inner.includes("}")) return null;
  return { start, partial: inner.trim() };
}

/**
 * A text input for header-value templates. Typing "{{" opens a popover
 * listing stored credential keys; picking one inserts "{{ KEY }}" at the
 * caret. Outside a placeholder it behaves exactly like a plain Input.
 */
export default function TemplateInput({
  value,
  onChange,
  suggestions,
  placeholder,
  onEnter,
}: TemplateInputProps) {
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);
  const [caret, setCaret] = useState(0);
  const [focused, setFocused] = useState(false);
  const [dismissed, setDismissed] = useState(false);
  const [highlighted, setHighlighted] = useState(0);
  const [pos, setPos] = useState({ top: 0, left: 0, width: 0 });
  // Caret restore target after a programmatic insert, applied post-render.
  const pendingCaret = useRef<number | null>(null);

  const token = focused && !dismissed ? openToken(value, caret) : null;
  const query = token?.partial.toLowerCase() ?? "";
  const matches = token
    ? suggestions.filter((k) => !query || k.toLowerCase().includes(query))
    : [];
  const open = matches.length > 0;

  useEffect(() => {
    setDismissed(false);
  }, [value]);

  useEffect(() => {
    if (highlighted >= matches.length) setHighlighted(0);
  }, [matches.length, highlighted]);

  // The popover is position:fixed, so scrolling any ancestor (page or the
  // sheet body) would leave it stranded — track the input while open.
  useEffect(() => {
    if (!open) return;
    function reposition() {
      if (!inputRef.current) return;
      const rect = inputRef.current.getBoundingClientRect();
      setPos({ top: rect.bottom + 4, left: rect.left, width: rect.width });
    }
    reposition();
    window.addEventListener("scroll", reposition, true);
    window.addEventListener("resize", reposition);
    return () => {
      window.removeEventListener("scroll", reposition, true);
      window.removeEventListener("resize", reposition);
    };
  }, [open]);

  useEffect(() => {
    if (pendingCaret.current === null || !inputRef.current) return;
    inputRef.current.setSelectionRange(pendingCaret.current, pendingCaret.current);
    setCaret(pendingCaret.current);
    pendingCaret.current = null;
  }, [value]);

  function syncCaret(el: HTMLInputElement) {
    setCaret(el.selectionStart ?? 0);
  }

  function insert(key: string) {
    const t = openToken(value, caret);
    if (!t) return;
    // Consume a closing "}}" the user may have already typed after the caret.
    const after = value.slice(caret).replace(/^\s*\}\}/, "");
    const inserted = `{{ ${key} }}`;
    pendingCaret.current = t.start + inserted.length;
    onChange(value.slice(0, t.start) + inserted + after);
    inputRef.current?.focus();
  }

  function handleKeyDown(e: React.KeyboardEvent<HTMLInputElement>) {
    if (!open) {
      if (e.key === "Enter") onEnter?.();
      return;
    }
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setHighlighted((h) => (h + 1) % matches.length);
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setHighlighted((h) => (h - 1 + matches.length) % matches.length);
    } else if (e.key === "Enter" || e.key === "Tab") {
      e.preventDefault();
      insert(matches[Math.min(highlighted, matches.length - 1)]);
    } else if (e.key === "Escape") {
      e.stopPropagation();
      setDismissed(true);
    }
  }

  return (
    <div className="relative w-full">
      <input
        ref={inputRef}
        value={value}
        placeholder={placeholder}
        autoComplete="off"
        onChange={(e) => {
          onChange(e.target.value);
          syncCaret(e.target);
          setHighlighted(0);
        }}
        onSelect={(e) => syncCaret(e.currentTarget)}
        onFocus={(e) => {
          setFocused(true);
          syncCaret(e.currentTarget);
        }}
        onBlur={() => setFocused(false)}
        onKeyDown={handleKeyDown}
        role="combobox"
        aria-expanded={open}
        className="w-full px-4 py-3 bg-surface-raised border border-border rounded-lg text-text text-sm outline-none transition-colors focus:border-border-focus focus:shadow-[0_0_0_3px_var(--color-primary-ring)]"
      />
      {open &&
        createPortal(
          <div
            ref={listRef}
            className="fixed z-50 bg-surface border border-border rounded-lg shadow-[0_4px_16px_rgba(0,0,0,0.12)] py-1 max-h-64 overflow-y-auto thin-scrollbar"
            style={{ top: pos.top, left: pos.left, width: pos.width }}
          >
            <div className="px-4 py-1.5 text-[11px] font-mono uppercase tracking-[0.18em] text-text-dim">
              Credentials
            </div>
            {matches.map((key, i) => (
              <button
                key={key}
                type="button"
                // mousedown so selection wins over the input's blur handling
                onMouseDown={(e) => {
                  e.preventDefault();
                  insert(key);
                }}
                onMouseEnter={() => setHighlighted(i)}
                className={`w-full text-left px-4 py-2 font-mono text-sm text-text transition-colors ${i === highlighted ? "bg-bg" : ""}`}
              >
                {key}
              </button>
            ))}
          </div>,
          document.body
        )}
    </div>
  );
}
