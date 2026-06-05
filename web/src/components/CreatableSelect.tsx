import { useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";

export interface CreatableSelectOption {
  value: string;
  label?: string;
  description?: string;
}

interface CreatableSelectProps {
  values: string[];
  onChange: (values: string[]) => void;
  options?: CreatableSelectOption[];
  placeholder?: string;
}

export default function CreatableSelect({ values, onChange, options = [], placeholder }: CreatableSelectProps) {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [highlighted, setHighlighted] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const wrapperRef = useRef<HTMLDivElement>(null);
  const listRef = useRef<HTMLDivElement>(null);
  const [pos, setPos] = useState({ top: 0, left: 0, width: 0 });

  const q = query.trim().toLowerCase();
  const available = options.filter((o) => !values.includes(o.value));
  const filtered = q
    ? available.filter((o) => o.value.toLowerCase().includes(q) || o.label?.toLowerCase().includes(q) || o.description?.toLowerCase().includes(q))
    : available;
  const exactMatch = options.some((o) => o.value.toLowerCase() === q) || values.some((v) => v.toLowerCase() === q);
  const showCreate = q && !exactMatch;

  const items: { type: "option" | "create"; option?: CreatableSelectOption; createValue?: string }[] = [
    ...filtered.map((o) => ({ type: "option" as const, option: o })),
    ...(showCreate ? [{ type: "create" as const, createValue: query.trim() }] : []),
  ];

  useEffect(() => {
    if (!open) return;
    function handleClick(e: MouseEvent) {
      if (
        listRef.current && !listRef.current.contains(e.target as Node) &&
        wrapperRef.current && !wrapperRef.current.contains(e.target as Node)
      ) {
        setOpen(false);
      }
    }
    document.addEventListener("mousedown", handleClick);
    return () => document.removeEventListener("mousedown", handleClick);
  }, [open]);

  function show() {
    if (wrapperRef.current) {
      const rect = wrapperRef.current.getBoundingClientRect();
      setPos({ top: rect.bottom + 4, left: rect.left, width: rect.width });
    }
    setHighlighted(0);
    setOpen(true);
  }

  function addValue(v: string) {
    if (!v || values.includes(v)) return;
    onChange([...values, v]);
    setQuery("");
    setHighlighted(0);
  }

  function removeValue(v: string) {
    onChange(values.filter((x) => x !== v));
  }

  function toggleOption(v: string) {
    if (values.includes(v)) {
      removeValue(v);
    } else {
      addValue(v);
    }
  }

  function handleKeyDown(e: React.KeyboardEvent) {
    if (e.key === "Backspace" && !query && values.length > 0) {
      onChange(values.slice(0, -1));
      return;
    }
    if (!open || items.length === 0) return;
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setHighlighted((h) => (h + 1) % items.length);
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setHighlighted((h) => (h - 1 + items.length) % items.length);
    } else if (e.key === "Enter") {
      e.preventDefault();
      const item = items[Math.min(highlighted, items.length - 1)];
      if (item.type === "create" && item.createValue) {
        addValue(item.createValue);
      } else if (item.type === "option" && item.option) {
        toggleOption(item.option.value);
      }
    } else if (e.key === "Escape") {
      e.stopPropagation();
      setOpen(false);
    }
  }

  return (
    <div ref={wrapperRef} className="relative">
      <div
        className={`flex items-center gap-1.5 w-full min-h-[46px] px-3 py-2 bg-surface-raised border rounded-lg text-sm transition-colors cursor-text ${open ? "border-border-focus shadow-[0_0_0_3px_var(--color-primary-ring)]" : "border-border"}`}
        onClick={() => { inputRef.current?.focus(); }}
      >
        <div className="flex flex-wrap items-center gap-1.5 flex-1 min-w-0">
          {values.map((v) => {
            const opt = options.find((o) => o.value === v);
            return (
              <span key={v} className="inline-flex items-center gap-1 bg-primary/10 text-primary border border-primary/20 text-xs font-medium rounded-md px-2 py-1 max-w-[200px]">
                <span className="truncate">{opt?.label || v}</span>
                <button
                  type="button"
                  tabIndex={-1}
                  onClick={(e) => { e.stopPropagation(); removeValue(v); }}
                  className="flex-shrink-0 text-text-dim hover:text-text transition-colors"
                >
                  <svg className="w-3 h-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" /></svg>
                </button>
              </span>
            );
          })}
          <input
            ref={inputRef}
            value={query}
            placeholder={values.length === 0 ? placeholder : undefined}
            onChange={(e) => { setQuery(e.target.value); setHighlighted(0); show(); }}
            onFocus={show}
            onKeyDown={handleKeyDown}
            autoComplete="off"
            className="flex-1 min-w-[80px] bg-transparent outline-none text-text text-sm py-1"
          />
        </div>
        <div className="flex items-center gap-1 flex-shrink-0 self-start mt-2">
          {values.length > 0 && (
            <button
              type="button"
              tabIndex={-1}
              aria-label="Clear all"
              onMouseDown={(e) => { e.preventDefault(); onChange([]); setQuery(""); }}
              className="text-text-dim hover:text-text transition-colors"
            >
              <svg className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" /></svg>
            </button>
          )}
          <button
            type="button"
            tabIndex={-1}
            aria-label="Show suggestions"
            onMouseDown={(e) => {
              e.preventDefault();
              if (open) { setOpen(false); } else { inputRef.current?.focus(); show(); }
            }}
            className="w-4 h-4 text-text-muted hover:text-text transition-colors"
          >
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <polyline points="6 9 12 15 18 9" />
            </svg>
          </button>
        </div>
      </div>
      {open && items.length > 0 &&
        createPortal(
          <div
            ref={listRef}
            className="fixed z-50 bg-surface border border-border rounded-lg shadow-[0_4px_16px_rgba(0,0,0,0.12)] py-1 max-h-64 overflow-y-auto"
            style={{ top: pos.top, left: pos.left, width: pos.width, scrollbarWidth: "thin", scrollbarColor: "var(--color-border) var(--color-surface)" }}
          >
            {items.map((item, i) => {
              if (item.type === "create") {
                return (
                  <button
                    key="__create__"
                    type="button"
                    onMouseDown={(e) => { e.preventDefault(); addValue(item.createValue!); }}
                    onMouseEnter={() => setHighlighted(i)}
                    className={`w-full text-left px-4 py-2.5 transition-colors border-t border-border ${i === highlighted ? "bg-bg" : ""}`}
                  >
                    <span className="text-sm text-primary">Add "{item.createValue}"</span>
                  </button>
                );
              }
              const opt = item.option!;
              const selected = values.includes(opt.value);
              return (
                <button
                  key={opt.value}
                  type="button"
                  onMouseDown={(e) => { e.preventDefault(); toggleOption(opt.value); }}
                  onMouseEnter={() => setHighlighted(i)}
                  className={`w-full text-left px-4 py-2.5 transition-colors flex items-center justify-between ${i === highlighted ? "bg-bg" : ""}`}
                >
                  <div className="min-w-0">
                    <span className="block text-sm text-text truncate">{opt.label || opt.value}</span>
                    {opt.description && <span className="block text-xs text-text-dim truncate">{opt.description}</span>}
                  </div>
                  {selected && (
                    <svg className="w-4 h-4 flex-shrink-0 text-primary ml-2" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12" /></svg>
                  )}
                </button>
              );
            })}
          </div>,
          document.body
        )}
    </div>
  );
}
