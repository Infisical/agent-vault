import type { ReactNode } from "react";

interface FormFieldProps {
  label: string;
  helperText?: ReactNode;
  tooltip?: ReactNode;
  required?: boolean;
  error?: string;
  children: ReactNode;
}

export default function FormField({ label, helperText, tooltip, required, error, children }: FormFieldProps) {
  return (
    <div>
      <label className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-text-muted mb-2">
        <span>
          {label}
          {required && <span aria-hidden="true" className="ml-0.5 text-danger">*</span>}
        </span>
        {tooltip && (
          <span className="relative group inline-flex">
            <span
              tabIndex={0}
              aria-label="More info"
              className="inline-flex items-center justify-center w-3.5 h-3.5 rounded-full border border-text-dim text-text-dim cursor-help normal-case font-normal text-[10px] leading-none focus:outline-none focus:border-text-muted focus:text-text-muted hover:border-text-muted hover:text-text-muted"
            >
              ?
            </span>
            <span
              role="tooltip"
              className="pointer-events-none absolute left-0 top-full mt-1.5 z-20 w-72 px-3 py-2 rounded-md bg-surface-raised border border-border text-xs text-text-muted leading-snug shadow-lg opacity-0 group-hover:opacity-100 group-focus-within:opacity-100 transition-opacity duration-100 normal-case tracking-normal font-normal"
            >
              {tooltip}
            </span>
          </span>
        )}
      </label>
      {children}
      {helperText && !error && (
        <p className="mt-2 text-sm text-text-muted">{helperText}</p>
      )}
      {error && (
        <p className="mt-2 text-sm text-danger">{error}</p>
      )}
    </div>
  );
}
