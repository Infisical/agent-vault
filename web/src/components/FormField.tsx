import type { ReactNode } from "react";
import InfoTooltip from "./InfoTooltip";

interface FormFieldProps {
  label: string;
  helperText?: ReactNode;
  tooltip?: ReactNode;
  required?: boolean;
  error?: string;
  /** Extra classes on the field wrapper, e.g. to let a field flex-grow. */
  className?: string;
  children: ReactNode;
}

export default function FormField({ label, helperText, tooltip, required, error, className = "", children }: FormFieldProps) {
  return (
    <div className={className}>
      {/* shrink-0 is inert unless the wrapper is a flex column, where it
          keeps the label and helper/error text from being squeezed by a
          flex-grow field. */}
      <label className="flex shrink-0 items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-text-muted mb-2">
        <span>
          {label}
          {required && <span aria-hidden="true" className="ml-0.5 text-danger">*</span>}
        </span>
        {tooltip && <InfoTooltip>{tooltip}</InfoTooltip>}
      </label>
      {children}
      {helperText && !error && (
        <p className="mt-2 shrink-0 text-sm text-text-muted">{helperText}</p>
      )}
      {error && (
        <p className="mt-2 shrink-0 text-sm text-danger">{error}</p>
      )}
    </div>
  );
}
