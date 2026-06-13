import type { ReactNode } from "react";
import InfoTooltip from "./InfoTooltip";

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
        {tooltip && <InfoTooltip>{tooltip}</InfoTooltip>}
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
