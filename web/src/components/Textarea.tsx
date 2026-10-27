import { forwardRef, type TextareaHTMLAttributes } from "react";

interface TextareaProps extends TextareaHTMLAttributes<HTMLTextAreaElement> {
  error?: boolean;
}

// Sized by `rows` or by the caller's height/flex classes, never by a drag
// handle: manual resize would let the box grow past its container and push
// sibling helper text out of view.

const Textarea = forwardRef<HTMLTextAreaElement, TextareaProps>(
  ({ error, className = "", ...props }, ref) => {
    return (
      <textarea
        ref={ref}
        className={`w-full px-4 py-3 bg-surface-raised border rounded-lg text-text text-sm font-mono leading-relaxed resize-none outline-none transition-colors focus:border-border-focus focus:shadow-[0_0_0_3px_var(--color-primary-ring)] ${error ? "border-danger" : "border-border"} ${className}`}
        {...props}
      />
    );
  }
);

Textarea.displayName = "Textarea";
export default Textarea;
