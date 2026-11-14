import { useState } from "react";

interface CopyButtonProps {
  value: string;
  label?: string;
  copiedLabel?: string;
  className?: string;
}

export default function CopyButton({
  value,
  label = "Copy",
  copiedLabel = "Copied!",
  className = "shrink-0 px-4 py-3 bg-primary text-primary-text rounded-lg text-sm font-semibold hover:bg-primary-hover transition-colors",
}: CopyButtonProps) {
  const [copied, setCopied] = useState(false);

  async function handleCopy() {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // clipboard API may not be available
    }
  }

  return (
    <button type="button" onClick={handleCopy} className={className} aria-live="polite">
      {copied ? copiedLabel : label}
    </button>
  );
}
