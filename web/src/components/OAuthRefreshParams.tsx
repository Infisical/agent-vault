import { useState } from "react";
import FormField from "./FormField";
import Input from "./Input";

interface RefreshParamEntry {
  key: string;
  value: string;
}

export default function OAuthRefreshParams({
  value,
  onChange,
}: {
  value?: Record<string, string>;
  onChange: (value: Record<string, string>) => void;
}) {
  const [entries, setEntries] = useState<RefreshParamEntry[]>(() => {
    const initial = Object.entries(value ?? {}).map(([key, entryValue]) => ({ key, value: entryValue }));
    return initial.length > 0 ? initial : [{ key: "", value: "" }];
  });

  function update(next: RefreshParamEntry[]) {
    setEntries(next);
    const params: Record<string, string> = {};
    for (const entry of next) {
      if (entry.key.trim()) params[entry.key.trim()] = entry.value;
    }
    onChange(params);
  }

  return (
    <FormField
      label="Additional Refresh Parameters"
      helperText="Extra form fields sent only during token refresh. Reserved OAuth fields cannot be overridden."
    >
      <div className="space-y-2">
        {entries.map((entry, index) => (
          <div key={index} className="grid grid-cols-1 sm:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_auto] gap-2 sm:items-center">
            <div className="min-w-0">
              <Input
                aria-label={`Refresh parameter ${index + 1} name`}
                placeholder="Parameter name"
                value={entry.key}
                onChange={(event) => update(entries.map((item, itemIndex) => itemIndex === index ? { ...item, key: event.target.value } : item))}
              />
            </div>
            <div className="min-w-0">
              <Input
                aria-label={`Refresh parameter ${index + 1} value`}
                placeholder="Parameter value"
                value={entry.value}
                onChange={(event) => update(entries.map((item, itemIndex) => itemIndex === index ? { ...item, value: event.target.value } : item))}
              />
            </div>
            {entries.length > 1 && (
              <button
                type="button"
                aria-label="Remove refresh parameter"
                onClick={() => update(entries.filter((_, itemIndex) => itemIndex !== index))}
                className="w-9 h-9 flex-shrink-0 flex items-center justify-center rounded-lg text-text-dim hover:text-danger hover:bg-danger-bg transition-colors"
              >
                <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <line x1="18" y1="6" x2="6" y2="18" />
                  <line x1="6" y1="6" x2="18" y2="18" />
                </svg>
              </button>
            )}
          </div>
        ))}
        <button
          type="button"
          onClick={() => update([...entries, { key: "", value: "" }])}
          className="text-sm font-medium text-primary hover:text-primary-hover transition-colors"
        >
          + Add parameter
        </button>
      </div>
    </FormField>
  );
}
