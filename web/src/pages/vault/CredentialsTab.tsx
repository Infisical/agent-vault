import { useState, useEffect, useRef } from "react";
import { useVaultParams, LoadingSpinner, ErrorBanner } from "./shared";
import DropdownMenu from "../../components/DropdownMenu";
import DataTable, { type Column } from "../../components/DataTable";
import Modal from "../../components/Modal";
import Button from "../../components/Button";
import Input from "../../components/Input";
import FormField from "../../components/FormField";
import { apiFetch } from "../../lib/api";

export default function CredentialsTab() {
  const { vaultName, vaultRole } = useVaultParams();
  const [keys, setKeys] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  // Add/Edit modal state
  const [modalOpen, setModalOpen] = useState(false);
  const [editingKey, setEditingKey] = useState<string | null>(null);

  // Delete confirmation modal state
  const [deleteKey, setDeleteKey] = useState<string | null>(null);
  const [deleteReferencing, setDeleteReferencing] = useState<{ host: string; description?: string }[]>([]);
  const [deleting, setDeleting] = useState(false);
  const [deleteError, setDeleteError] = useState("");

  useEffect(() => {
    fetchKeys();
  }, []);

  async function fetchKeys() {
    try {
      const resp = await fetch(
        `/v1/credentials?vault=${encodeURIComponent(vaultName)}`
      );
      if (resp.ok) {
        const data = await resp.json();
        setKeys(data.keys ?? []);
      } else {
        const data = await resp.json();
        setError(data.error || "Failed to load credentials.");
      }
    } catch {
      setError("Network error.");
    } finally {
      setLoading(false);
    }
  }

  async function openDeleteModal(key: string) {
    setDeleteKey(key);
    setDeleteError("");
    setDeleteReferencing([]);
    try {
      const resp = await fetch(
        `/v1/vaults/${encodeURIComponent(vaultName)}/services/credential-usage?key=${encodeURIComponent(key)}`
      );
      if (resp.ok) {
        const data = await resp.json();
        setDeleteReferencing(data.services ?? []);
      }
    } catch {
      // Non-critical — proceed without dependency info.
    }
  }

  async function handleDelete() {
    if (!deleteKey) return;
    setDeleting(true);
    setDeleteError("");
    try {
      const resp = await apiFetch("/v1/credentials", {
        method: "DELETE",
        body: JSON.stringify({ vault: vaultName, keys: [deleteKey] }),
      });
      if (!resp.ok) {
        const data = await resp.json();
        setDeleteError(data.error || "Failed to delete credential.");
        return;
      }
      setDeleteKey(null);
      await fetchKeys();
    } catch {
      setDeleteError("Network error.");
    } finally {
      setDeleting(false);
    }
  }

  const isAdmin = vaultRole === "admin";

  const columns: Column<string>[] = [
    {
      key: "key",
      header: "Key",
      render: (key) => (
        <div className="flex items-center gap-2">
          <svg
            className="w-4 h-4 text-text-dim flex-shrink-0"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          >
            <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
            <path d="M7 11V7a5 5 0 0 1 10 0v4" />
          </svg>
          <span className="text-sm font-mono text-text">{key}</span>
        </div>
      ),
    },
    ...(isAdmin
      ? [
          {
            key: "actions",
            header: "",
            align: "right" as const,
            render: (key: string) => (
              <DropdownMenu
                items={[
                  { label: "Edit", onClick: () => { setEditingKey(key); setModalOpen(true); } },
                  { label: "Delete", onClick: () => openDeleteModal(key), variant: "danger" },
                ]}
              />
            ),
          } as Column<string>,
        ]
      : []),
  ];

  return (
    <div className="p-8 w-full max-w-[960px]">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h2 className="text-[22px] font-semibold text-text tracking-tight mb-1">
            Credentials
          </h2>
          <p className="text-sm text-text-muted">
            Store and manage encrypted credentials used by services.
          </p>
        </div>
        {isAdmin && (
          <Button
            onClick={() => {
              setEditingKey(null);
              setModalOpen(true);
            }}
          >
            <svg
              className="w-4 h-4"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              <line x1="12" y1="5" x2="12" y2="19" />
              <line x1="5" y1="12" x2="19" y2="12" />
            </svg>
            Add credential
          </Button>
        )}
      </div>

      {loading ? (
        <LoadingSpinner />
      ) : error ? (
        <ErrorBanner message={error} />
      ) : (
        <DataTable
          columns={columns}
          data={keys}
          rowKey={(key) => key}
          emptyTitle="No credentials stored"
          emptyDescription="Credentials will appear here when agents request and you approve them."
        />
      )}

      {/* Delete confirmation modal */}
      <Modal
        open={deleteKey !== null}
        onClose={() => {
          setDeleteKey(null);
          setDeleteError("");
          setDeleteReferencing([]);
        }}
        title="Delete credential"
        description={`Permanently delete "${deleteKey}". This action cannot be undone.`}
        footer={
          <>
            <Button variant="secondary" onClick={() => setDeleteKey(null)}>
              Cancel
            </Button>
            <Button
              onClick={handleDelete}
              loading={deleting}
              className="!bg-danger !text-white hover:!bg-danger/90"
            >
              Delete
            </Button>
          </>
        }
      >
        {deleteReferencing.length > 0 && (
          <div className="bg-warning-bg border border-warning/20 rounded-lg p-4 text-sm text-warning">
            <p className="font-medium mb-1">This credential is used by the following services:</p>
            <ul className="list-disc list-inside">
              {deleteReferencing.map((svc) => (
                <li key={svc.host}>
                  {svc.host}{svc.description ? ` (${svc.description})` : ""}
                </li>
              ))}
            </ul>
            <p className="mt-2 text-text-muted">Deleting it will break authentication for these services.</p>
          </div>
        )}
        {deleteError && <ErrorBanner message={deleteError} className="mt-3" />}
      </Modal>

      {modalOpen && (
        <CredentialModal
          vaultName={vaultName}
          editingKey={editingKey}
          onClose={() => {
            setModalOpen(false);
            setEditingKey(null);
          }}
          onSaved={() => {
            setModalOpen(false);
            setEditingKey(null);
            fetchKeys();
          }}
        />
      )}
    </div>
  );
}

/* ── Add / Edit modal ── */

interface Entry {
  key: string;
  value: string;
}

function CredentialModal({
  vaultName,
  editingKey,
  onClose,
  onSaved,
}: {
  vaultName: string;
  editingKey: string | null;
  onClose: () => void;
  onSaved: () => void;
}) {
  const isEdit = editingKey !== null;
  const [entries, setEntries] = useState<Entry[]>(
    isEdit ? [{ key: editingKey, value: "" }] : [{ key: "", value: "" }]
  );
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [dragOver, setDragOver] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  function updateEntry(index: number, field: keyof Entry, value: string) {
    setEntries((prev) =>
      prev.map((e, i) => (i === index ? { ...e, [field]: value } : e))
    );
  }

  function removeEntry(index: number) {
    setEntries((prev) => prev.filter((_, i) => i !== index));
  }

  function addEntry() {
    setEntries((prev) => [...prev, { key: "", value: "" }]);
  }

  const canSubmit = entries.every((e) => e.key.trim() && e.value.trim());

  async function handleSubmit() {
    if (!canSubmit) return;
    setSaving(true);
    setError("");
    try {
      const credentials: Record<string, string> = {};
      for (const entry of entries) {
        credentials[entry.key.trim()] = entry.value.trim();
      }
      const resp = await apiFetch("/v1/credentials", {
        method: "POST",
        body: JSON.stringify({ vault: vaultName, credentials }),
      });
      if (!resp.ok) {
        const data = await resp.json();
        throw new Error(data.error || "Failed to save credentials.");
      }
      onSaved();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "An error occurred.");
    } finally {
      setSaving(false);
    }
  }

  function parseEnvContent(text: string) {
    const parsed: Entry[] = [];
    for (const line of text.split("\n")) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#")) continue;
      const eqIndex = trimmed.indexOf("=");
      if (eqIndex === -1) continue;
      const key = trimmed.slice(0, eqIndex).trim();
      let value = trimmed.slice(eqIndex + 1).trim();
      // Strip surrounding quotes
      if (
        (value.startsWith('"') && value.endsWith('"')) ||
        (value.startsWith("'") && value.endsWith("'"))
      ) {
        value = value.slice(1, -1);
      }
      if (key) parsed.push({ key, value });
    }
    return parsed;
  }

  function handleFileDrop(e: React.DragEvent) {
    e.preventDefault();
    setDragOver(false);
    const file = e.dataTransfer.files[0];
    if (file) readFile(file);
  }

  function handleFileSelect(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (file) readFile(file);
  }

  function readFile(file: File) {
    const reader = new FileReader();
    reader.onload = () => {
      const parsed = parseEnvContent(reader.result as string);
      if (parsed.length > 0) {
        // Replace empty entries, append to non-empty ones
        setEntries((prev) => {
          const nonEmpty = prev.filter((e) => e.key.trim() || e.value.trim());
          return nonEmpty.length > 0 ? [...nonEmpty, ...parsed] : parsed;
        });
      }
    };
    reader.readAsText(file);
  }

  return (
    <Modal
      open
      onClose={onClose}
      title={isEdit ? "Edit Credential" : "Add Credential"}
      description="Credentials are injected into proxied requests via services. Values are encrypted at rest and cannot be viewed after saving."
      footer={
        <>
          <Button variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button
            onClick={handleSubmit}
            disabled={!canSubmit}
            loading={saving}
          >
            {isEdit ? "Save" : "Add"}
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        {entries.map((entry, i) => (
          <div key={i} className="flex gap-3 items-start">
            <div className="flex-1 min-w-0">
              <FormField label="Key">
                <Input
                  placeholder="e.g. STRIPE_KEY"
                  value={entry.key}
                  onChange={(e) => updateEntry(i, "key", e.target.value)}
                  readOnly={isEdit}
                  autoFocus={!isEdit && i === 0}
                />
              </FormField>
            </div>
            <div className="flex-1 min-w-0">
              <FormField label="Value">
                <Input
                  placeholder="Credential value"
                  value={entry.value}
                  onChange={(e) => updateEntry(i, "value", e.target.value)}
                  type="password"
                  autoFocus={isEdit && i === 0}
                  onKeyDown={(e) => {
                    if (e.key === "Enter") handleSubmit();
                  }}
                />
              </FormField>
            </div>
            {!isEdit && entries.length > 1 && (
              <button
                onClick={() => removeEntry(i)}
                className="mt-7 w-8 h-8 flex-shrink-0 flex items-center justify-center rounded-lg text-text-dim hover:text-danger hover:bg-danger-bg transition-colors"
              >
                <svg
                  className="w-4 h-4"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="2"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                >
                  <line x1="18" y1="6" x2="6" y2="18" />
                  <line x1="6" y1="6" x2="18" y2="18" />
                </svg>
              </button>
            )}
          </div>
        ))}

        {!isEdit && (
          <button
            onClick={addEntry}
            className="text-sm font-medium text-primary hover:text-primary-hover transition-colors"
          >
            + Add another
          </button>
        )}

        {!isEdit && (
          <div
            onDragOver={(e) => {
              e.preventDefault();
              setDragOver(true);
            }}
            onDragLeave={() => setDragOver(false)}
            onDrop={handleFileDrop}
            onClick={() => fileInputRef.current?.click()}
            className={`rounded-lg border-2 border-dashed p-6 text-center cursor-pointer transition-colors ${
              dragOver
                ? "border-primary bg-primary/5"
                : "border-border hover:border-text-dim"
            }`}
          >
            <input
              ref={fileInputRef}
              type="file"
              accept=".env,.txt"
              onChange={handleFileSelect}
              className="hidden"
            />
            <p className="text-sm text-text-dim">
              Drop a .env file here to import
            </p>
            <p className="text-xs text-text-dim mt-1">
              Parses KEY=value pairs automatically
            </p>
          </div>
        )}

        {error && <ErrorBanner message={error} />}
      </div>
    </Modal>
  );
}
