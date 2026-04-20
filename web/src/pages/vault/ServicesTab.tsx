import { useState, useEffect } from "react";
import {
  useVaultParams,
  LoadingSpinner,
  ErrorBanner,
} from "./shared";
import DropdownMenu from "../../components/DropdownMenu";
import DataTable, { type Column } from "../../components/DataTable";
import Modal from "../../components/Modal";
import Button from "../../components/Button";
import Input from "../../components/Input";
import FormField from "../../components/FormField";
import Toggle from "../../components/Toggle";
import { type Auth, AUTH_TYPE_LABELS } from "../../components/ProposalPreview";
import { apiFetch } from "../../lib/api";

interface Service {
  host: string;
  description?: string;
  enabled?: boolean;
  auth: Auth;
}

function isEnabled(service: Service): boolean {
  return service.enabled !== false;
}

const AUTH_TYPE_OPTIONS: { value: string; label: string }[] = [
  { value: "bearer", label: "Bearer token" },
  { value: "basic", label: "HTTP Basic Auth" },
  { value: "api-key", label: "API key" },
  { value: "custom", label: "Custom headers" },
  { value: "passthrough", label: "Passthrough" },
];

export default function ServicesTab() {
  const { vaultName, vaultRole } = useVaultParams();
  const [services, setServices] = useState<Service[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  // Add/Edit modal state: null = closed, -1 = add, 0+ = edit index
  const [editingIndex, setEditingIndex] = useState<number | null>(null);

  // Delete confirmation modal state
  const [deleteIndex, setDeleteIndex] = useState<number | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [deleteError, setDeleteError] = useState("");

  useEffect(() => {
    fetchServices();
  }, []);

  async function fetchServices() {
    try {
      const resp = await apiFetch(
        `/v1/vaults/${encodeURIComponent(vaultName)}/services`
      );
      if (resp.ok) {
        const data = await resp.json();
        setServices(data.services ?? []);
      } else {
        const data = await resp.json();
        setError(data.error || "Failed to load services.");
      }
    } catch {
      setError("Network error.");
    } finally {
      setLoading(false);
    }
  }

  async function saveServices(updatedServices: Service[]) {
    const resp = await apiFetch(
      `/v1/vaults/${encodeURIComponent(vaultName)}/services`,
      {
        method: "PUT",
        body: JSON.stringify({ services: updatedServices }),
      }
    );
    if (!resp.ok) {
      const data = await resp.json();
      throw new Error(data.error || "Failed to save services.");
    }
    setServices(updatedServices);
  }

  async function toggleEnabled(index: number, next: boolean) {
    const service = services[index];
    if (!service) return;
    const applyEnabled = (want: boolean) => (list: Service[]) =>
      list.map((s) => (s.host === service.host ? { ...s, enabled: want } : s));
    setServices(applyEnabled(next));
    try {
      const resp = await apiFetch(
        `/v1/vaults/${encodeURIComponent(vaultName)}/services/${encodeURIComponent(service.host)}`,
        {
          method: "PATCH",
          body: JSON.stringify({ enabled: next }),
        }
      );
      if (!resp.ok) {
        const data = await resp.json();
        throw new Error(data.error || "Failed to update service.");
      }
    } catch (err: unknown) {
      setServices(applyEnabled(!next));
      setError(err instanceof Error ? err.message : "Failed to update service.");
    }
  }

  async function handleDelete() {
    if (deleteIndex === null) return;
    setDeleting(true);
    setDeleteError("");
    const updated = services.filter((_, i) => i !== deleteIndex);
    try {
      await saveServices(updated);
      setDeleteIndex(null);
    } catch (err: unknown) {
      setDeleteError(err instanceof Error ? err.message : "An error occurred.");
    } finally {
      setDeleting(false);
    }
  }

  const isAdmin = vaultRole === "admin";

  const columns: Column<Service>[] = [
    {
      key: "host",
      header: "Host",
      render: (service) => (
        <div>
          <div className="text-sm font-semibold text-text">{service.host}</div>
          {service.description && (
            <div className="text-xs text-text-muted mt-0.5">
              {service.description}
            </div>
          )}
        </div>
      ),
    },
    {
      key: "auth",
      header: "Auth",
      render: (service) => {
        const label = AUTH_TYPE_LABELS[service.auth?.type] || service.auth?.type || "\u2014";
        return (
          <div className="text-sm text-text">
            {label}
          </div>
        );
      },
    },
    {
      key: "enabled",
      header: "Enabled",
      render: (service, index) => (
        <Toggle
          checked={isEnabled(service)}
          disabled={!isAdmin}
          onChange={(next) => toggleEnabled(index, next)}
          ariaLabel={`Toggle ${service.host}`}
        />
      ),
    },
    ...(isAdmin
      ? [
          {
            key: "actions",
            header: "",
            align: "right" as const,
            render: (_service: Service, index: number) => (
              <DropdownMenu
                items={[
                  { label: "Edit", onClick: () => setEditingIndex(index) },
                  { label: "Delete", onClick: () => setDeleteIndex(index), variant: "danger" },
                ]}
              />
            ),
          } as Column<Service>,
        ]
      : []),
  ];

  return (
    <div className="p-8 w-full max-w-[960px]">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h2 className="text-[22px] font-semibold text-text tracking-tight mb-1">
            Services
          </h2>
          <p className="text-sm text-text-muted">
            Define allowed hosts and configure authentication methods.
          </p>
        </div>
        {isAdmin && (
          <Button onClick={() => setEditingIndex(-1)}>
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
            Add service
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
          data={services}
          rowKey={(_, i) => i}
          emptyTitle="No services configured"
          emptyDescription="Add a service to allow agents to proxy requests through this vault."
        />
      )}

      {/* Delete confirmation modal */}
      <Modal
        open={deleteIndex !== null}
        onClose={() => {
          setDeleteIndex(null);
          setDeleteError("");
        }}
        title="Delete service"
        description={
          deleteIndex !== null && services[deleteIndex]
            ? `Permanently delete the service for "${services[deleteIndex].host}". Agents will no longer be able to proxy requests to this host.`
            : "Permanently delete this service."
        }
        footer={
          <>
            <Button variant="secondary" onClick={() => setDeleteIndex(null)}>
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
        {deleteError && <ErrorBanner message={deleteError} />}
      </Modal>

      {editingIndex !== null && (
        <ServiceModal
          title={editingIndex === -1 ? "Add Service" : "Edit Service"}
          initial={editingIndex >= 0 ? services[editingIndex] : undefined}
          onClose={() => setEditingIndex(null)}
          onSave={async (service) => {
            const updated = [...services];
            if (editingIndex === -1) {
              updated.push(service);
            } else {
              updated[editingIndex] = service;
            }
            await saveServices(updated);
            setEditingIndex(null);
          }}
        />
      )}
    </div>
  );
}

/* -- Add / Edit modal -- */

function ServiceModal({
  title,
  initial,
  onClose,
  onSave,
}: {
  title: string;
  initial?: Service;
  onClose: () => void;
  onSave: (service: Service) => Promise<void>;
}) {
  const [host, setHost] = useState(initial?.host ?? "");
  const [description, setDescription] = useState(initial?.description ?? "");
  const [enabled, setEnabled] = useState(initial ? initial.enabled !== false : true);
  const [authType, setAuthType] = useState(initial?.auth?.type ?? "bearer");

  // Bearer fields
  const [token, setToken] = useState(initial?.auth?.token ?? "");

  // Basic fields
  const [username, setUsername] = useState(initial?.auth?.username ?? "");
  const [password, setPassword] = useState(initial?.auth?.password ?? "");

  // API key fields
  const [apiKey, setApiKey] = useState(initial?.auth?.key ?? "");
  const [apiKeyHeader, setApiKeyHeader] = useState(initial?.auth?.header ?? "");
  const [apiKeyPrefix, setApiKeyPrefix] = useState(initial?.auth?.prefix ?? "");

  // Custom header fields (multiple)
  const [customHeaders, setCustomHeaders] = useState<{ name: string; value: string }[]>(() => {
    if (initial?.auth?.headers && Object.keys(initial.auth.headers).length > 0) {
      return Object.entries(initial.auth.headers).map(([name, value]) => ({ name, value }));
    }
    return [{ name: "", value: "" }];
  });

  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");

  const canSubmit = (() => {
    if (!host.trim()) return false;
    switch (authType) {
      case "bearer":
        return !!token.trim();
      case "basic":
        return !!username.trim();
      case "api-key":
        return !!apiKey.trim();
      case "custom":
        return customHeaders.length > 0 && customHeaders.every((h) => h.name.trim() && h.value.trim());
      case "passthrough":
        return true;
      default:
        return false;
    }
  })();

  function buildAuth(): Auth {
    switch (authType) {
      case "bearer":
        return { type: "bearer", token: token.trim() };
      case "basic": {
        const auth: Auth = { type: "basic", username: username.trim() };
        if (password.trim()) auth.password = password.trim();
        return auth;
      }
      case "api-key": {
        const auth: Auth = { type: "api-key", key: apiKey.trim() };
        if (apiKeyHeader.trim()) auth.header = apiKeyHeader.trim();
        if (apiKeyPrefix) auth.prefix = apiKeyPrefix;
        return auth;
      }
      case "custom": {
        const headers: Record<string, string> = {};
        for (const h of customHeaders) {
          if (h.name.trim()) headers[h.name.trim()] = h.value.trim();
        }
        return { type: "custom", headers };
      }
      case "passthrough":
        return { type: "passthrough" };
      default:
        return { type: authType };
    }
  }

  async function handleSubmit() {
    if (!canSubmit) return;
    setSaving(true);
    setError("");
    try {
      const service: Service = {
        host: host.trim(),
        ...(description.trim() && { description: description.trim() }),
        ...(enabled ? {} : { enabled: false }),
        auth: buildAuth(),
      };
      await onSave(service);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "An error occurred.");
    } finally {
      setSaving(false);
    }
  }

  return (
    <Modal
      open
      onClose={onClose}
      title={title}
      description="Services define which hosts are proxied and how credentials are injected."
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
            {initial ? "Save" : "Add service"}
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <FormField label="Host Pattern">
          <Input
            placeholder="e.g. api.stripe.com"
            value={host}
            onChange={(e) => setHost(e.target.value)}
            autoFocus
          />
        </FormField>
        <FormField label="Description">
          <Input
            placeholder="e.g. Stripe API"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
          />
        </FormField>
        <FormField
          label="Enabled"
          helperText="Disabled services remain configured but return 403 to agents until re-enabled."
        >
          <Toggle checked={enabled} onChange={setEnabled} ariaLabel="Enabled" />
        </FormField>
        <FormField label="Authentication Method">
          <select
            className="w-full px-4 py-3 bg-surface-raised border border-border rounded-lg text-sm text-text focus:outline-none focus:border-border-focus focus:shadow-[0_0_0_3px_var(--color-primary-ring)]"
            value={authType}
            onChange={(e) => setAuthType(e.target.value)}
          >
            {AUTH_TYPE_OPTIONS.map((opt) => (
              <option key={opt.value} value={opt.value}>
                {opt.label}
              </option>
            ))}
          </select>
        </FormField>

        {authType === "bearer" && (
          <FormField
            label="Token Credential Key"
            helperText="The UPPER_SNAKE_CASE name of the credential storing the token."
          >
            <Input
              placeholder="e.g. STRIPE_KEY"
              value={token}
              onChange={(e) => setToken(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") handleSubmit();
              }}
            />
          </FormField>
        )}

        {authType === "basic" && (
          <>
            <FormField
              label="Username Credential Key"
              helperText="Credential key for the Basic Auth username."
            >
              <Input
                placeholder="e.g. ASHBY_API_KEY"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
              />
            </FormField>
            <FormField
              label="Password Credential Key"
              helperText="Optional — leave empty if the service only requires a username."
            >
              <Input
                placeholder="e.g. ASHBY_PASSWORD"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") handleSubmit();
                }}
              />
            </FormField>
          </>
        )}

        {authType === "api-key" && (
          <>
            <FormField
              label="API Key Credential"
              helperText="The UPPER_SNAKE_CASE name of the credential storing the API key."
            >
              <Input
                placeholder="e.g. OPENAI_API_KEY"
                value={apiKey}
                onChange={(e) => setApiKey(e.target.value)}
              />
            </FormField>
            <FormField
              label="Header Name"
              helperText="Which header to inject. Defaults to Authorization."
            >
              <Input
                placeholder="Authorization"
                value={apiKeyHeader}
                onChange={(e) => setApiKeyHeader(e.target.value)}
              />
            </FormField>
            <FormField
              label="Prefix"
              helperText='Optional prefix before the key value (e.g. "Bearer ").'
            >
              <Input
                placeholder='e.g. Bearer '
                value={apiKeyPrefix}
                onChange={(e) => setApiKeyPrefix(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") handleSubmit();
                }}
              />
            </FormField>
          </>
        )}

        {authType === "passthrough" && (
          <div className="rounded-lg border border-border bg-bg p-3 text-sm text-text-muted leading-relaxed">
            Passthrough forwards your client's request headers unchanged to
            the target. Agent Vault will not look up or inject a credential,
            and will strip only hop-by-hop headers and broker-scoped headers
            (<span className="font-mono">X-Vault</span>,{" "}
            <span className="font-mono">Proxy-Authorization</span>). Use this
            when the agent already holds the credential.
          </div>
        )}

        {authType === "custom" && (
          <div className="space-y-3">
            <FormField
              label="Headers"
              helperText="Type {{ CREDENTIAL_KEY }} to reference a stored credential."
            >
              <div className="space-y-3">
                {customHeaders.map((header, i) => (
                  <div key={i} className="flex gap-3 items-center">
                    <Input
                      placeholder="Header name"
                      value={header.name}
                      onChange={(e) =>
                        setCustomHeaders((prev) =>
                          prev.map((h, j) => (j === i ? { ...h, name: e.target.value } : h))
                        )
                      }
                    />
                    <Input
                      placeholder="e.g. Bearer {{ STRIPE_KEY }}"
                      value={header.value}
                      onChange={(e) =>
                        setCustomHeaders((prev) =>
                          prev.map((h, j) => (j === i ? { ...h, value: e.target.value } : h))
                        )
                      }
                      onKeyDown={(e) => {
                        if (e.key === "Enter") handleSubmit();
                      }}
                    />
                    {customHeaders.length > 1 && (
                      <button
                        onClick={() => setCustomHeaders((prev) => prev.filter((_, j) => j !== i))}
                        className="w-8 h-8 flex-shrink-0 flex items-center justify-center rounded-lg text-text-dim hover:text-danger hover:bg-danger-bg transition-colors"
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
              </div>
            </FormField>
            <button
              onClick={() => setCustomHeaders((prev) => [...prev, { name: "", value: "" }])}
              className="text-sm font-medium text-primary hover:text-primary-hover transition-colors"
            >
              + Add another
            </button>
          </div>
        )}

        {error && <ErrorBanner message={error} />}
      </div>
    </Modal>
  );
}
