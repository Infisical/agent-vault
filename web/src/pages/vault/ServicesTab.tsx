import { useState, useEffect, useRef } from "react";
import {
  useVaultParams,
  LoadingSpinner,
  ErrorBanner,
} from "./shared";
import DropdownMenu from "../../components/DropdownMenu";
import DataTable, { type Column } from "../../components/DataTable";
import Modal from "../../components/Modal";
import Sheet from "../../components/Sheet";
import Button from "../../components/Button";
import Input from "../../components/Input";
import FormField from "../../components/FormField";
import Toggle from "../../components/Toggle";
import {
  type Auth,
  type Substitution,
  AUTH_TYPE_LABELS,
  SUBSTITUTION_SURFACES,
  DEFAULT_SUBSTITUTION_SURFACES,
} from "../../components/ProposalPreview";
import { apiFetch, apiRequest } from "../../lib/api";

interface Service {
  host: string;
  description?: string;
  enabled?: boolean;
  auth: Auth;
  substitutions?: Substitution[];
}

type SubstitutionSurface = (typeof SUBSTITUTION_SURFACES)[number];

interface CatalogTemplate {
  id: string;
  name: string;
  host: string;
  description: string;
  auth_type: string;
  suggested_credential_key: string;
  header?: string;
  prefix?: string;
}

function isEnabled(service: Service): boolean {
  return service.enabled !== false;
}

type AuthType = "bearer" | "basic" | "api-key" | "custom" | "passthrough";

const AUTH_TYPE_OPTIONS: { value: AuthType; label: string }[] = [
  { value: "bearer", label: "Bearer" },
  { value: "basic", label: "Basic" },
  { value: "api-key", label: "API key" },
  { value: "custom", label: "Custom" },
  { value: "passthrough", label: "Passthrough" },
];

export default function ServicesTab() {
  const { vaultName, vaultRole } = useVaultParams();
  const [services, setServices] = useState<Service[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [catalog, setCatalog] = useState<CatalogTemplate[]>([]);

  // Add/Edit modal state: null = closed, -1 = add, 0+ = edit index
  const [editingIndex, setEditingIndex] = useState<number | null>(null);

  // Delete confirmation modal state
  const [deleteIndex, setDeleteIndex] = useState<number | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [deleteError, setDeleteError] = useState("");

  useEffect(() => {
    fetchServices();
    fetchCatalog();
  }, []);

  async function fetchCatalog() {
    try {
      const data = await apiRequest<{ services: CatalogTemplate[] }>("/v1/service-catalog");
      const entries = data.services ?? [];
      entries.sort((a, b) => a.name.localeCompare(b.name));
      setCatalog(entries);
    } catch {
      // Catalog is optional — degrade silently to manual entry.
    }
  }

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
        const subCount = service.substitutions?.length ?? 0;
        return (
          <div className="text-sm text-text">
            {label}
            {subCount > 0 && (
              <span className="ml-2 text-xs text-text-muted">
                + {subCount} substitution{subCount === 1 ? "" : "s"}
              </span>
            )}
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
          catalog={catalog}
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
  catalog,
  onClose,
  onSave,
}: {
  title: string;
  initial?: Service;
  catalog: CatalogTemplate[];
  onClose: () => void;
  onSave: (service: Service) => Promise<void>;
}) {
  const [host, setHost] = useState(initial?.host ?? "");
  const [description, setDescription] = useState(initial?.description ?? "");
  const [enabled, setEnabled] = useState(initial ? initial.enabled !== false : true);
  const [authType, setAuthType] = useState<AuthType>((initial?.auth?.type as AuthType) ?? "bearer");

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

  // Substitution editor state — independent of auth type so it composes
  // with all of them (including passthrough).
  const [subs, setSubs] = useState<Substitution[]>(() =>
    initial?.substitutions
      ? initial.substitutions.map((s) => ({
          key: s.key,
          placeholder: s.placeholder,
          in: s.in && s.in.length > 0 ? [...s.in] : [...DEFAULT_SUBSTITUTION_SURFACES],
        }))
      : []
  );

  // Snapshot the catalog at open time so a fetch resolving mid-form doesn't
  // shift the preset picker into view above fields the user is already editing.
  const [catalogSnapshot] = useState<CatalogTemplate[]>(() => catalog);
  const [selectedPreset, setSelectedPreset] = useState("");
  const showPresets = !initial && catalogSnapshot.length > 0;

  function resetFields() {
    setHost("");
    setDescription("");
    setAuthType("bearer");
    setToken("");
    setUsername("");
    setPassword("");
    setApiKey("");
    setApiKeyHeader("");
    setApiKeyPrefix("");
    setCustomHeaders([{ name: "", value: "" }]);
    setSubs([]);
  }

  function applyPreset(id: string) {
    setSelectedPreset(id);
    resetFields();
    if (!id) return;
    const tpl = catalogSnapshot.find((t) => t.id === id);
    if (!tpl) return;
    setHost(tpl.host);
    setDescription(tpl.description);
    setAuthType(tpl.auth_type as AuthType);
    if (tpl.auth_type === "bearer") setToken(tpl.suggested_credential_key);
    // Catalogued basic-auth services (Twilio, Jira) carry a token that belongs
    // in the password slot — the username (AccountSID, email) is user-specific.
    if (tpl.auth_type === "basic") setPassword(tpl.suggested_credential_key);
    if (tpl.auth_type === "api-key") {
      setApiKey(tpl.suggested_credential_key);
      setApiKeyHeader(tpl.header ?? "");
      setApiKeyPrefix(tpl.prefix ?? "");
    }
  }

  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [subsExpanded, setSubsExpanded] = useState(subs.length > 0);

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

  const cleanedSubs = subs
    .map((s) => ({
      key: s.key.trim(),
      placeholder: s.placeholder.trim(),
      in: s.in && s.in.length > 0 ? s.in : DEFAULT_SUBSTITUTION_SURFACES,
    }))
    .filter((s) => s.key !== "" || s.placeholder !== "");
  const subsValid = cleanedSubs.every((s) => s.key !== "" && s.placeholder !== "");

  async function handleSubmit() {
    if (!canSubmit || !subsValid) return;
    setSaving(true);
    setError("");
    try {
      const service: Service = {
        host: host.trim(),
        ...(description.trim() && { description: description.trim() }),
        ...(enabled ? {} : { enabled: false }),
        auth: buildAuth(),
        ...(cleanedSubs.length > 0 && { substitutions: cleanedSubs }),
      };
      await onSave(service);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "An error occurred.");
    } finally {
      setSaving(false);
    }
  }

  return (
    <Sheet
      open
      onClose={onClose}
      eyebrow="Service"
      title={title}
      headerExtra={
        showPresets ? (
          <PresetPicker
            catalog={catalogSnapshot}
            selected={selectedPreset}
            onSelect={applyPreset}
          />
        ) : undefined
      }
      footer={
        <>
          <Button variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button
            onClick={handleSubmit}
            disabled={!canSubmit || !subsValid}
            loading={saving}
          >
            {initial ? "Save" : "Add service"}
          </Button>
        </>
      }
    >
      <div className="space-y-6">
        <Section title="Basics">
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
          <div className="flex items-start justify-between gap-4 pt-1">
            <div className="min-w-0">
              <div className="text-sm font-medium text-text">Enabled</div>
              <div className="text-xs text-text-muted mt-0.5">
                Disabled services return 403 until re-enabled.
              </div>
            </div>
            <Toggle checked={enabled} onChange={setEnabled} ariaLabel="Enabled" />
          </div>
        </Section>

        <Section title="Authentication">
          <SegmentedTabs
            options={AUTH_TYPE_OPTIONS}
            value={authType}
            onChange={setAuthType}
            ariaLabel="Authentication method"
          />

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
                  placeholder="e.g. Bearer "
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
                      <IconButton
                        onClick={() =>
                          setCustomHeaders((prev) => prev.filter((_, j) => j !== i))
                        }
                        ariaLabel="Remove header"
                      />
                    )}
                  </div>
                ))}
                <button
                  onClick={() =>
                    setCustomHeaders((prev) => [...prev, { name: "", value: "" }])
                  }
                  className="text-sm font-medium text-primary hover:text-primary-hover transition-colors"
                >
                  + Add another
                </button>
              </div>
            </FormField>
          )}
        </Section>

        <CollapsibleSection
          title="URL substitutions"
          badge="Optional"
          summary={
            subs.length === 0
              ? "None configured"
              : `${subs.length} configured`
          }
          expanded={subsExpanded}
          onToggle={() => setSubsExpanded((v) => !v)}
        >
          <p className="text-xs text-text-muted leading-relaxed">
            The broker rewrites the placeholder in the selected surfaces with
            the credential's value before forwarding the request.
          </p>
          <div className="space-y-3">
            {subs.map((sub, i) => (
              <div
                key={i}
                className="rounded-lg border border-border bg-bg p-4 flex items-start gap-3"
              >
                <div className="flex-1 flex flex-wrap items-center gap-x-2 gap-y-2 text-sm text-text-muted">
                  <span>Replace</span>
                  <InlineInput
                    widthClass="w-44"
                    placeholder="__placeholder__"
                    value={sub.placeholder}
                    onChange={(value) =>
                      setSubs((prev) =>
                        prev.map((s, j) => (j === i ? { ...s, placeholder: value } : s))
                      )
                    }
                  />
                  <span>in</span>
                  {SUBSTITUTION_SURFACES.map((surface) => {
                    const checked = (sub.in ?? DEFAULT_SUBSTITUTION_SURFACES).includes(
                      surface
                    );
                    return (
                      <button
                        key={surface}
                        type="button"
                        role="switch"
                        aria-checked={checked}
                        onClick={() => {
                          setSubs((prev) =>
                            prev.map((s, j) => {
                              if (j !== i) return s;
                              const current = new Set<SubstitutionSurface>(
                                (s.in ?? DEFAULT_SUBSTITUTION_SURFACES) as SubstitutionSurface[]
                              );
                              if (current.has(surface)) current.delete(surface);
                              else current.add(surface);
                              return {
                                ...s,
                                in: SUBSTITUTION_SURFACES.filter((sf) => current.has(sf)),
                              };
                            })
                          );
                        }}
                        className={`px-2.5 py-1 rounded-md font-mono text-xs border transition-colors ${
                          checked
                            ? "border-primary text-primary bg-[var(--color-primary-ring)]"
                            : "border-border text-text-dim hover:text-text-muted"
                        }`}
                      >
                        {surface}
                      </button>
                    );
                  })}
                  <span>with value of</span>
                  <InlineInput
                    widthClass="w-48"
                    placeholder="CREDENTIAL_KEY"
                    value={sub.key}
                    onChange={(value) =>
                      setSubs((prev) =>
                        prev.map((s, j) => (j === i ? { ...s, key: value } : s))
                      )
                    }
                  />
                </div>
                <IconButton
                  onClick={() => setSubs((prev) => prev.filter((_, j) => j !== i))}
                  ariaLabel="Remove substitution"
                />
              </div>
            ))}
            <button
              onClick={() =>
                setSubs((prev) => [
                  ...prev,
                  { key: "", placeholder: "", in: [...DEFAULT_SUBSTITUTION_SURFACES] },
                ])
              }
              className="text-sm font-medium text-primary hover:text-primary-hover transition-colors"
            >
              + Add substitution
            </button>
          </div>
        </CollapsibleSection>

        {error && <ErrorBanner message={error} />}
      </div>
    </Sheet>
  );
}

/* -- Layout helpers -- */

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="space-y-3">
      <h3 className="text-[11px] font-mono uppercase tracking-[0.18em] text-text-muted">
        {title}
      </h3>
      <div className="space-y-4">{children}</div>
    </section>
  );
}

function CollapsibleSection({
  title,
  badge,
  summary,
  expanded,
  onToggle,
  children,
}: {
  title: string;
  badge?: string;
  summary?: string;
  expanded: boolean;
  onToggle: () => void;
  children: React.ReactNode;
}) {
  return (
    <section className="rounded-lg border border-border">
      <button
        type="button"
        onClick={onToggle}
        aria-expanded={expanded}
        className="w-full flex items-center gap-3 px-3 py-2.5 text-left hover:bg-bg transition-colors rounded-lg"
      >
        <svg
          className={`w-3.5 h-3.5 text-text-muted transition-transform ${expanded ? "rotate-90" : ""}`}
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
        >
          <polyline points="9 6 15 12 9 18" />
        </svg>
        <span className="text-[11px] font-mono uppercase tracking-[0.18em] text-text">
          {title}
        </span>
        {badge && (
          <span className="text-[11px] font-mono uppercase tracking-[0.18em] text-text-dim">
            {badge}
          </span>
        )}
        {summary && (
          <span className="ml-auto text-xs text-text-muted">{summary}</span>
        )}
      </button>
      {expanded && <div className="px-3 pb-3 pt-1 space-y-3">{children}</div>}
    </section>
  );
}

function SegmentedTabs<T extends string>({
  options,
  value,
  onChange,
  ariaLabel,
}: {
  options: { value: T; label: string }[];
  value: T;
  onChange: (next: T) => void;
  ariaLabel?: string;
}) {
  return (
    <div
      role="tablist"
      aria-label={ariaLabel}
      className="inline-flex flex-wrap gap-1 p-1 bg-bg border border-border rounded-lg"
    >
      {options.map((opt) => {
        const active = opt.value === value;
        return (
          <button
            key={opt.value}
            type="button"
            role="tab"
            aria-selected={active}
            onClick={() => onChange(opt.value)}
            className={`px-3 py-1.5 rounded-md text-sm font-medium transition-colors ${
              active
                ? "bg-surface-raised text-text border border-border"
                : "text-text-muted hover:text-text border border-transparent"
            }`}
          >
            {opt.label}
          </button>
        );
      })}
    </div>
  );
}

function InlineInput({
  widthClass,
  placeholder,
  value,
  onChange,
}: {
  widthClass: string;
  placeholder: string;
  value: string;
  onChange: (next: string) => void;
}) {
  return (
    <input
      className={`${widthClass} px-3 py-1.5 bg-surface-raised border border-border rounded-md font-mono text-sm text-text outline-none transition-colors focus:border-border-focus focus:shadow-[0_0_0_3px_var(--color-primary-ring)]`}
      placeholder={placeholder}
      value={value}
      onChange={(e) => onChange(e.target.value)}
    />
  );
}

function IconButton({ onClick, ariaLabel }: { onClick: () => void; ariaLabel: string }) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-label={ariaLabel}
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
  );
}

function PresetPicker({
  catalog,
  selected,
  onSelect,
}: {
  catalog: CatalogTemplate[];
  selected: string;
  onSelect: (id: string) => void;
}) {
  const [open, setOpen] = useState(false);
  const popoverRef = useRef<HTMLDivElement>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    if (!open) return;
    function handleClick(e: MouseEvent) {
      if (
        popoverRef.current &&
        !popoverRef.current.contains(e.target as Node) &&
        triggerRef.current &&
        !triggerRef.current.contains(e.target as Node)
      ) {
        setOpen(false);
      }
    }
    document.addEventListener("mousedown", handleClick);
    return () => document.removeEventListener("mousedown", handleClick);
  }, [open]);

  const selectedTpl = catalog.find((t) => t.id === selected);
  const triggerLabel = selectedTpl ? selectedTpl.name : "Preset…";

  return (
    <div className="flex items-center gap-3 text-sm text-text-muted">
      <span>Start from</span>
      <div className="relative">
        <button
          ref={triggerRef}
          type="button"
          onClick={() => setOpen((v) => !v)}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-bg border border-border text-text text-sm font-medium hover:bg-surface-hover transition-colors"
        >
          <svg
            className="w-3.5 h-3.5 text-primary"
            viewBox="0 0 24 24"
            fill="currentColor"
          >
            <path d="M12 2l1.5 5.5L19 9l-5.5 1.5L12 16l-1.5-5.5L5 9l5.5-1.5L12 2z" />
          </svg>
          {triggerLabel}
          <svg
            className={`w-3.5 h-3.5 text-text-muted transition-transform ${open ? "rotate-180" : ""}`}
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          >
            <polyline points="6 9 12 15 18 9" />
          </svg>
        </button>
        {open && (
          <div
            ref={popoverRef}
            className="absolute left-0 top-full mt-2 w-[320px] max-h-[320px] overflow-y-auto bg-surface border border-border rounded-lg shadow-[0_8px_24px_rgba(0,0,0,0.3)] py-1 z-10"
          >
            <button
              type="button"
              onClick={() => {
                onSelect("");
                setOpen(false);
              }}
              className={`w-full text-left px-3 py-2 text-sm hover:bg-bg transition-colors ${
                selected === "" ? "text-text" : "text-text-muted"
              }`}
            >
              Custom (blank)
            </button>
            {catalog.map((tpl) => (
              <button
                key={tpl.id}
                type="button"
                onClick={() => {
                  onSelect(tpl.id);
                  setOpen(false);
                }}
                className={`w-full text-left px-3 py-2 text-sm transition-colors ${
                  selected === tpl.id ? "bg-bg" : "hover:bg-bg"
                }`}
              >
                <div className="font-medium">{tpl.name}</div>
                <div className="text-xs text-text-muted truncate">{tpl.host}</div>
              </button>
            ))}
          </div>
        )}
      </div>
      <span className="text-xs">or configure manually below</span>
    </div>
  );
}
