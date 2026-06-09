import { useState, useEffect, useRef } from "react";
import { useSearch } from "@tanstack/react-router";
import {
  useVaultParams,
  LoadingSpinner,
  ErrorBanner,
  timeAgo,
} from "./shared";
import DropdownMenu from "../../components/DropdownMenu";
import DataTable, { type Column } from "../../components/DataTable";
import Modal from "../../components/Modal";
import Sheet from "../../components/Sheet";
import Button from "../../components/Button";
import Input from "../../components/Input";
import FormField from "../../components/FormField";
import Toggle from "../../components/Toggle";
import SegmentedTabs from "../../components/SegmentedTabs";
import {
  type Auth,
  type Substitution,
  AUTH_TYPE_LABELS,
  SUBSTITUTION_SURFACES,
  DEFAULT_SUBSTITUTION_SURFACES,
} from "../../components/ProposalPreview";
import { apiFetch, apiRequest } from "../../lib/api";

interface Service {
  name: string;
  host: string;
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
  { value: "passthrough", label: "Passthrough" },
  { value: "bearer", label: "Bearer" },
  { value: "basic", label: "Basic" },
  { value: "api-key", label: "API key" },
  { value: "custom", label: "Custom" },
];

function slugifyHost(host: string): string {
  let slug = host
    .toLowerCase()
    .replace(/[^a-z0-9]/g, "-")
    .replace(/-{2,}/g, "-")
    .replace(/^-|-$/g, "");
  if (slug.length > 64) slug = slug.slice(0, 64).replace(/-$/, "");
  if (slug.length < 3) slug = slug || "svc";
  return slug;
}

export default function ServicesTab() {
  const { vaultName, vaultRole } = useVaultParams();
  const { preset: presetParam } = useSearch({ strict: false }) as { preset?: string };
  const [services, setServices] = useState<Service[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [catalog, setCatalog] = useState<CatalogTemplate[]>([]);
  const presetApplied = useRef(false);

  // Add/Edit modal state: null = closed, -1 = add, 0+ = edit index
  const [editingIndex, setEditingIndex] = useState<number | null>(null);

  // Delete confirmation modal state
  const [deleteIndex, setDeleteIndex] = useState<number | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [deleteError, setDeleteError] = useState("");

  // Discovered hosts state
  const [discoveredHosts, setDiscoveredHosts] = useState<
    { host: string; request_count: number; last_seen: string; auth_scheme?: string; auth_header?: string }[]
  >([]);
  const [discoveredTotal, setDiscoveredTotal] = useState(0);
  const [discoveredExpanded, setDiscoveredExpanded] = useState(false);
  const [discoveredCollapsed, setDiscoveredCollapsed] = useState(false);
  const [addWithHost, setAddWithHost] = useState<{ host: string; authScheme?: string; authHeader?: string } | null>(null);

  useEffect(() => {
    fetchServices();
    fetchCatalog();
    fetchDiscoveredHosts();
  }, []);

  useEffect(() => {
    if (presetParam && catalog.length > 0 && !presetApplied.current) {
      const match = catalog.find((t) => t.id === presetParam);
      if (match) {
        presetApplied.current = true;
        setEditingIndex(-1);
      }
    }
  }, [presetParam, catalog]);

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

  async function fetchDiscoveredHosts(limit = 5) {
    try {
      const resp = await apiFetch(
        `/v1/vaults/${encodeURIComponent(vaultName)}/discovered-hosts?limit=${limit}`
      );
      if (resp.ok) {
        const data = await resp.json();
        setDiscoveredHosts(data.hosts ?? []);
        setDiscoveredTotal(data.total ?? 0);
      }
    } catch {
      // Discovered hosts are supplementary; degrade silently.
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
    // Re-fetch so the local copy always reflects exactly what the
    // server stored (e.g. inline-host re-joining for the read surface).
    await fetchServices();
    fetchDiscoveredHosts(discoveredExpanded ? 100 : 5);
  }

  async function toggleEnabled(index: number, next: boolean) {
    const service = services[index];
    if (!service) return;
    const applyEnabled = (want: boolean) => (list: Service[]) =>
      list.map((s) => (s.name === service.name ? { ...s, enabled: want } : s));
    setServices(applyEnabled(next));
    try {
      const resp = await apiFetch(
        `/v1/vaults/${encodeURIComponent(vaultName)}/services/${encodeURIComponent(service.name)}`,
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
      key: "name",
      header: "Service",
      render: (service) => (
        <div>
          <div className="text-sm font-semibold text-text">{service.name}</div>
          <div className="text-xs text-text-muted mt-0.5">{service.host}</div>
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
          ariaLabel={`Toggle ${service.name}`}
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

      {discoveredTotal > 0 && !loading && (
        <div className="mb-6 rounded-lg border border-warning/20 bg-warning-bg">
          <button
            type="button"
            className="flex w-full items-center justify-between px-4 py-3 text-left"
            onClick={() => setDiscoveredCollapsed((c) => !c)}
          >
            <span className="flex items-center gap-2 text-sm font-medium text-warning">
              <svg width="16" height="16" viewBox="0 0 16 16" fill="none"><circle cx="8" cy="8" r="7" stroke="currentColor" strokeWidth="1.5"/><path d="M8 5v3M8 10h.01" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/></svg>
              {discoveredTotal} {discoveredTotal === 1 ? "host" : "hosts"} detected in recent traffic
            </span>
            <svg
              className={`w-4 h-4 text-text-muted transition-transform ${discoveredCollapsed ? "" : "rotate-180"}`}
              viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"
            >
              <polyline points="6 9 12 15 18 9" />
            </svg>
          </button>
          {!discoveredCollapsed && (
            <div className="border-t border-info/20 px-4 pb-3">
              {discoveredHosts.map((dh) => (
                <div key={dh.host} className="flex items-center justify-between py-2.5 border-b border-border last:border-b-0">
                  <div>
                    <div className="font-mono text-sm text-text">{dh.host}</div>
                    <div className="text-xs text-text-muted mt-0.5">
                      {dh.request_count} {dh.request_count === 1 ? "request" : "requests"} &middot; {timeAgo(dh.last_seen)}
                    </div>
                  </div>
                  {isAdmin && (
                    <button
                      type="button"
                      className="rounded border border-border bg-surface px-2.5 py-1 text-xs text-text-muted hover:bg-surface-hover hover:text-text transition-colors"
                      onClick={() => {
                        setAddWithHost({ host: dh.host, authScheme: dh.auth_scheme, authHeader: dh.auth_header });
                        setEditingIndex(-1);
                      }}
                    >
                      Add as service
                    </button>
                  )}
                </div>
              ))}
              {discoveredTotal > 5 && !discoveredExpanded && (
                <button
                  type="button"
                  className="mt-2 text-xs text-warning hover:text-warning/80"
                  onClick={() => {
                    setDiscoveredExpanded(true);
                    fetchDiscoveredHosts(100);
                  }}
                >
                  Show all ({discoveredTotal})
                </button>
              )}
            </div>
          )}
        </div>
      )}

      {loading ? (
        <LoadingSpinner />
      ) : error ? (
        <ErrorBanner message={error} />
      ) : (
        <DataTable
          columns={columns}
          data={services}
          rowKey={(s) => s.name}
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
            ? `Permanently delete "${services[deleteIndex].name}" (${services[deleteIndex].host}). Agents will no longer be able to proxy requests through this service.`
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
          defaultHost={editingIndex === -1 ? addWithHost?.host : undefined}
          defaultName={editingIndex === -1 && addWithHost ? slugifyHost(addWithHost.host) : undefined}
          defaultAuthScheme={editingIndex === -1 ? addWithHost?.authScheme : undefined}
          defaultAuthHeader={editingIndex === -1 ? addWithHost?.authHeader : undefined}
          defaultPreset={editingIndex === -1 && !addWithHost ? presetParam : undefined}
          catalog={catalog}
          onClose={() => {
            setEditingIndex(null);
            setAddWithHost(null);
          }}
          onSave={async (service) => {
            const updated = [...services];
            if (editingIndex === -1) {
              updated.push(service);
            } else {
              updated[editingIndex] = service;
            }
            await saveServices(updated);
            setEditingIndex(null);
            setAddWithHost(null);
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
  defaultHost,
  defaultName,
  defaultAuthScheme,
  defaultAuthHeader,
  defaultPreset,
  catalog,
  onClose,
  onSave,
}: {
  title: string;
  initial?: Service;
  defaultHost?: string;
  defaultName?: string;
  defaultAuthScheme?: string;
  defaultAuthHeader?: string;
  defaultPreset?: string;
  catalog: CatalogTemplate[];
  onClose: () => void;
  onSave: (service: Service) => Promise<void>;
}) {
  const [name, setName] = useState(initial?.name ?? defaultName ?? "");
  const [pattern, setPattern] = useState(initial?.host ?? defaultHost ?? "");
  const [enabled, setEnabled] = useState(initial ? initial.enabled !== false : true);
  const [authType, setAuthType] = useState<AuthType>((initial?.auth?.type as AuthType) ?? (defaultAuthScheme as AuthType) ?? "passthrough");

  // Bearer fields
  const [token, setToken] = useState(initial?.auth?.token ?? "");

  // Basic fields
  const [username, setUsername] = useState(initial?.auth?.username ?? "");
  const [password, setPassword] = useState(initial?.auth?.password ?? "");

  // API key fields
  const [apiKey, setApiKey] = useState(initial?.auth?.key ?? "");
  const [apiKeyHeader, setApiKeyHeader] = useState(initial?.auth?.header ?? (defaultAuthScheme === "api-key" ? defaultAuthHeader ?? "" : ""));
  const [apiKeyPrefix, setApiKeyPrefix] = useState(initial?.auth?.prefix ?? "");

  // Stable row IDs so React reconciliation keys editable rows by identity
  // rather than array index — without this, deleting a middle row causes
  // input values to bleed between adjacent rows during the re-render.
  const rowIdSeq = useRef(0);
  const nextRowId = () => ++rowIdSeq.current;

  // Custom header fields (multiple). _id is local-only — stripped before
  // submitting; never round-tripped to the server.
  type HeaderRow = { _id: number; name: string; value: string };
  const [customHeaders, setCustomHeaders] = useState<HeaderRow[]>(() => {
    if (initial?.auth?.headers && Object.keys(initial.auth.headers).length > 0) {
      return Object.entries(initial.auth.headers).map(([name, value]) => ({ _id: nextRowId(), name, value }));
    }
    return [{ _id: nextRowId(), name: "", value: "" }];
  });

  // Substitution editor state — independent of auth type so it composes
  // with all of them (including passthrough).
  type SubRow = Substitution & { _id: number };
  const [subs, setSubs] = useState<SubRow[]>(() =>
    initial?.substitutions
      ? initial.substitutions.map((s) => ({
          _id: nextRowId(),
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
  const presetInitialized = useRef(false);

  function resetFields() {
    setName("");
    setPattern("");
    setAuthType("passthrough");
    setToken("");
    setUsername("");
    setPassword("");
    setApiKey("");
    setApiKeyHeader("");
    setApiKeyPrefix("");
    setCustomHeaders([{ _id: nextRowId(), name: "", value: "" }]);
    setSubs([]);
  }

  function applyPreset(id: string) {
    setSelectedPreset(id);
    resetFields();
    if (!id) return;
    const tpl = catalogSnapshot.find((t) => t.id === id);
    if (!tpl) return;
    setPattern(tpl.host);
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

  useEffect(() => {
    if (defaultPreset && !presetInitialized.current) {
      presetInitialized.current = true;
      applyPreset(defaultPreset);
    }
  }, [defaultPreset]);

  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [subsExpanded, setSubsExpanded] = useState(subs.length > 0);

  const canSubmit = (() => {
    if (!name.trim()) return false;
    if (!pattern.trim()) return false;
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
      // Send only `host` (inline-form accepted). Server splits into
      // host + path on ingest — the UI never names a separate path field.
      const service: Service = {
        name: name.trim(),
        host: pattern.trim(),
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
          <FormField
            label="Name"
            tooltip="Slug-style identifier (3–64 chars, lowercase, hyphens). The canonical per-vault key for this service."
            required
          >
            <Input
              placeholder="e.g. stripe, slack-bot, internal-billing"
              value={name}
              onChange={(e) => setName(e.target.value)}
              autoFocus
            />
          </FormField>
          <FormField
            label="Host Pattern"
            tooltip="Host with optional port and path glob. Omit port to match any port. * is a subdomain label in the host (*.github.com) and a greedy glob in the path (/api/*). Examples: api.stripe.com, internal.corp.com:3000, slack.com/api/*, internal.corp.com:8080/api/*."
            required
          >
            <Input
              placeholder="e.g. api.stripe.com, internal.corp.com:3000, or slack.com/api/*"
              value={pattern}
              onChange={(e) => setPattern(e.target.value)}
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
              tooltip="The UPPER_SNAKE_CASE name of the credential storing the token."
              required
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
                tooltip="Credential key for the Basic Auth username."
                required
              >
                <Input
                  placeholder="e.g. ASHBY_API_KEY"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                />
              </FormField>
              <FormField
                label="Password Credential Key"
                tooltip="Optional — leave empty if the service only requires a username."
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
                tooltip="The UPPER_SNAKE_CASE name of the credential storing the API key."
                required
              >
                <Input
                  placeholder="e.g. OPENAI_API_KEY"
                  value={apiKey}
                  onChange={(e) => setApiKey(e.target.value)}
                />
              </FormField>
              <FormField
                label="Header Name"
                tooltip="Which header to inject. Defaults to Authorization."
              >
                <Input
                  placeholder="Authorization"
                  value={apiKeyHeader}
                  onChange={(e) => setApiKeyHeader(e.target.value)}
                />
              </FormField>
              <FormField
                label="Prefix"
                tooltip='Optional prefix before the key value (e.g. "Bearer ").'
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
              Passthrough allowlists the host without injecting a credential —
              same header forwarding as every other auth type, just with no
              broker-injected auth header on top. Use this when the agent
              already holds the credential.
            </div>
          )}

          {authType === "custom" && (
            <FormField
              label="Headers"
              tooltip="Type {{ CREDENTIAL_KEY }} to reference a stored credential."
              required
            >
              <div className="space-y-3">
                {customHeaders.map((header, i) => (
                  <div key={header._id} className="flex gap-3 items-center">
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
                    setCustomHeaders((prev) => [...prev, { _id: nextRowId(), name: "", value: "" }])
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
                key={sub._id}
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
                  { _id: nextRowId(), key: "", placeholder: "", in: [...DEFAULT_SUBSTITUTION_SURFACES] },
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
