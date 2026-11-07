import { useState, useEffect } from "react";
import DataTable, { type Column } from "../../components/DataTable";
import Button from "../../components/Button";
import Input from "../../components/Input";
import Select from "../../components/Select";
import Toggle from "../../components/Toggle";
import Modal from "../../components/Modal";
import FormField from "../../components/FormField";
import ConfirmDeleteModal from "../../components/ConfirmDeleteModal";
import DropdownMenu from "../../components/DropdownMenu";
import { ErrorBanner, LoadingSpinner, timeAgo } from "../../components/shared";
import {
  type UpstreamProxy,
  type UpstreamProxyPatch,
  listUpstreamProxies,
  createUpstreamProxy,
  updateUpstreamProxy,
  deleteUpstreamProxy,
} from "../../lib/api";

// Wire values accepted by the admin API. Mirrors brokercore's scheme and
// failure-mode constants; the server rejects anything else, but offering the
// closed set here keeps typos from round-tripping as 400s.
const SCHEME_OPTIONS = [
  { value: "http", label: "HTTP" },
  { value: "https", label: "HTTPS (proxy over TLS)" },
  { value: "socks5", label: "SOCKS5 (local DNS)" },
  { value: "socks5h", label: "SOCKS5h (proxy DNS)" },
];

const FAILURE_OPTIONS = [
  { value: "fail_closed", label: "Fail closed (recommended)" },
  { value: "fail_open", label: "Fail open (direct fallback)" },
];

const SCHEME_LABELS: Record<string, string> = Object.fromEntries(
  SCHEME_OPTIONS.map((o) => [o.value, o.label]),
);

const FAILURE_LABELS: Record<string, string> = {
  fail_closed: "Fail closed",
  fail_open: "Fail open",
};

const DEFAULT_FAILURE = "fail_closed";

// Profile names are referenced verbatim from a service's `upstream_proxy`
// field, so enforce the broker's validation rules before submitting.
const FORBIDDEN_NAME_CHARS = " \t\r\n\"'\\/@#:,";

function endpoint(proxy: UpstreamProxy): string {
  return `${proxy.scheme}://${proxy.host}`;
}

function validateName(name: string): string | null {
  const trimmed = name.trim();
  if (!trimmed) return "Name is required.";
  if (trimmed.length > 64) return "Name must be at most 64 characters.";
  for (const ch of trimmed) {
    if (ch < " " || ch === "\x7f") return "Name must not contain control characters.";
    if (FORBIDDEN_NAME_CHARS.includes(ch)) {
      return `Name must not contain "${ch === " " ? "spaces" : ch}". Use letters, digits, dots, hyphens, or underscores.`;
    }
  }
  return null;
}

// Mirrors egress.ValidateHost: the proxy endpoint must carry an explicit
// numeric port, and the host part must be bare (no scheme, path, or userinfo).
function validateHost(host: string): string | null {
  const trimmed = host.trim();
  if (!trimmed) return "Host is required.";
  if (trimmed.includes("://")) return 'Omit the scheme — pick it above and enter "host:port".';
  if (trimmed.includes("/")) return "Host must not contain a path.";

  const lastColon = trimmed.lastIndexOf(":");
  if (lastColon === -1) return 'Host must include a port, e.g. "proxy.corp.internal:3128".';

  const name = trimmed.slice(0, lastColon);
  const port = trimmed.slice(lastColon + 1);
  if (!port) return "Host must include a port.";
  for (const ch of port) {
    if (ch < "0" || ch > "9") return "Port must be numeric.";
  }
  if (!name) return "Host is missing a hostname.";
  if (name.length > 253) return "Host must be at most 253 characters.";
  return null;
}

export default function UpstreamProxiesTab() {
  const [rows, setRows] = useState<UpstreamProxy[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  // null = closed; "" = create; otherwise the name of the profile being edited.
  const [editing, setEditing] = useState<string | null>(null);
  const [deleting, setDeleting] = useState<UpstreamProxy | null>(null);

  useEffect(() => {
    fetchProxies();
  }, []);

  async function fetchProxies() {
    try {
      setRows(await listUpstreamProxies());
      setError("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load upstream proxies.");
    } finally {
      setLoading(false);
    }
  }

  async function handleDelete(proxy: UpstreamProxy) {
    await deleteUpstreamProxy(proxy.name);
    setDeleting(null);
    await fetchProxies();
  }

  const columns: Column<UpstreamProxy>[] = [
    {
      key: "name",
      header: "Name",
      render: (p) => (
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-sm font-semibold text-text">{p.name}</span>
          {p.is_default && (
            <span className="inline-flex items-center px-2 py-0.5 rounded-full text-[11px] font-medium border bg-primary/10 text-primary border-primary/20">
              Default
            </span>
          )}
          {!p.enabled && (
            <span className="inline-flex items-center px-2 py-0.5 rounded-full text-[11px] font-medium border bg-danger-bg text-danger border-danger/20">
              Disabled
            </span>
          )}
        </div>
      ),
    },
    {
      key: "endpoint",
      header: "Endpoint",
      render: (p) => (
        <div>
          <div className="text-sm text-text font-mono">{endpoint(p)}</div>
          <div className="text-xs text-text-dim mt-0.5">
            {SCHEME_LABELS[p.scheme] ?? p.scheme}
            {p.has_ca && " · custom CA"}
          </div>
        </div>
      ),
    },
    {
      key: "auth",
      header: "Credentials",
      render: (p) =>
        p.has_auth ? (
          <span className="text-sm text-text-muted">Set</span>
        ) : (
          <span className="text-sm text-text-dim">Not set</span>
        ),
    },
    {
      key: "no_proxy",
      header: "Bypass list",
      render: (p) =>
        p.no_proxy ? (
          <span className="text-sm text-text-muted font-mono break-all">{p.no_proxy}</span>
        ) : (
          <span className="text-sm text-text-dim">&mdash;</span>
        ),
    },
    {
      key: "on_failure",
      header: "On failure",
      render: (p) => (
        <span className="text-sm text-text-muted">
          {FAILURE_LABELS[p.on_failure] ?? p.on_failure ?? FAILURE_LABELS[DEFAULT_FAILURE]}
        </span>
      ),
    },
    {
      key: "updated_at",
      header: "Updated",
      render: (p) => <span className="text-sm text-text-muted">{timeAgo(p.updated_at)}</span>,
    },
    {
      key: "actions",
      header: "",
      align: "right",
      render: (p) => (
        <DropdownMenu
          width={150}
          items={[
            { label: "Edit", onClick: () => setEditing(p.name) },
            { label: "Delete", onClick: () => setDeleting(p), variant: "danger" },
          ]}
        />
      ),
    },
  ];

  return (
    <div className="p-8 w-full max-w-[960px]">
      <div className="flex items-start justify-between gap-4 mb-6">
        <div>
          <h2 className="text-[22px] font-semibold text-text tracking-tight mb-1">
            Upstream Proxies
          </h2>
          <p className="text-sm text-text-muted">
            Instance-level egress profiles. New services dial directly unless
            explicitly configured to use the instance default or a named profile.
          </p>
        </div>
        {rows.length > 0 && (
          <Button onClick={() => setEditing("")}>
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
            Add proxy
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
          data={rows}
          rowKey={(p) => p.name}
          emptyTitle="No upstream proxies"
          emptyDescription="Add a proxy to route a service's outbound requests through an egress hop instead of dialing the target directly."
          emptyAction={
            <Button onClick={() => setEditing("")}>
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
              Add proxy
            </Button>
          }
        />
      )}

      {editing !== null && (
        <ProxyFormModal
          initial={editing === "" ? undefined : rows.find((p) => p.name === editing)}
          onClose={() => setEditing(null)}
          onSaved={async () => {
            setEditing(null);
            await fetchProxies();
          }}
        />
      )}

      {deleting && (
        <ConfirmDeleteModal
          open
          onClose={() => setDeleting(null)}
          onConfirm={() => handleDelete(deleting)}
          title="Delete upstream proxy"
          description={
            deleting.is_default
              ? `Delete the default proxy "${deleting.name}"? Services opted into it or still inheriting it will dial directly, as will unmatched requests.`
              : `Delete "${deleting.name}"? Services referencing it must be updated before this is allowed.`
          }
          confirmLabel="Delete proxy"
          confirmValue={deleting.name}
          inputLabel={`Type the proxy name "${deleting.name}" to confirm`}
        />
      )}
    </div>
  );
}

function ProxyFormModal({
  initial,
  onClose,
  onSaved,
}: {
  initial?: UpstreamProxy;
  onClose: () => void;
  onSaved: () => Promise<void>;
}) {
  const isEdit = initial !== undefined;

  const [name, setName] = useState(initial?.name ?? "");
  const [scheme, setScheme] = useState(initial?.scheme ?? "http");
  const [host, setHost] = useState(initial?.host ?? "");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [clearAuth, setClearAuth] = useState(false);
  const [noProxy, setNoProxy] = useState(initial?.no_proxy ?? "");
  const [caPem, setCaPem] = useState("");
  const [clearCA, setClearCA] = useState(false);
  const [onFailure, setOnFailure] = useState(initial?.on_failure || DEFAULT_FAILURE);
  const [isDefault, setIsDefault] = useState(initial?.is_default ?? false);
  const [enabled, setEnabled] = useState(initial?.enabled ?? true);

  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");

  // Empty edit fields mean "keep"; each nonempty credential is an independent update.

  function validate(): string | null {
    if (!isEdit) {
      const nameError = validateName(name);
      if (nameError) return nameError;
    }
    return validateHost(host);
  }

  async function handleSubmit() {
    const validationError = validate();
    if (validationError) {
      setError(validationError);
      return;
    }

    setSaving(true);
    setError("");
    try {
      if (!isEdit) {
        await createUpstreamProxy({
          name: name.trim(),
          scheme,
          host: host.trim(),
          ...(username.trim() ? { username: username.trim() } : {}),
          ...(password ? { password } : {}),
          ...(noProxy.trim() ? { no_proxy: noProxy.trim() } : {}),
          ...(caPem.trim() ? { proxy_ca_pem: caPem.trim() } : {}),
          on_failure: onFailure,
          is_default: isDefault,
          enabled,
        });
      } else {
        const patch: UpstreamProxyPatch = {
          scheme,
          host: host.trim(),
          no_proxy: noProxy.trim(),
          on_failure: onFailure,
          is_default: isDefault,
          enabled,
        };
        if (clearAuth) {
          patch.clear_auth = true;
        } else {
          if (username.trim()) patch.username = username.trim();
          if (password) patch.password = password;
        }
        if (clearCA || caPem.trim()) {
          patch.proxy_ca_pem = clearCA ? "" : caPem.trim();
        }
        await updateUpstreamProxy(initial.name, patch);
      }
      await onSaved();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to save upstream proxy.");
    } finally {
      setSaving(false);
    }
  }

  const nameLocked = isEdit;
  const hasStoredCA = isEdit && initial.has_ca;

  return (
    <Modal
      open
      onClose={onClose}
      title={isEdit ? `Edit ${initial.name}` : "Add upstream proxy"}
      description={
        isEdit
          ? "Names are referenced by services and cannot be changed. Leave blank to keep the stored value."
          : "Assign this profile to selected services. Leave Instance default off to keep other traffic direct."
      }
      footer={
        <>
          <Button variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button onClick={handleSubmit} loading={saving}>
            {isEdit ? "Save" : "Add proxy"}
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <FormField
          label="Name"
          required
          tooltip="Referenced by a service's `upstream_proxy` field. Lowercase, digits, dots, hyphens, or underscores (max 64)."
          error={isEdit ? undefined : (validateName(name) ?? undefined)}
          helperText={nameLocked ? "Cannot be changed after creation." : undefined}
        >
          <Input
            value={name}
            onChange={(e) => setName(e.target.value)}
            disabled={nameLocked}
            placeholder="corp-egress"
            maxLength={64}
            autoFocus={!isEdit}
          />
        </FormField>

        <FormField label="Scheme" required>
          <Select value={scheme} onChange={(e) => setScheme(e.target.value)}>
            {SCHEME_OPTIONS.map((o) => (
              <option key={o.value} value={o.value}>
                {o.label}
              </option>
            ))}
          </Select>
        </FormField>

        <FormField
          label="Host"
          required
          tooltip="Host and port of the proxy, without a scheme. Example: proxy.corp.internal:3128"
        >
          <Input
            value={host}
            onChange={(e) => setHost(e.target.value)}
            placeholder="proxy.corp.internal:3128"
          />
        </FormField>

        <div className="border-t border-border pt-4">
          <div className="text-xs font-semibold uppercase tracking-wider text-text-muted mb-3">
            Credentials (optional)
          </div>
          <div className="space-y-4">
            <FormField
              label="Username"
              helperText={isEdit ? "Leave blank to keep the stored value." : undefined}
            >
              <Input
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                disabled={clearAuth}
                placeholder={isEdit ? "Leave blank to keep the stored value" : undefined}
                autoComplete="off"
              />
            </FormField>
            <FormField
              label={isEdit ? "New password" : "Password"}
              helperText={isEdit ? "Leave blank to keep the stored value." : undefined}
            >
              <Input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                disabled={clearAuth}
                placeholder={isEdit ? "Leave blank to keep the stored value" : undefined}
                autoComplete="new-password"
              />
            </FormField>
            {isEdit && initial.has_auth && (
              <div className="flex items-start justify-between gap-4">
                <div className="min-w-0">
                  <div className="text-sm font-medium text-text">Remove stored credentials</div>
                  <p className="text-sm text-text-muted mt-0.5">
                    Drops the username and password currently in use.
                  </p>
                </div>
                <div className="flex-shrink-0 pt-1">
                  <Toggle checked={clearAuth} onChange={setClearAuth} ariaLabel="Remove stored credentials" />
                </div>
              </div>
            )}
          </div>
        </div>

        <div className="border-t border-border pt-4 space-y-4">
          <FormField
            label="Bypass list (NO_PROXY)"
            tooltip="Comma-separated hosts (optionally with :port) that skip the proxy. A leading dot matches subdomains; * bypasses everything. URL paths and CIDR ranges are not supported; use the service editor's Direct option for path-specific bypass."
          >
            <Input
              value={noProxy}
              onChange={(e) => setNoProxy(e.target.value)}
              placeholder="internal.corp.com, .local, api.example.com:443"
            />
          </FormField>

          <FormField
            label={hasStoredCA ? "Replace CA certificate (PEM)" : "CA certificate (PEM)"}
            tooltip="Additional certificate authority for an HTTPS proxy. System roots remain trusted; this does not configure SOCKS TLS or target trust."
            helperText={isEdit && hasStoredCA && !clearCA ? "A certificate is configured. Pasting a new one replaces it." : undefined}
          >
            <textarea
              value={caPem}
              onChange={(e) => setCaPem(e.target.value)}
              disabled={clearCA}
              rows={4}
              spellCheck={false}
              placeholder="-----BEGIN CERTIFICATE-----"
              className="w-full px-4 py-3 bg-surface-raised border border-border rounded-lg text-text text-xs font-mono outline-none transition-colors focus:border-border-focus resize-y disabled:opacity-50 disabled:cursor-not-allowed"
            />
          </FormField>

          {hasStoredCA && (
            <div className="flex items-start justify-between gap-4">
              <div className="min-w-0">
                <div className="text-sm font-medium text-text">Remove CA certificate</div>
                <p className="text-sm text-text-muted mt-0.5">
                  Falls back to the system trust store when dialing the proxy.
                </p>
              </div>
              <div className="flex-shrink-0 pt-1">
                <Toggle checked={clearCA} onChange={setClearCA} ariaLabel="Remove CA certificate" />
              </div>
            </div>
          )}

          <FormField
            label="Unreachable proxy"
            tooltip="Fail closed rejects the request when the proxy cannot be reached, guaranteeing traffic never leaks over a direct connection. Fail open dials the target directly and logs a warning."
          >
            <Select value={onFailure} onChange={(e) => setOnFailure(e.target.value)}>
              {FAILURE_OPTIONS.map((o) => (
                <option key={o.value} value={o.value}>
                  {o.label}
                </option>
              ))}
            </Select>
          </FormField>
        </div>

        <div className="border-t border-border pt-4 space-y-4">
          <FormField
            label="Instance default"
            helperText="Off by default. On: opted-in services, older services inheriting it, unmatched requests, and server-originated calls use this profile."
          >
            <div className="flex items-center gap-3 pt-1">
              <Toggle checked={isDefault} onChange={setIsDefault} ariaLabel="Instance default" />
              <span className="text-sm text-text-muted">{isDefault ? "Default" : "Not default"}</span>
            </div>
          </FormField>

          <FormField
            label="Enabled"
            helperText="Disabled profiles are skipped; their services fall back to the default or dial directly."
          >
            <div className="flex items-center gap-3 pt-1">
              <Toggle checked={enabled} onChange={setEnabled} ariaLabel="Enabled" />
              <span className="text-sm text-text-muted">{enabled ? "Enabled" : "Disabled"}</span>
            </div>
          </FormField>
        </div>

        {error && <ErrorBanner message={error} />}
      </div>
    </Modal>
  );
}
