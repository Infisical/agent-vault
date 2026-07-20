import { useState, useEffect, useRef } from "react";
import { useRouter } from "@tanstack/react-router";
import { useVaultParams, LoadingSpinner, ErrorBanner } from "./shared";
import { InfoBanner } from "../../components/shared";
import DropdownMenu from "../../components/DropdownMenu";
import DataTable, { type Column } from "../../components/DataTable";
import Modal from "../../components/Modal";
import Button from "../../components/Button";
import Input from "../../components/Input";
import FormField from "../../components/FormField";
import Select from "../../components/Select";
import Combobox from "../../components/Combobox";
import CreatableSelect from "../../components/CreatableSelect";
import { Link } from "@tanstack/react-router";
import { apiFetch, apiRequest } from "../../lib/api";
import { OAUTH_PROVIDERS } from "../../lib/oauthProviders";

export default function CredentialsTab() {
  const router = useRouter();
  const { vaultName, vaultRole, credentialStore } = useVaultParams();
  const externalKind = credentialStore?.kind;
  const isExternal = !!externalKind;
  const pollSecs = credentialStore?.poll_interval_seconds;
  interface CredentialInfo {
    key: string;
    type?: string;
    connected_at?: string;
    last_refreshed_at?: string;
    last_refresh_error?: string;
    authorization_url?: string;
    token_url?: string;
    client_id?: string;
    scopes?: string;
    client_secret?: string;
    token_auth_method?: string;
    access_token?: string;
    refresh_token?: string;
    unavailable?: boolean;
  }
  const [credentials, setCredentials] = useState<CredentialInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [syncing, setSyncing] = useState(false);
  const [syncError, setSyncError] = useState("");

  // Add/Edit modal state
  const [modalOpen, setModalOpen] = useState(false);
  const [editingKey, setEditingKey] = useState<string | null>(null);

  // Delete confirmation modal state
  const [deleteKey, setDeleteKey] = useState<string | null>(null);
  const [deleteReferencing, setDeleteReferencing] = useState<{ host: string; name?: string }[]>([]);
  const [deleting, setDeleting] = useState(false);
  const [deleteError, setDeleteError] = useState("");

  // Service suggestions: credentials matching catalog entries that aren't used by any service
  interface CatalogTemplate { id: string; name: string; host: string; suggested_credential_key: string; }
  interface ServiceInfo { name: string; host: string; auth: { type: string; token?: string; username?: string; password?: string; key?: string; headers?: Record<string, string> }; substitutions?: { key: string; placeholder: string; in?: string[] }[]; }

  // Mirrors Service.CredentialKeys() in broker.go: auth keys + substitution keys.
  function serviceCredentialKeys(svc: ServiceInfo): string[] {
    const keys: string[] = [];
    switch (svc.auth.type) {
      case "bearer":
        if (svc.auth.token) keys.push(svc.auth.token);
        break;
      case "basic":
        if (svc.auth.username) keys.push(svc.auth.username);
        if (svc.auth.password) keys.push(svc.auth.password);
        break;
      case "api-key":
        if (svc.auth.key) keys.push(svc.auth.key);
        break;
      case "custom":
        if (svc.auth.headers) {
          for (const v of Object.values(svc.auth.headers)) {
            for (const m of v.matchAll(/\{\{\s*(\w+)\s*\}\}/g)) keys.push(m[1]);
          }
        }
        break;
    }
    if (svc.substitutions) {
      for (const sub of svc.substitutions) {
        if (sub.key) keys.push(sub.key);
      }
    }
    return keys;
  }
  const [catalog, setCatalog] = useState<CatalogTemplate[]>([]);
  const [usedCredentialKeys, setUsedCredentialKeys] = useState<Set<string>>(new Set());

  useEffect(() => {
    fetchKeys();
    fetchCatalogAndServices();
  }, []);

  async function fetchCatalogAndServices() {
    try {
      const [catalogResp, servicesResp] = await Promise.all([
        apiRequest<{ services: CatalogTemplate[] }>("/v1/service-catalog"),
        apiFetch(`/v1/vaults/${encodeURIComponent(vaultName)}/services`),
      ]);
      setCatalog(catalogResp.services ?? []);
      if (servicesResp.ok) {
        const data = await servicesResp.json();
        const services: ServiceInfo[] = data.services ?? [];
        const keys = new Set<string>();
        for (const svc of services) {
          for (const k of serviceCredentialKeys(svc)) keys.add(k);
        }
        setUsedCredentialKeys(keys);
      }
    } catch {
      // Supplementary -- degrade silently.
    }
  }

  const suggestions = credentials
    .map((cred) => {
      const template = catalog.find((t) => t.suggested_credential_key === cred.key);
      if (!template) return null;
      if (usedCredentialKeys.has(cred.key)) return null;
      return { credKey: cred.key, template };
    })
    .filter(Boolean) as { credKey: string; template: CatalogTemplate }[];

  async function fetchKeys() {
    try {
      const resp = await apiFetch(
        `/v1/credentials?vault=${encodeURIComponent(vaultName)}`
      );
      if (resp.ok) {
        const data = await resp.json();
        setCredentials(data.credentials ?? (data.keys ?? []).map((k: string) => ({ key: k })));
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

  async function handleSyncNow() {
    setSyncing(true);
    setSyncError("");
    try {
      const resp = await apiFetch(
        `/v1/vaults/${encodeURIComponent(vaultName)}/sync`,
        { method: "POST" }
      );
      if (!resp.ok) {
        const data = await resp.json().catch(() => ({}));
        setSyncError(data.error || "Sync failed.");
        return;
      }
      // Invalidate the vault subtree so SettingsTab picks up the updated
      // sync health without refetching the parent route's loaders.
      await Promise.all([
        fetchKeys(),
        router.invalidate({ filter: (m) => m.routeId.startsWith("/vaults/") }),
      ]);
    } catch {
      setSyncError("Network error.");
    } finally {
      setSyncing(false);
    }
  }

  async function openDeleteModal(key: string) {
    setDeleteKey(key);
    setDeleteError("");
    setDeleteReferencing([]);
    try {
      const resp = await apiFetch(
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

  const isAdmin = vaultRole === "admin" && !isExternal;
  const canReveal = vaultRole === "member" || vaultRole === "admin";

  // Reveal state: tracks which credential values have been fetched and are visible.
  const [revealedValues, setRevealedValues] = useState<Record<string, string>>({});
  const [revealing, setRevealing] = useState<Record<string, boolean>>({});

  async function toggleReveal(key: string) {
    if (revealedValues[key] !== undefined) {
      // Already revealed -> hide it.
      setRevealedValues((prev) => {
        const next = { ...prev };
        delete next[key];
        return next;
      });
      return;
    }
    setRevealing((prev) => ({ ...prev, [key]: true }));
    try {
      const resp = await apiFetch(
        `/v1/credentials?vault=${encodeURIComponent(vaultName)}&reveal=true&key=${encodeURIComponent(key)}`
      );
      if (resp.ok) {
        const data = await resp.json();
        const val = data.credentials?.[0]?.value ?? "";
        setRevealedValues((prev) => ({ ...prev, [key]: val }));
      }
    } catch {
      // Silently fail — user can retry.
    } finally {
      setRevealing((prev) => ({ ...prev, [key]: false }));
    }
  }

  const columns: Column<CredentialInfo>[] = [
    {
      key: "key",
      header: "Key",
      className: canReveal ? "w-1/4" : undefined,
      render: (cred) => (
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
          <span className="text-sm font-mono text-text">{cred.key}</span>
        </div>
      ),
    },
    {
      key: "type",
      header: "Type",
      className: "w-[140px]",
      render: (cred) => {
        const label =
          cred.type === "oauth" ? "OAuth" : cred.type === "dynamic" ? "Dynamic" : "Static";
        return <span className="text-sm text-text">{label}</span>;
      },
    },
    ...(canReveal
      ? [
          {
            key: "value",
            header: "Value",
            render: (cred: CredentialInfo) => (
              <div className="flex items-center gap-2">
                {cred.unavailable ? (
                  <span className="text-sm text-warning italic" title="The Infisical machine identity could not lease this dynamic secret. Grant it dynamic-secret lease permission.">
                    Unavailable (check lease permissions)
                  </span>
                ) : cred.type === "oauth" && !cred.connected_at ? (
                  <span className="text-sm text-text-dim italic">Not connected</span>
                ) : revealedValues[cred.key] !== undefined ? (
                  <span className="text-sm font-mono text-text break-all select-all">
                    {revealedValues[cred.key]}
                  </span>
                ) : (
                  <span className="text-sm text-text-dim select-none">
                    ••••••••
                  </span>
                )}
                {!cred.unavailable && (cred.type !== "oauth" || cred.connected_at) && (
                  <button
                    onClick={() => toggleReveal(cred.key)}
                    disabled={revealing[cred.key]}
                    className="ml-1 p-1 rounded text-text-dim hover:text-text transition-colors disabled:opacity-50"
                    title={revealedValues[cred.key] !== undefined ? "Hide value" : "Reveal value"}
                  >
                    {revealing[cred.key] ? (
                      <svg className="w-4 h-4 animate-spin" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83" />
                      </svg>
                    ) : revealedValues[cred.key] !== undefined ? (
                      <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94" />
                        <path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19" />
                        <line x1="1" y1="1" x2="23" y2="23" />
                      </svg>
                    ) : (
                      <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
                        <circle cx="12" cy="12" r="3" />
                      </svg>
                    )}
                  </button>
                )}
              </div>
            ),
          } as Column<CredentialInfo>,
        ]
      : []),
    ...(isAdmin
      ? [
          {
            key: "actions",
            header: "",
            align: "right" as const,
            // Dynamic credentials are leased from Infisical, not editable/deletable here.
            render: (cred: CredentialInfo) =>
              cred.type === "dynamic" ? null : (
                <DropdownMenu
                  items={[
                    { label: "Edit", onClick: () => { setEditingKey(cred.key); setModalOpen(true); } },
                    { label: "Delete", onClick: () => openDeleteModal(cred.key), variant: "danger" as const },
                  ]}
                />
              ),
          } as Column<CredentialInfo>,
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

      {suggestions.map((s) => (
        <div key={s.credKey} className="mb-4 flex items-center justify-between rounded-lg border border-warning/20 bg-warning-bg px-4 py-3">
          <span className="text-sm text-text">
            <span className="font-mono text-warning">{s.credKey}</span>
            {" "}is unused. Add <span className="font-medium">{s.template.name}</span> ({s.template.host}) as a service?
          </span>
          <Link
            to="/vaults/$name/services"
            params={{ name: vaultName }}
            search={{ preset: s.template.id }}
            className="rounded border border-border bg-surface px-2.5 py-1 text-xs text-text-muted hover:bg-surface-hover hover:text-text transition-colors whitespace-nowrap"
          >
            Add as service
          </Link>
        </div>
      ))}

      {isExternal && (
        <>
          <InfoBanner
            className={syncError ? "mb-2" : "mb-4"}
            action={
              canReveal ? (
                <Button
                  variant="secondary"
                  onClick={handleSyncNow}
                  loading={syncing}
                  disabled={syncing}
                >
                  Manual sync
                </Button>
              ) : undefined
            }
          >
            Credentials for this vault are synced read-only from{" "}
            <span className="font-medium text-text">{externalKind}</span>
            {pollSecs ? ` every ${pollSecs}s` : ""}.
          </InfoBanner>
          {syncError && <ErrorBanner message={syncError} className="mb-4" />}
        </>
      )}

      {loading ? (
        <LoadingSpinner />
      ) : error ? (
        <ErrorBanner message={error} />
      ) : (
        <DataTable
          columns={columns}
          data={credentials}
          rowKey={(cred) => cred.key}
          emptyTitle={isExternal ? "No credentials synced yet" : "No credentials stored"}
          emptyDescription={
            isExternal
              ? "Add credentials in the upstream system; they'll appear here after the next sync."
              : "Credentials will appear here when agents request and you approve them."
          }
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
                <li key={svc.name ?? svc.host}>
                  {svc.host}{svc.name ? ` (${svc.name})` : ""}
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
          editingCred={editingKey ? credentials.find((c) => c.key === editingKey) : undefined}
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

function CredentialModal({ vaultName, editingKey, editingCred, onClose, onSaved }: {
  vaultName: string; editingKey: string | null; editingCred?: { type?: string; authorization_url?: string; token_url?: string; client_id?: string; scopes?: string; client_secret?: string; token_auth_method?: string; access_token?: string; refresh_token?: string }; onClose: () => void; onSaved: () => void;
}) {
  const isEdit = editingKey !== null;
  const editType = editingCred?.type;
  const [credType, setCredType] = useState<"static" | "oauth">(editType === "oauth" ? "oauth" : "static");
  const [entries, setEntries] = useState<Entry[]>(isEdit ? [{ key: editingKey, value: "" }] : [{ key: "", value: "" }]);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [dragOver, setDragOver] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const [oauthKey, setOauthKey] = useState(editType === "oauth" && editingKey ? editingKey : "");
  const [oauthAuthUrl, setOauthAuthUrl] = useState(editingCred?.authorization_url ?? "");
  const [oauthTokenUrl, setOauthTokenUrl] = useState(editingCred?.token_url ?? "");
  const [oauthClientId, setOauthClientId] = useState(editingCred?.client_id ?? "");
  const [oauthClientSecret, setOauthClientSecret] = useState(editingCred?.client_secret ?? "");
  const [oauthTokenAuthMethod, setOauthTokenAuthMethod] = useState(editingCred?.token_auth_method ?? (editingCred?.client_secret ? "client_secret_post" : "none"));
  const [oauthScopes, setOauthScopes] = useState<string[]>(editingCred?.scopes ? editingCred.scopes.split(" ").filter(Boolean) : []);
  const [oauthAccessToken, setOauthAccessToken] = useState(editingCred?.access_token ?? "");
  const [oauthRefreshToken, setOauthRefreshToken] = useState(editingCred?.refresh_token ?? "");
  const [oauthConnecting, setOauthConnecting] = useState(false);
  const [oauthConnected, setOauthConnected] = useState(false);
  const [pollTimer, setPollTimer] = useState<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => { return () => { if (pollTimer) clearInterval(pollTimer); }; }, [pollTimer]);

  function updateEntry(i: number, field: keyof Entry, value: string) { setEntries((p) => p.map((e, j) => j === i ? { ...e, [field]: value } : e)); }
  function removeEntry(i: number) { setEntries((p) => p.filter((_, j) => j !== i)); }
  function addEntry() { setEntries((p) => [...p, { key: "", value: "" }]); }

  const [oauthMode, setOauthMode] = useState<"connect" | "upload">(!isEdit || editingCred?.authorization_url ? "connect" : "upload");
  const isTokenUpload = oauthMode === "upload";
  const canSubmitStatic = entries.every((e) => e.key.trim() && e.value.trim());
  const canSubmitOAuthConnect = !!(oauthKey.trim() && oauthTokenUrl.trim() && oauthClientId.trim() && oauthAuthUrl.trim());
  const canSubmitOAuthTokens = !!(oauthKey.trim() && (oauthAccessToken.trim() || oauthRefreshToken.trim()));
  const canSubmit = credType === "static" ? canSubmitStatic : isTokenUpload ? canSubmitOAuthTokens : oauthConnected;

  async function handleSubmit() {
    if (!canSubmit) return;
    setSaving(true); setError("");
    try {
      if (credType === "static") {
        const credentials: Record<string, string> = {};
        for (const entry of entries) credentials[entry.key.trim()] = entry.value.trim();
        const resp = await apiFetch("/v1/credentials", { method: "POST", body: JSON.stringify({ vault: vaultName, credentials }) });
        if (!resp.ok) { const d = await resp.json(); throw new Error(d.error || "Failed to save."); }
      } else if (isTokenUpload) {
        const body: Record<string, unknown> = { vault: vaultName, key: oauthKey.trim(), access_token: oauthAccessToken.trim() };
        if (oauthRefreshToken.trim()) body.refresh_token = oauthRefreshToken.trim();
        if (oauthTokenUrl.trim()) body.token_url = oauthTokenUrl.trim();
        if (oauthClientId.trim()) body.client_id = oauthClientId.trim();
        if (oauthClientSecret.trim() && oauthClientSecret !== "••••••••") body.client_secret = oauthClientSecret.trim();
        if (oauthTokenAuthMethod && oauthTokenAuthMethod !== "none") body.token_auth_method = oauthTokenAuthMethod;
        const resp = await apiFetch("/v1/credentials/oauth/tokens", { method: "POST", body: JSON.stringify(body) });
        if (!resp.ok) { const d = await resp.json(); throw new Error(d.error || "Failed to save."); }
      }
      onSaved();
    } catch (err: unknown) { setError(err instanceof Error ? err.message : "An error occurred."); } finally { setSaving(false); }
  }

  // The "custom" pinned option intentionally falls through the guard below:
  // selecting it just closes the list and leaves all fields free-form.
  const customOption = { id: "custom", label: "Custom Provider", sublabel: "Enter provider manually", pinned: true };

  const currentProvider = OAUTH_PROVIDERS.find((p) => p.authorizationUrl === oauthAuthUrl || p.tokenUrl === oauthTokenUrl);
  const scopeOptions = (currentProvider?.scopes ?? []).map((s) => ({ value: s.value, description: s.description }));

  function applyProvider(id: string) {
    const p = OAUTH_PROVIDERS.find((p) => p.id === id);
    if (!p) return;
    setOauthAuthUrl(p.authorizationUrl);
    setOauthTokenUrl(p.tokenUrl);
    setOauthTokenAuthMethod(p.tokenAuthMethod);
    if (!isEdit) setOauthKey(p.suggestedKey);
    setOauthScopes([]);
  }

  async function handleOAuthConnect() {
    setOauthConnecting(true); setError("");
    try {
      const resp = await apiFetch("/v1/credentials/oauth/connect", {
        method: "POST",
        body: JSON.stringify({ vault: vaultName, key: oauthKey.trim(), authorization_url: oauthAuthUrl.trim(), token_url: oauthTokenUrl.trim(), client_id: oauthClientId.trim(), client_secret: oauthClientSecret.trim() || undefined, scopes: oauthScopes.join(" ") || undefined, token_auth_method: oauthTokenAuthMethod === "none" ? undefined : oauthTokenAuthMethod }),
      });
      if (!resp.ok) { const d = await resp.json(); throw new Error(d.error || "Failed to start OAuth."); }
      const data = await resp.json();
      window.open(data.authorization_url, "_blank", "noopener,noreferrer");
      const timer = setInterval(async () => {
        try {
          const sr = await apiFetch(`/v1/credentials/oauth/status?vault=${encodeURIComponent(vaultName)}&key=${encodeURIComponent(oauthKey.trim())}`);
          if (sr.ok) { const sd = await sr.json(); if (sd.connected) { setOauthConnected(true); setOauthConnecting(false); clearInterval(timer); setPollTimer(null); } }
        } catch { /* ignore */ }
      }, 2500);
      setPollTimer(timer);
      setTimeout(() => { clearInterval(timer); setPollTimer(null); setOauthConnecting(false); }, 300000);
    } catch (err: unknown) { setError(err instanceof Error ? err.message : "An error occurred."); setOauthConnecting(false); }
  }

  function parseEnvContent(text: string) {
    const parsed: Entry[] = [];
    for (const line of text.split("\n")) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#")) continue;
      const eq = trimmed.indexOf("="); if (eq === -1) continue;
      const key = trimmed.slice(0, eq).trim();
      let value = trimmed.slice(eq + 1).trim();
      if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) value = value.slice(1, -1);
      if (key) parsed.push({ key, value });
    }
    return parsed;
  }

  function handleFileDrop(e: React.DragEvent) { e.preventDefault(); setDragOver(false); const f = e.dataTransfer.files[0]; if (f) readFile(f); }
  function handleFileSelect(e: React.ChangeEvent<HTMLInputElement>) { const f = e.target.files?.[0]; if (f) readFile(f); }
  function readFile(file: File) {
    const reader = new FileReader();
    reader.onload = () => { const p = parseEnvContent(reader.result as string); if (p.length > 0) setEntries((prev) => { const ne = prev.filter((e) => e.key.trim() || e.value.trim()); return ne.length > 0 ? [...ne, ...p] : p; }); };
    reader.readAsText(file);
  }

  return (
    <Modal open onClose={onClose}
      title={isEdit ? "Edit Credential" : "Add Credential"}
      description={credType === "oauth" ? "Set up an OAuth 2.0 credential. The proxy automatically refreshes the access token." : "Credentials are injected into proxied requests. Values are encrypted at rest."}
      footer={<>
        <Button variant="secondary" onClick={onClose}>Cancel</Button>
        {credType === "oauth" && !isTokenUpload && !oauthConnected ? (
          <Button onClick={handleOAuthConnect} disabled={!canSubmitOAuthConnect} loading={oauthConnecting}>
            {oauthConnecting ? "Waiting for authorization..." : "Connect"}
          </Button>
        ) : (
          <Button onClick={handleSubmit} disabled={!canSubmit} loading={saving}>
            {isEdit ? "Save" : credType === "oauth" && oauthConnected ? "Done" : "Add"}
          </Button>
        )}
      </>}
    >
      <div className="space-y-4">
        {!isEdit && (
          <div className="flex gap-1 p-1 bg-bg-secondary rounded-lg w-fit">
            <button onClick={() => setCredType("static")} className={`px-3 py-1.5 rounded-md text-sm font-medium transition-colors ${credType === "static" ? "bg-bg text-text shadow-sm" : "text-text-dim hover:text-text"}`}>Static</button>
            <button onClick={() => setCredType("oauth")} className={`px-3 py-1.5 rounded-md text-sm font-medium transition-colors ${credType === "oauth" ? "bg-bg text-text shadow-sm" : "text-text-dim hover:text-text"}`}>OAuth</button>
          </div>
        )}

        {credType === "static" ? (<>
          {entries.map((entry, i) => (
            <div key={i} className="flex gap-3 items-start">
              <div className="flex-1 min-w-0">
                <FormField label="Key"><Input placeholder="e.g. STRIPE_KEY" value={entry.key} onChange={(e) => updateEntry(i, "key", e.target.value)} readOnly={isEdit} autoFocus={!isEdit && i === 0} /></FormField>
              </div>
              <div className="flex-1 min-w-0">
                <FormField label="Value"><Input placeholder="Credential value" value={entry.value} onChange={(e) => updateEntry(i, "value", e.target.value)} type="password" autoFocus={isEdit && i === 0} onKeyDown={(e) => { if (e.key === "Enter") handleSubmit(); }} /></FormField>
              </div>
              {!isEdit && entries.length > 1 && (
                <button onClick={() => removeEntry(i)} className="mt-7 w-8 h-8 flex-shrink-0 flex items-center justify-center rounded-lg text-text-dim hover:text-danger hover:bg-danger-bg transition-colors">
                  <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" /></svg>
                </button>
              )}
            </div>
          ))}
          {!isEdit && <button onClick={addEntry} className="text-sm font-medium text-primary hover:text-primary-hover transition-colors">+ Add another</button>}
          {!isEdit && (
            <div onDragOver={(e) => { e.preventDefault(); setDragOver(true); }} onDragLeave={() => setDragOver(false)} onDrop={handleFileDrop} onClick={() => fileInputRef.current?.click()}
              className={`rounded-lg border-2 border-dashed p-6 text-center cursor-pointer transition-colors ${dragOver ? "border-primary bg-primary/5" : "border-border hover:border-text-dim"}`}>
              <input ref={fileInputRef} type="file" accept=".env,.txt" onChange={handleFileSelect} className="hidden" />
              <p className="text-sm text-text-dim">Drop a .env file here to import</p>
              <p className="text-xs text-text-dim mt-1">Parses KEY=value pairs automatically</p>
            </div>
          )}
        </>) : (<>
          {oauthConnected && (
            <div className="bg-success-bg border border-success/20 rounded-lg p-4 text-sm text-success flex items-center gap-2">
              <svg className="w-5 h-5 flex-shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" /><polyline points="22 4 12 14.01 9 11.01" /></svg>
              Connected successfully! Click "Done" to close.
            </div>
          )}
          <FormField label="Credential Key"><Input placeholder="e.g. GOOGLE, GITHUB" value={oauthKey} onChange={(e) => setOauthKey(e.target.value.toUpperCase().replace(/[^A-Z0-9_]/g, ""))} readOnly={isEdit} autoFocus={!isEdit} /></FormField>

          {!isEdit && (
            <div className="flex gap-1 p-1 bg-bg-secondary rounded-lg w-fit">
              <button onClick={() => setOauthMode("connect")} className={`px-3 py-1.5 rounded-md text-sm font-medium transition-colors ${oauthMode === "connect" ? "bg-bg text-text shadow-sm" : "text-text-dim hover:text-text"}`}>Connect with provider</button>
              <button onClick={() => setOauthMode("upload")} className={`px-3 py-1.5 rounded-md text-sm font-medium transition-colors ${oauthMode === "upload" ? "bg-bg text-text shadow-sm" : "text-text-dim hover:text-text"}`}>Paste tokens</button>
            </div>
          )}

          {!isTokenUpload ? (
            <>
              <FormField label="Authorization URL" helperText="Pick a provider or paste any URL">
                <Combobox
                  placeholder="e.g. https://accounts.google.com/o/oauth2/v2/auth"
                  value={oauthAuthUrl}
                  onChange={setOauthAuthUrl}
                  options={[...OAUTH_PROVIDERS.map((p) => ({ id: p.id, label: p.name, sublabel: p.authorizationUrl })), customOption]}
                  onSelect={applyProvider}
                />
              </FormField>
              <FormField label="Token URL"><Input placeholder="e.g. https://oauth2.googleapis.com/token" value={oauthTokenUrl} onChange={(e) => setOauthTokenUrl(e.target.value)} /></FormField>
              <div className="flex gap-3">
                <div className="flex-1"><FormField label="Client ID"><Input placeholder="OAuth app client ID" value={oauthClientId} onChange={(e) => setOauthClientId(e.target.value)} /></FormField></div>
                <div className="flex-1"><FormField label="Client Secret" helperText="Optional for public clients"><Input placeholder="OAuth app client secret" value={oauthClientSecret} onChange={(e) => setOauthClientSecret(e.target.value)} type="password" /></FormField></div>
                <div className="w-36"><FormField label="Auth Method">
                  <Select value={oauthTokenAuthMethod} onChange={(e) => setOauthTokenAuthMethod(e.target.value)}>
                    <option value="none">None</option>
                    <option value="client_secret_post">POST body</option>
                    <option value="client_secret_basic">Basic auth</option>
                  </Select>
                </FormField></div>
              </div>
              <FormField label="Scopes">
                <CreatableSelect
                  values={oauthScopes}
                  onChange={setOauthScopes}
                  options={scopeOptions}
                  placeholder="Add scopes"
                />
              </FormField>
            </>
          ) : (
            <>
              <div className="flex gap-3">
                <div className="flex-1"><FormField label="Access Token" helperText="Optional when refresh token is provided"><Input placeholder="Access token" value={oauthAccessToken} onChange={(e) => setOauthAccessToken(e.target.value)} type="password" /></FormField></div>
                <div className="flex-1"><FormField label="Refresh Token" helperText="Validated immediately on save"><Input placeholder="Refresh token" value={oauthRefreshToken} onChange={(e) => setOauthRefreshToken(e.target.value)} type="password" /></FormField></div>
              </div>
              <FormField label="Token URL" helperText="Required for refresh. Pick a provider or paste any URL.">
                <Combobox
                  placeholder="e.g. https://oauth2.googleapis.com/token"
                  value={oauthTokenUrl}
                  onChange={setOauthTokenUrl}
                  options={[...OAUTH_PROVIDERS.map((p) => ({ id: p.id, label: p.name, sublabel: p.tokenUrl })), customOption]}
                  onSelect={applyProvider}
                />
              </FormField>
              <div className="flex gap-3">
                <div className="flex-1"><FormField label="Client ID" helperText="Required for refresh"><Input placeholder="OAuth app client ID" value={oauthClientId} onChange={(e) => setOauthClientId(e.target.value)} /></FormField></div>
                <div className="flex-1"><FormField label="Client Secret" helperText="Optional"><Input placeholder="OAuth app client secret" value={oauthClientSecret} onChange={(e) => setOauthClientSecret(e.target.value)} type="password" /></FormField></div>
                <div className="w-36"><FormField label="Auth Method">
                  <Select value={oauthTokenAuthMethod} onChange={(e) => setOauthTokenAuthMethod(e.target.value)}>
                    <option value="none">None</option>
                    <option value="client_secret_post">POST body</option>
                    <option value="client_secret_basic">Basic auth</option>
                  </Select>
                </FormField></div>
              </div>
            </>
          )}
        </>)}
        {error && <ErrorBanner message={error} />}
      </div>
    </Modal>
  );
}
