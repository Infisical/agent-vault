import { useEffect, useMemo, useState } from "react";

import { apiFetch } from "../lib/api";
import {
  canEditAcquisitionPolicy,
  normalizeHandlerCatalog,
  normalizeVaultAcquisitionPolicy,
  serializeAcquisitionPolicy,
  type VaultAcquisitionHandlerSummary,
  type VaultAcquisitionPolicy,
} from "../lib/acquisition";
import Button from "./Button";
import Sheet from "./Sheet";
import { ErrorBanner } from "./shared";

const emptyPolicy: VaultAcquisitionPolicy = {
  enabled_handlers: [],
  browser_dom_enabled: false,
};

export default function AcquisitionPolicyPanel({
  vaultName,
  canManage,
}: {
  vaultName: string;
  canManage: boolean;
}) {
  const [policy, setPolicy] = useState<VaultAcquisitionPolicy | null>(null);
  const [handlers, setHandlers] = useState<VaultAcquisitionHandlerSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [policyStale, setPolicyStale] = useState(false);
  const [catalogReady, setCatalogReady] = useState(false);
  const [editing, setEditing] = useState(false);

  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    setError("");
    setCatalogReady(false);
    (async () => {
      try {
        const policyResp = await apiFetch(
          `/v1/vaults/${encodeURIComponent(vaultName)}/acquisition-policy`,
          { signal: controller.signal },
        );
        if (!policyResp.ok) {
          const body = await policyResp.json().catch(() => ({}));
          throw new Error(body.error || "Failed to load acquisition policy");
        }
        const normalizedPolicy = normalizeVaultAcquisitionPolicy(await policyResp.json());
        if (!normalizedPolicy) throw new Error("Invalid acquisition policy response");
        setPolicy(normalizedPolicy);
        setPolicyStale(policyResp.headers.get("X-Agent-Vault-Policy-Stale") === "true");

        if (canManage) {
          const catalogResp = await apiFetch(
            `/v1/vaults/${encodeURIComponent(vaultName)}/acquisition-handlers`,
            { signal: controller.signal },
          );
          if (!catalogResp.ok) {
            const body = await catalogResp.json().catch(() => ({}));
            throw new Error(body.error || "Failed to load acquisition handlers");
          }
          const catalog = normalizeHandlerCatalog(await catalogResp.json());
          if (!catalog) throw new Error("Invalid acquisition handler catalog response");
          setHandlers(catalog);
          setCatalogReady(true);
        }
      } catch (err) {
        if (!controller.signal.aborted) {
          setError(err instanceof Error ? err.message : "Failed to load acquisition policy");
        }
      } finally {
        if (!controller.signal.aborted) setLoading(false);
      }
    })();
    return () => controller.abort();
  }, [vaultName, canManage]);

  const canEdit = canEditAcquisitionPolicy({
    canManage,
    loading,
    policyLoaded: policy !== null,
    catalogReady,
  });

  return (
    <section className="mb-8">
      <div className="relative border border-border rounded-xl bg-surface p-5">
        {canManage && (
          <Button
            variant="secondary"
            onClick={() => setEditing(true)}
            disabled={!canEdit}
            className="absolute top-4 right-4 !px-3 !py-1.5"
          >
            Manage
          </Button>
        )}
        <h3 className="text-sm font-semibold text-text mb-1">Credential acquisition</h3>
        <p className="text-sm text-text-muted mb-5 max-w-[680px]">
          Allow only registered provider handlers to satisfy proposal credential slots. Provider output is encrypted by Agent Vault and is never shown here.
        </p>
        <div className="grid grid-cols-2 gap-6 pr-24">
          <PolicyValue
            label="Enabled handlers"
            value={loading ? "—" : String(policy?.enabled_handlers.length ?? 0)}
          />
          <PolicyValue
            label="Browser capture"
            value={loading ? "—" : "Unavailable in V1"}
          />
        </div>
        {error && <ErrorBanner message={error} className="mt-4" />}
        {policyStale && !error && (
          <ErrorBanner
            message="This policy references an unavailable handler. Open Manage and remove the unavailable entry before starting new acquisitions."
            className="mt-4"
          />
        )}
      </div>

      {policy && (
        <AcquisitionPolicySheet
          open={editing}
          onClose={() => setEditing(false)}
          vaultName={vaultName}
          policy={policy}
          handlers={handlers}
          onSaved={setPolicy}
        />
      )}
    </section>
  );
}

function PolicyValue({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <div className="text-xs font-semibold uppercase tracking-wider text-text-muted mb-2">{label}</div>
      <div className="text-sm font-mono text-text">{value}</div>
    </div>
  );
}

function AcquisitionPolicySheet({
  open,
  onClose,
  vaultName,
  policy,
  handlers,
  onSaved,
}: {
  open: boolean;
  onClose: () => void;
  vaultName: string;
  policy: VaultAcquisitionPolicy;
  handlers: VaultAcquisitionHandlerSummary[];
  onSaved: (policy: VaultAcquisitionPolicy) => void;
}) {
  const [draft, setDraft] = useState<VaultAcquisitionPolicy>(emptyPolicy);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    if (!open) return;
    setDraft({
      enabled_handlers: policy.enabled_handlers.slice(),
      browser_dom_enabled: false,
    });
    setError("");
  }, [open, policy]);

  const changed = useMemo(() => {
    const current = [...policy.enabled_handlers].sort();
    const next = [...draft.enabled_handlers].sort();
    return current.length !== next.length || current.some((id, index) => id !== next[index]);
  }, [draft, policy]);
  const unavailableHandlerIDs = draft.enabled_handlers.filter(
    (id) => !handlers.some((handler) => handler.id === id),
  );

  function toggleHandler(id: string, enabled: boolean) {
    setDraft((current) => ({
      ...current,
      enabled_handlers: enabled
        ? [...new Set([...current.enabled_handlers, id])].sort()
        : current.enabled_handlers.filter((candidate) => candidate !== id),
    }));
  }

  async function save() {
    setSaving(true);
    setError("");
    try {
      const resp = await apiFetch(
        `/v1/vaults/${encodeURIComponent(vaultName)}/acquisition-policy`,
        { method: "PATCH", body: serializeAcquisitionPolicy(draft) },
      );
      if (!resp.ok) {
        const body = await resp.json().catch(() => ({}));
        throw new Error(body.error || "Failed to save acquisition policy");
      }
      const saved = normalizeVaultAcquisitionPolicy(await resp.json());
      if (!saved) throw new Error("Invalid acquisition policy response");
      onSaved(saved);
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to save acquisition policy");
    } finally {
      setSaving(false);
    }
  }

  return (
    <Sheet
      open={open}
      onClose={onClose}
      eyebrow="Vault policy"
      title="Credential acquisition"
      footer={
        <>
          <Button variant="secondary" onClick={onClose}>Cancel</Button>
          <Button onClick={save} loading={saving} disabled={!changed}>Save policy</Button>
        </>
      }
    >
      <div className="space-y-5">
        <div>
          <h4 className="text-sm font-semibold text-text mb-2">Registered handlers</h4>
          {handlers.length === 0 ? (
            unavailableHandlerIDs.length === 0 && (
              <p className="text-sm text-text-muted">No verified handlers are available for this vault.</p>
            )
          ) : (
            <div className="space-y-2">
              {handlers.map((handler) => {
                const checked = draft.enabled_handlers.includes(handler.id);
                return (
                  <label key={handler.id} className="flex items-start gap-3 rounded-lg border border-border p-3 cursor-pointer">
                    <input
                      type="checkbox"
                      className="mt-1"
                      checked={checked}
                      onChange={(event) => toggleHandler(handler.id, event.target.checked)}
                    />
                    <span className="min-w-0">
                      <span className="block text-sm font-mono text-text">{handler.id}</span>
                      <span className="block text-xs text-text-muted mt-1">
                        Keys: {handler.allowed_keys.join(", ") || "none"} · Profiles: {handler.allowed_profiles.join(", ") || "none"}
                      </span>
                    </span>
                  </label>
                );
              })}
            </div>
          )}
          {unavailableHandlerIDs.length > 0 && (
            <div className="space-y-2 mt-2">
              {unavailableHandlerIDs.map((id) => (
                <label key={id} className="flex items-start gap-3 rounded-lg border border-danger/20 p-3 cursor-pointer">
                  <input
                    type="checkbox"
                    className="mt-1"
                    checked
                    onChange={() => toggleHandler(id, false)}
                  />
                  <span>
                    <span className="block text-sm font-mono text-text">{id}</span>
                    <span className="block text-xs text-danger mt-1">Unavailable — clear this selection to repair the policy.</span>
                  </span>
                </label>
              ))}
            </div>
          )}
        </div>

        <div className="border-t border-border pt-5">
          <div>
            <h4 className="text-sm font-semibold text-text">Browser credential capture is unavailable</h4>
            <p className="text-xs text-text-muted mt-1 leading-relaxed">
              V1 permanently rejects browser_dom handlers. Proposals cannot supply selectors, page text, screenshots, cookies, or credentials. Any future browser capture requires a new security review and an explicit product change.
            </p>
          </div>
        </div>

        {error && <ErrorBanner message={error} />}
      </div>
    </Sheet>
  );
}
