import { useEffect, useRef, useState } from "react";
import { apiFetch, isAbortError } from "../../lib/api";
import { useVaultParams, ErrorBanner } from "./shared";
import Button from "../../components/Button";

interface PendingRequest {
  id: string;
  service: string;
  actor_id: string;
  method: string;
  host: string;
  path: string;
  body_bytes: number;
  created_at: string;
  expires_at: string;
}

export default function RequestApprovalsTab() {
  const { vaultName } = useVaultParams();
  const currentVault = useRef(vaultName);
  currentVault.current = vaultName;
  const [snapshot, setSnapshot] = useState<{ vault: string; items: PendingRequest[] }>({ vault: vaultName, items: [] });
  const items = snapshot.vault === vaultName ? snapshot.items : [];
  const [error, setError] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  const base = `/v1/vaults/${encodeURIComponent(vaultName)}/request-approvals`;

  useEffect(() => {
    let active = true;
    const controllers = new Set<AbortController>();
    setSnapshot({ vault: vaultName, items: [] });
    setError("");
    setBusy(null);
    async function refresh() {
      const controller = new AbortController();
      controllers.add(controller);
      try {
        const response = await apiFetch(base, { signal: controller.signal });
        if (!response.ok) throw new Error((await response.json()).error || "Could not load requests");
        const data = await response.json();
        if (active && currentVault.current === vaultName) {
          setSnapshot({ vault: vaultName, items: data.approvals ?? [] });
          setError("");
        }
      } catch (err) {
        if (active && currentVault.current === vaultName && !isAbortError(err)) {
          setError(err instanceof Error ? err.message : "Could not load requests");
        }
      } finally {
        controllers.delete(controller);
      }
    }
    refresh();
    const interval = setInterval(refresh, 2_000);
    return () => {
      active = false;
      clearInterval(interval);
      controllers.forEach((controller) => controller.abort());
    };
  }, [vaultName]);

  async function decide(item: PendingRequest, approve: boolean) {
    if (approve && !window.confirm(`Allow this one ${item.method} request to ${item.host}${item.path}? Request query, headers, and body are not shown.`)) return;
    setBusy(item.id);
    try {
      const response = await apiFetch(`${base}/${encodeURIComponent(item.id)}/${approve ? "approve" : "reject"}`, { method: "POST" });
      if (!response.ok) throw new Error((await response.json()).error || "Decision failed");
      if (currentVault.current === vaultName) {
        setSnapshot((current) => ({ vault: vaultName, items: current.items.filter((candidate) => candidate.id !== item.id) }));
        setError("");
      }
    } catch (err) {
      if (currentVault.current === vaultName) setError(err instanceof Error ? err.message : "Decision failed");
    } finally {
      if (currentVault.current === vaultName) setBusy(null);
    }
  }

  return <div className="p-8 w-full max-w-[960px]">
    <h2 className="text-[22px] font-semibold text-text tracking-tight mb-1">Request approvals</h2>
    <p className="text-sm text-text-muted mb-6">Each decision releases only the request shown here. Unanswered requests expire after two minutes.</p>
    {error && <ErrorBanner message={error} />}
    {items.length === 0 ? <div className="rounded-lg border border-border bg-surface p-6 text-sm text-text-muted">No requests waiting for approval.</div> :
      <div className="space-y-3">{items.map((item) => <div key={item.id} className="rounded-lg border border-border bg-surface p-5">
        <div className="font-mono text-sm text-text break-all">{item.method} {item.host}{item.path}</div>
        <div className="mt-2 text-xs text-text-muted">Service: {item.service} · Agent: {item.actor_id} · Body: {item.body_bytes < 0 ? "unknown size" : `${item.body_bytes} bytes`} · Expires: {new Date(item.expires_at).toLocaleTimeString()}</div>
        <p className="mt-2 text-xs text-warning">Query parameters, headers, and body content are not displayed. Approve only if you trust this action.</p>
        <div className="mt-4 flex gap-2">
          <Button onClick={() => decide(item, true)} disabled={busy !== null}>Approve once</Button>
          <Button variant="secondary" onClick={() => decide(item, false)} disabled={busy !== null}>Reject</Button>
        </div>
      </div>)}</div>}
  </div>;
}
