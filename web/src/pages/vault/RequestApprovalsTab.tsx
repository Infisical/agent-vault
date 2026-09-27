import { useEffect, useState } from "react";
import { apiFetch } from "../../lib/api";
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
  const [items, setItems] = useState<PendingRequest[]>([]);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  const base = `/v1/vaults/${encodeURIComponent(vaultName)}/request-approvals`;

  async function refresh() {
    try {
      const response = await apiFetch(base);
      if (!response.ok) throw new Error((await response.json()).error || "Could not load requests");
      const data = await response.json();
      setItems(data.approvals ?? []);
      setError("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not load requests");
    }
  }

  useEffect(() => {
    refresh();
    const interval = setInterval(refresh, 2_000);
    return () => clearInterval(interval);
  }, [vaultName]);

  async function decide(item: PendingRequest, approve: boolean) {
    if (approve && !window.confirm(`Allow this one ${item.method} request to ${item.host}${item.path}? Request query, headers, and body are not shown.`)) return;
    setBusy(item.id);
    try {
      const response = await apiFetch(`${base}/${encodeURIComponent(item.id)}/${approve ? "approve" : "reject"}`, { method: "POST" });
      if (!response.ok) throw new Error((await response.json()).error || "Decision failed");
      setItems((current) => current.filter((candidate) => candidate.id !== item.id));
      setError("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Decision failed");
      await refresh();
    } finally {
      setBusy(null);
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
