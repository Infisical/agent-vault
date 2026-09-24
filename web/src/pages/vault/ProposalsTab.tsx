import { useState, useEffect, useRef, useMemo, type FormEvent } from "react";
import { useVaultParams, StatusBadge, LoadingSpinner, ErrorBanner, timeAgo } from "./shared";
import { InfoBanner } from "../../components/shared";
import DataTable, { type Column } from "../../components/DataTable";
import Modal from "../../components/Modal";
import Button from "../../components/Button";
import Input from "../../components/Input";
import FormField from "../../components/FormField";
import ProposalPreview, { parseServices, parseCredentials, type CredentialSlot } from "../../components/ProposalPreview";
import { apiFetch, isAbortError } from "../../lib/api";
import {
  acquisitionCancelRequest,
  acquisitionStartRequest,
  acquisitionStatusPath,
  buildApprovalCredentialPayload,
  isAcquisitionActive,
  normalizeAcquisitionRecord,
  pollAcquisitionStatuses,
  type AcquisitionDeclaration,
  type ProposalAcquisition,
} from "../../lib/acquisition";

interface Proposal {
  id: number;
  status: string;
  message: string;
  user_message?: string;
  services_json?: string;
  credentials_json?: string;
  review_note?: string;
  reviewed_at?: string;
  created_at: string;
}

export default function ProposalsTab() {
  const { vaultName, credentialStore } = useVaultParams();
  const [proposals, setProposals] = useState<Proposal[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [filter, setFilter] = useState<"pending" | "all">("pending");
  const [pendingCount, setPendingCount] = useState(0);
  const [totalCount, setTotalCount] = useState<number | null>(null);
  const [selected, setSelected] = useState<Proposal | null>(null);

  useEffect(() => {
    fetchProposals();
  }, [filter]);

  const abortRef = useRef<AbortController | null>(null);

  async function fetchProposals() {
    // Abort any in-flight fetch to prevent stale state updates.
    abortRef.current?.abort();
    const controller = new AbortController();
    abortRef.current = controller;

    setLoading(true);
    setError("");
    try {
      const qs = filter === "pending" ? "&status=pending" : "";
      const resp = await apiFetch(
        `/v1/admin/proposals?vault=${encodeURIComponent(vaultName)}${qs}`,
        { signal: controller.signal }
      );
      if (!resp.ok) {
        const data = await resp.json();
        setError(data.error || "Failed to load requests.");
        return;
      }

      const data = await resp.json();
      setProposals(data.proposals ?? []);
      if (filter === "pending") {
        setPendingCount((data.proposals ?? []).length);
      } else {
        setTotalCount((data.proposals ?? []).length);
      }

      // Fetch the complementary count in the background.
      const countQs = filter !== "pending" ? "&status=pending" : "";
      const countResp = await apiFetch(
        `/v1/admin/proposals?vault=${encodeURIComponent(vaultName)}${countQs}`,
        { signal: controller.signal }
      );
      if (countResp.ok) {
        const countData = await countResp.json();
        if (filter !== "pending") {
          setPendingCount((countData.proposals ?? []).length);
        } else {
          setTotalCount((countData.proposals ?? []).length);
        }
      }
    } catch (err) {
      if (isAbortError(err)) return;
      setError("Network error.");
    } finally {
      setLoading(false);
    }
  }

  const columns: Column<Proposal>[] = [
    {
      key: "request",
      header: "Request",
      render: (cs) => <ProposalCell proposal={cs} />,
    },
    {
      key: "agent",
      header: "Agent",
      render: () => <span className="text-sm text-text-muted">Agent</span>,
    },
    {
      key: "status",
      header: "Status",
      render: (cs) => <StatusBadge status={cs.status} />,
    },
    {
      key: "received",
      header: "Received",
      render: (cs) => (
        <span className="text-sm text-text-muted">
          {timeAgo(cs.created_at)}
        </span>
      ),
    },
  ];

  return (
    <div className="p-8 w-full max-w-[960px]">
      <div className="mb-6">
        <h2 className="text-[22px] font-semibold text-text tracking-tight mb-1">
          Proposals
        </h2>
        <p className="text-sm text-text-muted">
          Review and approve access requests proposed by agents.
        </p>
      </div>

      {credentialStore && (
        <InfoBanner className="mb-6">
          Proposals on this vault may include service changes only. Credential
          additions are rejected. Manage credentials in{" "}
          <span className="font-medium text-text">{credentialStore.kind}</span>.
        </InfoBanner>
      )}

      {/* Filter tabs */}
      <div className="flex mb-6 border border-border rounded-lg overflow-hidden w-fit">
        <button
          onClick={() => setFilter("pending")}
          className={`px-5 py-2.5 text-sm font-medium transition-colors ${
            filter === "pending"
              ? "bg-surface text-text"
              : "bg-bg text-text-muted hover:text-text"
          }`}
        >
          Needs action
          {pendingCount > 0 && (
            <span className="ml-2 inline-flex items-center justify-center min-w-[20px] h-5 px-1.5 rounded-full text-xs font-semibold bg-warning-bg text-warning border border-warning/20">
              {pendingCount}
            </span>
          )}
        </button>
        <button
          onClick={() => setFilter("all")}
          className={`px-5 py-2.5 text-sm font-medium transition-colors border-l border-border ${
            filter === "all"
              ? "bg-surface text-text"
              : "bg-bg text-text-muted hover:text-text"
          }`}
        >
          All
        </button>
      </div>

      {loading ? (
        <LoadingSpinner />
      ) : error ? (
        <ErrorBanner message={error} />
      ) : (
        <DataTable
          columns={columns}
          data={proposals}
          rowKey={(cs) => cs.id}
          onRowClick={(cs) => setSelected(cs)}
          emptyTitle={totalCount === 0 ? "No proposals yet" : "Nothing needs your attention"}
          emptyDescription={
            totalCount === 0 ? (
              <div className="flex flex-col items-center">
                <span>Connect an agent to get started. It will request access to services and credentials to be approved here.</span>
                <a
                  href="https://docs.agent-vault.dev/first-proposal"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-1.5 mt-4 px-4 py-2 text-sm font-medium text-text border border-border rounded-lg hover:bg-bg transition-colors"
                >
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6" /><polyline points="15 3 21 3 21 9" /><line x1="10" y1="14" x2="21" y2="3" /></svg>
                  Read the docs
                </a>
              </div>
            ) : (
              "Agents will request access here when they need it."
            )
          }
        />
      )}

      {selected && (
        <ProposalModal
          proposal={selected}
          vaultName={vaultName}
          onClose={() => setSelected(null)}
          onAction={() => {
            setSelected(null);
            fetchProposals();
          }}
        />
      )}
    </div>
  );
}

// --- Proposal Detail Modal ---

function ProposalModal({
  proposal,
  vaultName,
  onClose,
  onAction,
}: {
  proposal: Proposal;
  vaultName: string;
  onClose: () => void;
  onAction: () => void;
}) {
  const services = parseServices(proposal.services_json);
  const credentials = parseCredentials(proposal.credentials_json);
  const isPending = proposal.status === "pending";

  const previewData = {
    proposal_id: proposal.id,
    vault: vaultName,
    status: proposal.status,
    message: proposal.message,
    user_message: proposal.user_message,
    services,
    credentials,
    created_at: proposal.created_at,
  };

  const [credentialValues, setCredentialValues] = useState<Record<string, string>>({});
  const [formError, setFormError] = useState("");
  const [submitting, setSubmitting] = useState(false);

  // OAuth state
  const [oauthFields, setOauthFields] = useState<Record<string, Record<string, string>>>({});
  const [oauthConnected, setOauthConnected] = useState<Record<string, boolean>>({});
  const [oauthConnecting, setOauthConnecting] = useState<Record<string, boolean>>({});
  const pollTimers = useRef<Record<string, ReturnType<typeof setInterval>>>({});
  useEffect(() => { return () => { Object.values(pollTimers.current).forEach(clearInterval); }; }, []);

  // Provider-acquisition state is metadata only. Responses are normalized into
  // an allowlisted shape before they enter React state.
  const [acquisitionJobs, setAcquisitionJobs] = useState<ProposalAcquisition[]>([]);
  const [acquisitionError, setAcquisitionError] = useState("");
  const [acquisitionActionKey, setAcquisitionActionKey] = useState("");
  const [acquisitionPollGeneration, setAcquisitionPollGeneration] = useState(0);

  useEffect(() => {
    const controller = new AbortController();

    void pollAcquisitionStatuses({
      signal: controller.signal,
      fetchStatus: async (signal) => {
        const resp = await apiFetch(acquisitionStatusPath(vaultName, proposal.id), {
          signal,
        });
        if (!resp.ok) {
          const body = await resp.json().catch(() => ({}));
          throw new Error(body.error || "Failed to load acquisition status");
        }
        return resp.json();
      },
      onJobs: (jobs) => {
        setAcquisitionJobs(jobs);
        setAcquisitionError("");
      },
      onError: (err) => setAcquisitionError(err.message),
    });
    return () => controller.abort();
  }, [proposal.id, vaultName, acquisitionPollGeneration]);

  const acquisitionByKey = useMemo(() => {
    const result = new Map<string, ProposalAcquisition>();
    for (const job of acquisitionJobs) {
      const current = result.get(job.key);
      if (!current || job.attempt > current.attempt) result.set(job.key, job);
    }
    return result;
  }, [acquisitionJobs]);

  const setCredentials = credentials.filter(
    (s: CredentialSlot) => s.action === "set" && !s.has_value
  );
  const allFilled = setCredentials.every((s: CredentialSlot) => {
    if (acquisitionByKey.get(s.key)?.state === "succeeded") return true;
    if (s.type === "oauth") {
      const fields = oauthFields[s.key] ?? {};
      const isUpload = !s.oauth?.authorization_url && !fields.authorization_url;
      if (isUpload) return (fields.access_token ?? "").trim() !== "" || (fields.refresh_token ?? "").trim() !== "";
      return oauthConnected[s.key] === true;
    }
    return (credentialValues[s.key] ?? "").trim() !== "";
  });

  async function startAcquisition(cred: CredentialSlot) {
    if (!cred.acquisition) return;
    setAcquisitionActionKey(cred.key);
    setAcquisitionError("");
    const request = acquisitionStartRequest(
      vaultName,
      proposal.id,
      cred.key,
      cred.acquisition.handler,
      cred.acquisition.profile,
    );
    try {
      const resp = await apiFetch(request.path, request.init);
      if (!resp.ok) {
        const body = await resp.json().catch(() => ({}));
        throw new Error(body.error || "Failed to start credential acquisition");
      }
      const job = normalizeAcquisitionRecord(await resp.json());
      if (!job) throw new Error("Invalid acquisition response");
      setAcquisitionJobs((current) => [job, ...current.filter((item) => item.id !== job.id)]);
      setAcquisitionPollGeneration((value) => value + 1);
    } catch (err) {
      setAcquisitionError(err instanceof Error ? err.message : "Failed to start credential acquisition");
    } finally {
      setAcquisitionActionKey("");
    }
  }

  async function cancelAcquisition(cred: CredentialSlot) {
    setAcquisitionActionKey(cred.key);
    setAcquisitionError("");
    const request = acquisitionCancelRequest(vaultName, proposal.id, cred.key);
    try {
      const resp = await apiFetch(request.path, request.init);
      if (!resp.ok) {
        const body = await resp.json().catch(() => ({}));
        throw new Error(body.error || "Failed to cancel credential acquisition");
      }
      const job = normalizeAcquisitionRecord(await resp.json());
      if (!job) throw new Error("Invalid acquisition response");
      setAcquisitionJobs((current) => [job, ...current.filter((item) => item.id !== job.id)]);
      setAcquisitionPollGeneration((value) => value + 1);
    } catch (err) {
      setAcquisitionError(err instanceof Error ? err.message : "Failed to cancel credential acquisition");
    } finally {
      setAcquisitionActionKey("");
    }
  }

  function updateOauthField(credKey: string, field: string, value: string) {
    setOauthFields((prev) => ({ ...prev, [credKey]: { ...(prev[credKey] ?? {}), [field]: value } }));
  }

  async function handleOAuthConnect(credKey: string) {
    const fields = oauthFields[credKey] ?? {};
    const oauth = setCredentials.find((c: CredentialSlot) => c.key === credKey)?.oauth;
    setOauthConnecting((prev) => ({ ...prev, [credKey]: true }));
    setFormError("");
    try {
      const resp = await apiFetch("/v1/credentials/oauth/connect", {
        method: "POST",
        body: JSON.stringify({
          vault: vaultName, key: credKey,
          authorization_url: fields.authorization_url || oauth?.authorization_url || "",
          token_url: fields.token_url || oauth?.token_url || "",
          client_id: fields.client_id || "", client_secret: fields.client_secret || "",
          scopes: fields.scopes || oauth?.scopes || "",
        }),
      });
      if (!resp.ok) { const d = await resp.json(); throw new Error(d.error || "Failed to start OAuth."); }
      const data = await resp.json();
      window.open(data.authorization_url, "_blank", "noopener,noreferrer");
      const timer = setInterval(async () => {
        try {
          const sr = await apiFetch(`/v1/credentials/oauth/status?vault=${encodeURIComponent(vaultName)}&key=${encodeURIComponent(credKey)}`);
          if (sr.ok) { const sd = await sr.json(); if (sd.connected) { setOauthConnected((p) => ({ ...p, [credKey]: true })); setOauthConnecting((p) => ({ ...p, [credKey]: false })); clearInterval(timer); delete pollTimers.current[credKey]; } }
        } catch { /* ignore */ }
      }, 2500);
      pollTimers.current[credKey] = timer;
      setTimeout(() => { clearInterval(timer); delete pollTimers.current[credKey]; setOauthConnecting((p) => ({ ...p, [credKey]: false })); }, 300000);
    } catch (err: unknown) { setFormError(err instanceof Error ? err.message : "An error occurred."); setOauthConnecting((p) => ({ ...p, [credKey]: false })); }
  }

  async function handleOAuthTokenUpload(credKey: string) {
    const fields = oauthFields[credKey] ?? {};
    const oauth = setCredentials.find((c: CredentialSlot) => c.key === credKey)?.oauth;
    setSubmitting(true); setFormError("");
    try {
      const body: Record<string, unknown> = { vault: vaultName, key: credKey };
      if (fields.access_token?.trim()) body.access_token = fields.access_token.trim();
      if (fields.refresh_token?.trim()) body.refresh_token = fields.refresh_token.trim();
      body.token_url = fields.token_url || oauth?.token_url || "";
      body.client_id = fields.client_id || oauth?.client_id || "";
      const resp = await apiFetch("/v1/credentials/oauth/tokens", { method: "POST", body: JSON.stringify(body) });
      if (!resp.ok) { const d = await resp.json(); throw new Error(d.error || "Failed to upload tokens."); }
      setOauthConnected((p) => ({ ...p, [credKey]: true }));
    } catch (err: unknown) { setFormError(err instanceof Error ? err.message : "An error occurred."); } finally { setSubmitting(false); }
  }

  async function handleApprove(e: FormEvent) {
    e.preventDefault();
    setFormError("");
    setSubmitting(true);

    const credentialPayload = buildApprovalCredentialPayload(
      setCredentials,
      credentialValues,
      acquisitionByKey,
    );

    try {
      const resp = await apiFetch(
        `/v1/admin/proposals/${proposal.id}/approve`,
        {
          method: "POST",
          body: JSON.stringify({ vault: vaultName, credentials: credentialPayload }),
        }
      );
      if (resp.ok) {
        onAction();
      } else {
        const data = await resp.json();
        setFormError(data.error || "Failed to approve.");
        setSubmitting(false);
      }
    } catch {
      setFormError("Network error.");
      setSubmitting(false);
    }
  }

  async function handleReject() {
    setFormError("");
    setSubmitting(true);

    try {
      const resp = await apiFetch(
        `/v1/admin/proposals/${proposal.id}/reject`,
        {
          method: "POST",
          body: JSON.stringify({ vault: vaultName, reason: "Rejected via dashboard" }),
        }
      );
      if (resp.ok) {
        onAction();
      } else {
        const data = await resp.json();
        setFormError(data.error || "Failed to reject.");
        setSubmitting(false);
      }
    } catch {
      setFormError("Network error.");
      setSubmitting(false);
    }
  }

  const footer = isPending ? (
    <>
      <Button variant="secondary" onClick={handleReject} disabled={submitting}>
        Deny
      </Button>
      <Button
        onClick={handleApprove}
        disabled={submitting || !allFilled}
        loading={submitting}
      >
        Allow
      </Button>
    </>
  ) : undefined;

  return (
    <Modal open onClose={onClose} title="Request details" description="Review the access and credentials requested by an agent." footer={footer}>
      <ProposalPreview data={previewData} />

      {isPending && setCredentials.length > 0 && (
        <form onSubmit={handleApprove} className="mt-5 space-y-4">
          {setCredentials.map((cred: CredentialSlot) => {
            const acquisitionJob = acquisitionByKey.get(cred.key);
            const acquisitionSatisfied = acquisitionJob?.state === "succeeded";
            if (cred.type === "oauth") {
              const fields = oauthFields[cred.key] ?? {};
              const hasAuthUrl = !!(cred.oauth?.authorization_url || fields.authorization_url);
              const connected = oauthConnected[cred.key];
              const connecting = oauthConnecting[cred.key];
              return (
                <div key={cred.key} className="rounded-lg border border-border p-4 space-y-3">
                  <div className="flex items-center justify-between">
                    <div>
                      <span className="text-sm font-semibold text-text">{cred.key}</span>
                      {cred.description && <span className="text-sm text-text-muted ml-2">{cred.description}</span>}
                    </div>
                    <span className="text-xs text-text-dim">
                      {connected ? "Connected" : "OAuth"}
                    </span>
                  </div>
                  {cred.acquisition && (
                    <CredentialAcquisitionControl
                      declaration={cred.acquisition}
                      job={acquisitionJob}
                      busy={acquisitionActionKey === cred.key}
                      onStart={() => startAcquisition(cred)}
                      onCancel={() => cancelAcquisition(cred)}
                    />
                  )}
                  {acquisitionSatisfied ? (
                    <p className="text-sm text-success">Credential acquired and encrypted for this proposal.</p>
                  ) : connected ? (
                    <p className="text-sm text-success">Connected successfully.</p>
                  ) : (
                    <>
                      {cred.obtain_instructions && <p className="text-sm text-text-muted">{cred.obtain_instructions}</p>}
                      {hasAuthUrl ? (
                        <>
                          <div className="space-y-1 text-xs text-text-dim">
                            <p><span className="text-text-muted">Provider:</span> {cred.oauth?.authorization_url}</p>
                            <p><span className="text-text-muted">Token URL:</span> {cred.oauth?.token_url}</p>
                            {cred.oauth?.scopes && <p><span className="text-text-muted">Scopes:</span> {cred.oauth.scopes}</p>}
                          </div>
                          <div className="grid grid-cols-2 gap-3">
                            <FormField label="Client ID"><Input placeholder="OAuth app client ID" value={fields.client_id ?? ""} onChange={(e) => updateOauthField(cred.key, "client_id", e.target.value)} /></FormField>
                            <FormField label="Client Secret"><Input type="password" placeholder="OAuth app client secret" value={fields.client_secret ?? ""} onChange={(e) => updateOauthField(cred.key, "client_secret", e.target.value)} /></FormField>
                          </div>
                          <Button type="button" onClick={() => handleOAuthConnect(cred.key)} disabled={connecting || connected || !(fields.client_id ?? "").trim()} loading={connecting} className="w-full">
                            {connecting ? "Waiting for authorization..." : "Connect"}
                          </Button>
                        </>
                      ) : (
                        <>
                          {cred.oauth?.token_url && (
                            <div className="text-xs text-text-dim">
                              <span className="text-text-muted">Token URL:</span> {cred.oauth.token_url}
                            </div>
                          )}
                          <FormField label="Access Token" helperText="Optional when refresh token is provided"><Input type="password" placeholder="Access token" value={fields.access_token ?? ""} onChange={(e) => updateOauthField(cred.key, "access_token", e.target.value)} /></FormField>
                          <FormField label="Refresh Token" helperText="Validated immediately on save"><Input type="password" placeholder="Refresh token" value={fields.refresh_token ?? ""} onChange={(e) => updateOauthField(cred.key, "refresh_token", e.target.value)} /></FormField>
                          <FormField label="Client ID" helperText="Required for refresh"><Input placeholder="OAuth client ID" value={fields.client_id ?? cred.oauth?.client_id ?? ""} onChange={(e) => updateOauthField(cred.key, "client_id", e.target.value)} /></FormField>
                          <Button type="button" onClick={() => handleOAuthTokenUpload(cred.key)} disabled={!(fields.access_token ?? "").trim() && !(fields.refresh_token ?? "").trim()} loading={submitting} className="w-full">
                            Save Tokens
                          </Button>
                        </>
                      )}
                    </>
                  )}
                </div>
              );
            }
            return (
              <div key={cred.key} className="space-y-3">
                {cred.acquisition && (
                  <CredentialAcquisitionControl
                    declaration={cred.acquisition}
                    job={acquisitionJob}
                    busy={acquisitionActionKey === cred.key}
                    onStart={() => startAcquisition(cred)}
                    onCancel={() => cancelAcquisition(cred)}
                  />
                )}
                {acquisitionSatisfied ? (
                  <p className="text-sm text-success">Credential acquired and encrypted for this proposal.</p>
                ) : (
                  <FormField
                    label={cred.description || cred.key}
                    helperText={
                      (cred.obtain || cred.obtain_instructions) ? (
                        <span>
                          {cred.obtain ? (
                            <a href={cred.obtain.startsWith("http") ? cred.obtain : `https://${cred.obtain}`} target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">Get it here</a>
                          ) : null}
                          {cred.obtain && cred.obtain_instructions ? " — " : ""}
                          {cred.obtain_instructions}
                        </span>
                      ) : undefined
                    }
                  >
                    <Input
                      type="password"
                      placeholder={`Paste your ${cred.description || cred.key}`}
                      autoComplete="off"
                      value={credentialValues[cred.key] ?? ""}
                      onChange={(e) => setCredentialValues((prev) => ({ ...prev, [cred.key]: e.target.value }))}
                    />
                  </FormField>
                )}
              </div>
            );
          })}
        </form>
      )}

      {!isPending && proposal.review_note && (
        <div className="mt-4 p-3 bg-bg rounded-lg border border-border">
          <div className="text-xs font-semibold text-text-muted uppercase tracking-wider mb-1">
            Review note
          </div>
          <p className="text-sm text-text">{proposal.review_note}</p>
        </div>
      )}

      {acquisitionError && <ErrorBanner message={acquisitionError} className="mt-4" />}
      {formError && <ErrorBanner message={formError} className="mt-4" />}
    </Modal>
  );
}

function CredentialAcquisitionControl({
  declaration,
  job,
  busy,
  onStart,
  onCancel,
}: {
  declaration: AcquisitionDeclaration;
  job?: ProposalAcquisition;
  busy: boolean;
  onStart: () => void;
  onCancel: () => void;
}) {
  const active = !!job && isAcquisitionActive(job.state);
  const succeeded = job?.state === "succeeded";
  return (
    <div className="rounded-lg border border-border bg-bg p-3">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="text-xs font-semibold uppercase tracking-wider text-text-muted">Secure provider</div>
          <div className="text-sm font-mono text-text mt-1 break-all">
            {declaration.handler} · {declaration.profile} · {declaration.mode}
          </div>
          {job?.error_code && (
            <p className="text-xs text-danger mt-1">Provider failed: {job.error_code}</p>
          )}
          {job?.state === "awaiting_user" && (
            <p className="text-xs text-text-muted mt-1">Waiting for the provider's local user interaction.</p>
          )}
        </div>
        {job && <StatusBadge status={job.state} />}
      </div>
      {!succeeded && (
        <div className="mt-3 flex justify-end">
          {active ? (
            <Button type="button" variant="secondary" onClick={onCancel} loading={busy}>
              Cancel acquisition
            </Button>
          ) : (
            <Button type="button" onClick={onStart} loading={busy}>
              {job ? "Try provider again" : "Acquire securely"}
            </Button>
          )}
        </div>
      )}
    </div>
  );
}

// --- Table Cell ---

function ProposalCell({ proposal }: { proposal: Proposal }) {
  const { title, description } = useMemo(() => {
    return deriveProposalTitle(proposal);
  }, [proposal]);

  return (
    <>
      <div className="text-sm font-medium text-text">{title}</div>
      {description && (
        <div className="text-xs text-text-muted mt-0.5 truncate max-w-[400px]">
          {description}
        </div>
      )}
    </>
  );
}

function deriveProposalTitle(cs: Proposal): {
  title: string;
  description: string;
} {
  let services: { action: string; host: string; name?: string }[] = [];
  try {
    if (cs.services_json) {
      const parsed = JSON.parse(cs.services_json);
      if (Array.isArray(parsed)) services = parsed;
    }
  } catch {
    // ignore
  }

  const setServices = services.filter((r) => r.action === "set");
  if (setServices.length === 1) {
    const r = setServices[0];
    return {
      title: `Connect to ${r.name || r.host}`,
      description: cs.user_message || cs.message || "",
    };
  }
  if (setServices.length > 1) {
    return {
      title: `Connect to ${setServices.length} services`,
      description: cs.user_message || cs.message || "",
    };
  }

  return {
    title: cs.message || "Service change",
    description: cs.user_message || "",
  };
}
