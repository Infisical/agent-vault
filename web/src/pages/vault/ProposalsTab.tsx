import { useState, useEffect, useRef, useMemo, type FormEvent } from "react";
import { useVaultParams, StatusBadge, LoadingSpinner, ErrorBanner, timeAgo } from "./shared";
import DataTable, { type Column } from "../../components/DataTable";
import Modal from "../../components/Modal";
import Button from "../../components/Button";
import Input from "../../components/Input";
import FormField from "../../components/FormField";
import ProposalPreview, { parseRules, parseCredentials, type CredentialSlot } from "../../components/ProposalPreview";
import { apiFetch } from "../../lib/api";

interface Proposal {
  id: number;
  status: string;
  message: string;
  user_message?: string;
  rules_json?: string;
  credentials_json?: string;
  review_note?: string;
  reviewed_at?: string;
  created_at: string;
}

export default function ProposalsTab() {
  const { vaultName } = useVaultParams();
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
      const resp = await fetch(
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
      const countResp = await fetch(
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
      if (err instanceof DOMException && err.name === "AbortError") return;
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
                <span>Invite an agent to get started. It will request access to services and credentials to be approved here.</span>
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
  const rules = parseRules(proposal.rules_json);
  const credentials = parseCredentials(proposal.credentials_json);
  const isPending = proposal.status === "pending";

  const previewData = {
    proposal_id: proposal.id,
    vault: vaultName,
    status: proposal.status,
    message: proposal.message,
    user_message: proposal.user_message,
    rules,
    credentials,
    created_at: proposal.created_at,
  };

  const [credentialValues, setCredentialValues] = useState<Record<string, string>>({});
  const [formError, setFormError] = useState("");
  const [submitting, setSubmitting] = useState(false);

  const setCredentials = credentials.filter(
    (s: CredentialSlot) => s.action === "set" && !s.has_value
  );
  const allFilled = setCredentials.every(
    (s: CredentialSlot) => (credentialValues[s.key] ?? "").trim() !== ""
  );

  async function handleApprove(e: FormEvent) {
    e.preventDefault();
    setFormError("");
    setSubmitting(true);

    const credentialPayload: Record<string, string> = {};
    for (const s of setCredentials) {
      credentialPayload[s.key] = (credentialValues[s.key] ?? "").trim();
    }

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
          {setCredentials.map((cred: CredentialSlot) => (
            <FormField
              key={cred.key}
              label={cred.description || cred.key}
              helperText={
                (cred.obtain || cred.obtain_instructions) ? (
                  <span>
                    {cred.obtain ? (
                      <a
                        href={cred.obtain.startsWith("http") ? cred.obtain : `https://${cred.obtain}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-primary hover:underline"
                      >
                        Get it here
                      </a>
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
                onChange={(e) =>
                  setCredentialValues((prev) => ({
                    ...prev,
                    [cred.key]: e.target.value,
                  }))
                }
              />
            </FormField>
          ))}
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

      {formError && <ErrorBanner message={formError} className="mt-4" />}
    </Modal>
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
  let rules: { action: string; host: string; description?: string }[] = [];
  try {
    if (cs.rules_json) rules = JSON.parse(cs.rules_json);
  } catch {
    // ignore
  }

  const setRules = rules.filter((r) => r.action === "set");
  if (setRules.length === 1) {
    const r = setRules[0];
    return {
      title: r.description
        ? `Connect to ${r.description}`
        : `Connect to ${r.host}`,
      description: cs.user_message || cs.message || "",
    };
  }
  if (setRules.length > 1) {
    return {
      title: `Connect to ${setRules.length} services`,
      description: cs.user_message || cs.message || "",
    };
  }

  return {
    title: cs.message || "Policy change",
    description: cs.user_message || "",
  };
}
