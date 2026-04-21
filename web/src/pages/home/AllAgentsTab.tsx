import { useState, useEffect, useMemo, useCallback, type ReactNode } from "react";
import { useRouteContext } from "@tanstack/react-router";
import { LoadingSpinner, ErrorBanner, StatusBadge, timeAgo } from "../../components/shared";
import DataTable, { type Column } from "../../components/DataTable";
import DropdownMenu from "../../components/DropdownMenu";
import ConfirmDeleteModal from "../../components/ConfirmDeleteModal";
import Modal from "../../components/Modal";
import Button from "../../components/Button";
import Input from "../../components/Input";
import FormField from "../../components/FormField";
import CopyButton from "../../components/CopyButton";
import Select from "../../components/Select";
import { apiFetch } from "../../lib/api";
import type { AuthContext } from "../../router";

interface AgentRow {
  name: string;
  role: string; // instance-level role: "owner" or "member"
  status: string;
  created_at: string;
  vaults: { vault_name: string; vault_role: string }[];
  // For pending invites shown inline
  invite_id?: number;
}

interface VaultOption {
  id: string;
  name: string;
  role: string;
}

function RowActions({
  agent,
  isOwner,
  onRevoke,
  onDone,
}: {
  agent: AgentRow;
  isOwner: boolean;
  onRevoke: (agent: AgentRow) => void;
  onDone: () => void;
}) {
  if (agent.status === "revoked") return null;

  if (agent.status === "pending" && agent.invite_id) {
    return (
      <DropdownMenu
        width={192}
        items={[
          {
            label: "Revoke invite",
            onClick: async () => {
              await apiFetch(
                `/v1/agents/invites/by-id/${agent.invite_id}`,
                { method: "DELETE" }
              );
              onDone();
            },
            variant: "danger",
          },
        ]}
      />
    );
  }

  const items: { label: string; onClick: () => void; variant?: "danger" }[] = [];

  if (isOwner) {
    const targetRole = agent.role === "owner" ? "member" : "owner";
    items.push({
      label: `Set role: ${targetRole}`,
      onClick: async () => {
        await apiFetch(
          `/v1/agents/${encodeURIComponent(agent.name)}/role`,
          { method: "POST", body: JSON.stringify({ role: targetRole }) }
        );
        onDone();
      },
    });
  }

  items.push({ label: "Revoke agent", onClick: () => onRevoke(agent), variant: "danger" });

  return (
    <DropdownMenu
      width={192}
      items={items}
    />
  );
}

export default function AllAgentsTab() {
  const { auth } = useRouteContext({ from: "/_auth" }) as { auth: AuthContext };
  const [rows, setRows] = useState<AgentRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [revokeTarget, setRevokeTarget] = useState<AgentRow | null>(null);

  const fetchData = useCallback(async () => {
    try {
      const [agentsResp, invResp] = await Promise.all([
        apiFetch("/v1/agents"),
        apiFetch("/v1/agents/invites?status=pending"),
      ]);

      if (!agentsResp.ok) {
        const data = await agentsResp.json();
        setError(data.error || "Failed to load agents.");
        return;
      }

      const agentsData = await agentsResp.json();
      const activeRows: AgentRow[] = (agentsData.agents ?? []).map(
        (a: { name: string; role: string; status: string; created_at: string; vaults?: { vault_name: string; vault_role: string }[] }) => ({
          name: a.name,
          role: a.role || "member",
          status: a.status,
          created_at: a.created_at,
          vaults: a.vaults ?? [],
        })
      );

      let pendingRows: AgentRow[] = [];
      if (invResp.ok) {
        const invData = await invResp.json();
        const agentNames = new Set(activeRows.map((a) => a.name));
        pendingRows = (invData.invites ?? [])
          .filter((inv: { agent_name: string; status: string }) =>
            inv.status === "pending" && !agentNames.has(inv.agent_name)
          )
          .map(
            (inv: { id: number; agent_name: string; agent_role?: string; created_at: string; vaults?: { vault_name: string; vault_role: string }[] }) => ({
              name: inv.agent_name,
              role: inv.agent_role || "member",
              status: "pending",
              created_at: inv.created_at,
              vaults: inv.vaults ?? [],
              invite_id: inv.id,
            })
          );
      }

      setRows([...activeRows, ...pendingRows]);
    } catch {
      setError("Network error.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  const columns = useMemo<Column<AgentRow>[]>(() => {
    const cols: Column<AgentRow>[] = [
      {
        key: "name",
        header: "Name",
        render: (agent) => (
          <span className="text-sm font-mono font-medium text-text">
            {agent.name}
          </span>
        ),
      },
      {
        key: "status",
        header: "Status",
        render: (agent) => <StatusBadge status={agent.status} />,
      },
      {
        key: "role",
        header: "Role",
        render: (agent) => (
          <span className="text-sm text-text-muted capitalize">{agent.role}</span>
        ),
      },
      {
        key: "vaults",
        header: "Vaults",
        render: (agent) => {
          if (agent.vaults.length === 0) return <span className="text-sm text-text-dim">{"\u2014"}</span>;
          return (
            <div className="flex flex-wrap gap-1">
              {agent.vaults.map((v) => (
                <span
                  key={v.vault_name}
                  className="inline-block px-2 py-0.5 bg-primary/10 text-primary text-xs font-medium rounded-full"
                >
                  {v.vault_name}:{v.vault_role}
                </span>
              ))}
            </div>
          );
        },
      },
      {
        key: "created_at",
        header: "Created",
        render: (agent) => (
          <span className="text-sm text-text-muted">{timeAgo(agent.created_at)}</span>
        ),
      },
      {
        key: "actions",
        header: "",
        align: "right" as const,
        render: (agent: AgentRow) => (
          <RowActions agent={agent} isOwner={auth.is_owner} onRevoke={setRevokeTarget} onDone={fetchData} />
        ),
      },
    ];
    return cols;
  }, [fetchData, auth.is_owner]);

  return (
    <div className="p-8 w-full max-w-[960px]">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h2 className="text-[22px] font-semibold text-text tracking-tight mb-1">
            Agents
          </h2>
          <p className="text-sm text-text-muted">
            All agents across the instance.
          </p>
        </div>
        <InviteAgentButton onInvited={fetchData} isOwner={auth.is_owner} />
      </div>

      {loading ? (
        <LoadingSpinner />
      ) : error ? (
        <ErrorBanner message={error} />
      ) : (
        <DataTable
          columns={columns}
          data={rows}
          rowKey={(row) => row.invite_id ? `invite-${row.invite_id}` : row.name}
          emptyTitle="No agents"
          emptyDescription="Invite an agent to give it access to your instance."
        />
      )}

      <ConfirmDeleteModal
        open={revokeTarget !== null}
        onClose={() => setRevokeTarget(null)}
        onConfirm={async () => {
          if (!revokeTarget) return;
          const resp = await apiFetch(
            `/v1/agents/${encodeURIComponent(revokeTarget.name)}`,
            { method: "DELETE" }
          );
          if (!resp.ok) {
            const data = await resp.json().catch(() => ({}));
            throw new Error(data.error || "Failed to revoke agent");
          }
          setRevokeTarget(null);
          fetchData();
        }}
        title="Revoke agent"
        description={`This will permanently revoke the agent "${revokeTarget?.name}" and invalidate all its sessions. This action cannot be undone.`}
        confirmLabel="Revoke agent"
        confirmValue={revokeTarget?.name ?? ""}
        inputLabel="Type the agent name to confirm"
      />
    </div>
  );
}

interface VaultAssignment {
  vault_name: string;
  vault_role: "proxy" | "member" | "admin";
}

function InviteAgentButton({
  onInvited,
  isOwner,
}: {
  onInvited: () => void;
  isOwner: boolean;
}) {
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [agentRole, setAgentRole] = useState<"owner" | "member">("member");
  const [vaultAssignments, setVaultAssignments] = useState<VaultAssignment[]>([]);
  const [availableVaults, setAvailableVaults] = useState<VaultOption[]>([]);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");
  const [inviteResult, setInviteResult] = useState<{ token: string } | null>(null);

  useEffect(() => {
    if (!open) return;
    apiFetch("/v1/vaults")
      .then((r) => r.json())
      .then((data) => {
        const vaults = (data.vaults ?? []).filter(
          (v: VaultOption) => isOwner || v.role === "admin"
        );
        setAvailableVaults(vaults);
      })
      .catch(() => {});
  }, [open, isOwner]);

  function close() {
    setOpen(false);
    setName("");
    setAgentRole("member");
    setVaultAssignments([]);
    setError("");
    setInviteResult(null);
  }

  function addVault() {
    const assignedNames = new Set(vaultAssignments.map((a) => a.vault_name));
    const next = availableVaults.find((v) => !assignedNames.has(v.name));
    if (next) {
      setVaultAssignments([...vaultAssignments, { vault_name: next.name, vault_role: "proxy" }]);
    }
  }

  function removeVault(idx: number) {
    setVaultAssignments(vaultAssignments.filter((_, i) => i !== idx));
  }

  function updateVault(idx: number, field: "vault_name" | "vault_role", value: string) {
    const updated = [...vaultAssignments];
    updated[idx] = { ...updated[idx], [field]: value };
    setVaultAssignments(updated);
  }

  async function handleCreate() {
    if (!name.trim()) return;
    setSubmitting(true);
    setError("");
    try {
      const payload: Record<string, unknown> = { name: name.trim() };
      if (isOwner && agentRole !== "member") {
        payload.role = agentRole;
      }
      if (vaultAssignments.length > 0) {
        payload.vaults = vaultAssignments;
      }
      const resp = await apiFetch("/v1/agents/invites", {
        method: "POST",
        body: JSON.stringify(payload),
      });
      const data = await resp.json();
      if (resp.ok) {
        onInvited();
        setInviteResult({ token: data.token });
      } else {
        setError(data.error || "Failed to create invite.");
      }
    } catch {
      setError("Network error.");
    } finally {
      setSubmitting(false);
    }
  }

  function buildPrompt(): string {
    const inviteUrl = `${window.location.origin}/invite/${inviteResult?.token}`;
    return [
      "You are being invited to register as an agent with Agent Vault, a local HTTP proxy that lets you call external APIs without seeing credentials.",
      "",
      "To accept this invite, make the following HTTP request:",
      "",
      `POST ${inviteUrl}`,
      "Content-Type: application/json",
      "",
      "{}",
      "",
      "The response contains your agent token and usage instructions.",
      "",
      "This invite expires in 15 minutes and can only be used once.",
    ].join("\n");
  }

  const assignedNames = new Set(vaultAssignments.map((a) => a.vault_name));
  const canAddMore = availableVaults.some((v) => !assignedNames.has(v.name));

  return (
    <>
      <Button onClick={() => setOpen(true)}>
        <svg
          className="w-4 h-4"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
        >
          <rect x="4" y="4" width="16" height="16" rx="2" ry="2" />
          <rect x="9" y="9" width="6" height="6" />
          <line x1="9" y1="1" x2="9" y2="4" />
          <line x1="15" y1="1" x2="15" y2="4" />
          <line x1="9" y1="20" x2="9" y2="23" />
          <line x1="15" y1="20" x2="15" y2="23" />
          <line x1="20" y1="9" x2="23" y2="9" />
          <line x1="20" y1="14" x2="23" y2="14" />
          <line x1="1" y1="9" x2="4" y2="9" />
          <line x1="1" y1="14" x2="4" y2="14" />
        </svg>
        Invite agent
      </Button>

      <Modal
        open={open}
        onClose={close}
        title={inviteResult ? "Connect Your Agent" : "Invite Agent"}
        description={inviteResult ? "Paste this into your agent's chat." : "Invite an AI agent to the instance."}
        footer={
          inviteResult ? (
            <Button onClick={close}>Done</Button>
          ) : (
            <>
              <Button variant="secondary" onClick={close}>Cancel</Button>
              <Button onClick={handleCreate} disabled={!name.trim()} loading={submitting}>
                Create invite
              </Button>
            </>
          )
        }
      >
        {inviteResult ? (
          <InviteResultView token={inviteResult.token} buildPrompt={buildPrompt} onRedeemed={onInvited} />
        ) : (
          <div className="space-y-4">
            <FormField
              label="Agent name"
              helperText="Lowercase letters, numbers, and hyphens (3-64 chars)."
            >
              <Input
                type="text"
                placeholder="my-agent"
                value={name}
                onChange={(e) => setName(e.target.value)}
                autoFocus
              />
            </FormField>

            {isOwner && (
              <FormField
                label="Instance role"
                helperText={agentRole === "owner"
                  ? "This agent will be able to manage users, vaults, and instance settings."
                  : "This agent will have standard access, scoped to its assigned vaults."}
              >
                <Select
                  value={agentRole}
                  onChange={(e) => setAgentRole(e.target.value as "owner" | "member")}
                >
                  <option value="member">Member</option>
                  <option value="owner">Owner</option>
                </Select>
              </FormField>
            )}

            <div>
              <div className="flex items-center justify-between mb-2">
                <label className="text-xs font-semibold text-text-muted uppercase tracking-wider">
                  Vault access (optional)
                </label>
                {canAddMore && (
                  <button
                    type="button"
                    onClick={addVault}
                    className="text-xs text-primary hover:underline"
                  >
                    + Add vault
                  </button>
                )}
              </div>
              {vaultAssignments.length === 0 ? (
                <p className="text-sm text-text-muted">
                  No vaults pre-assigned. The agent will join the instance without vault access.
                </p>
              ) : (
                <div className="space-y-2">
                  {vaultAssignments.map((assignment, idx) => (
                    <div key={idx} className="flex items-center gap-2">
                      <select
                        value={assignment.vault_name}
                        onChange={(e) => updateVault(idx, "vault_name", e.target.value)}
                        className="flex-1 px-3 py-2 bg-surface border border-border rounded-lg text-text text-sm outline-none"
                      >
                        {availableVaults.map((v) => (
                          <option
                            key={v.name}
                            value={v.name}
                            disabled={assignedNames.has(v.name) && v.name !== assignment.vault_name}
                          >
                            {v.name}
                          </option>
                        ))}
                      </select>
                      <Select
                        value={assignment.vault_role}
                        onChange={(e) => updateVault(idx, "vault_role", e.target.value)}
                        className="w-28"
                      >
                        <option value="proxy">Proxy</option>
                        <option value="member">Member</option>
                        <option value="admin">Admin</option>
                      </Select>
                      <button
                        type="button"
                        onClick={() => removeVault(idx)}
                        className="text-text-muted hover:text-danger p-1"
                        title="Remove"
                      >
                        <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                          <line x1="18" y1="6" x2="6" y2="18" />
                          <line x1="6" y1="6" x2="18" y2="18" />
                        </svg>
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {error && <ErrorBanner message={error} />}
          </div>
        )}
      </Modal>
    </>
  );
}

type InviteTab = "prompt" | "manual";

function InviteResultView({
  token,
  buildPrompt,
  onRedeemed,
}: {
  token: string;
  buildPrompt: () => string;
  onRedeemed: () => void;
}) {
  const [tab, setTab] = useState<InviteTab>("prompt");
  const [redeeming, setRedeeming] = useState(false);
  const [redeemError, setRedeemError] = useState("");
  const [sessionToken, setSessionToken] = useState<string | null>(null);
  const prompt = buildPrompt();

  async function handleRedeem() {
    setRedeeming(true);
    setRedeemError("");
    try {
      const resp = await apiFetch(`/invite/${token}`, {
        method: "POST",
        body: "{}",
      });
      if (!resp.ok) {
        const data = await resp.json().catch(() => ({}));
        setRedeemError(data.message || data.error || "Failed to redeem invite.");
        return;
      }
      const data = await resp.json();
      setSessionToken(data.av_agent_token);
      onRedeemed();
    } catch {
      setRedeemError("Network error.");
    } finally {
      setRedeeming(false);
    }
  }

  return (
    <div className="space-y-4">
      <div className="inline-flex rounded-lg bg-bg p-0.5 border border-border">
        {([
          { key: "prompt" as const, label: "Chat prompt" },
          { key: "manual" as const, label: "Manual setup" },
        ]).map(({ key, label }) => (
          <button
            key={key}
            onClick={() => setTab(key)}
            className={`px-3 py-1.5 text-sm font-medium rounded-md transition-colors ${
              tab === key
                ? "bg-surface text-text shadow-sm"
                : "text-text-muted hover:text-text"
            }`}
          >
            {label}
          </button>
        ))}
      </div>

      {tab === "prompt" ? (
        <>
          <p className="text-sm text-text-muted">
            Paste this into your agent's chat and it will connect automatically.
          </p>
          <div className="relative">
            <textarea
              readOnly
              value={prompt}
              rows={10}
              className="w-full px-4 py-3 bg-bg border border-border rounded-lg text-text text-sm font-mono outline-none select-all resize-none leading-relaxed"
              onFocus={(e) => e.target.select()}
            />
            <CopyButton
              value={prompt}
              className="absolute top-2 right-2 px-3 py-1.5 bg-primary text-primary-text rounded-md text-xs font-semibold hover:bg-primary-hover transition-colors"
            />
          </div>
          <p className="text-xs text-text-dim">
            Works with Claude Code, Cursor, ChatGPT, and other chat-based agents. For agents you can't paste into, see <strong>Manual setup</strong>.
          </p>
        </>
      ) : (
        <ManualSetupView
          sessionToken={sessionToken}
          redeeming={redeeming}
          redeemError={redeemError}
          onRedeem={handleRedeem}
        />
      )}
    </div>
  );
}

type TrustTab = "macos" | "linux" | "node" | "python";

function ManualSetupView({
  sessionToken,
  redeeming,
  redeemError,
  onRedeem,
}: {
  sessionToken: string | null;
  redeeming: boolean;
  redeemError: string;
  onRedeem: () => Promise<void>;
}) {
  const [mitm, setMitm] = useState<{ available: boolean; port: string } | null>(null);
  const [trustTab, setTrustTab] = useState<TrustTab>("macos");

  useEffect(() => {
    let cancelled = false;
    fetch("/v1/mitm/ca.pem")
      .then((r) => {
        if (cancelled) return;
        if (r.ok) {
          setMitm({ available: true, port: r.headers.get("X-MITM-Port") ?? "14322" });
        } else {
          setMitm({ available: false, port: "" });
        }
      })
      .catch(() => {
        if (!cancelled) setMitm({ available: false, port: "" });
      });
    return () => {
      cancelled = true;
    };
  }, []);

  if (mitm === null) {
    return <LoadingSpinner />;
  }

  if (!mitm.available) {
    return (
      <div className="px-4 py-3 bg-bg border border-border rounded-lg">
        <p className="text-sm text-text">Transparent proxy is disabled on this server.</p>
        <p className="text-xs text-text-muted mt-1">
          Restart Agent Vault with <code className="text-text-muted">--mitm-port</code> greater than 0 to enable it, or use the <strong>Chat prompt</strong> flow.
        </p>
      </div>
    );
  }

  const host = window.location.hostname;
  const tokenDisplay = sessionToken ?? "<TOKEN>";
  const httpsProxy = `https://${tokenDisplay}@${host}:${mitm.port}`;
  const trustSnippets: Record<TrustTab, string> = {
    macos: `sudo security add-trusted-cert -d -r trustRoot \\\n  -k /Library/Keychains/System.keychain agent-vault-ca.pem`,
    linux: `sudo cp agent-vault-ca.pem /usr/local/share/ca-certificates/agent-vault-ca.crt\nsudo update-ca-certificates`,
    node: `export NODE_EXTRA_CA_CERTS="$(pwd)/agent-vault-ca.pem"`,
    python: `export REQUESTS_CA_BUNDLE="$(pwd)/agent-vault-ca.pem"`,
  };
  const trustTabs: { key: TrustTab; label: string }[] = [
    { key: "macos", label: "macOS" },
    { key: "linux", label: "Linux" },
    { key: "node", label: "Node" },
    { key: "python", label: "Python" },
  ];

  return (
    <div className="space-y-5">
      <ManualStep n={1} title="Download the root CA">
        <p className="text-sm text-text-muted">
          Agent Vault's transparent proxy presents TLS leaves signed by its own CA. Save the certificate and trust it so your agent's HTTPS client can verify those leaves.
        </p>
        <a
          href="/v1/mitm/ca.pem"
          download="agent-vault-ca.pem"
          className="inline-flex items-center gap-2 px-3 py-2 bg-primary text-primary-text rounded-lg text-sm font-semibold hover:bg-primary-hover transition-colors"
        >
          Download CA
        </a>
      </ManualStep>

      <ManualStep n={2} title="Trust the CA">
        <div className="inline-flex rounded-lg bg-bg p-0.5 border border-border">
          {trustTabs.map(({ key, label }) => (
            <button
              key={key}
              onClick={() => setTrustTab(key)}
              className={`px-3 py-1 text-xs font-medium rounded-md transition-colors ${
                trustTab === key
                  ? "bg-surface text-text shadow-sm"
                  : "text-text-muted hover:text-text"
              }`}
            >
              {label}
            </button>
          ))}
        </div>
        <Snippet value={trustSnippets[trustTab]} />
      </ManualStep>

      <ManualStep n={3} title="Point the agent at the proxy">
        <p className="text-sm text-text-muted">
          The session token is embedded in the proxy URL — HTTP clients send it as <code className="text-text-muted">Proxy-Authorization</code> on every CONNECT handshake.
        </p>
        <Snippet value={`export HTTPS_PROXY="${httpsProxy}"`} />
        {!sessionToken && (
          <div className="flex items-center gap-2">
            <Button onClick={onRedeem} loading={redeeming}>
              Reveal token
            </Button>
            {redeemError && <span className="text-sm text-danger">{redeemError}</span>}
          </div>
        )}
        <p className="text-xs text-text-dim">
          If Agent Vault is behind a reverse proxy, replace <code className="text-text-muted">{host}</code> with the externally reachable hostname.
        </p>
      </ManualStep>

      <p className="text-xs text-text-dim pt-3 border-t border-border">
        <code className="text-text-muted">agent-vault run --vault &lt;name&gt; -- &lt;command&gt;</code> does all of this automatically.
      </p>
    </div>
  );
}

function ManualStep({
  n,
  title,
  children,
}: {
  n: number;
  title: string;
  children: ReactNode;
}) {
  return (
    <div className="space-y-2">
      <h4 className="text-sm font-semibold text-text">
        <span className="text-text-dim mr-2">{n}.</span>
        {title}
      </h4>
      {children}
    </div>
  );
}

function Snippet({ value }: { value: string }) {
  return (
    <div className="relative">
      <pre className="px-4 py-3 bg-bg border border-border rounded-lg text-text text-sm font-mono overflow-x-auto whitespace-pre">{value}</pre>
      <CopyButton
        value={value}
        className="absolute top-2 right-2 px-3 py-1.5 bg-primary text-primary-text rounded-md text-xs font-semibold hover:bg-primary-hover transition-colors"
      />
    </div>
  );
}
