import { useState, useEffect, useMemo, useCallback, useRef, type ReactNode } from "react";
import { useRouteContext } from "@tanstack/react-router";
import { LoadingSpinner, ErrorBanner, StatusBadge, timeAgo, formatInstanceRole, INSTANCE_ROLE_OPTIONS, type InstanceRole } from "../../components/shared";
import DataTable, { type Column } from "../../components/DataTable";
import DropdownMenu from "../../components/DropdownMenu";
import ConfirmDeleteModal from "../../components/ConfirmDeleteModal";
import Modal from "../../components/Modal";
import Button from "../../components/Button";
import Input from "../../components/Input";
import FormField from "../../components/FormField";
import CopyButton from "../../components/CopyButton";
import Select from "../../components/Select";
import SegmentedTabs from "../../components/SegmentedTabs";
import { apiFetch, isAbortError } from "../../lib/api";
import type { AuthContext, InstanceStatus } from "../../router";

interface AgentRow {
  name: string;
  role: string;
  status: string;
  created_at: string;
  vaults: { vault_name: string; vault_role: string }[];
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
  onError,
}: {
  agent: AgentRow;
  isOwner: boolean;
  onRevoke: (agent: AgentRow) => void;
  onDone: () => void;
  onError: (msg: string) => void;
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
              const resp = await apiFetch(
                `/v1/agents/invites/by-id/${agent.invite_id}`,
                { method: "DELETE" }
              );
              if (!resp.ok) {
                const data = await resp.json().catch(() => ({}));
                onError(data.error || "Failed to revoke invite");
                return;
              }
              onDone();
            },
            variant: "danger",
          },
        ]}
      />
    );
  }

  async function setRoleTo(newRole: InstanceRole) {
    const resp = await apiFetch(
      `/v1/agents/${encodeURIComponent(agent.name)}/role`,
      { method: "POST", body: JSON.stringify({ role: newRole }) }
    );
    if (!resp.ok) {
      const data = await resp.json().catch(() => ({}));
      onError(data.error || "Failed to change role");
      return;
    }
    onDone();
  }

  const items: { label: string; onClick: () => void; variant?: "danger" }[] = [];

  if (isOwner) {
    for (const opt of INSTANCE_ROLE_OPTIONS) {
      if (opt.role === agent.role) continue;
      items.push({
        label: `Set role: ${opt.label}`,
        onClick: () => setRoleTo(opt.role),
      });
    }
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
  const { auth, status } = useRouteContext({ from: "/_auth" }) as { auth: AuthContext; status: InstanceStatus };
  const [rows, setRows] = useState<AgentRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [revokeTarget, setRevokeTarget] = useState<AgentRow | null>(null);

  const fetchData = useCallback(async () => {
    try {
      const agentsResp = await apiFetch("/v1/agents");

      if (!agentsResp.ok) {
        const data = await agentsResp.json();
        setError(data.error || "Failed to load agents.");
        return;
      }

      const agentsData = await agentsResp.json();
      const nextRows: AgentRow[] = (agentsData.agents ?? []).map(
        (a: { name: string; role: string; status: string; created_at: string; vaults?: { vault_name: string; vault_role: string }[]; invite_id?: number }) => ({
          name: a.name,
          role: a.role || "member",
          status: a.status,
          created_at: a.created_at,
          vaults: a.vaults ?? [],
          invite_id: a.invite_id,
        })
      );

      setRows(nextRows);
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
          <span className="text-sm text-text-muted">{formatInstanceRole(agent.role)}</span>
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
          <RowActions agent={agent} isOwner={auth.is_owner} onRevoke={setRevokeTarget} onDone={fetchData} onError={setError} />
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
        <InviteAgentButton onInvited={fetchData} isOwner={auth.is_owner} baseURL={status.base_url} />
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
  baseURL,
}: {
  onInvited: () => void;
  isOwner: boolean;
  baseURL?: string;
}) {
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [agentRole, setAgentRole] = useState<InstanceRole>("no-access");
  const [vaultAssignments, setVaultAssignments] = useState<VaultAssignment[]>([]);
  const [availableVaults, setAvailableVaults] = useState<VaultOption[]>([]);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");
  const [inviteResult, setInviteResult] = useState<{ agentToken: string } | null>(null);
  const abortRef = useRef<AbortController | null>(null);

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

  // Unmount paths that bypass close() (browser back, programmatic redirect)
  // would otherwise let an in-flight redeem land its token on an unmounted
  // component and disappear.
  useEffect(() => {
    return () => {
      abortRef.current?.abort();
    };
  }, []);

  function close() {
    abortRef.current?.abort();
    setOpen(false);
    setName("");
    setAgentRole("no-access");
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
    abortRef.current?.abort();
    const controller = new AbortController();
    abortRef.current = controller;
    setSubmitting(true);
    setError("");
    try {
      // Probe MITM before minting anything: agent tokens are returned exactly
      // once at redemption, so creating a session when MITM is off loses it.
      const mitmResp = await apiFetch("/v1/mitm/ca.pem", {
        method: "HEAD",
        signal: controller.signal,
      });
      if (mitmResp.status === 404) {
        setError("Transparent proxy is disabled on this server. Restart Agent Vault with --mitm-port greater than 0 to enable agent connections.");
        return;
      }
      if (!mitmResp.ok) {
        setError(`Couldn't reach the transparent proxy (HTTP ${mitmResp.status}). Check the server and try again.`);
        return;
      }
      const payload: Record<string, unknown> = { name: name.trim() };
      // Non-owners don't see the picker, so agentRole stays at "no-access",
      // which is what we want them creating.
      payload.role = agentRole;
      if (vaultAssignments.length > 0) {
        payload.vaults = vaultAssignments;
      }
      const createResp = await apiFetch("/v1/agents/invites", {
        method: "POST",
        body: JSON.stringify(payload),
        signal: controller.signal,
      });
      const createData = await createResp.json();
      if (!createResp.ok) {
        setError(createData.error || "Failed to create invite.");
        return;
      }
      if (!createData.token) {
        setError("Server returned no invite token. Try again.");
        return;
      }
      const redeemResp = await apiFetch(`/invite/${createData.token}`, {
        method: "POST",
        body: "{}",
        signal: controller.signal,
      });
      const redeemData = await redeemResp.json().catch((err) => {
        if (isAbortError(err)) throw err;
        return {};
      });
      // Refresh regardless of outcome: a failed redeem leaves an orphan
      // pending invite, and a 2xx with a missing token still means the
      // session was persisted. Either way the operator needs to see the row.
      onInvited();
      if (!redeemResp.ok) {
        setError(redeemData.message || redeemData.error || "Failed to issue agent token.");
        return;
      }
      if (!redeemData.av_agent_token) {
        setError("Server returned no agent token. Try again.");
        return;
      }
      setInviteResult({ agentToken: redeemData.av_agent_token });
    } catch (err) {
      // Server may have committed the create or redeem before the abort or
      // drop, so refresh so any orphan invite or live session shows up.
      onInvited();
      if (isAbortError(err)) return;
      setError("Network error.");
    } finally {
      // Skip if a re-entrant handleCreate has taken over: that call already
      // set submitting=true on entry and owns clearing it.
      if (abortRef.current === controller) setSubmitting(false);
    }
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
        Add agent
      </Button>

      <Modal
        open={open}
        onClose={close}
        title={inviteResult ? "Connect Your Agent" : "Add Agent"}
        description={inviteResult ? "The Agent Vault CLI runs alongside your agent and reads these env vars to bootstrap its environment, so every outbound API call routes through Agent Vault for credential injection." : "Connect an agent, app, or service to Agent Vault."}
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
          <InviteResultView agentToken={inviteResult.agentToken} baseURL={baseURL} />
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
                helperText={
                  agentRole === "owner"
                    ? "This agent will be able to manage users, vaults, and instance settings."
                    : agentRole === "member"
                    ? "This agent will have standard access, scoped to its assigned vaults."
                    : "This agent has no instance-level access. It can only operate within vaults you grant it below."
                }
              >
                <Select
                  value={agentRole}
                  onChange={(e) => setAgentRole(e.target.value as InstanceRole)}
                >
                  <option value="no-access">No Access</option>
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
                      <div className="flex-1">
                        <Select
                          value={assignment.vault_name}
                          onChange={(e) => updateVault(idx, "vault_name", e.target.value)}
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
                        </Select>
                      </div>
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

type InstallTab = "shell" | "docker";

const INSTALL_SNIPPETS: Record<InstallTab, string> = {
  shell: "curl --proto '=https' --proto-redir '=https' --tlsv1.2 -fsSL https://get.agent-vault.dev | sh",
  docker: "COPY --from=infisical/agent-vault:latest /usr/local/bin/agent-vault /usr/local/bin/agent-vault",
};

const RUN_SNIPPETS: Record<InstallTab, string> = {
  shell: "agent-vault run -- claude",
  docker: `ENTRYPOINT ["agent-vault", "run", "--", "claude"]`,
};

// Loopback and bind-wildcard values almost never reach a remote agent,
// so treat them as unset and let the operator fill in the right hostname.
function resolveAgentVaultAddr(baseURL?: string): string {
  const placeholder = "<AGENT_VAULT_ADDR>";
  if (!baseURL) return placeholder;
  try {
    const host = new URL(baseURL).hostname;
    // URL.hostname preserves IPv6 brackets per WHATWG URL host serializer.
    if (
      host === "localhost" ||
      host === "[::1]" ||
      host === "[::]" ||
      host === "0.0.0.0" ||
      /^127\./.test(host)
    ) {
      return placeholder;
    }
  } catch {
    return placeholder;
  }
  return baseURL;
}

function InviteResultView({
  agentToken,
  baseURL,
}: {
  agentToken: string;
  baseURL?: string;
}) {
  const [installTab, setInstallTab] = useState<InstallTab>("shell");

  const addr = resolveAgentVaultAddr(baseURL);
  const envSnippet = [
    `export AGENT_VAULT_ADDR="${addr}"`,
    `export AGENT_VAULT_TOKEN="${agentToken}"`,
    `export AGENT_VAULT_VAULT="<VAULT_NAME>"`,
  ].join("\n");

  return (
    <div className="space-y-5">
      <SegmentedTabs<InstallTab>
        ariaLabel="Install method"
        value={installTab}
        onChange={setInstallTab}
        options={[
          { value: "shell", label: "Shell" },
          { value: "docker", label: "Dockerfile" },
        ]}
      />

      <ManualStep n={1} title="Install the Agent Vault CLI">
        <p className="text-sm text-text-muted">
          Add the <code className="text-text-muted">agent-vault</code> binary to the environment where your agent runs.
        </p>
        <Snippet value={INSTALL_SNIPPETS[installTab]} />
      </ManualStep>

      <ManualStep n={2} title="Set environment variables">
        <p className="text-sm text-text-muted">
          The CLI reads these on launch to authenticate with Agent Vault and scope its session to the right vault.
        </p>
        <Snippet value={envSnippet} />
      </ManualStep>

      <ManualStep n={3} title="Run your agent under agent-vault">
        <p className="text-sm text-text-muted">
          <code className="text-text-muted">agent-vault run</code> launches your agent with <code className="text-text-muted">HTTPS_PROXY</code> and <code className="text-text-muted">HTTP_PROXY</code> pre-set so both its HTTPS and plain HTTP calls route through Agent Vault for credential injection.
        </p>
        <Snippet value={RUN_SNIPPETS[installTab]} />
      </ManualStep>
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
      <pre className="pl-4 pr-20 py-3 bg-bg border border-border rounded-lg text-text text-sm font-mono overflow-x-auto whitespace-pre">{value}</pre>
      <CopyButton
        value={value}
        className="absolute top-2 right-2 px-3 py-1.5 bg-primary text-primary-text rounded-md text-xs font-semibold hover:bg-primary-hover transition-colors"
      />
    </div>
  );
}
