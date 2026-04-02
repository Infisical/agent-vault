import { useState, useEffect } from "react";
import { useVaultParams, StatusBadge, LoadingSpinner, ErrorBanner, timeAgo, timeUntil } from "./shared";
import DataTable, { type Column } from "../../components/DataTable";
import Modal from "../../components/Modal";
import DropdownMenu from "../../components/DropdownMenu";
import Button from "../../components/Button";
import Input from "../../components/Input";
import Select from "../../components/Select";
import FormField from "../../components/FormField";
import CopyButton from "../../components/CopyButton";
import { apiFetch } from "../../lib/api";

interface AgentRow {
  name: string;
  vault_role?: string;
  status: string;
  created_at: string;
  invite_token?: string;
  session_expires_at?: string;
}

function RowActions({
  agent,
  onDone,
}: {
  agent: AgentRow;
  onDone: () => void;
}) {
  if (agent.status === "revoked") return null;

  async function handleRevoke() {
    if (agent.status === "pending" && agent.invite_token) {
      await fetch(`/v1/invites/${encodeURIComponent(agent.invite_token)}`, {
        method: "DELETE",
      });
    } else {
      await fetch(
        `/v1/admin/agents/${encodeURIComponent(agent.name)}`,
        { method: "DELETE" }
      );
    }
    onDone();
  }

  return (
    <DropdownMenu
      width={192}
      items={[
        {
          label: agent.status === "pending" ? "Revoke invite" : "Revoke agent",
          onClick: handleRevoke,
          variant: "danger",
        },
      ]}
    />
  );
}

export default function AgentsTab() {
  const { vaultName, vaultRole } = useVaultParams();
  const [rows, setRows] = useState<AgentRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const columns: Column<AgentRow>[] = [
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
      key: "vault_role",
      header: "Role",
      render: (agent) => (
        <span className="text-sm text-text-muted capitalize">
          {agent.vault_role || "\u2014"}
        </span>
      ),
    },
    {
      key: "status",
      header: "Status",
      render: (agent) => <StatusBadge status={agent.status} />,
    },
    {
      key: "created",
      header: "Last Seen",
      render: (agent) => (
        <span className="text-sm text-text-muted">
          {agent.invite_token ? "\u2014" : timeAgo(agent.created_at)}
        </span>
      ),
    },
    {
      key: "session_expires",
      header: "Session Expires",
      render: (agent) => {
        if (!agent.session_expires_at) {
          return <span className="text-sm text-text-dim">{"\u2014"}</span>;
        }
        const label = timeUntil(agent.session_expires_at);
        const isExpired = label === "Expired";
        return (
          <span className={`text-sm ${isExpired ? "text-danger" : "text-text-muted"}`}>
            {label}
          </span>
        );
      },
    },
    ...(vaultRole === "admin"
      ? [
          {
            key: "actions" as const,
            header: "",
            align: "right" as const,
            render: (agent: AgentRow) => (
              <RowActions agent={agent} onDone={fetchData} />
            ),
          },
        ]
      : []),
  ];

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 5000);
    return () => clearInterval(interval);
  }, []);

  async function fetchData() {
    try {
      const agentsResp = await fetch(
        `/v1/admin/agents?vault=${encodeURIComponent(vaultName)}`
      );
      if (!agentsResp.ok) {
        const data = await agentsResp.json();
        setError(data.error || "Failed to load agents.");
        return;
      }
      const agentsData = await agentsResp.json();
      const activeRows: AgentRow[] = (agentsData.agents ?? []).map(
        (a: { name: string; vault_role?: string; status: string; created_at: string; session_expires_at?: string }) => ({
          name: a.name,
          vault_role: a.vault_role,
          status: a.status,
          created_at: a.created_at,
          session_expires_at: a.session_expires_at,
        })
      );

      // Fetch invites to show alongside agents in the table
      let inviteRows: AgentRow[] = [];
      if (vaultRole === "admin" || vaultRole === "member") {
        const invResp = await fetch(
          `/v1/invites?vault=${encodeURIComponent(vaultName)}`
        );
        if (invResp.ok) {
          const invites = await invResp.json();
          const agentNames = new Set(activeRows.map((a) => a.name));
          inviteRows = (invites ?? [])
            .filter((inv: { status: string; persistent: boolean; agent_name?: string }) => {
              if (inv.status === "pending" || inv.status === "revoked") return true;
              if (inv.status === "redeemed") {
                // Skip persistent redeemed invites — they already appear as agent rows
                if (inv.persistent && inv.agent_name && agentNames.has(inv.agent_name)) return false;
                return true;
              }
              return false;
            })
            .map(
              (inv: { agent_name?: string; vault_role?: string; persistent: boolean; token: string; status: string; created_at: string; session_expires_at?: string }) => ({
                name: inv.agent_name || (inv.persistent ? "Unnamed agent" : "Session"),
                vault_role: inv.vault_role,
                status: inv.status === "redeemed" ? "active" : inv.status,
                created_at: inv.created_at,
                invite_token: inv.token,
                session_expires_at: inv.session_expires_at,
              })
            );
        }
      }

      setRows([...activeRows, ...inviteRows]);
    } catch {
      setError("Network error.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="p-8 w-full max-w-[960px]">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h2 className="text-[22px] font-semibold text-text tracking-tight mb-1">
            Agents
          </h2>
          <p className="text-sm text-text-muted">
            AI agents with access to this vault.
          </p>
        </div>
        {(vaultRole === "admin" || vaultRole === "member") && (
          <InviteAgentButton vaultName={vaultName} vaultRole={vaultRole} onInvited={fetchData} />
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
          rowKey={(row) => row.invite_token ?? row.name}
          emptyTitle="No agents registered"
          emptyDescription="Invite an agent to give it access to this vault."
        />
      )}
    </div>
  );
}

type InviteType = "temporary" | "persistent";
type InviteStep = "select" | "configure" | "done";
type DeliveryTab = "prompt" | "envvars";

type VaultRoleOption = "consumer" | "member" | "admin";

const roleDescriptions: Record<VaultRoleOption, string> = {
  consumer: "Proxy requests, discover services, and raise proposals. Recommended for most use cases.",
  member: "All consumer permissions, plus set/delete credentials, approve proposals, and manage policy.",
  admin: "All member permissions, plus invite users and agents with any role.",
};

function RoleSelector({
  value,
  onChange,
  disabled,
}: {
  value: VaultRoleOption;
  onChange: (role: VaultRoleOption) => void;
  disabled: boolean;
}) {
  return (
    <FormField
      label="Role"
      helperText={<>{disabled ? "Members can only invite consumers." : roleDescriptions[value]} <a href="https://docs.agent-vault.dev/learn/permissions#vault-roles" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">Learn more</a></>}
    >
      <Select
        value={value}
        onChange={(e) => onChange(e.target.value as VaultRoleOption)}
        disabled={disabled}
      >
        <option value="consumer">Consumer</option>
        <option value="member">Member</option>
        <option value="admin">Admin</option>
      </Select>
    </FormField>
  );
}

function InviteAgentButton({
  vaultName,
  vaultRole,
  onInvited,
}: {
  vaultName: string;
  vaultRole: string;
  onInvited: () => void;
}) {
  const [open, setOpen] = useState(false);
  const [step, setStep] = useState<InviteStep>("select");
  const [inviteType, setInviteType] = useState<InviteType>("temporary");
  const [name, setName] = useState("");
  const [selectedRole, setSelectedRole] = useState<VaultRoleOption>("consumer");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");
  const [inviteToken, setInviteToken] = useState("");
  const [sessionTTL, setSessionTTL] = useState(86400);
  const [sessionLabel, setSessionLabel] = useState("");
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [deliveryTab, setDeliveryTab] = useState<DeliveryTab>("prompt");
  const [directConnectResult, setDirectConnectResult] = useState<{
    av_addr: string;
    av_session_token: string;
    av_vault: string;
    vault_role: string;
    expires_at: string;
  } | null>(null);
  const [loadingEnvVars, setLoadingEnvVars] = useState(false);

  // Members can only invite consumers
  const canSelectRole = vaultRole === "admin";

  function close() {
    setOpen(false);
    setStep("select");
    setInviteType("temporary");
    setName("");
    setSelectedRole("consumer");
    setError("");
    setInviteToken("");
    setSessionTTL(86400);
    setSessionLabel("");
    setShowAdvanced(false);
    setDeliveryTab("prompt");
    setDirectConnectResult(null);
    setLoadingEnvVars(false);
  }

  async function handleCreate() {
    setSubmitting(true);
    setError("");
    try {
      const persistent = inviteType === "persistent";
      const resp = await apiFetch("/v1/invites", {
        method: "POST",
        body: JSON.stringify({
          vault: vaultName,
          persistent,
          vault_role: canSelectRole ? selectedRole : "consumer",
          ...(persistent && name.trim() ? { agent_name: name.trim() } : {}),
          ...(!persistent ? { session_ttl_seconds: sessionTTL } : {}),
          ...(!persistent && sessionLabel.trim() ? { session_label: sessionLabel.trim() } : {}),
        }),
      });
      const data = await resp.json();
      if (resp.ok) {
        onInvited();
        setInviteToken(data.token || "");
        setStep("done");
      } else {
        setError(data.error || "Failed to create invite.");
      }
    } catch {
      setError("Network error.");
    } finally {
      setSubmitting(false);
    }
  }

  async function fetchEnvVars() {
    if (directConnectResult) return;
    setLoadingEnvVars(true);
    try {
      const resp = await apiFetch("/v1/sessions/direct", {
        method: "POST",
        body: JSON.stringify({
          vault: vaultName,
          vault_role: canSelectRole ? selectedRole : "consumer",
          ttl_seconds: sessionTTL,
          ...(sessionLabel.trim() ? { label: sessionLabel.trim() } : {}),
        }),
      });
      const data = await resp.json();
      if (resp.ok) {
        setDirectConnectResult(data);
      } else {
        setError(data.error || "Failed to create session.");
      }
    } catch {
      setError("Network error.");
    } finally {
      setLoadingEnvVars(false);
    }
  }

  function handleNext() {
    if (inviteType === "temporary") {
      handleCreate();
    } else {
      setStep("configure");
    }
  }

  function buildPrompt(): string {
    const inviteUrl = `${window.location.origin}/invite/${inviteToken}`;
    if (inviteType === "persistent") {
      const bodyExample = name.trim() ? "{}" : '{"name": "your-agent-name"}';
      const lines = [
        "You are being invited to register as a persistent agent with Agent Vault, a local HTTP proxy that lets you call external APIs without seeing credentials.",
        "",
      ];
      if (!name.trim()) {
        lines.push(
          "You must provide a name for yourself in the request body. Choose a short, descriptive name (lowercase, hyphens allowed, 3-64 chars).",
          "",
        );
      }
      lines.push(
        "To accept this invite, make the following HTTP request:",
        "",
        `POST ${inviteUrl}`,
        "Content-Type: application/json",
        "",
        bodyExample,
        "",
        "The response contains your service token and usage instructions. Store the service token securely — it cannot be retrieved again.",
        "",
        "This invite expires in 15 minutes and can only be used once.",
      );
      return lines.join("\n");
    }
    return [
      "You are being invited to use Agent Vault, a local HTTP proxy that lets you call external APIs (Stripe, GitHub, etc.) without seeing the underlying credentials.",
      "",
      "To accept this invite, make the following HTTP request:",
      "",
      `GET ${inviteUrl}`,
      "",
      "The response contains your session token and usage instructions. Do this before making any external API calls.",
      "",
      "This invite expires in 15 minutes and can only be used once.",
    ].join("\n");
  }

  const title =
    step === "done"
      ? "Connect Your Agent"
      : step === "configure"
        ? "Agent Details"
        : "Invite Agent";

  const description =
    step === "done"
      ? "Choose how you'd like to connect."
      : step === "configure"
        ? "Configure the agent identity before creating the invite."
        : "Connect an AI agent to this vault.";

  const footer =
    step === "done" ? (
      <Button onClick={close}>Done</Button>
    ) : step === "configure" ? (
      <>
        <Button variant="secondary" onClick={() => { setStep("select"); setError(""); }}>
          Back
        </Button>
        <Button onClick={handleCreate} loading={submitting}>
          Create invite
        </Button>
      </>
    ) : (
      <>
        <Button variant="secondary" onClick={close}>Cancel</Button>
        <Button onClick={handleNext} loading={submitting}>
          {inviteType === "persistent" ? "Next" : "Create invite"}
        </Button>
      </>
    );

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

      <Modal open={open} onClose={close} title={title} description={description} footer={footer}>
        {step === "done" ? (
          <div className="space-y-4">
            {inviteType === "temporary" && (
              <div className="flex border-b border-border">
                <button
                  onClick={() => setDeliveryTab("prompt")}
                  className={`px-4 py-2 text-sm font-medium transition-colors relative ${
                    deliveryTab === "prompt"
                      ? "text-primary"
                      : "text-text-muted hover:text-text"
                  }`}
                >
                  Paste into chat
                  {deliveryTab === "prompt" && (
                    <div className="absolute bottom-0 left-0 right-0 h-0.5 bg-primary" />
                  )}
                </button>
                <button
                  onClick={() => {
                    setDeliveryTab("envvars");
                    fetchEnvVars();
                  }}
                  className={`px-4 py-2 text-sm font-medium transition-colors relative ${
                    deliveryTab === "envvars"
                      ? "text-primary"
                      : "text-text-muted hover:text-text"
                  }`}
                >
                  Manual setup
                  {deliveryTab === "envvars" && (
                    <div className="absolute bottom-0 left-0 right-0 h-0.5 bg-primary" />
                  )}
                </button>
              </div>
            )}

            {deliveryTab === "prompt" || inviteType === "persistent" ? (
              <>
                <p className="text-sm text-text-muted">
                  Paste this into your agent's chat and it will connect automatically to Agent Vault.
                </p>
                <div className="relative">
                  <textarea
                    readOnly
                    value={buildPrompt()}
                    rows={10}
                    className="w-full px-4 py-3 bg-bg border border-border rounded-lg text-text text-sm font-mono outline-none select-all resize-none leading-relaxed"
                    onFocus={(e) => e.target.select()}
                  />
                  <CopyButton
                    value={buildPrompt()}
                    className="absolute top-2 right-2 px-3 py-1.5 bg-primary text-primary-text rounded-md text-xs font-semibold hover:bg-primary-hover transition-colors"
                  />
                </div>
                <p className="text-xs text-text-dim">
                  Works with Claude Code, Cursor, ChatGPT, and other chat-based agents.
                </p>
              </>
            ) : loadingEnvVars ? (
              <div className="py-8 flex justify-center">
                <LoadingSpinner />
              </div>
            ) : directConnectResult ? (
              <>
                <p className="text-sm text-text-muted">
                  Your agent needs these values to connect to Agent Vault. <a href="https://docs.agent-vault.dev/guides/connect-custom-agent" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">Learn more</a>
                </p>
                <div className="space-y-2">
                  {([
                    { label: "AGENT_VAULT_ADDR", value: directConnectResult.av_addr },
                    { label: "AGENT_VAULT_SESSION_TOKEN", value: directConnectResult.av_session_token },
                  ] as const).map((env) => (
                    <div key={env.label}>
                      <label className="block text-xs font-medium text-text-muted mb-1">{env.label}</label>
                      <div className="flex items-center gap-2">
                        <input
                          readOnly
                          value={env.value}
                          className="flex-1 px-3 py-2 bg-bg border border-border rounded-lg text-text text-sm font-mono outline-none select-all"
                          onFocus={(e) => e.target.select()}
                        />
                        <CopyButton value={env.value} />
                      </div>
                    </div>
                  ))}
                </div>
                <p className="text-xs text-text-dim">
                  Role: {directConnectResult.vault_role} &middot; Expires: {new Date(directConnectResult.expires_at).toLocaleString()}
                </p>
              </>
            ) : null}
          </div>
        ) : step === "configure" ? (
          <div className="space-y-4">
            <FormField
              label="Agent name"
              helperText="Lowercase letters, numbers, and hyphens. If left blank, the agent chooses its own name on redemption."
            >
              <Input
                type="text"
                placeholder="my-agent"
                value={name}
                onChange={(e) => setName(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") handleCreate();
                }}
                autoFocus
              />
            </FormField>
            {error && <ErrorBanner message={error} />}
          </div>
        ) : (
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-3">
              <button
                onClick={() => setInviteType("temporary")}
                className={`relative text-left p-4 rounded-xl border-2 transition-all ${
                  inviteType === "temporary"
                    ? "border-primary bg-primary/[0.04]"
                    : "border-border hover:border-border-focus bg-surface"
                }`}
              >
                <div className="flex items-start gap-3">
                  <div
                    className={`mt-0.5 w-4 h-4 rounded-full border-2 flex items-center justify-center shrink-0 transition-colors ${
                      inviteType === "temporary"
                        ? "border-primary"
                        : "border-text-dim"
                    }`}
                  >
                    {inviteType === "temporary" && (
                      <div className="w-2 h-2 rounded-full bg-primary" />
                    )}
                  </div>
                  <div className="min-w-0">
                    <div className="text-sm font-semibold text-text mb-1">Session</div>
                    <p className="text-xs text-text-muted leading-relaxed">
                      Temporary access for a coding session. Best for Claude Code, Cursor, etc.
                    </p>
                  </div>
                </div>
              </button>

              <button
                onClick={() => setInviteType("persistent")}
                className={`relative text-left p-4 rounded-xl border-2 transition-all ${
                  inviteType === "persistent"
                    ? "border-primary bg-primary/[0.04]"
                    : "border-border hover:border-border-focus bg-surface"
                }`}
              >
                <div className="flex items-start gap-3">
                  <div
                    className={`mt-0.5 w-4 h-4 rounded-full border-2 flex items-center justify-center shrink-0 transition-colors ${
                      inviteType === "persistent"
                        ? "border-primary"
                        : "border-text-dim"
                    }`}
                  >
                    {inviteType === "persistent" && (
                      <div className="w-2 h-2 rounded-full bg-primary" />
                    )}
                  </div>
                  <div className="min-w-0">
                    <div className="text-sm font-semibold text-text mb-1">Persistent</div>
                    <p className="text-xs text-text-muted leading-relaxed">
                      Long-lived access for always-on agents like Devin or custom services.
                    </p>
                  </div>
                </div>
              </button>
            </div>

            <RoleSelector
              value={selectedRole}
              onChange={setSelectedRole}
              disabled={!canSelectRole}
            />

            {inviteType !== "persistent" && (
              <div>
                <button
                  type="button"
                  onClick={() => setShowAdvanced((v) => !v)}
                  className="flex items-center gap-1.5 text-xs font-medium text-text-muted hover:text-text transition-colors"
                >
                  <svg
                    className={`w-3 h-3 transition-transform ${showAdvanced ? "rotate-90" : ""}`}
                    viewBox="0 0 24 24"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="2"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  >
                    <polyline points="9 18 15 12 9 6" />
                  </svg>
                  Advanced options
                </button>
                {showAdvanced && (
                  <div className="mt-3 space-y-3">
                    <div>
                      <label className="block text-xs font-semibold text-text-muted uppercase tracking-wider mb-2">
                        Session duration
                      </label>
                      <div className="flex gap-2">
                        {([
                          { label: "1h", value: 3600 },
                          { label: "8h", value: 28800 },
                          { label: "24h", value: 86400 },
                          { label: "7d", value: 604800 },
                        ] as const).map((opt) => (
                          <button
                            key={opt.value}
                            type="button"
                            onClick={() => setSessionTTL(opt.value)}
                            className={`px-3 py-1.5 rounded-lg text-sm font-medium transition-colors ${
                              sessionTTL === opt.value
                                ? "bg-primary text-primary-text"
                                : "bg-bg border border-border text-text-muted hover:border-border-focus"
                            }`}
                          >
                            {opt.label}
                          </button>
                        ))}
                      </div>
                    </div>
                    <FormField
                      label="Label"
                      helperText="Optional. Helps identify this session later."
                    >
                      <Input
                        type="text"
                        placeholder="e.g. testing stripe"
                        value={sessionLabel}
                        onChange={(e) => setSessionLabel(e.target.value)}
                        maxLength={128}
                      />
                    </FormField>
                  </div>
                )}
              </div>
            )}

            {error && <ErrorBanner message={error} />}
          </div>
        )}
      </Modal>
    </>
  );
}
