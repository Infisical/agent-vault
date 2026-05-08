import { useState, useEffect } from "react";
import { useVaultParams, StatusBadge, LoadingSpinner, ErrorBanner } from "./shared";
import DataTable, { type Column } from "../../components/DataTable";
import Modal from "../../components/Modal";
import DropdownMenu from "../../components/DropdownMenu";
import Button from "../../components/Button";
import Select from "../../components/Select";
import FormField from "../../components/FormField";
import { apiFetch } from "../../lib/api";

interface AgentRow {
  name: string;
  role: string;
  status: string;
}

// Rendered only inside the admin-gated actions column, so no role guard
// here. Instance role changes happen on the instance-level Agents tab.
function RowActions({
  agent,
  vaultName,
  onDone,
}: {
  agent: AgentRow;
  vaultName: string;
  onDone: () => void;
}) {
  if (agent.status === "revoked") return null;

  async function handleRemove() {
    await apiFetch(
      `/v1/vaults/${encodeURIComponent(vaultName)}/agents/${encodeURIComponent(agent.name)}`,
      { method: "DELETE" }
    );
    onDone();
  }

  return (
    <DropdownMenu
      width={192}
      items={[
        { label: "Remove from vault", onClick: handleRemove, variant: "danger" as const },
      ]}
    />
  );
}

export default function AgentsTab() {
  const { vaultName, isAdmin } = useVaultParams();
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
      key: "status",
      header: "Status",
      render: (agent) => <StatusBadge status={agent.status} />,
    },
    {
      key: "role",
      header: "Role",
      render: (agent) => (
        <span className="text-sm text-text-muted capitalize">
          {agent.role || "—"}
        </span>
      ),
    },
    ...(isAdmin
      ? [
          {
            key: "actions" as const,
            header: "",
            align: "right" as const,
            render: (agent: AgentRow) => (
              <RowActions
                agent={agent}
                vaultName={vaultName}
                onDone={fetchData}
              />
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
      const resp = await apiFetch(
        `/v1/vaults/${encodeURIComponent(vaultName)}/agents`
      );

      if (!resp.ok) {
        const data = await resp.json();
        setError(data.error || "Failed to load agents.");
        return;
      }

      const data = await resp.json();
      setRows(
        (data.agents ?? []).map(
          (a: { name: string; role: string; status: string }) => ({
            name: a.name,
            role: a.role,
            status: a.status,
          })
        )
      );
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
            AI agents with access to this vault. Permissions inside the vault come from each agent's instance role.
          </p>
        </div>
        {isAdmin && (
          <AddAgentButton vaultName={vaultName} vaultAgents={rows} onAdded={fetchData} />
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
          rowKey={(row) => row.name}
          emptyTitle="No agents in this vault"
          emptyDescription="Add an existing agent to give it access to this vault."
        />
      )}
    </div>
  );
}

interface InstanceAgent {
  name: string;
  role: string;
  status: string;
}

function AddAgentButton({
  vaultName,
  vaultAgents,
  onAdded,
}: {
  vaultName: string;
  vaultAgents: AgentRow[];
  onAdded: () => void;
}) {
  const [open, setOpen] = useState(false);
  const [agentName, setAgentName] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");
  const [instanceAgents, setInstanceAgents] = useState<InstanceAgent[]>([]);

  useEffect(() => {
    if (!open) return;
    apiFetch("/v1/agents")
      .then((r) => r.json())
      .then((data) => setInstanceAgents(data.agents ?? []))
      .catch(() => {});
  }, [open]);

  // Owners auto-access every vault, so they aren't candidates for an
  // explicit grant. Filter them out alongside agents that already
  // have access.
  const availableAgents = instanceAgents.filter(
    (a) =>
      (a.status === "active" || a.status === "pending") &&
      a.role !== "owner" &&
      !vaultAgents.some((va) => va.name === a.name),
  );

  function close() {
    setOpen(false);
    setAgentName("");
    setError("");
  }

  async function handleAdd() {
    if (!agentName) return;
    setSubmitting(true);
    setError("");
    try {
      const resp = await apiFetch(
        `/v1/vaults/${encodeURIComponent(vaultName)}/agents`,
        {
          method: "POST",
          body: JSON.stringify({ name: agentName }),
        }
      );
      if (resp.ok) {
        onAdded();
        close();
      } else {
        const data = await resp.json();
        setError(data.error || "Failed to add agent.");
      }
    } catch {
      setError("Network error.");
    } finally {
      setSubmitting(false);
    }
  }

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
          <line x1="12" y1="5" x2="12" y2="19" />
          <line x1="5" y1="12" x2="19" y2="12" />
        </svg>
        Add agent
      </Button>

      <Modal
        open={open}
        onClose={close}
        title="Add Agent to Vault"
        description="Grant an existing instance agent access to this vault. Effective permissions inside the vault come from the agent's instance role."
        footer={
          <>
            <Button variant="secondary" onClick={close}>Cancel</Button>
            <Button onClick={handleAdd} disabled={!agentName} loading={submitting}>
              Add agent
            </Button>
          </>
        }
      >
        <div className="space-y-4">
          <FormField label="Agent">
            {availableAgents.length === 0 ? (
              <p className="text-sm text-text-muted py-2">
                Every eligible instance agent already has access to this vault.
              </p>
            ) : (
              <Select
                value={agentName}
                onChange={(e) => setAgentName(e.target.value)}
                autoFocus
              >
                <option value="" disabled>
                  Select an agent...
                </option>
                {availableAgents.map((a) => (
                  <option key={a.name} value={a.name}>
                    {a.name} ({a.role})
                  </option>
                ))}
              </Select>
            )}
          </FormField>

          {error && <ErrorBanner message={error} />}
        </div>
      </Modal>
    </>
  );
}
