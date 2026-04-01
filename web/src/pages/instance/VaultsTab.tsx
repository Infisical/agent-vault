import { useState, useEffect } from "react";
import { LoadingSpinner, ErrorBanner, timeAgo } from "../../components/shared";
import DataTable, { type Column } from "../../components/DataTable";
import DropdownMenu from "../../components/DropdownMenu";
import ConfirmDeleteModal from "../../components/ConfirmDeleteModal";

interface InstanceVault {
  id: string;
  name: string;
  is_default: boolean;
  created_at: string;
}

function RowActions({
  vault,
  onRemove,
}: {
  vault: InstanceVault;
  onRemove: (vault: InstanceVault) => void;
}) {
  if (vault.is_default) return null;

  return (
    <DropdownMenu
      width={192}
      items={[
        { label: "Delete vault", onClick: () => onRemove(vault), variant: "danger" },
      ]}
    />
  );
}

export default function InstanceVaultsTab() {
  const [vaults, setVaults] = useState<InstanceVault[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [deleteTarget, setDeleteTarget] = useState<InstanceVault | null>(null);

  useEffect(() => {
    fetchVaults();
  }, []);

  async function fetchVaults() {
    try {
      const resp = await fetch("/v1/admin/vaults");
      if (!resp.ok) {
        const data = await resp.json();
        setError(data.error || "Failed to load vaults.");
        return;
      }
      const data = await resp.json();
      setVaults(data.vaults ?? []);
    } catch {
      setError("Network error.");
    } finally {
      setLoading(false);
    }
  }

  async function handleDeleteVault() {
    if (!deleteTarget) return;
    const resp = await fetch(
      `/v1/vaults/${encodeURIComponent(deleteTarget.name)}`,
      { method: "DELETE" }
    );
    if (!resp.ok) {
      const data = await resp.json().catch(() => ({}));
      throw new Error(data.error || "Failed to delete vault");
    }
    setDeleteTarget(null);
    fetchVaults();
  }

  const columns: Column<InstanceVault>[] = [
    {
      key: "name",
      header: "Name",
      render: (v) => <span className="text-sm text-text font-medium">{v.name}</span>,
    },
    {
      key: "created_at",
      header: "Created",
      render: (v) => (
        <span className="text-sm text-text-muted">{timeAgo(v.created_at)}</span>
      ),
    },
    {
      key: "actions",
      header: "",
      align: "right" as const,
      render: (v: InstanceVault) => (
        <RowActions vault={v} onRemove={setDeleteTarget} />
      ),
    },
  ];

  return (
    <div className="p-8 w-full max-w-[960px]">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h2 className="text-[22px] font-semibold text-text tracking-tight mb-1">
            Vaults
          </h2>
          <p className="text-sm text-text-muted">
            All vaults across the instance.
          </p>
        </div>
      </div>

      {loading ? (
        <LoadingSpinner />
      ) : error ? (
        <ErrorBanner message={error} />
      ) : (
        <DataTable
          columns={columns}
          data={vaults}
          rowKey={(v) => v.id}
          emptyTitle="No vaults"
          emptyDescription="No vaults have been created yet."
        />
      )}

      <ConfirmDeleteModal
        open={deleteTarget !== null}
        onClose={() => setDeleteTarget(null)}
        onConfirm={handleDeleteVault}
        title="Delete vault"
        description={`This will permanently delete the vault "${deleteTarget?.name}" and all its data including rules, credentials, agents, and proposals. Type the vault name to confirm.`}
        confirmLabel="Delete permanently"
        confirmValue={deleteTarget?.name ?? ""}
        inputLabel="Vault name"
      />
    </div>
  );
}
