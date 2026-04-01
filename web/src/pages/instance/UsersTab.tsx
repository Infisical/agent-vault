import { useState, useEffect } from "react";
import { useRouteContext } from "@tanstack/react-router";
import { LoadingSpinner, ErrorBanner, timeAgo } from "../../components/shared";
import DataTable, { type Column } from "../../components/DataTable";
import DropdownMenu from "../../components/DropdownMenu";
import ConfirmDeleteModal from "../../components/ConfirmDeleteModal";
import type { AuthContext } from "../../router";

interface InstanceUser {
  email: string;
  role: string;
  vaults: string[];
  created_at: string;
}

function RowActions({
  user,
  currentEmail,
  onDone,
  onRemove,
}: {
  user: InstanceUser;
  currentEmail: string;
  onDone: () => void;
  onRemove: (user: InstanceUser) => void;
}) {
  if (user.email === currentEmail) return null;

  const isOwner = user.role === "owner";

  async function handleToggleRole() {
    const newRole = isOwner ? "member" : "owner";
    await fetch(`/v1/admin/users/${encodeURIComponent(user.email)}/role`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ role: newRole }),
    });
    onDone();
  }

  return (
    <DropdownMenu
      width={192}
      items={[
        {
          label: isOwner ? "Demote to member" : "Promote to owner",
          onClick: handleToggleRole,
        },
        { label: "Remove user", onClick: () => onRemove(user), variant: "danger" },
      ]}
    />
  );
}

export default function InstanceUsersTab() {
  const { auth } = useRouteContext({ from: "/_auth" }) as { auth: AuthContext };
  const [users, setUsers] = useState<InstanceUser[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [deleteTarget, setDeleteTarget] = useState<InstanceUser | null>(null);

  useEffect(() => {
    fetchUsers();
  }, []);

  async function fetchUsers() {
    try {
      const resp = await fetch("/v1/admin/users");
      if (!resp.ok) {
        const data = await resp.json();
        setError(data.error || "Failed to load users.");
        return;
      }
      const data = await resp.json();
      setUsers(data.users ?? []);
    } catch {
      setError("Network error.");
    } finally {
      setLoading(false);
    }
  }

  async function handleDeleteUser() {
    if (!deleteTarget) return;
    const resp = await fetch(
      `/v1/admin/users/${encodeURIComponent(deleteTarget.email)}`,
      { method: "DELETE" }
    );
    if (!resp.ok) {
      const data = await resp.json().catch(() => ({}));
      throw new Error(data.error || "Failed to remove user");
    }
    setDeleteTarget(null);
    fetchUsers();
  }

  const columns: Column<InstanceUser>[] = [
    {
      key: "email",
      header: "Email",
      render: (u) => <span className="text-sm text-text">{u.email}</span>,
    },
    {
      key: "role",
      header: "Role",
      render: (u) => (
        <span className="text-sm text-text-muted capitalize">{u.role}</span>
      ),
    },
    {
      key: "vaults",
      header: "Vaults",
      render: (u) => (
        <span className="text-sm text-text-muted">
          {u.vaults && u.vaults.length > 0 ? u.vaults.join(", ") : "—"}
        </span>
      ),
    },
    {
      key: "created_at",
      header: "Created",
      render: (u) => (
        <span className="text-sm text-text-muted">{timeAgo(u.created_at)}</span>
      ),
    },
    {
      key: "actions",
      header: "",
      align: "right" as const,
      render: (u: InstanceUser) => (
        <RowActions
          user={u}
          currentEmail={auth.email}
          onDone={fetchUsers}
          onRemove={setDeleteTarget}
        />
      ),
    },
  ];

  return (
    <div className="p-8 w-full max-w-[960px]">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h2 className="text-[22px] font-semibold text-text tracking-tight mb-1">
            Users
          </h2>
          <p className="text-sm text-text-muted">
            All users across the instance.
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
          data={users}
          rowKey={(u) => u.email}
          emptyTitle="No users"
          emptyDescription="No users have registered yet."
        />
      )}

      <ConfirmDeleteModal
        open={deleteTarget !== null}
        onClose={() => setDeleteTarget(null)}
        onConfirm={handleDeleteUser}
        title="Remove user"
        description={`This will permanently remove "${deleteTarget?.email}" and revoke all their access. Type the email to confirm.`}
        confirmLabel="Remove permanently"
        confirmValue={deleteTarget?.email ?? ""}
        inputLabel="Email address"
      />
    </div>
  );
}
