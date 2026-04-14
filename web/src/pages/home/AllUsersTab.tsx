import { useState, useEffect, useMemo, useCallback } from "react";
import { useRouteContext } from "@tanstack/react-router";
import { LoadingSpinner, ErrorBanner, timeAgo } from "../../components/shared";
import DataTable, { type Column } from "../../components/DataTable";
import DropdownMenu from "../../components/DropdownMenu";
import ConfirmDeleteModal from "../../components/ConfirmDeleteModal";
import type { AuthContext } from "../../router";

interface PublicUser {
  email: string;
  role: string;
  vaults?: string[];
  created_at: string;
}

function RowActions({
  user,
  currentEmail,
  onDone,
  onRemove,
}: {
  user: PublicUser;
  currentEmail: string;
  onDone: () => void;
  onRemove: (user: PublicUser) => void;
}) {
  if (user.email === currentEmail) return null;

  const isOwner = user.role === "owner";

  async function handleToggleRole() {
    const newRole = isOwner ? "member" : "owner";
    const resp = await fetch(`/v1/admin/users/${encodeURIComponent(user.email)}/role`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ role: newRole }),
    });
    if (!resp.ok) {
      const data = await resp.json().catch(() => ({}));
      alert(data.error || "Failed to change role");
      return;
    }
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

export default function AllUsersTab() {
  const { auth } = useRouteContext({ from: "/_auth" }) as { auth: AuthContext };
  const [users, setUsers] = useState<PublicUser[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [deleteTarget, setDeleteTarget] = useState<PublicUser | null>(null);

  const fetchUsers = useCallback(async () => {
    try {
      const resp = await fetch("/v1/users");
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
  }, []);

  useEffect(() => {
    fetchUsers();
  }, [fetchUsers]);

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

  const columns = useMemo<Column<PublicUser>[]>(() => {
    const cols: Column<PublicUser>[] = [
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
    ];

    if (auth.is_owner) {
      cols.push({
        key: "vaults",
        header: "Vaults",
        render: (u) => (
          <span className="text-sm text-text-muted">
            {u.vaults && u.vaults.length > 0 ? u.vaults.join(", ") : "\u2014"}
          </span>
        ),
      });
    }

    cols.push({
      key: "created_at",
      header: "Created",
      render: (u) => (
        <span className="text-sm text-text-muted">{timeAgo(u.created_at)}</span>
      ),
    });

    if (auth.is_owner) {
      cols.push({
        key: "actions",
        header: "",
        align: "right" as const,
        render: (u: PublicUser) => (
          <RowActions
            user={u}
            currentEmail={auth.email}
            onDone={fetchUsers}
            onRemove={setDeleteTarget}
          />
        ),
      });
    }

    return cols;
  }, [auth.is_owner, auth.email, fetchUsers]);

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

      {auth.is_owner && (
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
      )}
    </div>
  );
}
