import { useState, useEffect } from "react";
import {
  useVaultParams,
  LoadingSpinner,
  ErrorBanner,
  StatusBadge,
} from "./shared";
import DataTable, { type Column } from "../../components/DataTable";
import Modal from "../../components/Modal";
import DropdownMenu, { type DropdownMenuItem } from "../../components/DropdownMenu";
import Button from "../../components/Button";
import Select from "../../components/Select";
import FormField from "../../components/FormField";
import { apiFetch } from "../../lib/api";

interface VaultUser {
  email: string;
  role: string;
  status: "active" | "pending";
}

function RowActions({
  user,
  vaultName,
  currentEmail,
  onDone,
  onError,
}: {
  user: VaultUser;
  vaultName: string;
  currentEmail: string;
  onDone: () => void;
  onError: (msg: string) => void;
}) {
  if (user.email === currentEmail) return null;

  const newRole = user.role === "admin" ? "member" : "admin";

  async function handleChangeRole() {
    const resp = await apiFetch(
      `/v1/vaults/${encodeURIComponent(vaultName)}/users/${encodeURIComponent(user.email)}/role`,
      {
        method: "POST",
        body: JSON.stringify({ role: newRole }),
      }
    );
    if (!resp.ok) {
      const data = await resp.json().catch(() => ({}));
      onError(data.error || "Failed to change role");
      return;
    }
    onDone();
  }

  async function handleRemove() {
    const resp = await apiFetch(
      `/v1/vaults/${encodeURIComponent(vaultName)}/users/${encodeURIComponent(user.email)}`,
      { method: "DELETE" }
    );
    if (!resp.ok) {
      const data = await resp.json().catch(() => ({}));
      onError(data.error || "Failed to remove user");
      return;
    }
    onDone();
  }

  const items: DropdownMenuItem[] = [
    { label: `Make ${newRole}`, onClick: handleChangeRole },
    {
      label: "Remove",
      onClick: handleRemove,
      variant: "danger" as const,
    },
  ];

  return <DropdownMenu items={items} width={192} />;
}

export default function UsersTab() {
  const { vaultName, vaultRole, email: currentEmail } = useVaultParams();
  const [users, setUsers] = useState<VaultUser[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const columns: Column<VaultUser>[] = [
    {
      key: "email",
      header: "Email",
      render: (u) => <span className="text-sm text-text">{u.email}</span>,
    },
    {
      key: "status",
      header: "Status",
      render: (u) => <StatusBadge status={u.status} />,
    },
    {
      key: "role",
      header: "Role",
      render: (u) => (
        <span className="text-sm text-text-muted capitalize">{u.role}</span>
      ),
    },
    ...(vaultRole === "admin"
      ? [
          {
            key: "actions" as const,
            header: "",
            align: "right" as const,
            render: (u: VaultUser) => (
              <RowActions
                user={u}
                vaultName={vaultName}
                currentEmail={currentEmail}
                onDone={fetchUsers}
                onError={setError}
              />
            ),
          },
        ]
      : []),
  ];

  useEffect(() => {
    fetchUsers();
  }, []);

  async function fetchUsers() {
    try {
      const resp = await apiFetch(
        `/v1/vaults/${encodeURIComponent(vaultName)}/users`
      );
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

  return (
    <div className="p-8 w-full max-w-[960px]">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h2 className="text-[22px] font-semibold text-text tracking-tight mb-1">
            Users
          </h2>
          <p className="text-sm text-text-muted">
            People with access to this vault.
          </p>
        </div>
        {vaultRole === "admin" && (
          <AddUserButton vaultName={vaultName} vaultUsers={users} onAdded={fetchUsers} />
        )}
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
          emptyDescription="Add existing instance users to give them access to this vault."
        />
      )}
    </div>
  );
}

interface InstanceUser {
  email: string;
  role: string;
}

function AddUserButton({
  vaultName,
  vaultUsers,
  onAdded,
}: {
  vaultName: string;
  vaultUsers: VaultUser[];
  onAdded: () => void;
}) {
  const [open, setOpen] = useState(false);
  const [email, setEmail] = useState("");
  const [role, setRole] = useState<"member" | "admin">("member");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");
  const [instanceUsers, setInstanceUsers] = useState<InstanceUser[]>([]);

  useEffect(() => {
    if (!open) return;
    apiFetch("/v1/users")
      .then((r) => r.json())
      .then((data) => setInstanceUsers(data.users ?? []))
      .catch(() => {});
  }, [open]);

  const availableUsers = instanceUsers.filter(
    (u) => !vaultUsers.some((vu) => vu.email === u.email)
  );

  function close() {
    setOpen(false);
    setEmail("");
    setRole("member");
    setError("");
  }

  async function handleAdd() {
    if (!email) return;
    setSubmitting(true);
    setError("");
    try {
      const resp = await apiFetch(
        `/v1/vaults/${encodeURIComponent(vaultName)}/users`,
        {
          method: "POST",
          body: JSON.stringify({ email, role }),
        }
      );
      if (resp.ok) {
        onAdded();
        close();
      } else {
        const data = await resp.json();
        setError(data.error || "Failed to add user.");
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
          <path d="M16 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2" />
          <circle cx="8.5" cy="7" r="4" />
          <line x1="20" y1="8" x2="20" y2="14" />
          <line x1="23" y1="11" x2="17" y2="11" />
        </svg>
        Add user
      </Button>

      <Modal
        open={open}
        onClose={close}
        title="Add User to Vault"
        description="Grant an existing instance user access to this vault."
        footer={
          <>
            <Button variant="secondary" onClick={close}>Cancel</Button>
            <Button
              onClick={handleAdd}
              disabled={!email}
              loading={submitting}
            >
              Add user
            </Button>
          </>
        }
      >
        <div className="space-y-4">
          <FormField label="User">
            {availableUsers.length === 0 ? (
              <p className="text-sm text-text-muted py-2">
                All instance users already have access to this vault.
              </p>
            ) : (
              <Select
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                autoFocus
              >
                <option value="" disabled>Select a user...</option>
                {availableUsers.map((u) => (
                  <option key={u.email} value={u.email}>{u.email}</option>
                ))}
              </Select>
            )}
          </FormField>
          <FormField
            label="Role"
            helperText={<>{role === "member"
              ? "Manage credentials, use proxy, approve proposals, and manage services."
              : "All member permissions, plus invite users and agents with any role."} <a href="https://docs.agent-vault.dev/learn/permissions#vault-roles" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">Learn more</a></>}
          >
            <Select
              value={role}
              onChange={(e) => setRole(e.target.value as "member" | "admin")}
            >
              <option value="member">Member</option>
              <option value="admin">Admin</option>
            </Select>
          </FormField>
          {error && <ErrorBanner message={error} />}
        </div>
      </Modal>
    </>
  );
}
