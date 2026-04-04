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
import Input from "../../components/Input";
import Select from "../../components/Select";
import FormField from "../../components/FormField";
import CopyButton from "../../components/CopyButton";
import { apiFetch } from "../../lib/api";

interface VaultUser {
  email: string;
  role: string;
  status: "active" | "pending";
  invite_token?: string;
}

function RowActions({
  user,
  vaultName,
  currentEmail,
  onDone,
  onReinviteLink,
}: {
  user: VaultUser;
  vaultName: string;
  currentEmail: string;
  onDone: () => void;
  onReinviteLink: (email: string, link: string) => void;
}) {
  if (user.email === currentEmail) return null;

  const newRole = user.role === "admin" ? "member" : "admin";

  async function handleChangeRole() {
    let resp: Response;
    if (user.status === "pending" && user.invite_token) {
      resp = await apiFetch(
        `/v1/vaults/${encodeURIComponent(vaultName)}/invites/${encodeURIComponent(user.invite_token)}`,
        {
          method: "PATCH",
          body: JSON.stringify({ role: newRole }),
        }
      );
    } else {
      resp = await apiFetch(
        `/v1/vaults/${encodeURIComponent(vaultName)}/users/${encodeURIComponent(user.email)}/role`,
        {
          method: "POST",
          body: JSON.stringify({ role: newRole }),
        }
      );
    }
    if (!resp.ok) {
      const data = await resp.json().catch(() => ({}));
      alert(data.error || "Failed to change role");
      return;
    }
    onDone();
  }

  async function handleRemove() {
    let resp: Response;
    if (user.status === "pending" && user.invite_token) {
      resp = await fetch(
        `/v1/vaults/${encodeURIComponent(vaultName)}/invites/${encodeURIComponent(user.invite_token)}`,
        { method: "DELETE" }
      );
    } else {
      resp = await fetch(
        `/v1/vaults/${encodeURIComponent(vaultName)}/users/${encodeURIComponent(user.email)}`,
        { method: "DELETE" }
      );
    }
    if (!resp.ok) {
      const data = await resp.json().catch(() => ({}));
      alert(data.error || "Failed to remove user");
      return;
    }
    onDone();
  }

  async function handleReinvite() {
    const resp = await fetch(
      `/v1/vaults/${encodeURIComponent(vaultName)}/invites/${encodeURIComponent(user.invite_token!)}/reinvite`,
      { method: "POST" }
    );
    if (resp.ok) {
      const data = await resp.json();
      onDone();
      if (!data.email_sent && data.invite_link) {
        onReinviteLink(user.email, data.invite_link);
      }
    }
  }

  const items: DropdownMenuItem[] = [
    { label: `Make ${newRole}`, onClick: handleChangeRole },
    ...(user.status === "pending" && user.invite_token
      ? [{ label: "Reinvite", onClick: handleReinvite }]
      : []),
    {
      label: user.status === "pending" ? "Delete" : "Remove",
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
  const [reinviteLink, setReinviteLink] = useState<{
    email: string;
    link: string;
  } | null>(null);

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
                onReinviteLink={(email, link) =>
                  setReinviteLink({ email, link })
                }
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
      const usersResp = await fetch(
        `/v1/vaults/${encodeURIComponent(vaultName)}/users`
      );
      if (!usersResp.ok) {
        const data = await usersResp.json();
        setError(data.error || "Failed to load users.");
        return;
      }
      const usersData = await usersResp.json();
      const activeUsers: VaultUser[] = (usersData.users ?? []).map(
        (u: { email: string; role: string }) => ({
          ...u,
          status: "active" as const,
        })
      );

      // Fetch pending invites if admin
      let pendingUsers: VaultUser[] = [];
      if (vaultRole === "admin") {
        const invResp = await fetch(
          `/v1/vaults/${encodeURIComponent(vaultName)}/invites?status=pending`
        );
        if (invResp.ok) {
          const invData = await invResp.json();
          pendingUsers = (invData.invites ?? []).map(
            (inv: { email: string; role: string; token: string }) => ({
              email: inv.email,
              role: inv.role,
              status: "pending" as const,
              invite_token: inv.token,
            })
          );
        }
      }

      setUsers([...activeUsers, ...pendingUsers]);
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
          <InviteUserButton vaultName={vaultName} onInvited={fetchUsers} />
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
          emptyDescription="Invite people to give them access to this vault."
        />
      )}

      <Modal
        open={!!reinviteLink}
        onClose={() => setReinviteLink(null)}
        title="Invite Link"
        description="Share this link to grant vault access."
        footer={
          <Button onClick={() => setReinviteLink(null)}>Done</Button>
        }
      >
        {reinviteLink && (
          <div className="space-y-4">
            <p className="text-sm text-text-muted">
              Email delivery is not configured. Share this link with{" "}
              <span className="font-medium text-text">
                {reinviteLink.email}
              </span>{" "}
              so they can accept the invite.
            </p>
            <div className="flex items-center gap-2">
              <Input
                readOnly
                value={reinviteLink.link}
                className="flex-1 px-4 py-3 bg-bg border border-border rounded-lg text-text text-sm font-mono outline-none select-all"
                onFocus={(e) => e.target.select()}
              />
              <CopyButton value={reinviteLink.link} />
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
}

function InviteUserButton({
  vaultName,
  onInvited,
}: {
  vaultName: string;
  onInvited: () => void;
}) {
  const [open, setOpen] = useState(false);
  const [email, setEmail] = useState("");
  const [role, setRole] = useState<"member" | "admin">("member");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");
  const [inviteLink, setInviteLink] = useState("");

  function close() {
    setOpen(false);
    setEmail("");
    setRole("member");
    setError("");
    setInviteLink("");
  }

  async function handleInvite() {
    if (!email.trim()) return;
    setSubmitting(true);
    setError("");
    try {
      const resp = await apiFetch(
        `/v1/vaults/${encodeURIComponent(vaultName)}/invites`,
        {
          method: "POST",
          body: JSON.stringify({ email: email.trim(), role }),
        }
      );
      const data = await resp.json();
      if (resp.ok) {
        onInvited();
        if (data.email_sent) {
          close();
        } else {
          setInviteLink(data.invite_link || "");
        }
      } else {
        setError(data.error || "Failed to send invite.");
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
        Invite user
      </Button>

      <Modal
        open={open}
        onClose={close}
        title={inviteLink ? "Invite Created" : "Invite User"}
        description={inviteLink ? "Share this link to grant vault access." : "Grant a user access to this vault."}
        footer={
          inviteLink ? (
            <Button onClick={close}>Done</Button>
          ) : (
            <>
              <Button variant="secondary" onClick={close}>Cancel</Button>
              <Button
                onClick={handleInvite}
                disabled={!email.trim()}
                loading={submitting}
              >
                Send invite
              </Button>
            </>
          )
        }
      >
        {inviteLink ? (
          <div className="space-y-4">
            <p className="text-sm text-text-muted">
              Email delivery is not configured. Share this link with{" "}
              <span className="font-medium text-text">{email}</span> so
              they can accept the invite.
            </p>
            <div className="flex items-center gap-2">
              <Input
                readOnly
                value={inviteLink}
                className="flex-1 px-4 py-3 bg-bg border border-border rounded-lg text-text text-sm font-mono outline-none select-all"
                onFocus={(e) => e.target.select()}
              />
              <CopyButton value={inviteLink} />
            </div>
          </div>
        ) : (
          <div className="space-y-4">
            <FormField label="Email">
              <Input
                type="email"
                placeholder="name@company.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") handleInvite();
                }}
                autoFocus
              />
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
        )}
      </Modal>
    </>
  );
}
