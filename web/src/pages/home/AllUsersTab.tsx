import { useState, useEffect, useMemo, useCallback } from "react";
import { useRouteContext } from "@tanstack/react-router";
import { LoadingSpinner, ErrorBanner, timeAgo } from "../../components/shared";
import DataTable, { type Column } from "../../components/DataTable";
import DropdownMenu from "../../components/DropdownMenu";
import ConfirmDeleteModal from "../../components/ConfirmDeleteModal";
import Modal from "../../components/Modal";
import Button from "../../components/Button";
import Input from "../../components/Input";
import FormField from "../../components/FormField";
import CopyButton from "../../components/CopyButton";
import { apiFetch } from "../../lib/api";
import type { AuthContext } from "../../router";

interface PublicUser {
  email: string;
  role: string;
  status: "active" | "pending";
  vaults?: string[];
  created_at: string;
  invite_token?: string;
}

interface VaultOption {
  id: string;
  name: string;
  role: string;
}

function RowActions({
  user,
  currentEmail,
  onDone,
  onRemove,
  onError,
}: {
  user: PublicUser;
  currentEmail: string;
  onDone: () => void;
  onRemove: (user: PublicUser) => void;
  onError: (msg: string) => void;
}) {
  if (user.email === currentEmail) return null;

  if (user.status === "pending") {
    return (
      <DropdownMenu
        width={192}
        items={[
          { label: "Revoke invite", onClick: () => onRemove(user), variant: "danger" },
        ]}
      />
    );
  }

  const isOwner = user.role === "owner";

  async function handleToggleRole() {
    const newRole = isOwner ? "member" : "owner";
    const resp = await apiFetch(`/v1/admin/users/${encodeURIComponent(user.email)}/role`, {
      method: "POST",
      body: JSON.stringify({ role: newRole }),
    });
    if (!resp.ok) {
      const data = await resp.json().catch(() => ({}));
      onError(data.error || "Failed to change role");
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
      const [usersResp, invResp] = await Promise.all([
        apiFetch("/v1/users"),
        apiFetch("/v1/users/invites?status=pending"),
      ]);

      if (!usersResp.ok) {
        const data = await usersResp.json();
        setError(data.error || "Failed to load users.");
        return;
      }
      const data = await usersResp.json();
      const activeUsers: PublicUser[] = (data.users ?? []).map(
        (u: PublicUser) => ({ ...u, status: "active" as const })
      );

      let pendingUsers: PublicUser[] = [];
      if (invResp.ok) {
        const invData = await invResp.json();
        pendingUsers = (invData.invites ?? []).map(
          (inv: { email: string; token: string; created_at: string; vaults?: { vault_name: string }[] }) => ({
            email: inv.email,
            role: "member",
            status: "pending" as const,
            vaults: inv.vaults?.map((v: { vault_name: string }) => v.vault_name) ?? [],
            created_at: inv.created_at,
            invite_token: inv.token,
          })
        );
      }

      setUsers([...activeUsers, ...pendingUsers]);
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
    if (deleteTarget.status === "pending") {
      if (!deleteTarget.invite_token) return;
      const resp = await apiFetch(
        `/v1/users/invites/${encodeURIComponent(deleteTarget.invite_token)}`,
        { method: "DELETE" }
      );
      if (!resp.ok) {
        const data = await resp.json().catch(() => ({}));
        throw new Error(data.error || "Failed to revoke invite");
      }
      setDeleteTarget(null);
      fetchUsers();
      return;
    }
    const resp = await apiFetch(
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
        key: "status",
        header: "Status",
        render: (u) => (
          <span className={`text-xs font-medium px-2 py-0.5 rounded-full ${
            u.status === "pending"
              ? "bg-yellow-500/10 text-yellow-500"
              : "bg-green-500/10 text-green-500"
          }`}>
            {u.status === "pending" ? "Pending" : "Active"}
          </span>
        ),
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
            onError={setError}
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
        <InviteUserButton onInvited={fetchUsers} isOwner={auth.is_owner} />
      </div>

      {loading ? (
        <LoadingSpinner />
      ) : error ? (
        <ErrorBanner message={error} />
      ) : (
        <DataTable
          columns={columns}
          data={users}
          rowKey={(u) => u.email + u.status}
          emptyTitle="No users"
          emptyDescription="No users have registered yet."
        />
      )}

      {auth.is_owner && deleteTarget?.status !== "pending" && (
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

interface VaultAssignment {
  vault_name: string;
  vault_role: "member" | "admin";
}

function InviteUserButton({
  onInvited,
  isOwner,
}: {
  onInvited: () => void;
  isOwner: boolean;
}) {
  const [open, setOpen] = useState(false);
  const [email, setEmail] = useState("");
  const [vaultAssignments, setVaultAssignments] = useState<VaultAssignment[]>([]);
  const [availableVaults, setAvailableVaults] = useState<VaultOption[]>([]);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");
  const [inviteLink, setInviteLink] = useState("");

  useEffect(() => {
    if (!open) return;
    // Fetch vaults the user can assign
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
    setEmail("");
    setVaultAssignments([]);
    setError("");
    setInviteLink("");
  }

  function addVault() {
    const assignedNames = new Set(vaultAssignments.map((a) => a.vault_name));
    const next = availableVaults.find((v) => !assignedNames.has(v.name));
    if (next) {
      setVaultAssignments([...vaultAssignments, { vault_name: next.name, vault_role: "member" }]);
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

  async function handleInvite() {
    if (!email.trim()) return;
    setSubmitting(true);
    setError("");
    try {
      const payload: Record<string, unknown> = { email: email.trim() };
      if (vaultAssignments.length > 0) {
        payload.vaults = vaultAssignments;
      }
      const resp = await apiFetch("/v1/users/invites", {
        method: "POST",
        body: JSON.stringify(payload),
      });
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
        description={inviteLink ? "Share this link to grant access." : "Invite a user to Agent Vault."}
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
                  No vaults pre-assigned. User will join the instance without vault access.
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
                      <select
                        value={assignment.vault_role}
                        onChange={(e) => updateVault(idx, "vault_role", e.target.value)}
                        className="w-28 px-3 py-2 bg-surface border border-border rounded-lg text-text text-sm outline-none"
                      >
                        <option value="member">Member</option>
                        <option value="admin">Admin</option>
                      </select>
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
