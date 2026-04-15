import { useState, useEffect, useMemo } from "react";
import { Link, useNavigate, useRouteContext } from "@tanstack/react-router";
import type { AuthContext } from "../../router";
import Modal from "../../components/Modal";
import FormField from "../../components/FormField";
import Input from "../../components/Input";
import Button from "../../components/Button";
import ConfirmDeleteModal from "../../components/ConfirmDeleteModal";
import { ErrorBanner, LoadingSpinner, timeAgo } from "../../components/shared";
import { apiFetch } from "../../lib/api";

interface Vault {
  id: string;
  name: string;
  role: string;
  membership: "explicit" | "implicit";
  is_default?: boolean;
  created_at: string;
  pending_proposals: number;
}

export default function VaultsListTab() {
  const { auth } = useRouteContext({ from: "/_auth" }) as { auth: AuthContext };
  const navigate = useNavigate();
  const [vaults, setVaults] = useState<Vault[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [search, setSearch] = useState("");
  const [deleteTarget, setDeleteTarget] = useState<Vault | null>(null);

  useEffect(() => {
    fetchVaults();
  }, []);

  async function fetchVaults() {
    try {
      const resp = await apiFetch("/v1/vaults");
      if (resp.ok) {
        const data = await resp.json();
        setVaults(data.vaults || []);
      } else {
        const data = await resp.json();
        setError(data.error || "Failed to load vaults.");
      }
    } catch {
      setError("Network error. Please check your connection.");
    } finally {
      setLoading(false);
    }
  }

  async function handleDeleteVault() {
    if (!deleteTarget) return;
    const resp = await apiFetch(
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

  const filtered = useMemo(() => {
    if (!search.trim()) return vaults;
    const q = search.toLowerCase();
    return vaults.filter((v) => v.name.toLowerCase().includes(q));
  }, [vaults, search]);

  const myVaults = useMemo(() => filtered.filter((v) => v.membership === "explicit"), [filtered]);
  const otherVaults = useMemo(() => filtered.filter((v) => v.membership === "implicit"), [filtered]);

  return (
    <div className="w-full max-w-[960px] px-6 py-10">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h2 className="text-[22px] font-semibold text-text tracking-tight mb-1">
            Vaults
          </h2>
          <p className="text-sm text-text-muted">
            {auth.is_owner ? "All vaults across the instance." : "Vaults you have access to."}
          </p>
        </div>
        <CreateVaultButton onCreated={(name) => navigate({ to: "/vaults/$name", params: { name } })} />
      </div>

      {/* Search */}
      <div className="relative mb-6">
        <svg
          className="absolute left-4 top-1/2 -translate-y-1/2 w-[18px] h-[18px] text-text-dim"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
        >
          <circle cx="11" cy="11" r="8" />
          <line x1="21" y1="21" x2="16.65" y2="16.65" />
        </svg>
        <input
          type="text"
          placeholder="Search vaults..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="w-full pl-12 pr-4 py-3.5 bg-surface border border-border rounded-xl text-text text-sm outline-none transition-colors focus:border-border-focus focus:shadow-[0_0_0_3px_var(--color-primary-ring)]"
        />
      </div>

      {/* Content */}
      {loading ? (
        <LoadingSpinner />
      ) : error ? (
        <ErrorBanner message={error} />
      ) : filtered.length === 0 ? (
        <div className="text-center py-20 text-text-muted text-sm">
          {search ? "No vaults match your search." : "No vaults yet."}
        </div>
      ) : (
        <>
          {myVaults.length > 0 && (
            <div className={otherVaults.length > 0 ? "mb-10" : ""}>
              {otherVaults.length > 0 && (
                <h2 className="text-sm font-medium text-text-muted uppercase tracking-wide mb-3">My Vaults</h2>
              )}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                {myVaults.map((vault) => (
                  <VaultCard
                    key={vault.id}
                    vault={vault}
                    isOwner={auth.is_owner}
                    onDelete={setDeleteTarget}
                  />
                ))}
              </div>
            </div>
          )}
          {otherVaults.length > 0 && (
            <div>
              <h2 className="text-sm font-medium text-text-muted uppercase tracking-wide mb-3">Other Vaults</h2>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                {otherVaults.map((vault) => (
                  <VaultCard
                    key={vault.id}
                    vault={vault}
                    isOwner={auth.is_owner}
                    onJoined={fetchVaults}
                    onDelete={setDeleteTarget}
                  />
                ))}
              </div>
            </div>
          )}
        </>
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

function VaultCard({
  vault,
  isOwner,
  onJoined,
  onDelete,
}: {
  vault: Vault;
  isOwner: boolean;
  onJoined?: () => void;
  onDelete: (vault: Vault) => void;
}) {
  const [joining, setJoining] = useState(false);
  const [joinError, setJoinError] = useState("");
  const navigate = useNavigate();

  async function handleJoin(e: React.MouseEvent) {
    e.preventDefault();
    e.stopPropagation();
    setJoining(true);
    setJoinError("");
    try {
      const resp = await apiFetch(`/v1/vaults/${vault.name}/join`, { method: "POST" });
      if (resp.ok) {
        onJoined?.();
      } else {
        const data = await resp.json();
        setJoinError(data.error || "Failed to join vault.");
      }
    } catch {
      setJoinError("Network error.");
    } finally {
      setJoining(false);
    }
  }

  function handleDelete(e: React.MouseEvent) {
    e.preventDefault();
    e.stopPropagation();
    onDelete(vault);
  }

  const isImplicit = vault.membership === "implicit";
  const canDelete = isOwner && !vault.is_default;

  const card = (
    <div
      className={`bg-surface border border-border rounded-xl p-5 transition-colors ${isImplicit ? "" : "hover:border-border-focus/40 cursor-pointer"}`}
      onClick={isImplicit ? undefined : () => navigate({ to: "/vaults/$name", params: { name: vault.name } })}
    >
      <div className="flex items-start justify-between mb-3">
        <h3 className="text-base font-semibold text-text tracking-tight">
          {vault.name}
        </h3>
        <div className="flex items-center gap-2">
          {isImplicit ? (
            <button
              onClick={handleJoin}
              disabled={joining}
              className="inline-flex items-center gap-1.5 px-3 py-1 rounded-lg text-xs font-medium bg-primary text-primary-text hover:bg-primary-hover transition-colors disabled:opacity-50"
            >
              {joining ? "Joining..." : "Join"}
            </button>
          ) : vault.pending_proposals > 0 ? (
            <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold bg-warning-bg text-warning border border-warning/20">
              {vault.pending_proposals}{" "}
              {vault.pending_proposals === 1 ? "review needed" : "reviews needed"}
            </span>
          ) : null}
          {canDelete && (
            <button
              onClick={handleDelete}
              className="p-1 rounded text-text-dim hover:text-danger transition-colors"
              title="Delete vault"
            >
              <svg className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <polyline points="3 6 5 6 21 6" />
                <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2" />
              </svg>
            </button>
          )}
        </div>
      </div>
      {joinError && (
        <div className="text-xs text-danger mb-2">{joinError}</div>
      )}
      <div className="flex items-center gap-3 text-xs text-text-muted">
        <span className="flex items-center gap-1.5">
          <svg
            className="w-3.5 h-3.5"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          >
            <circle cx="12" cy="12" r="10" />
            <polyline points="12 6 12 12 16 14" />
          </svg>
          {timeAgo(vault.created_at)}
        </span>
        {vault.role && (
          <span className="text-text-dim">
            {vault.role}
          </span>
        )}
      </div>
    </div>
  );

  if (isImplicit) return card;

  return (
    <Link to="/vaults/$name" params={{ name: vault.name }} className="block no-underline">
      {card}
    </Link>
  );
}

function CreateVaultButton({ onCreated }: { onCreated: (name: string) => void }) {
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");

  function close() {
    setOpen(false);
    setName("");
    setError("");
  }

  async function handleCreate() {
    if (!name.trim()) return;
    setSubmitting(true);
    setError("");
    const trimmed = name.trim();
    try {
      const resp = await apiFetch("/v1/vaults", {
        method: "POST",
        body: JSON.stringify({ name: trimmed }),
      });
      if (resp.ok) {
        close();
        onCreated(trimmed);
      } else {
        const data = await resp.json();
        setError(data.error || "Failed to create vault.");
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
        New vault
      </Button>

      <Modal
        open={open}
        onClose={close}
        title="New Vault"
        description="Create an isolated environment with its own credentials and proxy rules."
        footer={
          <>
            <Button variant="secondary" onClick={close}>
              Cancel
            </Button>
            <Button
              onClick={handleCreate}
              loading={submitting}
              disabled={!name.trim()}
            >
              Create
            </Button>
          </>
        }
      >
        <FormField
          label="Vault Name"
          helperText="Lowercase letters, numbers, and hyphens. 3–64 characters."
          error={error}
        >
          <Input
            placeholder="e.g. my-project"
            value={name}
            onChange={(e) => setName(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") handleCreate();
            }}
            error={!!error}
            autoFocus
          />
        </FormField>
      </Modal>
    </>
  );
}
