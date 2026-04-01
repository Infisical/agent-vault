import { useState, useEffect, useMemo } from "react";
import { Link, useNavigate, useRouteContext } from "@tanstack/react-router";
import type { AuthContext } from "../router";
import Navbar from "../components/Navbar";
import Modal from "../components/Modal";
import FormField from "../components/FormField";
import Input from "../components/Input";
import Button from "../components/Button";
import { ErrorBanner, LoadingSpinner, timeAgo } from "../components/shared";
import { apiFetch } from "../lib/api";

interface Vault {
  id: string;
  name: string;
  role: string;
  membership: "explicit" | "implicit";
  created_at: string;
  pending_proposals: number;
}

export default function Vaults() {
  const { auth } = useRouteContext({ from: "/_auth" }) as { auth: AuthContext };
  const navigate = useNavigate();
  const [vaults, setVaults] = useState<Vault[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [search, setSearch] = useState("");

  useEffect(() => {
    fetchVaults();
  }, []);

  async function fetchVaults() {
    try {
      const resp = await fetch("/v1/vaults");
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

  const filtered = useMemo(() => {
    if (!search.trim()) return vaults;
    const q = search.toLowerCase();
    return vaults.filter((v) => v.name.toLowerCase().includes(q));
  }, [vaults, search]);

  const myVaults = useMemo(() => filtered.filter((v) => v.membership === "explicit"), [filtered]);
  const otherVaults = useMemo(() => filtered.filter((v) => v.membership === "implicit"), [filtered]);

  return (
    <div className="min-h-screen w-full flex flex-col bg-bg">
      <Navbar email={auth.email} isOwner={auth.is_owner} />
      <div className="flex-1 w-full max-w-[1200px] mx-auto px-6 py-10">
        {/* Header */}
        <div className="flex items-center justify-between mb-6">
          <h1 className="text-[28px] font-semibold tracking-tight text-text">
            Vaults
          </h1>
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
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
                  {myVaults.map((vault) => (
                    <VaultCard key={vault.id} vault={vault} />
                  ))}
                </div>
              </div>
            )}
            {otherVaults.length > 0 && (
              <div>
                <h2 className="text-sm font-medium text-text-muted uppercase tracking-wide mb-3">Other Vaults</h2>
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
                  {otherVaults.map((vault) => (
                    <VaultCard key={vault.id} vault={vault} onJoined={fetchVaults} />
                  ))}
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}

function VaultCard({ vault, onJoined }: { vault: Vault; onJoined?: () => void }) {
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

  const isImplicit = vault.membership === "implicit";

  const card = (
    <div
      className={`bg-surface border border-border rounded-xl p-5 transition-colors ${isImplicit ? "" : "hover:border-border-focus/40 cursor-pointer"}`}
      onClick={isImplicit ? undefined : () => navigate({ to: "/vaults/$name", params: { name: vault.name } })}
    >
      <div className="flex items-start justify-between mb-3">
        <h3 className="text-base font-semibold text-text tracking-tight">
          {vault.name}
        </h3>
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
        description="Create an isolated environment with its own credentials and broker rules."
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
          helperText="Vaults isolate credentials and broker rules."
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

