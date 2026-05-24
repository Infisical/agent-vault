import { useEffect, useState, Fragment } from "react";
import { useNavigate } from "@tanstack/react-router";
import { useVaultParams, ErrorBanner, timeAgo } from "./shared";
import { SyncStatusDot } from "../../components/shared";
import Button from "../../components/Button";
import Input from "../../components/Input";
import FormField from "../../components/FormField";
import ConfirmDeleteModal from "../../components/ConfirmDeleteModal";
import Toggle from "../../components/Toggle";
import { apiFetch } from "../../lib/api";

type UnmatchedHostPolicy = "passthrough" | "deny";

export default function SettingsTab() {
  const { vaultName, vaultRole, isOwner, credentialStore } = useVaultParams();
  const navigate = useNavigate();
  const canManage = vaultRole === "admin" || isOwner;
  const isDefault = vaultName === "default";

  // Rename state
  const [newName, setNewName] = useState(vaultName);
  const [renaming, setRenaming] = useState(false);
  const [renameError, setRenameError] = useState("");
  const [renameSuccess, setRenameSuccess] = useState("");

  // Delete state
  const [showDeleteModal, setShowDeleteModal] = useState(false);

  // null until the initial fetch lands; disables the toggle on first paint.
  const [policy, setPolicy] = useState<UnmatchedHostPolicy | null>(null);
  const [policySaving, setPolicySaving] = useState(false);
  const [policyError, setPolicyError] = useState("");

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const resp = await apiFetch(
          `/v1/vaults/${encodeURIComponent(vaultName)}/settings`
        );
        if (cancelled) return;
        if (!resp.ok) {
          setPolicy("passthrough");
          return;
        }
        const data = (await resp.json()) as {
          unmatched_host_policy?: UnmatchedHostPolicy;
        };
        if (cancelled) return;
        setPolicy(
          data.unmatched_host_policy === "deny" ? "deny" : "passthrough"
        );
      } catch {
        if (!cancelled) setPolicy("passthrough");
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [vaultName]);

  async function handlePolicyToggle(strictDeny: boolean) {
    const next: UnmatchedHostPolicy = strictDeny ? "deny" : "passthrough";
    const previous = policy;
    setPolicy(next);
    setPolicySaving(true);
    setPolicyError("");
    try {
      const resp = await apiFetch(
        `/v1/vaults/${encodeURIComponent(vaultName)}/settings`,
        {
          method: "PATCH",
          body: JSON.stringify({ unmatched_host_policy: next }),
        }
      );
      if (!resp.ok) {
        const data = await resp.json().catch(() => ({}));
        setPolicy(previous);
        setPolicyError(data.error || "Failed to update policy");
      }
    } catch {
      setPolicy(previous);
      setPolicyError("Network error");
    } finally {
      setPolicySaving(false);
    }
  }

  async function handleRename(e: React.FormEvent) {
    e.preventDefault();
    if (!newName || newName === vaultName) return;

    setRenaming(true);
    setRenameError("");
    setRenameSuccess("");

    try {
      const resp = await apiFetch(
        `/v1/vaults/${encodeURIComponent(vaultName)}/rename`,
        {
          method: "POST",
          body: JSON.stringify({ name: newName }),
        }
      );
      if (!resp.ok) {
        const data = await resp.json().catch(() => ({}));
        setRenameError(data.error || "Failed to rename vault");
        return;
      }
      setRenameSuccess(`Vault renamed to "${newName}"`);
      // Navigate to the new vault URL after a brief pause
      setTimeout(() => {
        navigate({
          to: "/vaults/$name/settings",
          params: { name: newName },
        });
      }, 500);
    } catch {
      setRenameError("Network error");
    } finally {
      setRenaming(false);
    }
  }

  async function handleDelete() {
    const resp = await apiFetch(
      `/v1/vaults/${encodeURIComponent(vaultName)}`,
      { method: "DELETE" }
    );
    if (!resp.ok) {
      const data = await resp.json().catch(() => ({}));
      throw new Error(data.error || "Failed to delete vault");
    }
    navigate({ to: "/" });
  }

  return (
    <div className="p-8 w-full max-w-[960px]">
      <div className="mb-6">
        <h2 className="text-[22px] font-semibold text-text tracking-tight mb-1">
          Settings
        </h2>
        <p className="text-sm text-text-muted">
          Manage vault configuration and preferences.
        </p>
      </div>

      {/* Credential store (read-only; immutable post-create) */}
      <section className="mb-8">
        <div className="border border-border rounded-xl bg-surface p-5">
          <h3 className="text-sm font-semibold text-text mb-1">Credential store</h3>
          {!credentialStore ? (
            <p className="text-sm text-text-muted">
              Agent Vault (built-in). Credentials are stored locally and managed through this UI.
            </p>
          ) : (
            <div className="space-y-2 text-sm">
              <p className="text-text-muted">
                This vault is backed by{" "}
                <span className="font-medium text-text">{credentialStore.kind}</span>.
                Credential mutations from Agent Vault are disabled; manage credentials in the
                upstream system.
              </p>
              {credentialStore.config && (
                <dl className="grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1 text-xs text-text-muted">
                  {Object.entries(credentialStore.config).map(([k, v]) => (
                    <Fragment key={k}>
                      <dt className="text-text-dim">{k}</dt>
                      <dd className="text-text break-all">{String(v)}</dd>
                    </Fragment>
                  ))}
                </dl>
              )}
              <div className="flex flex-wrap items-center gap-3 pt-2 text-xs text-text-muted">
                {credentialStore.poll_interval_seconds && (
                  <span>Poll every {credentialStore.poll_interval_seconds}s</span>
                )}
                {credentialStore.last_sync_status && (
                  <span className="inline-flex items-center gap-1.5">
                    <SyncStatusDot status={credentialStore.last_sync_status} />
                    Last sync: {credentialStore.last_sync_status}
                  </span>
                )}
                {credentialStore.last_synced_at && (
                  <span>{timeAgo(credentialStore.last_synced_at)}</span>
                )}
              </div>
              {credentialStore.last_sync_error && (
                <ErrorBanner message={credentialStore.last_sync_error} className="mt-2" />
              )}
            </div>
          )}
        </div>
      </section>

      {/* Vault config (rename + unmatched-host policy) */}
      <section className="mb-8">
        <div className="border border-border rounded-xl bg-surface p-5">
          <div className="max-w-md">
            <form onSubmit={handleRename} className="flex items-end gap-3">
              <div className="flex-1 min-w-0">
                <FormField label="Vault Name">
                  <Input
                    value={newName}
                    onChange={(e) => {
                      setNewName(e.target.value);
                      setRenameError("");
                      setRenameSuccess("");
                    }}
                    disabled={!canManage || isDefault}
                    placeholder="vault-name"
                  />
                </FormField>
              </div>
              <Button
                type="submit"
                disabled={!canManage || isDefault || !newName || newName === vaultName}
                loading={renaming}
              >
                Rename
              </Button>
            </form>

            {renameError && <ErrorBanner message={renameError} className="mt-3" />}
            {renameSuccess && (
              <div className="mt-3 bg-success-bg border border-success/20 rounded-lg p-4 text-sm text-success">
                {renameSuccess}
              </div>
            )}

            <div className="mt-5 pt-5 border-t border-border">
              <label className="block text-xs font-semibold uppercase tracking-wider text-text-muted mb-2">
                Strict deny mode
              </label>
              <div className="flex items-center justify-between gap-3">
                <p className="text-sm text-text-muted flex-1 min-w-0">
                  Reject unmatched hosts with HTTP 403 instead of forwarding them upstream unauthenticated.
                </p>
                <Toggle
                  checked={policy === "deny"}
                  onChange={handlePolicyToggle}
                  disabled={!canManage || policy === null || policySaving}
                  ariaLabel="Strict deny mode"
                />
              </div>
            </div>
            {policyError && (
              <ErrorBanner message={policyError} className="mt-3" />
            )}
          </div>
        </div>
      </section>

      {/* Danger zone */}
      <section>
        <div className="border border-danger/20 rounded-xl bg-surface p-5">
          <h3 className="text-sm font-semibold text-danger mb-1">Danger Zone</h3>
          <p className="text-sm text-text-muted mb-4">
            {isDefault
              ? "The default vault cannot be deleted."
              : "Permanently delete this vault, including its services, credentials, and proposals. This action cannot be undone."}
          </p>
          <Button
            variant="secondary"
            onClick={() => setShowDeleteModal(true)}
            disabled={!canManage || isDefault}
            className={canManage && !isDefault ? "!text-danger !border-danger/30 hover:!bg-danger-bg" : ""}
          >
            Delete vault
          </Button>
        </div>
      </section>

      {/* Delete confirmation modal */}
      <ConfirmDeleteModal
        open={showDeleteModal}
        onClose={() => setShowDeleteModal(false)}
        onConfirm={handleDelete}
        title="Delete vault"
        description={`This will permanently delete "${vaultName}" and all associated data. Type the vault name to confirm.`}
        confirmLabel="Delete permanently"
        confirmValue={vaultName}
        inputLabel="Vault name"
      />
    </div>
  );
}
