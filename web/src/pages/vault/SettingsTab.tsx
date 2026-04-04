import { useState } from "react";
import { useNavigate } from "@tanstack/react-router";
import { useVaultParams, ErrorBanner } from "./shared";
import Button from "../../components/Button";
import Input from "../../components/Input";
import FormField from "../../components/FormField";
import ConfirmDeleteModal from "../../components/ConfirmDeleteModal";
import { apiFetch } from "../../lib/api";

export default function SettingsTab() {
  const { vaultName, vaultRole, isOwner } = useVaultParams();
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
    navigate({ to: "/vaults" });
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

      {/* Rename section */}
      <section className="mb-8">
        <div className="border border-border rounded-xl bg-surface p-5">
          <form onSubmit={handleRename} className="flex items-end gap-3">
            <div className="flex-1 max-w-xs">
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
