import { useEffect, useState, type ReactNode } from "react";
import { useNavigate, useRouter } from "@tanstack/react-router";
import { useVaultParams, ErrorBanner, timeAgo } from "./shared";
import type { CredentialStoreInfo } from "../../router";
import Button from "../../components/Button";
import ConfirmDeleteModal from "../../components/ConfirmDeleteModal";
import InfoTooltip from "../../components/InfoTooltip";
import Sheet from "../../components/Sheet";
import VaultForm, {
  infisicalFieldsValid,
  buildInfisicalConfig,
  type VaultFormValues,
} from "../../components/VaultForm";
import { apiFetch } from "../../lib/api";

type UnmatchedHostPolicy = "passthrough" | "deny";

// Shape of an Infisical credential store's config (server stores it untyped).
type InfisicalConfig = {
  project_id?: string;
  environment?: string;
  secret_path?: string;
};

export default function SettingsTab() {
  const { vaultName, vaultRole, isOwner, credentialStore } = useVaultParams();
  const navigate = useNavigate();
  const canManage = vaultRole === "admin" || isOwner;
  const isDefault = vaultName === "default";

  // Delete state
  const [showDeleteModal, setShowDeleteModal] = useState(false);

  // Edit-settings drawer.
  const [editing, setEditing] = useState(false);

  // null until the initial fetch lands; keeps the displayed policy blank on
  // first paint and gates the drawer toggle.
  const [policy, setPolicy] = useState<UnmatchedHostPolicy | null>(null);

  // Whether the server can back vaults with Infisical (controls the switcher).
  const [infisicalAvailable, setInfisicalAvailable] = useState(false);

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
          infisical_available?: boolean;
        };
        if (cancelled) return;
        setPolicy(
          data.unmatched_host_policy === "deny" ? "deny" : "passthrough"
        );
        setInfisicalAvailable(!!data.infisical_available);
      } catch {
        if (!cancelled) setPolicy("passthrough");
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [vaultName]);

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

      {/* Read-only vault config; editing happens in the side drawer. */}
      <section className="mb-8">
        <div className="relative border border-border rounded-xl bg-surface">
          {canManage && (
            <Button
              variant="secondary"
              onClick={() => setEditing(true)}
              className="absolute top-4 right-4 !px-3 !py-1.5"
            >
              Edit settings
            </Button>
          )}
          <div className="p-5">
            <StoreField label="Vault Name" value={vaultName} />
          </div>

          <div className="border-t border-border mx-5" />

          <div className="p-5">
            <StoreField
              label="Strict deny mode"
              tooltip="Reject unmatched hosts with HTTP 403 instead of forwarding them upstream unauthenticated."
              value={
                policy === null
                  ? "—"
                  : policy === "deny"
                    ? "Enabled"
                    : "Disabled"
              }
            />
          </div>

          <CredentialStoreDisplay store={credentialStore} />
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

      <EditSettingsSheet
        open={editing}
        onClose={() => setEditing(false)}
        vaultName={vaultName}
        isDefault={isDefault}
        policy={policy}
        onPolicySaved={setPolicy}
        store={credentialStore}
        infisicalAvailable={infisicalAvailable}
      />
    </div>
  );
}

function CredentialStoreDisplay({ store }: { store?: CredentialStoreInfo }) {
  const config = (store?.config ?? {}) as InfisicalConfig;
  const isInfisical = store?.kind === "infisical";
  const kindLabel = !store ? "Built-in" : isInfisical ? "Infisical" : store.kind;

  return (
    <>
      <div className="border-t border-border mx-5" />
      <div className="p-5 grid grid-cols-2 gap-x-6 gap-y-4">
        <div className="col-span-2">
          <StoreField
            label="Credential store"
            tooltip="Built-in keeps credentials in Agent Vault. Infisical syncs read-only from your Infisical instance, overwriting the built-in credentials."
            value={kindLabel}
          />
        </div>
        {/* Config is redacted server-side for non-admin viewers; sync status
            stays populated for everyone. */}
        {isInfisical && store?.config && (
          <>
            <StoreField label="Project" value={config.project_id ?? "—"} />
            <StoreField label="Environment" value={config.environment ?? "—"} />
            <StoreField label="Secret path" value={config.secret_path || "/"} />
          </>
        )}
        {isInfisical && store?.last_synced_at && (
          <StoreField
            label={store.last_sync_status === "error" ? "Last attempt" : "Last sync"}
            value={timeAgo(store.last_synced_at)}
          />
        )}
      </div>

      {store?.last_sync_error && (
        <div className="px-5 pb-4">
          <ErrorBanner message={store.last_sync_error} />
        </div>
      )}
    </>
  );
}

function EditSettingsSheet({
  open,
  onClose,
  vaultName,
  isDefault,
  policy,
  onPolicySaved,
  store,
  infisicalAvailable,
}: {
  open: boolean;
  onClose: () => void;
  vaultName: string;
  isDefault: boolean;
  policy: UnmatchedHostPolicy | null;
  onPolicySaved: (p: UnmatchedHostPolicy) => void;
  store?: CredentialStoreInfo;
  infisicalAvailable: boolean;
}) {
  const navigate = useNavigate();
  const router = useRouter();

  const config = (store?.config ?? {}) as InfisicalConfig;
  const currentKind: "builtin" | "infisical" =
    store?.kind === "infisical" ? "infisical" : "builtin";

  const initialValues: VaultFormValues = {
    name: vaultName,
    policy: policy ?? "passthrough",
    kind: currentKind,
    projectID: config.project_id ?? "",
    environment: config.environment ?? "",
    secretPath: config.secret_path || "/",
  };

  // Draft state, re-seeded from the live values each time the drawer opens.
  const [values, setValues] = useState<VaultFormValues>(initialValues);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [showConfirm, setShowConfirm] = useState(false);

  useEffect(() => {
    if (!open) return;
    setValues(initialValues);
    setError("");
    setShowConfirm(false);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  const switchToInfisical = values.kind === "infisical";
  const trimmedName = values.name.trim();

  const nameChanged = !isDefault && !!trimmedName && trimmedName !== vaultName;
  const policyChanged = policy !== null && values.policy !== policy;
  const configChanged =
    switchToInfisical &&
    (values.projectID.trim() !== (config.project_id ?? "") ||
      values.environment.trim() !== (config.environment ?? "") ||
      (values.secretPath.trim() || "/") !== (config.secret_path || "/"));
  const storeChanged = values.kind !== currentKind || configChanged;

  // nameChanged already implies a non-empty trimmed name, so no extra guard.
  const canSave =
    (nameChanged || policyChanged || storeChanged) &&
    infisicalFieldsValid(values);

  // Runs every pending change in a safe order: non-destructive first, then the
  // credential-store overwrite, then rename last (it changes the vault URL).
  async function applyChanges() {
    setSaving(true);
    setError("");
    try {
      if (policyChanged) {
        const resp = await apiFetch(
          `/v1/vaults/${encodeURIComponent(vaultName)}/settings`,
          {
            method: "PATCH",
            body: JSON.stringify({ unmatched_host_policy: values.policy }),
          }
        );
        if (!resp.ok) {
          const data = await resp.json().catch(() => ({}));
          throw new Error(data.error || "Failed to update policy");
        }
        onPolicySaved(values.policy);
      }

      if (storeChanged) {
        const body: Record<string, unknown> = { kind: values.kind };
        if (switchToInfisical) {
          body.config = buildInfisicalConfig(values);
        }
        const resp = await apiFetch(
          `/v1/vaults/${encodeURIComponent(vaultName)}/credential-store`,
          { method: "PATCH", body: JSON.stringify(body) }
        );
        if (!resp.ok) {
          const data = await resp.json().catch(() => ({}));
          throw new Error(data.error || "Failed to switch credential store");
        }
      }

      if (nameChanged) {
        const resp = await apiFetch(
          `/v1/vaults/${encodeURIComponent(vaultName)}/rename`,
          { method: "POST", body: JSON.stringify({ name: trimmedName }) }
        );
        if (!resp.ok) {
          const data = await resp.json().catch(() => ({}));
          throw new Error(data.error || "Failed to rename vault");
        }
        // Close the drawer before navigating; the route change re-renders this
        // component in place rather than unmounting it, so it won't close itself.
        onClose();
        // The URL carries the old name; jump to the new one (reloads context).
        navigate({ to: "/vaults/$name/settings", params: { name: trimmedName } });
        return;
      }

      // Refresh the vault context so the read-only display reflects the change.
      await router.invalidate();
      onClose();
    } finally {
      setSaving(false);
    }
  }

  // The credential-store change is destructive (it overwrites credentials), so
  // gate it behind the type-the-vault-name confirmation. Other edits save directly.
  function handleSave() {
    if (storeChanged) {
      setShowConfirm(true);
      return;
    }
    applyChanges().catch((err) =>
      setError(err instanceof Error ? err.message : "Something went wrong")
    );
  }

  return (
    <>
      <Sheet
        open={open}
        onClose={onClose}
        eyebrow="Vault"
        title="Edit settings"
        footer={
          <>
            <Button variant="secondary" onClick={onClose}>
              Cancel
            </Button>
            <Button onClick={handleSave} loading={saving} disabled={!canSave}>
              Save
            </Button>
          </>
        }
      >
        <VaultForm
          values={values}
          onChange={(patch) => {
            setValues((v) => ({ ...v, ...patch }));
            setError("");
          }}
          showPolicy
          policyDisabled={policy === null}
          nameDisabled={isDefault}
          infisicalOptionDisabled={!infisicalAvailable && currentKind !== "infisical"}
          error={error}
          storeTooltip="Built-in keeps credentials in Agent Vault. Infisical syncs read-only from your Infisical instance, overwriting the built-in credentials."
        />
      </Sheet>

      <ConfirmDeleteModal
        open={showConfirm}
        onClose={() => setShowConfirm(false)}
        onConfirm={async () => {
          await applyChanges();
          setShowConfirm(false);
        }}
        title="Switch credential store"
        description={
          switchToInfisical
            ? `Switching to Infisical will OVERWRITE all current built-in credentials in "${vaultName}" with the secrets from the connected Infisical source. Type the vault name to confirm.`
            : `Switching to the built-in store disconnects Infisical from "${vaultName}". The secrets currently synced are kept as built-in credentials and stop updating from Infisical. Type the vault name to confirm.`
        }
        confirmLabel="Save changes"
        confirmValue={vaultName}
        inputLabel="Vault name"
      />
    </>
  );
}

function StoreField({
  label,
  value,
  tooltip,
}: {
  label: string;
  value: string;
  tooltip?: ReactNode;
}) {
  return (
    <div className="min-w-0">
      <div className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-text-muted mb-2">
        <span>{label}</span>
        {tooltip && <InfoTooltip>{tooltip}</InfoTooltip>}
      </div>
      <div className="text-sm font-mono text-text break-all">{value}</div>
    </div>
  );
}
