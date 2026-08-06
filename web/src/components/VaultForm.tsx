import type { ReactNode } from "react";
import Input from "./Input";
import Select from "./Select";
import FormField from "./FormField";
import Toggle from "./Toggle";
import { ErrorBanner } from "./shared";

// The fields a vault create/edit form edits. The same shape backs both flows;
// each parent decides what submitting it means (POST vs PATCH/rename).
export type VaultFormValues = {
  name: string;
  policy: "passthrough" | "deny";
  kind: "builtin" | "infisical" | "hashicorp";
  projectID: string;
  environment: string;
  secretPath: string;
  hcMount: string;
  hcPath: string;
  hcKvVersion: string;
};

export const emptyVaultForm: VaultFormValues = {
  name: "",
  policy: "passthrough",
  kind: "builtin",
  projectID: "",
  environment: "",
  secretPath: "/",
  hcMount: "secret",
  hcPath: "",
  hcKvVersion: "2",
};

// Infisical needs a project + environment; everything else may be blank.
export function infisicalFieldsValid(v: VaultFormValues): boolean {
  return (
    v.kind !== "infisical" || (!!v.projectID.trim() && !!v.environment.trim())
  );
}

// Trimmed, validated Infisical config block. Throws on a bad secret path.
export function buildInfisicalConfig(v: VaultFormValues) {
  const secretPath = v.secretPath.trim() || "/";
  if (!secretPath.startsWith("/")) {
    throw new Error('Secret path must start with "/".');
  }
  return {
    project_id: v.projectID.trim(),
    environment: v.environment.trim(),
    secret_path: secretPath,
  };
}

// HashiCorp needs a KV mount + secret path; everything else may be blank.
export function hashicorpFieldsValid(v: VaultFormValues): boolean {
  return v.kind !== "hashicorp" || (!!v.hcMount.trim() && !!v.hcPath.trim());
}

// Trimmed HashiCorp KV config block.
export function buildHashicorpConfig(v: VaultFormValues) {
  return {
    mount: v.hcMount.trim(),
    secret_path: v.hcPath.trim(),
    kv_version: Number(v.hcKvVersion),
  };
}

export default function VaultForm({
  values,
  onChange,
  infisicalOptionDisabled,
  hashicorpOptionDisabled = true,
  hideHashicorpFields = false,
  storeTooltip,
  showPolicy = false,
  policyDisabled = false,
  nameDisabled = false,
  namePlaceholder = "vault-name",
  autoFocusName = false,
  onEnter,
  error,
  header,
}: {
  values: VaultFormValues;
  onChange: (patch: Partial<VaultFormValues>) => void;
  infisicalOptionDisabled: boolean;
  hashicorpOptionDisabled?: boolean;
  // The edit/switch flow can't reconfigure a HashiCorp store (create-only), so
  // it suppresses the mount/path/version inputs and only offers switch-away.
  hideHashicorpFields?: boolean;
  storeTooltip: ReactNode;
  showPolicy?: boolean;
  policyDisabled?: boolean;
  nameDisabled?: boolean;
  namePlaceholder?: string;
  autoFocusName?: boolean;
  onEnter?: () => void;
  error?: string;
  header?: ReactNode;
}) {
  const isInfisical = values.kind === "infisical";
  const isHashicorp = values.kind === "hashicorp" && !hideHashicorpFields;

  return (
    <div className="space-y-5">
      {header}

      <FormField label="Vault Name">
        <Input
          value={values.name}
          onChange={(e) => onChange({ name: e.target.value })}
          onKeyDown={(e) => {
            if (e.key === "Enter" && onEnter) onEnter();
          }}
          disabled={nameDisabled}
          placeholder={namePlaceholder}
          autoFocus={autoFocusName}
        />
      </FormField>

      {showPolicy && (
        <FormField
          label="Strict deny mode"
          tooltip="Reject unmatched hosts with HTTP 403 instead of forwarding them upstream unauthenticated."
        >
          <Toggle
            checked={values.policy === "deny"}
            onChange={(v) => onChange({ policy: v ? "deny" : "passthrough" })}
            disabled={policyDisabled}
            ariaLabel="Strict deny mode"
          />
        </FormField>
      )}

      <FormField label="Credential store" tooltip={storeTooltip}>
        <Select
          value={values.kind}
          onChange={(e) =>
            onChange({ kind: e.target.value as VaultFormValues["kind"] })
          }
        >
          <option value="builtin">Built In</option>
          <option value="infisical" disabled={infisicalOptionDisabled}>
            Infisical
          </option>
          <option value="hashicorp" disabled={hashicorpOptionDisabled}>
            HashiCorp Vault
          </option>
        </Select>
      </FormField>

      {isInfisical && (
        <div className="space-y-3">
          <FormField label="Project ID" required>
            <Input
              placeholder="abcdef..."
              value={values.projectID}
              onChange={(e) => onChange({ projectID: e.target.value })}
            />
          </FormField>
          <FormField label="Environment Slug" required>
            <Input
              placeholder="dev"
              value={values.environment}
              onChange={(e) => onChange({ environment: e.target.value })}
            />
          </FormField>
          <FormField label="Secret path">
            <Input
              placeholder="/"
              value={values.secretPath}
              onChange={(e) => onChange({ secretPath: e.target.value })}
            />
          </FormField>
        </div>
      )}

      {isHashicorp && (
        <div className="space-y-3">
          <FormField label="Mount" required>
            <Input
              placeholder="secret"
              value={values.hcMount}
              onChange={(e) => onChange({ hcMount: e.target.value })}
            />
          </FormField>
          <FormField label="Secret path" required>
            <Input
              placeholder="agent-vault/demo"
              value={values.hcPath}
              onChange={(e) => onChange({ hcPath: e.target.value })}
            />
          </FormField>
          <FormField label="KV version">
            <Select
              value={values.hcKvVersion}
              onChange={(e) => onChange({ hcKvVersion: e.target.value })}
            >
              <option value="2">2</option>
              <option value="1">1</option>
            </Select>
          </FormField>
        </div>
      )}

      {error && <ErrorBanner message={error} />}
    </div>
  );
}
