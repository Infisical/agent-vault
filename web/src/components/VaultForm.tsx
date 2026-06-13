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
  kind: "builtin" | "infisical";
  projectID: string;
  environment: string;
  secretPath: string;
};

export const emptyVaultForm: VaultFormValues = {
  name: "",
  policy: "passthrough",
  kind: "builtin",
  projectID: "",
  environment: "",
  secretPath: "/",
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

export default function VaultForm({
  values,
  onChange,
  infisicalOptionDisabled,
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

      {error && <ErrorBanner message={error} />}
    </div>
  );
}
