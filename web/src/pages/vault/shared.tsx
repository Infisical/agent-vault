import { useRouteContext } from "@tanstack/react-router";
import type { AuthContext, VaultContext } from "../../router";

// Re-export shared UI components so existing vault imports don't break
export {
  StatusBadge,
  LoadingSpinner,
  ErrorBanner,
  EmptyState,
  timeAgo,
  timeUntil,
} from "../../components/shared";

export function useVaultParams() {
  const { auth } = useRouteContext({ from: "/_auth" }) as { auth: AuthContext };
  const vaultContext = useRouteContext({ from: "/_auth/vaults/$name" }) as VaultContext;
  return {
    vaultName: vaultContext.vault_name,
    vaultRole: vaultContext.vault_role,
    credentialStore: vaultContext.credential_store,
    email: auth.email,
    isOwner: auth.is_owner,
  };
}
