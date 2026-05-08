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
  const role = vaultContext.role;
  return {
    vaultName: vaultContext.vault_name,
    // Actor's instance role within this vault (owner | admin | agent).
    role,
    isAdmin: role === "owner" || role === "admin",
    isAgent: role === "agent",
    email: auth.email,
    isOwner: auth.is_owner,
  };
}
