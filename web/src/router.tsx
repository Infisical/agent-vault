import {
  createRouter,
  createRoute,
  createRootRoute,
  redirect,
  Outlet,
} from "@tanstack/react-router";
import { apiFetch } from "./lib/api";
import Login from "./pages/Login";
import Register from "./pages/Register";
import Vaults from "./pages/Vaults";
import VaultInvite from "./pages/VaultInvite";
import ProposalApprove from "./pages/ProposalApprove";
import VaultLayout from "./components/VaultLayout";
import ProposalsTab from "./pages/vault/ProposalsTab";
import PolicyTab from "./pages/vault/PolicyTab";
import CredentialsTab from "./pages/vault/CredentialsTab";
import UsersTab from "./pages/vault/UsersTab";
import AgentsTab from "./pages/vault/AgentsTab";
import SettingsTab from "./pages/vault/SettingsTab";
import InstanceLayout from "./components/InstanceLayout";
import AccountLayout from "./components/AccountLayout";
import AccountSettingsTab from "./pages/account/SettingsTab";
import InstanceUsersTab from "./pages/instance/UsersTab";
import InstanceVaultsTab from "./pages/instance/VaultsTab";
import InstanceAgentsTab from "./pages/instance/AgentsTab";

// --- Types ---

export interface AuthContext {
  email: string;
  role: string;
  is_owner: boolean;
}

export interface VaultContext {
  vault_name: string;
  vault_role: string;
}

// --- Root Route ---

const rootRoute = createRootRoute({
  component: Outlet,
});

// --- Helpers ---

async function requireInitializedOrRedirect() {
  const resp = await apiFetch("/v1/status");
  if (resp.ok) {
    const status = await resp.json();
    if (!status.initialized) {
      throw redirect({ to: "/register" });
    }
  }
}

// --- Public Routes ---

const loginRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/login",
  beforeLoad: async () => {
    await requireInitializedOrRedirect();
    const resp = await apiFetch("/v1/auth/me");
    if (resp.ok) {
      throw redirect({ to: "/vaults" });
    }
  },
  component: Login,
});

const registerRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/register",
  loader: async () => {
    const resp = await apiFetch("/v1/status");
    if (resp.ok) {
      return resp.json();
    }
    return { initialized: false, needs_first_user: true };
  },
  component: Register,
});

const vaultInviteRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/vault-invite/$token",
  loader: async ({ params }) => {
    const resp = await apiFetch(`/v1/vault-invites/${params.token}/details`);
    if (resp.ok) {
      return resp.json();
    }
    // Return error shape the component expects
    const data = await resp.json().catch(() => ({}));
    return {
      error: true,
      error_title: "Invite Unavailable",
      error_message: data.error || "This invite link is no longer valid.",
    };
  },
  component: VaultInvite,
});

const proposalApproveRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/approve/$id",
  validateSearch: (search: Record<string, unknown>) => ({
    token: (search.token as string) || "",
  }),
  loaderDeps: ({ search }) => ({ token: search.token }),
  loader: async ({ params, deps }) => {
    const { token } = deps;
    if (!token) {
      return {
        error: true,
        error_title: "Missing Token",
        error_message: "This approval link is incomplete. Please ask the agent for a new link.",
      };
    }
    const resp = await apiFetch(
      `/v1/proposals/approve-details?token=${encodeURIComponent(token)}&id=${encodeURIComponent(params.id)}`,
    );
    if (resp.ok) {
      return resp.json();
    }
    const data = await resp.json().catch(() => ({}));
    if (resp.status === 410) {
      return { error: true, error_title: "Link Expired", error_message: data.error || "This approval link has expired." };
    }
    return {
      error: true,
      error_title: data.error_title || "Unavailable",
      error_message: data.error_message || data.error || "This approval link is no longer valid.",
    };
  },
  component: ProposalApprove,
});

// --- Auth Layout (protected routes) ---

const authLayoutRoute = createRoute({
  getParentRoute: () => rootRoute,
  id: "_auth",
  beforeLoad: async () => {
    await requireInitializedOrRedirect();
    const resp = await apiFetch("/v1/auth/me");
    if (!resp.ok) {
      throw redirect({ to: "/login" });
    }
    const user: AuthContext = await resp.json();
    return { auth: user };
  },
  component: Outlet,
});

const vaultsRoute = createRoute({
  getParentRoute: () => authLayoutRoute,
  path: "/vaults",
  component: Vaults,
});

const accountRoute = createRoute({
  getParentRoute: () => authLayoutRoute,
  path: "/account",
  component: AccountLayout,
});

const accountIndexRoute = createRoute({
  getParentRoute: () => accountRoute,
  path: "/",
  beforeLoad: async () => {
    throw redirect({ to: "/account/settings" });
  },
});

const accountSettingsRoute = createRoute({
  getParentRoute: () => accountRoute,
  path: "/settings",
  component: AccountSettingsTab,
});

const manageInstanceRoute = createRoute({
  getParentRoute: () => authLayoutRoute,
  path: "/manage",
  beforeLoad: async ({ context }) => {
    const { auth } = context as { auth: AuthContext };
    if (!auth.is_owner) {
      throw redirect({ to: "/vaults" });
    }
  },
  component: InstanceLayout,
});

const manageIndexRoute = createRoute({
  getParentRoute: () => manageInstanceRoute,
  path: "/",
  beforeLoad: async () => {
    throw redirect({ to: "/manage/users" });
  },
});

const manageUsersRoute = createRoute({
  getParentRoute: () => manageInstanceRoute,
  path: "/users",
  component: InstanceUsersTab,
});

const manageVaultsRoute = createRoute({
  getParentRoute: () => manageInstanceRoute,
  path: "/vaults",
  component: InstanceVaultsTab,
});

const manageAgentsRoute = createRoute({
  getParentRoute: () => manageInstanceRoute,
  path: "/agents",
  component: InstanceAgentsTab,
});

// --- Vault Layout (sidebar) ---

const vaultLayoutRoute = createRoute({
  getParentRoute: () => authLayoutRoute,
  path: "/vaults/$name",
  beforeLoad: async ({ params }) => {
    const resp = await apiFetch(`/v1/vaults/${encodeURIComponent(params.name)}/context`);
    if (!resp.ok) {
      throw redirect({ to: "/vaults" });
    }
    const ctx: VaultContext = await resp.json();
    return ctx;
  },
  component: VaultLayout,
});

const vaultIndexRoute = createRoute({
  getParentRoute: () => vaultLayoutRoute,
  path: "/",
  beforeLoad: async ({ params }) => {
    throw redirect({ to: "/vaults/$name/proposals", params });
  },
});

const proposalsTabRoute = createRoute({
  getParentRoute: () => vaultLayoutRoute,
  path: "/proposals",
  component: ProposalsTab,
});

const policyTabRoute = createRoute({
  getParentRoute: () => vaultLayoutRoute,
  path: "/policy",
  component: PolicyTab,
});

const credentialsTabRoute = createRoute({
  getParentRoute: () => vaultLayoutRoute,
  path: "/credentials",
  component: CredentialsTab,
});

const usersTabRoute = createRoute({
  getParentRoute: () => vaultLayoutRoute,
  path: "/users",
  component: UsersTab,
});

const agentsTabRoute = createRoute({
  getParentRoute: () => vaultLayoutRoute,
  path: "/agents",
  component: AgentsTab,
});

const settingsTabRoute = createRoute({
  getParentRoute: () => vaultLayoutRoute,
  path: "/settings",
  component: SettingsTab,
});

// --- Index Route (root redirect) ---

const indexRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/",
  beforeLoad: async () => {
    await requireInitializedOrRedirect();
    const meResp = await apiFetch("/v1/auth/me");
    if (meResp.ok) {
      throw redirect({ to: "/vaults" });
    }
    throw redirect({ to: "/login" });
  },
});

// --- Route Tree ---

const routeTree = rootRoute.addChildren([
  indexRoute,
  loginRoute,
  registerRoute,
  vaultInviteRoute,
  proposalApproveRoute,
  authLayoutRoute.addChildren([
    vaultsRoute,
    accountRoute.addChildren([
      accountIndexRoute,
      accountSettingsRoute,
    ]),
    manageInstanceRoute.addChildren([
      manageIndexRoute,
      manageUsersRoute,
      manageVaultsRoute,
      manageAgentsRoute,
    ]),
    vaultLayoutRoute.addChildren([
      vaultIndexRoute,
      proposalsTabRoute,
      policyTabRoute,
      credentialsTabRoute,
      usersTabRoute,
      agentsTabRoute,
      settingsTabRoute,
    ]),
  ]),
]);

// --- Router ---

export const router = createRouter({ routeTree });

// Type registration for type-safe navigation
declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router;
  }
}
