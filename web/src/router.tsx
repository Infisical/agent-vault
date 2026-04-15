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
import ForgotPassword from "./pages/ForgotPassword";
import VaultsLayout from "./components/VaultsLayout";
import VaultsListTab from "./pages/home/VaultsListTab";
import AllUsersTab from "./pages/home/AllUsersTab";
import AllAgentsTab from "./pages/home/AllAgentsTab";
import UserInvite from "./pages/UserInvite";
import ProposalApprove from "./pages/ProposalApprove";
import VaultLayout from "./components/VaultLayout";
import ProposalsTab from "./pages/vault/ProposalsTab";
import ServicesTab from "./pages/vault/ServicesTab";
import CredentialsTab from "./pages/vault/CredentialsTab";
import UsersTab from "./pages/vault/UsersTab";
import AgentsTab from "./pages/vault/AgentsTab";
import SettingsTab from "./pages/vault/SettingsTab";
import InstanceLayout from "./components/InstanceLayout";
import AccountLayout from "./components/AccountLayout";
import AccountSettingsTab from "./pages/account/SettingsTab";
import InstanceSettingsTab from "./pages/instance/SettingsTab";
import OAuthCallback from "./pages/OAuthCallback";

// --- Types ---

export interface AuthContext {
  email: string;
  role: string;
  is_owner: boolean;
  has_password: boolean;
  oauth_providers: string[];
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

const forgotPasswordRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/forgot-password",
  beforeLoad: async () => {
    await requireInitializedOrRedirect();
    const resp = await apiFetch("/v1/auth/me");
    if (resp.ok) {
      throw redirect({ to: "/vaults" });
    }
  },
  component: ForgotPassword,
});

const userInviteRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/invite/$token",
  loader: async ({ params }) => {
    const resp = await apiFetch(`/v1/users/invites/${params.token}/details`);
    if (resp.ok) {
      const data = await resp.json();
      data.token = params.token;
      return data;
    }
    // Return error shape the component expects
    const data = await resp.json().catch(() => ({}));
    return {
      error: true,
      error_title: "Invite Unavailable",
      error_message: data.error || "This invite link is no longer valid.",
    };
  },
  component: UserInvite,
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

const oauthCallbackRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/oauth/callback",
  validateSearch: (search: Record<string, unknown>) => ({
    error: (search.error as string) || "",
  }),
  component: OAuthCallback,
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

// --- Vaults Layout (sidebar with Vaults + Users tabs) ---

const vaultsLayoutRoute = createRoute({
  getParentRoute: () => authLayoutRoute,
  path: "/vaults",
  component: VaultsLayout,
});

const vaultsIndexRoute = createRoute({
  getParentRoute: () => vaultsLayoutRoute,
  path: "/",
  component: VaultsListTab,
});

const vaultsUsersRoute = createRoute({
  getParentRoute: () => vaultsLayoutRoute,
  path: "/users",
  component: AllUsersTab,
});

const vaultsAgentsRoute = createRoute({
  getParentRoute: () => vaultsLayoutRoute,
  path: "/agents",
  component: AllAgentsTab,
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
    throw redirect({ to: "/manage/settings" });
  },
});

const manageSettingsRoute = createRoute({
  getParentRoute: () => manageInstanceRoute,
  path: "/settings",
  component: InstanceSettingsTab,
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
    throw redirect({ to: "/vaults/$name/services", params });
  },
});

const proposalsTabRoute = createRoute({
  getParentRoute: () => vaultLayoutRoute,
  path: "/proposals",
  component: ProposalsTab,
});

const servicesTabRoute = createRoute({
  getParentRoute: () => vaultLayoutRoute,
  path: "/services",
  component: ServicesTab,
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
  forgotPasswordRoute,
  userInviteRoute,
  proposalApproveRoute,
  oauthCallbackRoute,
  authLayoutRoute.addChildren([
    vaultsLayoutRoute.addChildren([
      vaultsIndexRoute,
      vaultsUsersRoute,
      vaultsAgentsRoute,
    ]),
    accountRoute.addChildren([
      accountIndexRoute,
      accountSettingsRoute,
    ]),
    manageInstanceRoute.addChildren([
      manageIndexRoute,
      manageSettingsRoute,
    ]),
    vaultLayoutRoute.addChildren([
      vaultIndexRoute,
      proposalsTabRoute,
      servicesTabRoute,
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
