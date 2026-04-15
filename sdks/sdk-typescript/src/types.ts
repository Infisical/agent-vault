/**
 * Shared configuration for Agent Vault clients.
 *
 * Both `AgentVault` (instance-level) and `VaultClient` (vault-scoped) accept this shape.
 * Token and address are resolved in order: config param > environment variable > default/throw.
 */
export interface ClientConfig {
  /**
   * Authentication token.
   * Falls back to `AGENT_VAULT_SESSION_TOKEN` environment variable.
   */
  token?: string;

  /**
   * Agent Vault server base URL.
   * Falls back to `AGENT_VAULT_ADDR` environment variable, then `"http://localhost:14321"`.
   */
  address?: string;

  /** Extra headers included on every request. */
  headers?: Record<string, string>;

  /** Custom fetch implementation (for testing or non-Node runtimes). */
  fetch?: typeof globalThis.fetch;

  /** Request timeout in milliseconds. Default: 30000. */
  timeout?: number;
}

/** Configuration for the instance-level AgentVault client. */
export type AgentVaultConfig = ClientConfig;

/** Configuration for the vault-scoped VaultClient. */
export type VaultClientConfig = ClientConfig;

// ---------------------------------------------------------------------------
// Core entity types (mirror Go API JSON responses)
// ---------------------------------------------------------------------------

export interface Vault {
  name: string;
  created_at: string;
}

export interface Credential {
  key: string;
  value?: string;
}

export interface ServiceAuth {
  type: "bearer" | "basic" | "api-key" | "custom";
  token?: string;
  username?: string;
  password?: string;
  key?: string;
  header?: string;
  prefix?: string;
  headers?: Record<string, string>;
}

export interface Service {
  host: string;
  description?: string;
  auth: ServiceAuth;
}

export interface DiscoverService {
  host: string;
  description?: string;
}

export interface DiscoverResponse {
  vault: string;
  proxy_url: string;
  services: DiscoverService[];
  available_credentials: string[];
}

export interface ProposalService {
  action: "set" | "delete";
  host: string;
  description?: string;
  auth?: ServiceAuth;
}

export interface ProposalCredentialSlot {
  action: "set" | "delete";
  key: string;
  description?: string;
  obtain?: string;
  obtain_instructions?: string;
  value?: string;
  has_value?: boolean;
}

export interface Proposal {
  id: number;
  status: "pending" | "applied" | "rejected" | "expired";
  vault: string;
  approval_url?: string;
  message?: string;
  user_message?: string;
  created_at: string;
}

export interface ScopedSession {
  token: string;
  expires_at: string;
  av_addr?: string;
  proxy_url?: string;
}
