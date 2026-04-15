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
// Internal wire types (match Go API JSON responses, used by resource methods)
// ---------------------------------------------------------------------------

/** @internal Wire format for POST /v1/sessions response. */
export interface ScopedSession {
  token: string;
  expires_at: string;
  av_addr?: string;
  proxy_url?: string;
}
