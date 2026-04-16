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

/** @internal Wire format for POST /v1/vaults response. */
export interface VaultCreated {
  id: string;
  name: string;
  created_at: string;
}

/** @internal Wire format for DELETE /v1/vaults/{name} response. */
export interface VaultDeleted {
  name: string;
  deleted: boolean;
}

/** @internal Wire entry in GET /v1/credentials response. */
export interface CredentialEntry {
  key: string;
  value?: string;
}

/** @internal Wire format for GET /v1/credentials response. */
export interface CredentialsList {
  keys: string[];
  credentials?: CredentialEntry[];
}

/** @internal Wire format for POST /v1/credentials response. */
export interface CredentialsSet {
  set: string[];
}

/** @internal Wire format for DELETE /v1/credentials response. */
export interface CredentialsDeleted {
  deleted: string[];
}

// ---------------------------------------------------------------------------
// Services wire types
// ---------------------------------------------------------------------------

/** @internal Wire format for service auth. */
export interface WireServiceAuth {
  type: string;
  token?: string;
  username?: string;
  password?: string;
  key?: string;
  header?: string;
  prefix?: string;
  headers?: Record<string, string>;
}

/** @internal Wire format for a service entry. */
export interface WireService {
  host: string;
  description?: string;
  auth: WireServiceAuth;
}

/** @internal Wire format for GET /v1/vaults/{name}/services response. */
export interface ServicesList {
  vault: string;
  services: WireService[];
}

/** @internal Wire format for POST /v1/vaults/{name}/services response. */
export interface ServicesUpserted {
  vault: string;
  upserted: string[];
  services_count: number;
}

/** @internal Wire format for PUT /v1/vaults/{name}/services response. */
export interface ServicesReplaced {
  vault: string;
  services_count: number;
}

/** @internal Wire format for DELETE /v1/vaults/{name}/services response. */
export interface ServicesCleared {
  vault: string;
  cleared: boolean;
}

/** @internal Wire format for DELETE /v1/vaults/{name}/services/{host} response. */
export interface ServiceRemoved {
  vault: string;
  removed: string;
  services_count: number;
}

/** @internal Wire format for credential-usage response entry. */
export interface WireCredentialUsageEntry {
  host: string;
  description?: string;
}

/** @internal Wire format for GET /v1/vaults/{name}/services/credential-usage response. */
export interface WireCredentialUsageResult {
  services: WireCredentialUsageEntry[];
}
