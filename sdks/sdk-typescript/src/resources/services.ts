import type { HttpClient } from "../http.js";
import type {
  ServicesList,
  ServicesUpserted,
  ServicesReplaced,
  ServicesCleared,
  ServiceRemoved,
  WireCredentialUsageResult,
} from "../types.js";

// ---------------------------------------------------------------------------
// Auth discriminated union
// ---------------------------------------------------------------------------

/** Bearer token auth — references a credential key. */
export interface BearerAuth {
  type: "bearer";
  /** Credential key for the bearer token (UPPER_SNAKE_CASE). */
  token: string;
}

/** HTTP Basic auth — references credential keys for username and optional password. */
export interface BasicAuth {
  type: "basic";
  /** Credential key for the username (UPPER_SNAKE_CASE). */
  username: string;
  /** Credential key for the password (UPPER_SNAKE_CASE, optional). */
  password?: string;
}

/** API key auth — references a credential key, injected into a header with optional prefix. */
export interface ApiKeyAuth {
  type: "api-key";
  /** Credential key for the API key (UPPER_SNAKE_CASE). */
  key: string;
  /** Header name (defaults to "Authorization"). */
  header?: string;
  /** Prefix prepended to the key value. */
  prefix?: string;
}

/** Custom auth — arbitrary header templates with {{ CREDENTIAL }} placeholders. */
export interface CustomAuth {
  type: "custom";
  /** Map of header name to template value with {{ CREDENTIAL }} placeholders. */
  headers: Record<string, string>;
}

/** Authentication configuration for a service. */
export type ServiceAuth = BearerAuth | BasicAuth | ApiKeyAuth | CustomAuth;

// ---------------------------------------------------------------------------
// Service type
// ---------------------------------------------------------------------------

/** A vault service (proxy rule). */
export interface Service {
  /** Host pattern (exact match or wildcard like "*.github.com"). */
  host: string;
  /** Optional description. */
  description?: string;
  /** Authentication configuration. */
  auth: ServiceAuth;
}

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

/** Result of listing services. */
export interface ListServicesResult {
  /** Vault name. */
  vault: string;
  /** All services configured for this vault. */
  services: Service[];
}

/** Result of upserting services. */
export interface SetServicesResult {
  /** Vault name. */
  vault: string;
  /** Hosts that were upserted. */
  upserted: string[];
  /** Total services count after upsert. */
  servicesCount: number;
}

/** Result of replacing all services. */
export interface ReplaceAllServicesResult {
  /** Vault name. */
  vault: string;
  /** Total services count after replacement. */
  servicesCount: number;
}

/** Result of clearing all services. */
export interface ClearServicesResult {
  /** Vault name. */
  vault: string;
  /** Always true on success. */
  cleared: boolean;
}

/** Result of removing a service by host. */
export interface RemoveServiceResult {
  /** Vault name. */
  vault: string;
  /** Host that was removed. */
  removed: string;
  /** Total services count after removal. */
  servicesCount: number;
}

/** A service that references a given credential key. */
export interface CredentialUsageEntry {
  /** Service host. */
  host: string;
  /** Service description, if set. */
  description?: string;
}

/** Result of checking credential usage across services. */
export interface CredentialUsageResult {
  /** Services that reference the given credential key. */
  services: CredentialUsageEntry[];
}

// ---------------------------------------------------------------------------
// Resource class
// ---------------------------------------------------------------------------

/**
 * Resource for managing vault services (proxy rules).
 *
 * Maps to `GET/POST/PUT/DELETE /v1/vaults/{name}/services`.
 * Only available when the vault name is known (i.e. created via `AgentVault.vault(name)`).
 */
export class ServicesResource {
  private readonly basePath: string;

  constructor(
    private readonly httpClient: HttpClient,
    vaultName: string,
  ) {
    this.basePath = `/v1/vaults/${encodeURIComponent(vaultName)}/services`;
  }

  /**
   * List all services configured in this vault.
   *
   * @throws {ApiError} 403 if the caller lacks vault access.
   * @throws {ApiError} 404 if the vault is not found.
   */
  async list(): Promise<ListServicesResult> {
    const res = await this.httpClient.get<ServicesList>(this.basePath);
    return {
      vault: res.vault,
      services: res.services as Service[],
    };
  }

  /**
   * Upsert one or more services by host.
   *
   * If a service with the same host already exists, it is replaced.
   * Requires vault admin role.
   *
   * @param services - Services to add or update.
   * @throws {ApiError} 400 if services are empty or fail validation.
   * @throws {ApiError} 403 if the caller is not a vault admin.
   * @throws {ApiError} 404 if the vault is not found.
   */
  async set(services: Service[]): Promise<SetServicesResult> {
    const res = await this.httpClient.post<ServicesUpserted>(this.basePath, {
      services,
    });
    return {
      vault: res.vault,
      upserted: res.upserted,
      servicesCount: res.services_count,
    };
  }

  /**
   * Remove a specific service by host.
   *
   * Requires vault admin role.
   *
   * @param host - Exact host pattern to remove.
   * @throws {ApiError} 403 if the caller is not a vault admin.
   * @throws {ApiError} 404 if the vault or service is not found.
   */
  async remove(host: string): Promise<RemoveServiceResult> {
    const res = await this.httpClient.del<ServiceRemoved>(
      `${this.basePath}/${encodeURIComponent(host)}`,
    );
    return {
      vault: res.vault,
      removed: res.removed,
      servicesCount: res.services_count,
    };
  }

  /**
   * Replace ALL services in the vault.
   *
   * This is a destructive operation that removes all existing services
   * and sets the provided list. Use {@link set} for non-destructive upsert.
   * Requires vault admin role.
   *
   * @param services - Complete list of services to set.
   * @throws {ApiError} 400 if services fail validation.
   * @throws {ApiError} 403 if the caller is not a vault admin.
   * @throws {ApiError} 404 if the vault is not found.
   */
  async replaceAll(services: Service[]): Promise<ReplaceAllServicesResult> {
    const res = await this.httpClient.put<ServicesReplaced>(this.basePath, {
      services,
    });
    return {
      vault: res.vault,
      servicesCount: res.services_count,
    };
  }

  /**
   * Clear ALL services from the vault.
   *
   * Requires vault admin role.
   *
   * @throws {ApiError} 403 if the caller is not a vault admin.
   * @throws {ApiError} 404 if the vault is not found.
   */
  async clear(): Promise<ClearServicesResult> {
    const res = await this.httpClient.del<ServicesCleared>(this.basePath);
    return {
      vault: res.vault,
      cleared: res.cleared,
    };
  }

  /**
   * Find which services reference a given credential key.
   *
   * @param key - Credential key name (UPPER_SNAKE_CASE).
   * @throws {ApiError} 400 if key is missing.
   * @throws {ApiError} 403 if the caller lacks vault access.
   * @throws {ApiError} 404 if the vault is not found.
   */
  async credentialUsage(key: string): Promise<CredentialUsageResult> {
    const res = await this.httpClient.get<WireCredentialUsageResult>(
      `${this.basePath}/credential-usage`,
      { query: { key } },
    );
    return {
      services: res.services,
    };
  }
}
