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

/** Passthrough auth — host is allowlisted, headers flow through, no credential injected. */
export interface PassthroughAuth {
  type: "passthrough";
}

/** Authentication configuration for a service. */
export type ServiceAuth =
  | BearerAuth
  | BasicAuth
  | ApiKeyAuth
  | CustomAuth
  | PassthroughAuth;

// ---------------------------------------------------------------------------
// Substitution
// ---------------------------------------------------------------------------

/** Surfaces where a substitution may be applied. */
export type SubstitutionSurface = "path" | "query" | "header";

/** Replaces a placeholder in the request with a credential value before forwarding. */
export interface Substitution {
  /** Credential key (UPPER_SNAKE_CASE) whose value replaces the placeholder. */
  key: string;
  /** Literal placeholder string that appears in the outgoing request. */
  placeholder: string;
  /** Surfaces to scan. Defaults server-side to ["path", "query"] when omitted. */
  in?: SubstitutionSurface[];
}

// ---------------------------------------------------------------------------
// Service type
// ---------------------------------------------------------------------------

/**
 * Write shape for a vault service (proxy rule).
 *
 * Identity is `name` — a unique-per-vault slug. Required on write; pick
 * a deliberate identifier (e.g. `stripe`, `slack-bot`). The server does
 * not derive a name from `host`.
 *
 * `host` is the single matcher field on the wire. Accepts a bare
 * hostname (`api.stripe.com`), a one-level wildcard (`*.github.com`),
 * or an inline path-scoped form (`slack.com/api/*`). The server splits
 * the path off the host on ingest and resolves overlapping rules
 * deterministically: exact-host beats wildcard-host, then longer
 * literal path prefix wins, with declaration order as the final tiebreak.
 */
export interface ServiceInput {
  /** Service name (slug, 3–64 chars, lowercase alphanumeric and hyphens). Required on write. */
  name?: string;
  /** Host pattern. Accepts `api.stripe.com`, `*.github.com`, or an inline path form like `slack.com/api/*`. */
  host: string;
  /** Whether the service is active. Omitted/undefined is treated as enabled. */
  enabled?: boolean;
  /** Authentication configuration. */
  auth: ServiceAuth;
  /** Optional placeholder→credential substitutions applied before forwarding. */
  substitutions?: Substitution[];
}

/**
 * Read shape for a vault service.
 *
 * Mirrors {@link ServiceInput} symmetrically: `host` carries the joined
 * inline form on reads (`slack.com/api/*`) just as it does on writes,
 * so callers see the same single-field matcher pattern they sent.
 * Composed (not extended) from `ServiceInput` so a read value can't be
 * passed to a write method without an explicit conversion.
 */
export interface Service {
  /** Service name (slug). Server populates this on reads. */
  name?: string;
  /** Host pattern. Joined inline form: `api.stripe.com`, `*.github.com`, or `slack.com/api/*`. */
  host: string;
  /** Whether the service is active. Omitted/undefined is treated as enabled. */
  enabled?: boolean;
  /** Authentication configuration. */
  auth: ServiceAuth;
  /** Optional placeholder→credential substitutions applied before forwarding. */
  substitutions?: Substitution[];
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
  /** Service names (slugs) that were upserted. */
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

/** Result of removing a service. */
export interface RemoveServiceResult {
  /** Vault name. */
  vault: string;
  /** Canonical name (slug) of the service that was removed. */
  removed: string;
  /** Host of the removed service. */
  removedHost?: string;
  /** Total services count after removal. */
  servicesCount: number;
}

/** A service that references a given credential key. */
export interface CredentialUsageEntry {
  /** Service name (slug). Populated by the server even for legacy services. */
  name?: string;
  /** Service host pattern (joined inline form). */
  host: string;
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
   * Upsert one or more services by canonical name (slug).
   *
   * Identity is `name` and is required on every entry. Resubmitting the
   * same name replaces the stored entry. Requires vault admin role.
   *
   * @param services - Services to add or update.
   * @throws {ApiError} 400 if services are empty or fail validation.
   * @throws {ApiError} 403 if the caller is not a vault admin.
   * @throws {ApiError} 404 if the vault is not found.
   */
  async set(services: ServiceInput[]): Promise<SetServicesResult> {
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
   * Convenience wrapper that targets `DELETE /services/{host}`. The server
   * tries to match by canonical name first; if no name matches, it falls
   * back to host. When more than one service shares the host, the server
   * returns 409 with the candidate list — surfaced here as an `ApiError`.
   * For path-scoped services, prefer {@link removeByName}.
   *
   * Requires vault admin role.
   *
   * @param host - Exact host pattern to remove.
   * @throws {ApiError} 403 if the caller is not a vault admin.
   * @throws {ApiError} 404 if the vault or service is not found.
   * @throws {ApiError} 409 if multiple services share the host (use {@link removeByName}).
   */
  async remove(host: string): Promise<RemoveServiceResult> {
    return this.removeByRef(host);
  }

  /**
   * Remove a specific service by canonical name (slug).
   *
   * Recommended for path-scoped services: a name is unambiguous and
   * never returns 409. Requires vault admin role.
   *
   * @param name - The service's canonical name.
   * @throws {ApiError} 403 if the caller is not a vault admin.
   * @throws {ApiError} 404 if the vault or service is not found.
   */
  async removeByName(name: string): Promise<RemoveServiceResult> {
    return this.removeByRef(name);
  }

  private async removeByRef(ref: string): Promise<RemoveServiceResult> {
    const res = await this.httpClient.del<ServiceRemoved>(
      `${this.basePath}/${encodeURIComponent(ref)}`,
    );
    return {
      vault: res.vault,
      removed: res.removed,
      removedHost: res.removed_host,
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
  async replaceAll(services: ServiceInput[]): Promise<ReplaceAllServicesResult> {
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
