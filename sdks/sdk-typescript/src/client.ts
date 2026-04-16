import { HttpClient } from "./http.js";
import type { AgentVaultConfig, VaultCreated, VaultDeleted } from "./types.js";
import { VaultClient } from "./vault.js";

/**
 * Options for creating a vault.
 */
export interface CreateVaultOptions {
  /** Vault name (3-64 chars, lowercase alphanumeric and hyphens only). */
  name: string;
}

/**
 * A newly created vault.
 */
export interface Vault {
  /** Vault UUID. */
  id: string;
  /** Vault name. */
  name: string;
  /** ISO 8601 creation timestamp. */
  createdAt: string;
}

/**
 * Result of deleting a vault.
 */
export interface DeleteVaultResult {
  /** Name of the deleted vault. */
  name: string;
  /** Always `true` on success. */
  deleted: boolean;
}

/**
 * Instance-level client for Agent Vault.
 *
 * Use this when you have an instance-level agent token (`av_agt_...`) that
 * can access multiple vaults and perform instance-level operations.
 *
 * ```typescript
 * // Auto-detect from environment variables
 * const av = new AgentVault();
 *
 * // Explicit config
 * const av = new AgentVault({ token: "av_agt_...", address: "..." });
 *
 * // Get a vault-scoped client
 * const vault = av.vault("my-project");
 * ```
 */
export class AgentVault {
  /** @internal */
  readonly _httpClient: HttpClient;

  constructor(config?: AgentVaultConfig) {
    this._httpClient = HttpClient.fromConfig(config);
  }

  /**
   * Returns a {@link VaultClient} scoped to the named vault.
   *
   * For instance-level agent tokens, this injects the `X-Vault` header
   * so all requests are directed to the correct vault.
   */
  vault(name: string): VaultClient {
    return VaultClient._create(
      this._httpClient.withHeaders({ "X-Vault": name }),
      name,
    );
  }

  /**
   * Create a new vault.
   *
   * The calling actor becomes the vault admin. Any authenticated actor
   * (user or agent) can create vaults. Requires an instance-level session
   * (vault-scoped tokens cannot create vaults).
   *
   * @throws {ApiError} 400 if the name is invalid or reserved.
   * @throws {ApiError} 409 if a vault with this name already exists.
   */
  async createVault(options: CreateVaultOptions): Promise<Vault> {
    const res = await this._httpClient.post<VaultCreated>("/v1/vaults", {
      name: options.name,
    });

    return {
      id: res.id,
      name: res.name,
      createdAt: res.created_at,
    };
  }

  /**
   * Delete a vault by name.
   *
   * Requires vault admin role or instance owner. The default vault cannot
   * be deleted. Requires an instance-level session (vault-scoped tokens
   * cannot delete vaults).
   *
   * @throws {ApiError} 400 if attempting to delete the default vault.
   * @throws {ApiError} 403 if not a vault admin or instance owner.
   * @throws {ApiError} 404 if the vault does not exist.
   */
  async deleteVault(name: string): Promise<DeleteVaultResult> {
    const res = await this._httpClient.del<VaultDeleted>(
      `/v1/vaults/${encodeURIComponent(name)}`,
    );

    return {
      name: res.name,
      deleted: res.deleted,
    };
  }
}
