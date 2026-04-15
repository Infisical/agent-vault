import { HttpClient } from "./http.js";
import type { AgentVaultConfig } from "./types.js";
import { VaultClient } from "./vault.js";

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
}
