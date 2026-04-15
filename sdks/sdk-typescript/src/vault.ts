import { HttpClient } from "./http.js";
import { SessionsResource } from "./resources/sessions.js";
import type { VaultClientConfig } from "./types.js";

/** @internal Marker to distinguish the internal construction path. */
const INTERNAL = Symbol("VaultClient.internal");

interface InternalArgs {
  marker: typeof INTERNAL;
  httpClient: HttpClient;
  vaultName: string;
}

/**
 * Vault-scoped client for Agent Vault.
 *
 * Use this when you have a vault-scoped session token (e.g. minted by
 * `AgentVault.vault(name).sessions.create()` or via `vault run` / `vault token`).
 *
 * ```typescript
 * // Auto-detect from environment variables
 * const vault = new VaultClient();
 *
 * // Explicit config
 * const vault = new VaultClient({ token: "...", address: "..." });
 * ```
 *
 * Can also be obtained via `AgentVault.vault(name)` for instance-level tokens.
 */
export class VaultClient {
  /** @internal */
  readonly _httpClient: HttpClient;

  /** Vault name, if known. Undefined for standalone vault-scoped tokens. */
  readonly name: string | undefined;

  /**
   * Sessions resource for minting vault-scoped tokens.
   * Only available when the vault name is known (i.e. created via `AgentVault.vault(name)`).
   * Undefined for standalone VaultClient constructed with a vault-scoped token.
   */
  readonly sessions: SessionsResource | undefined;

  constructor(config?: VaultClientConfig | InternalArgs) {
    if (config && "marker" in config && config.marker === INTERNAL) {
      this._httpClient = config.httpClient;
      this.name = config.vaultName;
      this.sessions = new SessionsResource(config.httpClient, config.vaultName);
    } else {
      this._httpClient = HttpClient.fromConfig(config as VaultClientConfig | undefined);
      this.name = undefined;
      this.sessions = undefined;
    }
  }

  /** @internal Created by `AgentVault.vault(name)` with a pre-configured HttpClient. */
  static _create(httpClient: HttpClient, vaultName: string): VaultClient {
    return new VaultClient({ marker: INTERNAL, httpClient, vaultName });
  }
}
