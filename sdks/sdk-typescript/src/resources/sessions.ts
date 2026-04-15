import type { HttpClient } from "../http.js";
import type { ScopedSession } from "../types.js";

/**
 * Options for creating a vault-scoped session.
 */
export interface CreateSessionOptions {
  /** Vault role for the scoped session. Default: `"proxy"`. */
  vaultRole?: "proxy" | "member" | "admin";
  /** Session TTL in seconds (60-86400). Defaults to server's 24h. */
  ttlSeconds?: number;
}

/**
 * A minted vault-scoped session.
 */
export interface Session {
  /** The vault-scoped session token. */
  token: string;
  /** ISO 8601 expiration timestamp. */
  expiresAt: string;
  /** Agent Vault server base URL. */
  address: string;
  /** Full proxy URL (e.g. `http://localhost:14321/proxy`). */
  proxyUrl: string;
}

/**
 * Resource for minting vault-scoped session tokens.
 * Maps to `POST /v1/sessions`.
 */
export class SessionsResource {
  constructor(
    private readonly httpClient: HttpClient,
    private readonly vaultName: string,
  ) {}

  /**
   * Mint a vault-scoped session token.
   *
   * The returned token can be used to construct a standalone `VaultClient`
   * for use in agent sandboxes or scoped environments.
   */
  async create(options?: CreateSessionOptions): Promise<Session> {
    const res = await this.httpClient.post<ScopedSession>("/v1/sessions", {
      vault: this.vaultName,
      vault_role: options?.vaultRole,
      ttl_seconds: options?.ttlSeconds,
    });

    return {
      token: res.token,
      expiresAt: res.expires_at,
      address: res.av_addr ?? "",
      proxyUrl: res.proxy_url ?? "",
    };
  }
}
