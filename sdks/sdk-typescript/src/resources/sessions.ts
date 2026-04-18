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
 * Container configuration for routing a sandboxed agent's HTTPS traffic
 * through Agent Vault's transparent MITM proxy.
 */
export interface ContainerConfig {
  /** Environment variables to inject into the container. */
  env: {
    /** MITM proxy URL with embedded credentials. */
    HTTPS_PROXY: string;
    /** Hosts to bypass the proxy. */
    NO_PROXY: string;
  };
  /** Root CA certificate PEM content. Mount this into the container and
   *  point CA trust env vars (SSL_CERT_FILE, NODE_EXTRA_CA_CERTS, etc.)
   *  at the mount path. Use {@link buildProxyEnv} to generate the full
   *  env var set once you know the mount path. */
  caCertificate: string;
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
  /** Container configuration for transparent MITM proxy routing.
   *  `null` when the server has MITM disabled (`--mitm-port 0`). */
  containerConfig: ContainerConfig | null;
}

/** Default MITM proxy port when the server doesn't advertise one. */
const DEFAULT_MITM_PORT = 14322;

/**
 * Build the complete set of proxy environment variables for a container,
 * including CA trust variables pointing at the given certificate path.
 *
 * @param config - The container config from a minted session.
 * @param certPath - The path where the CA certificate will be mounted
 *   inside the container (e.g. `"/etc/ssl/agent-vault-ca.pem"`).
 * @returns A flat env var object ready to pass to the container runtime.
 */
export function buildProxyEnv(
  config: ContainerConfig,
  certPath: string,
): Record<string, string> {
  return {
    HTTPS_PROXY: config.env.HTTPS_PROXY,
    NO_PROXY: config.env.NO_PROXY,
    SSL_CERT_FILE: certPath,
    NODE_EXTRA_CA_CERTS: certPath,
    REQUESTS_CA_BUNDLE: certPath,
    CURL_CA_BUNDLE: certPath,
    GIT_SSL_CAINFO: certPath,
    DENO_CERT: certPath,
  };
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
   * The returned session includes a `containerConfig` with the MITM proxy
   * URL, bypass list, and root CA certificate. Pass these to your container
   * runtime so the sandboxed agent's HTTPS traffic routes through Agent Vault
   * transparently. Use {@link buildProxyEnv} to expand the config into a
   * complete env var set once you know the CA certificate mount path.
   *
   * `containerConfig` is `null` when the server has MITM disabled.
   */
  async create(options?: CreateSessionOptions): Promise<Session> {
    const [res, containerConfig] = await Promise.all([
      this.httpClient.post<ScopedSession>("/v1/sessions", {
        vault: this.vaultName,
        vault_role: options?.vaultRole,
        ttl_seconds: options?.ttlSeconds,
      }),
      this.fetchContainerConfig(),
    ]);

    if (containerConfig) {
      // Rebuild HTTPS_PROXY with the scoped token from the session response.
      const proxyUrl = new URL(containerConfig.env.HTTPS_PROXY);
      proxyUrl.username = encodeURIComponent(res.token);
      containerConfig.env.HTTPS_PROXY = proxyUrl.toString();
    }

    return {
      token: res.token,
      expiresAt: res.expires_at,
      address: res.av_addr ?? "",
      containerConfig,
    };
  }

  /**
   * Fetch the MITM CA certificate and build a preliminary container config.
   * The HTTPS_PROXY URL uses a placeholder token that `create()` replaces
   * with the real scoped token once the session response arrives.
   */
  private async fetchContainerConfig(): Promise<ContainerConfig | null> {
    const resp = await this.httpClient.raw("GET", "/v1/mitm/ca.pem");
    if (resp.status === 404) {
      return null;
    }
    if (!resp.ok) {
      return null;
    }

    const caCertificate = await resp.text();

    let port = DEFAULT_MITM_PORT;
    const portHeader = resp.headers.get("X-MITM-Port");
    if (portHeader) {
      const parsed = parseInt(portHeader, 10);
      if (parsed > 0 && parsed < 65536) {
        port = parsed;
      }
    }

    // Extract the host from the server address for the proxy URL.
    const baseUrl = this.httpClient.getBaseUrl();
    let mitmHost = "127.0.0.1";
    try {
      const u = new URL(baseUrl);
      if (u.hostname) {
        mitmHost = u.hostname;
      }
    } catch {
      // fall back to 127.0.0.1
    }

    // Use a placeholder token — create() replaces it with the real scoped token.
    const proxyUrl = `http://__TOKEN__:${encodeURIComponent(this.vaultName)}@${mitmHost}:${port}`;

    return {
      env: {
        HTTPS_PROXY: proxyUrl,
        NO_PROXY: "localhost,127.0.0.1",
      },
      caCertificate,
    };
  }
}
