import { AgentVaultError, ApiError } from "./errors.js";
import type { ClientConfig } from "./types.js";

export type HttpMethod = "GET" | "POST" | "PUT" | "DELETE" | "PATCH";

export interface RequestOptions {
  body?: unknown;
  headers?: Record<string, string>;
  query?: Record<string, string>;
  signal?: AbortSignal;
}

export interface HttpClientConfig {
  baseUrl: string;
  token: string;
  headers?: Record<string, string>;
  fetchFn?: typeof globalThis.fetch;
  timeout?: number;
}

const SDK_VERSION = "0.1.0";
const USER_AGENT = `agent-vault-sdk-typescript/${SDK_VERSION}`;
const DEFAULT_TIMEOUT = 30_000;
const DEFAULT_ADDRESS = "http://localhost:14321";
const ENV_TOKEN = "AGENT_VAULT_SESSION_TOKEN";
const ENV_ADDR = "AGENT_VAULT_ADDR";

/**
 * Internal HTTP client that wraps `fetch` with Agent Vault conventions.
 *
 * - Injects `Authorization: Bearer` and `Content-Type: application/json` headers
 * - Handles timeouts via `AbortController`
 * - Parses error responses into `ApiError`
 * - Supports immutable derivation via `withHeaders()` for X-Vault injection
 */
export class HttpClient {
  private readonly baseUrl: string;
  private readonly token: string;
  private readonly defaultHeaders: Record<string, string>;
  private readonly fetchFn: typeof globalThis.fetch;
  private readonly timeout: number;

  constructor(config: HttpClientConfig) {
    this.baseUrl = config.baseUrl.replace(/\/+$/, "");
    this.token = config.token;
    this.defaultHeaders = config.headers ?? {};
    this.fetchFn = config.fetchFn ?? globalThis.fetch;
    this.timeout = config.timeout ?? DEFAULT_TIMEOUT;
  }

  /**
   * Resolve a `ClientConfig` (from constructor args and/or env vars) into an `HttpClient`.
   * Token resolution: config > env var > throw. Address resolution: config > env var > default.
   */
  static fromConfig(config?: ClientConfig): HttpClient {
    const cfg = config ?? {};
    const token = cfg.token ?? process.env[ENV_TOKEN];
    if (!token) {
      throw new AgentVaultError(
        `Token is required. Provide it in the config or set the ${ENV_TOKEN} environment variable.`,
      );
    }
    const address = cfg.address ?? process.env[ENV_ADDR] ?? DEFAULT_ADDRESS;
    return new HttpClient({
      baseUrl: address,
      token,
      headers: cfg.headers,
      fetchFn: cfg.fetch,
      timeout: cfg.timeout,
    });
  }

  /**
   * Returns a new HttpClient with additional default headers merged in.
   * The original instance is not modified.
   */
  withHeaders(extra: Record<string, string>): HttpClient {
    return new HttpClient({
      baseUrl: this.baseUrl,
      token: this.token,
      headers: { ...this.defaultHeaders, ...extra },
      fetchFn: this.fetchFn,
      timeout: this.timeout,
    });
  }

  async request<T>(
    method: HttpMethod,
    path: string,
    options?: RequestOptions,
  ): Promise<T> {
    let url = `${this.baseUrl}${path}`;

    if (options?.query) {
      const params = new URLSearchParams();
      for (const [key, value] of Object.entries(options.query)) {
        if (value !== undefined) {
          params.set(key, value);
        }
      }
      const qs = params.toString();
      if (qs) {
        url += `?${qs}`;
      }
    }

    const hasBody = options?.body !== undefined;
    const headers: Record<string, string> = {
      "User-Agent": USER_AGENT,
      Authorization: `Bearer ${this.token}`,
      ...(hasBody ? { "Content-Type": "application/json" } : {}),
      ...this.defaultHeaders,
      ...options?.headers,
    };

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);

    // If the caller provided a signal, forward its abort to our controller
    // so both timeout and caller cancellation go through one AbortController.
    const callerSignal = options?.signal;
    const onCallerAbort = () => controller.abort();
    if (callerSignal) {
      if (callerSignal.aborted) {
        controller.abort();
      } else {
        callerSignal.addEventListener("abort", onCallerAbort, { once: true });
      }
    }

    let response: Response;
    try {
      response = await this.fetchFn(url, {
        method,
        headers,
        body: hasBody ? JSON.stringify(options.body) : undefined,
        signal: controller.signal,
      });
    } catch (err) {
      if (err instanceof DOMException && err.name === "AbortError") {
        throw new AgentVaultError(
          `Request timed out after ${this.timeout}ms: ${method} ${path}`,
        );
      }
      throw new AgentVaultError(
        `Network error: ${err instanceof Error ? err.message : String(err)}`,
      );
    } finally {
      clearTimeout(timeoutId);
      callerSignal?.removeEventListener("abort", onCallerAbort);
    }

    if (!response.ok) {
      throw await ApiError.fromResponse(response);
    }

    return (await response.json()) as T;
  }

  async get<T>(path: string, options?: Omit<RequestOptions, "body">): Promise<T> {
    return this.request<T>("GET", path, options);
  }

  async post<T>(path: string, body?: unknown, options?: Omit<RequestOptions, "body">): Promise<T> {
    return this.request<T>("POST", path, { ...options, body });
  }

  async put<T>(path: string, body?: unknown, options?: Omit<RequestOptions, "body">): Promise<T> {
    return this.request<T>("PUT", path, { ...options, body });
  }

  async del<T>(path: string, body?: unknown, options?: Omit<RequestOptions, "body">): Promise<T> {
    return this.request<T>("DELETE", path, { ...options, body });
  }
}
