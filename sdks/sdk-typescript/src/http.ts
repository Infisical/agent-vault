import { AgentVaultError, ApiError } from "./errors.js";
import type { ClientConfig } from "./types.js";

export type HttpMethod = "GET" | "POST" | "PUT" | "DELETE" | "PATCH" | "HEAD";

export interface RequestOptions {
  body?: unknown;
  headers?: Record<string, string>;
  query?: Record<string, string | number | boolean>;
  signal?: AbortSignal;
}

/** Body types accepted by `raw()`. Compatible with Node and browser runtimes. */
export type RawRequestBody = string | ArrayBuffer | Buffer | Uint8Array | ReadableStream;

export interface RawRequestOptions {
  headers?: Record<string, string>;
  query?: Record<string, string | number | boolean>;
  body?: RawRequestBody | null;
  signal?: AbortSignal;
  timeout?: number;
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

  /** Returns the base URL this client is configured to talk to. */
  getBaseUrl(): string {
    return this.baseUrl;
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

  private buildUrl(path: string, query?: Record<string, string | number | boolean>): string {
    let url = `${this.baseUrl}${path}`;
    if (query) {
      const params = new URLSearchParams();
      for (const [key, value] of Object.entries(query)) {
        if (value !== undefined) {
          params.set(key, String(value));
        }
      }
      const qs = params.toString();
      if (qs) {
        url += `?${qs}`;
      }
    }
    return url;
  }

  private buildHeaders(
    callerHeaders?: Record<string, string>,
  ): Record<string, string> {
    // Authorization and User-Agent are protected — callers cannot override them.
    return {
      ...this.defaultHeaders,
      ...callerHeaders,
      "User-Agent": USER_AGENT,
      Authorization: `Bearer ${this.token}`,
    };
  }

  private async doFetch(opts: {
    method: string;
    url: string;
    headers: Record<string, string>;
    body?: RawRequestBody | string | null;
    signal?: AbortSignal;
    timeoutMs: number;
    label: string;
  }): Promise<Response> {
    const controller = new AbortController();
    const useTimeout = opts.timeoutMs > 0 && isFinite(opts.timeoutMs);
    const timeoutId = useTimeout
      ? setTimeout(() => controller.abort(), opts.timeoutMs)
      : undefined;

    const callerSignal = opts.signal;
    const onCallerAbort = () => controller.abort();
    if (callerSignal) {
      if (callerSignal.aborted) {
        controller.abort();
      } else {
        callerSignal.addEventListener("abort", onCallerAbort, { once: true });
      }
    }

    try {
      return await this.fetchFn(opts.url, {
        method: opts.method,
        headers: opts.headers,
        body: opts.body,
        signal: controller.signal,
      });
    } catch (err) {
      if (err instanceof DOMException && err.name === "AbortError") {
        throw new AgentVaultError(
          `Request timed out after ${opts.timeoutMs}ms: ${opts.label}`,
        );
      }
      throw new AgentVaultError(
        `Network error: ${err instanceof Error ? err.message : String(err)}`,
      );
    } finally {
      if (timeoutId !== undefined) clearTimeout(timeoutId);
      callerSignal?.removeEventListener("abort", onCallerAbort);
    }
  }

  async request<T>(
    method: HttpMethod,
    path: string,
    options?: RequestOptions,
  ): Promise<T> {
    const url = this.buildUrl(path, options?.query);
    const hasBody = options?.body !== undefined;
    const callerHeaders = hasBody
      ? { ...options?.headers, "Content-Type": "application/json" }
      : options?.headers;
    const headers = this.buildHeaders(callerHeaders);

    const response = await this.doFetch({
      method,
      url,
      headers,
      body: hasBody ? JSON.stringify(options.body) : undefined,
      signal: options?.signal,
      timeoutMs: this.timeout,
      label: `${method} ${path}`,
    });

    if (!response.ok) {
      throw await ApiError.fromResponse(response);
    }

    return (await response.json()) as T;
  }

  /**
   * Perform an HTTP request and return the raw Response without parsing or
   * throwing on non-2xx. Used by ProxyResource where the response body format
   * is determined by the upstream service, not Agent Vault.
   */
  async raw(
    method: string,
    path: string,
    options?: RawRequestOptions,
  ): Promise<Response> {
    const url = this.buildUrl(path, options?.query);
    const headers = this.buildHeaders(options?.headers);
    const timeoutMs = options?.timeout ?? this.timeout;

    return this.doFetch({
      method,
      url,
      headers,
      body: options?.body,
      signal: options?.signal,
      timeoutMs,
      label: `${method} ${path}`,
    });
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
