import type { HttpClient, RawRequestBody } from "../http.js";
import { AgentVaultError, ApiError } from "../errors.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface ProxyRequestOptions {
  /** Path appended after the host (default: "/"). */
  path?: string;
  /** Query parameters appended to the upstream URL. */
  query?: Record<string, string | number | boolean>;
  /**
   * Headers forwarded to the upstream service.
   * Only headers in the server's allowlist are actually forwarded:
   * Content-Type, Accept, User-Agent, Idempotency-Key, X-Request-Id, etc.
   * The `Authorization` header is always stripped by the broker and replaced
   * with credentials from the vault's service configuration.
   */
  headers?: Record<string, string>;
  /**
   * Request body. Plain objects and arrays are JSON-stringified with
   * `Content-Type: application/json` set automatically. Strings and Buffers
   * are passed through — set Content-Type yourself if needed.
   */
  body?: RawRequestBody | Record<string, unknown> | unknown[];
  /** AbortSignal for cancellation. */
  signal?: AbortSignal;
  /** Per-request timeout in milliseconds. 0 disables timeout. */
  timeout?: number;
}

export interface ProxyResponse {
  /** HTTP status code from the upstream service. */
  status: number;
  /** HTTP status text from the upstream service. */
  statusText: string;
  /** True if status is in the 200–299 range. */
  ok: boolean;
  /** Response headers from the upstream service. */
  headers: Headers;
  /** Parse the response body as JSON. */
  json<T = unknown>(): Promise<T>;
  /** Read the response body as text. */
  text(): Promise<string>;
  /** Read the response body as an ArrayBuffer. */
  arrayBuffer(): Promise<ArrayBuffer>;
  /** Raw response body stream (null if already consumed). */
  body: ReadableStream<Uint8Array> | null;
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

const INVALID_HOST_CHARS = /[@?#/\\\s%]/;
const CONTROL_CHAR = /[\x00-\x1f\x7f]/;

function validateHost(host: string): void {
  if (!host) {
    throw new AgentVaultError("Proxy host must not be empty");
  }

  let hostname = host;
  const colonIdx = host.lastIndexOf(":");
  if (colonIdx !== -1) {
    hostname = host.slice(0, colonIdx);
    const port = host.slice(colonIdx + 1);
    if (!/^\d+$/.test(port)) {
      throw new AgentVaultError(`Invalid port in proxy host: ${host}`);
    }
  }

  if (!hostname) {
    throw new AgentVaultError("Proxy host must not be empty");
  }

  if (INVALID_HOST_CHARS.test(hostname) || CONTROL_CHAR.test(hostname)) {
    throw new AgentVaultError(
      `Invalid proxy host "${host}": contains forbidden characters`,
    );
  }
}

function validatePath(path: string): void {
  const segments = path.split("/");
  for (const segment of segments) {
    if (segment === "..") {
      throw new AgentVaultError(
        'Proxy path must not contain ".." segments (path traversal)',
      );
    }
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const BROKER_ERROR_HEADER = "X-Agent-Vault-Proxy-Error";

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null) return false;
  if (ArrayBuffer.isView(value) || value instanceof ArrayBuffer) return false;
  if (typeof ReadableStream !== "undefined" && value instanceof ReadableStream) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function wrapResponse(response: Response): ProxyResponse {
  return {
    status: response.status,
    statusText: response.statusText,
    ok: response.ok,
    headers: response.headers,
    json: <T = unknown>() => response.json() as Promise<T>,
    text: () => response.text(),
    arrayBuffer: () => response.arrayBuffer(),
    body: response.body,
  };
}

// ---------------------------------------------------------------------------
// Resource
// ---------------------------------------------------------------------------

export class ProxyResource {
  private readonly httpClient: HttpClient;

  constructor(httpClient: HttpClient) {
    this.httpClient = httpClient;
  }

  /**
   * Send an HTTP request through the Agent Vault proxy.
   *
   * The broker matches the target host against configured services, injects
   * credentials, and forwards the request to `https://{host}/{path}`.
   *
   * Upstream responses (including non-2xx) resolve normally as a `ProxyResponse`.
   * Broker-level errors (no matching service, missing credentials, auth failures)
   * throw `ApiError` or `ProxyForbiddenError`.
   */
  async request(
    method: string,
    host: string,
    options?: ProxyRequestOptions,
  ): Promise<ProxyResponse> {
    validateHost(host);

    const path = options?.path ?? "/";
    validatePath(path);

    const normalizedPath = path.startsWith("/") ? path : `/${path}`;
    const proxyPath = `/proxy/${host}${normalizedPath}`;

    let body: RawRequestBody | null | undefined;
    let headers = options?.headers;

    if (options?.body !== undefined) {
      if (Array.isArray(options.body) || isPlainObject(options.body)) {
        body = JSON.stringify(options.body);
        if (!headers?.["Content-Type"]) {
          headers = { ...headers, "Content-Type": "application/json" };
        }
      } else {
        body = options.body as RawRequestBody;
      }
    }

    const response = await this.httpClient.raw(method, proxyPath, {
      headers,
      query: options?.query,
      body,
      signal: options?.signal,
      timeout: options?.timeout,
    });

    if (
      !response.ok &&
      response.headers.get(BROKER_ERROR_HEADER) === "true"
    ) {
      throw await ApiError.fromResponse(response);
    }

    return wrapResponse(response);
  }

  private _verb(
    method: string,
    host: string,
    path?: string,
    options?: Omit<ProxyRequestOptions, "path">,
  ): Promise<ProxyResponse> {
    return this.request(method, host, { ...options, path });
  }

  async get(host: string, path?: string, options?: Omit<ProxyRequestOptions, "path">) {
    return this._verb("GET", host, path, options);
  }

  async post(host: string, path?: string, options?: Omit<ProxyRequestOptions, "path">) {
    return this._verb("POST", host, path, options);
  }

  async put(host: string, path?: string, options?: Omit<ProxyRequestOptions, "path">) {
    return this._verb("PUT", host, path, options);
  }

  async patch(host: string, path?: string, options?: Omit<ProxyRequestOptions, "path">) {
    return this._verb("PATCH", host, path, options);
  }

  async delete(host: string, path?: string, options?: Omit<ProxyRequestOptions, "path">) {
    return this._verb("DELETE", host, path, options);
  }
}
