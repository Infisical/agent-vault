export class ApiError extends Error {
  status: number;
  code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
  }
}

export async function apiFetch(
  url: string,
  options?: RequestInit,
): Promise<Response> {
  return fetch(url, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...options?.headers,
    },
  });
}

export function isAbortError(err: unknown): boolean {
  return err instanceof DOMException && err.name === "AbortError";
}

export async function apiRequest<T = unknown>(
  url: string,
  options?: RequestInit,
): Promise<T> {
  const resp = await apiFetch(url, options);
  if (!resp.ok) {
    const body = await resp.json().catch(() => ({}));
    throw new ApiError(
      resp.status,
      body.error ?? "unknown",
      body.message ?? body.error ?? resp.statusText,
    );
  }
  return resp.json();
}

// --- Upstream (egress) proxy profiles ---
//
// Profiles are instance-owned config: created in /manage/upstream-proxies and
// referenced by name from a service's `upstream_proxy` field. The read model
// deliberately carries no secret material — `has_auth`/`has_ca` report whether
// something is configured without revealing what.

export type UpstreamProxy = {
  name: string;
  scheme: string;
  host: string;
  has_auth: boolean;
  no_proxy: string;
  has_ca: boolean;
  on_failure: string;
  is_default: boolean;
  enabled: boolean;
  created_at: string;
  updated_at: string;
};

export type UpstreamProxyInput = {
  name: string;
  scheme: string;
  host: string;
  username?: string;
  password?: string;
  no_proxy?: string;
  proxy_ca_pem?: string;
  on_failure?: string;
  is_default?: boolean;
  enabled?: boolean;
};

// Every field is optional on update. Username and password are independent:
// omit one to retain it, or send an empty string to clear only that field.
// `clear_auth` explicitly drops both credentials.
export type UpstreamProxyPatch = {
  scheme?: string;
  host?: string;
  username?: string;
  password?: string;
  clear_auth?: boolean;
  no_proxy?: string;
  proxy_ca_pem?: string;
  on_failure?: string;
  is_default?: boolean;
  enabled?: boolean;
};

export async function listUpstreamProxies(): Promise<UpstreamProxy[]> {
  const data = await apiRequest<{ proxies?: UpstreamProxy[] }>(
    "/v1/admin/upstream-proxies",
  );
  return data.proxies ?? [];
}

export async function createUpstreamProxy(
  input: UpstreamProxyInput,
): Promise<UpstreamProxy> {
  const data = await apiRequest<{ proxy: UpstreamProxy }>(
    "/v1/admin/upstream-proxies",
    { method: "POST", body: JSON.stringify(input) },
  );
  return data.proxy;
}

export async function updateUpstreamProxy(
  name: string,
  patch: UpstreamProxyPatch,
): Promise<UpstreamProxy> {
  const data = await apiRequest<{ proxy: UpstreamProxy }>(
    `/v1/admin/upstream-proxies/${encodeURIComponent(name)}`,
    { method: "PATCH", body: JSON.stringify(patch) },
  );
  return data.proxy;
}

export async function deleteUpstreamProxy(name: string): Promise<void> {
  await apiRequest(
    `/v1/admin/upstream-proxies/${encodeURIComponent(name)}`,
    { method: "DELETE" },
  );
}
