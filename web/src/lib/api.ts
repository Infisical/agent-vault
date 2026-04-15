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
