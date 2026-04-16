import { vi } from "vitest";

export function createMockFetch(response: {
  ok?: boolean;
  status?: number;
  statusText?: string;
  body?: unknown;
  headers?: Record<string, string>;
}) {
  const ok = response.ok ?? true;
  const status = response.status ?? (ok ? 200 : 400);
  const headers = new Headers(response.headers);
  const bodyText = JSON.stringify(response.body ?? {});
  return vi.fn<typeof globalThis.fetch>().mockResolvedValue({
    ok,
    status,
    statusText: response.statusText ?? (ok ? "OK" : "Bad Request"),
    headers,
    json: () => Promise.resolve(response.body ?? {}),
    text: () => Promise.resolve(bodyText),
    arrayBuffer: () =>
      Promise.resolve(new TextEncoder().encode(bodyText).buffer),
    body: null,
  } as Response);
}
