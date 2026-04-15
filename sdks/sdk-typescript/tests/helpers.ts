import { vi } from "vitest";

export function createMockFetch(response: {
  ok?: boolean;
  status?: number;
  statusText?: string;
  body?: unknown;
}) {
  const ok = response.ok ?? true;
  const status = response.status ?? (ok ? 200 : 400);
  return vi.fn<typeof globalThis.fetch>().mockResolvedValue({
    ok,
    status,
    statusText: response.statusText ?? "OK",
    headers: new Headers(),
    json: () => Promise.resolve(response.body ?? {}),
  } as Response);
}
