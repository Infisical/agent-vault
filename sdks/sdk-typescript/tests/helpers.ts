import { vi } from "vitest";

interface MockResponseOptions {
  ok?: boolean;
  status?: number;
  statusText?: string;
  body?: unknown;
  headers?: Record<string, string>;
}

function buildMockResponse(response: MockResponseOptions): Response {
  const ok = response.ok ?? true;
  const status = response.status ?? (ok ? 200 : 400);
  const bodyText = typeof response.body === "string"
    ? response.body
    : JSON.stringify(response.body ?? {});
  return {
    ok,
    status,
    statusText: response.statusText ?? (ok ? "OK" : "Bad Request"),
    headers: new Headers(response.headers),
    json: () => Promise.resolve(response.body ?? {}),
    text: () => Promise.resolve(bodyText),
    arrayBuffer: () =>
      Promise.resolve(new TextEncoder().encode(bodyText).buffer),
    body: null,
  } as Response;
}

export function createMockFetch(response: MockResponseOptions) {
  return vi.fn<typeof globalThis.fetch>().mockResolvedValue(
    buildMockResponse(response),
  );
}

/** Create a mock fetch that routes by URL path substring. */
export function createRoutedMockFetch(routes: Record<string, MockResponseOptions>) {
  return vi.fn<typeof globalThis.fetch>().mockImplementation(async (input) => {
    const url = typeof input === "string" ? input : (input as Request).url;
    for (const [pattern, response] of Object.entries(routes)) {
      if (url.includes(pattern)) {
        return buildMockResponse(response);
      }
    }
    throw new Error(`Unexpected URL: ${url}`);
  });
}
