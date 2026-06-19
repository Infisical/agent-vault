import { afterEach, describe, test } from "node:test";
import assert from "node:assert/strict";

import { buildExampleApiUrl, exampleApiGet, normalizeExampleApiPath } from "./example-api.js";

type FetchCall = { url: string; init?: RequestInit };

const realFetch = globalThis.fetch;

function mockFetch(body: unknown, options: { status?: number; statusText?: string; contentType?: string } = {}) {
  const calls: FetchCall[] = [];
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input.toString();
    calls.push({ url, init });
    const text = typeof body === "string" ? body : JSON.stringify(body);
    return {
      status: options.status ?? 200,
      statusText: options.statusText ?? "OK",
      headers: new Headers({ "content-type": options.contentType ?? "application/json" }),
      text: async () => text,
    } as Response;
  }) as unknown as typeof fetch;
  return calls;
}

function firstText(result: unknown): string {
  const content = (result as { content?: Array<{ text?: unknown }> }).content;
  const text = content?.[0]?.text;
  return typeof text === "string" ? text : "";
}

afterEach(() => {
  globalThis.fetch = realFetch;
  delete process.env.EXAMPLE_API_BASE_URL;
});

describe("normalizeExampleApiPath", () => {
  test("accepts simple relative API paths", () => {
    assert.equal(normalizeExampleApiPath(" /v1/items?limit=2 "), "/v1/items?limit=2");
  });

  test("rejects non-relative or traversal-looking paths", () => {
    assert.throws(() => normalizeExampleApiPath("v1/items"), /start with/);
    assert.throws(() => normalizeExampleApiPath("https://example.com/v1/items"), /start with/);
    assert.throws(() => normalizeExampleApiPath("/../admin"), /schemes or traversal/);
  });
});

describe("buildExampleApiUrl", () => {
  test("builds against the configured base URL", () => {
    assert.equal(
      buildExampleApiUrl("/v1/items?limit=2", "https://api.example.com/base/").toString(),
      "https://api.example.com/base/v1/items?limit=2",
    );
  });

  test("requires EXAMPLE_API_BASE_URL", () => {
    assert.throws(() => buildExampleApiUrl("/v1/items"), /EXAMPLE_API_BASE_URL/);
  });
});

describe("exampleApiGet", () => {
  test("returns setup guidance when no base URL is configured", async () => {
    const calls = mockFetch({ ok: true });
    const result = await exampleApiGet.handler({ path: "/v1/items" }, undefined);

    assert.equal(calls.length, 0);
    assert.match(firstText(result), /EXAMPLE_API_BASE_URL is not set/);
  });

  test("fetches JSON from the configured base URL without auth headers", async () => {
    process.env.EXAMPLE_API_BASE_URL = "https://api.example.com";
    const calls = mockFetch({ items: [1, 2] });

    const result = await exampleApiGet.handler({ path: "/v1/items" }, undefined);
    const text = firstText(result);

    assert.equal(calls.length, 1);
    assert.equal(calls[0]?.url, "https://api.example.com/v1/items");
    assert.equal(calls[0]?.init?.redirect, "error");
    const headers = calls[0]?.init?.headers as Record<string, string> | undefined;
    assert.equal(headers?.Accept, "application/json");
    assert.equal(headers?.Authorization, undefined);
    assert.match(text, /Status: 200 OK/);
    assert.match(text, /"items"/);
  });
});
