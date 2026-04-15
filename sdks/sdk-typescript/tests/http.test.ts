import { describe, it, expect, vi } from "vitest";
import { HttpClient } from "../src/http.js";
import { ApiError, AgentVaultError } from "../src/errors.js";
import { createMockFetch } from "./helpers.js";

describe("HttpClient", () => {
  describe("URL construction", () => {
    it("strips trailing slashes from base URL", async () => {
      const mockFetch = createMockFetch({ body: { result: "ok" } });
      const client = new HttpClient({
        baseUrl: "http://localhost:14321/",
        token: "test",
        fetchFn: mockFetch,
      });

      await client.get("/v1/vaults");
      expect(mockFetch).toHaveBeenCalledWith(
        "http://localhost:14321/v1/vaults",
        expect.anything(),
      );
    });

    it("appends query parameters", async () => {
      const mockFetch = createMockFetch({ body: {} });
      const client = new HttpClient({
        baseUrl: "http://localhost:14321",
        token: "test",
        fetchFn: mockFetch,
      });

      await client.get("/v1/proposals", {
        query: { status: "pending", vault: "default" },
      });

      const url = mockFetch.mock.calls[0]![0] as string;
      expect(url).toContain("status=pending");
      expect(url).toContain("vault=default");
    });

    it("skips undefined query values", async () => {
      const mockFetch = createMockFetch({ body: {} });
      const client = new HttpClient({
        baseUrl: "http://localhost:14321",
        token: "test",
        fetchFn: mockFetch,
      });

      await client.get("/v1/test", {
        query: { included: "yes", excluded: undefined as unknown as string },
      });

      const url = mockFetch.mock.calls[0]![0] as string;
      expect(url).toContain("included=yes");
      expect(url).not.toContain("excluded");
    });
  });

  describe("headers", () => {
    it("sets Authorization on every request", async () => {
      const mockFetch = createMockFetch({ body: {} });
      const client = new HttpClient({
        baseUrl: "http://localhost:14321",
        token: "my-token",
        fetchFn: mockFetch,
      });

      await client.get("/test");
      const init = mockFetch.mock.calls[0]![1]!;
      const headers = init.headers as Record<string, string>;
      expect(headers["Authorization"]).toBe("Bearer my-token");
    });

    it("sets Content-Type only when body is present", async () => {
      const mockFetch = createMockFetch({ body: {} });
      const client = new HttpClient({
        baseUrl: "http://localhost:14321",
        token: "test",
        fetchFn: mockFetch,
      });

      await client.get("/no-body");
      const getHeaders = (mockFetch.mock.calls[0]![1]!).headers as Record<string, string>;
      expect(getHeaders["Content-Type"]).toBeUndefined();

      await client.post("/with-body", { key: "value" });
      const postHeaders = (mockFetch.mock.calls[1]![1]!).headers as Record<string, string>;
      expect(postHeaders["Content-Type"]).toBe("application/json");
    });

    it("includes default headers", async () => {
      const mockFetch = createMockFetch({ body: {} });
      const client = new HttpClient({
        baseUrl: "http://localhost:14321",
        token: "test",
        headers: { "X-Custom": "value" },
        fetchFn: mockFetch,
      });

      await client.get("/test");
      const init = mockFetch.mock.calls[0]![1]!;
      const headers = init.headers as Record<string, string>;
      expect(headers["X-Custom"]).toBe("value");
    });

    it("allows per-request headers to override defaults", async () => {
      const mockFetch = createMockFetch({ body: {} });
      const client = new HttpClient({
        baseUrl: "http://localhost:14321",
        token: "test",
        headers: { "X-Custom": "default" },
        fetchFn: mockFetch,
      });

      await client.get("/test", { headers: { "X-Custom": "override" } });
      const init = mockFetch.mock.calls[0]![1]!;
      const headers = init.headers as Record<string, string>;
      expect(headers["X-Custom"]).toBe("override");
    });
  });

  describe("withHeaders()", () => {
    it("returns a new instance with merged headers", async () => {
      const mockFetch = createMockFetch({ body: {} });
      const client = new HttpClient({
        baseUrl: "http://localhost:14321",
        token: "test",
        headers: { "X-Existing": "keep" },
        fetchFn: mockFetch,
      });

      const derived = client.withHeaders({ "X-Vault": "production" });
      expect(derived).not.toBe(client);

      await derived.get("/test");
      const init = mockFetch.mock.calls[0]![1]!;
      const headers = init.headers as Record<string, string>;
      expect(headers["X-Vault"]).toBe("production");
      expect(headers["X-Existing"]).toBe("keep");
    });

    it("does not mutate the original client", async () => {
      const mockFetch = createMockFetch({ body: {} });
      const client = new HttpClient({
        baseUrl: "http://localhost:14321",
        token: "test",
        fetchFn: mockFetch,
      });

      client.withHeaders({ "X-Vault": "production" });

      await client.get("/test");
      const init = mockFetch.mock.calls[0]![1]!;
      const headers = init.headers as Record<string, string>;
      expect(headers["X-Vault"]).toBeUndefined();
    });
  });

  describe("error parsing", () => {
    it("throws ApiError on non-2xx response", async () => {
      const mockFetch = createMockFetch({
        ok: false,
        status: 404,
        body: { error: "Vault not found" },
      });
      const client = new HttpClient({
        baseUrl: "http://localhost:14321",
        token: "test",
        fetchFn: mockFetch,
      });

      await expect(client.get("/v1/vaults")).rejects.toThrow(ApiError);
    });

    it("parses standard error format: {error: message}", async () => {
      const mockFetch = createMockFetch({
        ok: false,
        status: 400,
        body: { error: "Invalid request body" },
      });
      const client = new HttpClient({
        baseUrl: "http://localhost:14321",
        token: "test",
        fetchFn: mockFetch,
      });

      try {
        await client.get("/test");
        expect.unreachable("should have thrown");
      } catch (err) {
        expect(err).toBeInstanceOf(ApiError);
        const apiErr = err as ApiError;
        expect(apiErr.status).toBe(400);
        expect(apiErr.code).toBe("Invalid request body");
        expect(apiErr.message).toBe("Invalid request body");
      }
    });

    it("parses proxy error format: {error: code, message: detail}", async () => {
      const mockFetch = createMockFetch({
        ok: false,
        status: 403,
        body: { error: "forbidden", message: "Host not allowed" },
      });
      const client = new HttpClient({
        baseUrl: "http://localhost:14321",
        token: "test",
        fetchFn: mockFetch,
      });

      try {
        await client.get("/proxy/api.stripe.com/v1/charges");
        expect.unreachable("should have thrown");
      } catch (err) {
        expect(err).toBeInstanceOf(ApiError);
        const apiErr = err as ApiError;
        expect(apiErr.status).toBe(403);
        expect(apiErr.code).toBe("forbidden");
        expect(apiErr.message).toBe("Host not allowed");
      }
    });
  });

  describe("request methods", () => {
    it("sends GET with no body", async () => {
      const mockFetch = createMockFetch({ body: { ok: true } });
      const client = new HttpClient({
        baseUrl: "http://localhost:14321",
        token: "test",
        fetchFn: mockFetch,
      });

      await client.get("/test");
      const init = mockFetch.mock.calls[0]![1]!;
      expect(init.method).toBe("GET");
      expect(init.body).toBeUndefined();
    });

    it("sends POST with JSON body", async () => {
      const mockFetch = createMockFetch({ body: { id: 1 } });
      const client = new HttpClient({
        baseUrl: "http://localhost:14321",
        token: "test",
        fetchFn: mockFetch,
      });

      await client.post("/v1/sessions", { vault: "default" });
      const init = mockFetch.mock.calls[0]![1]!;
      expect(init.method).toBe("POST");
      expect(init.body).toBe(JSON.stringify({ vault: "default" }));
    });

    it("sends PUT with JSON body", async () => {
      const mockFetch = createMockFetch({ body: {} });
      const client = new HttpClient({
        baseUrl: "http://localhost:14321",
        token: "test",
        fetchFn: mockFetch,
      });

      await client.put("/v1/vaults/test/services", []);
      const init = mockFetch.mock.calls[0]![1]!;
      expect(init.method).toBe("PUT");
    });

    it("sends DELETE with JSON body", async () => {
      const mockFetch = createMockFetch({ body: { deleted: ["KEY"] } });
      const client = new HttpClient({
        baseUrl: "http://localhost:14321",
        token: "test",
        fetchFn: mockFetch,
      });

      await client.del("/v1/credentials", { keys: ["KEY"] });
      const init = mockFetch.mock.calls[0]![1]!;
      expect(init.method).toBe("DELETE");
    });
  });

  describe("timeout", () => {
    it("throws AgentVaultError on timeout", async () => {
      const mockFetch = vi
        .fn<typeof globalThis.fetch>()
        .mockImplementation((_url, init) => {
          return new Promise((_resolve, reject) => {
            init?.signal?.addEventListener("abort", () => {
              reject(new DOMException("The operation was aborted.", "AbortError"));
            });
          });
        });

      const client = new HttpClient({
        baseUrl: "http://localhost:14321",
        token: "test",
        fetchFn: mockFetch,
        timeout: 1, // 1ms timeout
      });

      await expect(client.get("/slow")).rejects.toThrow(AgentVaultError);
      await expect(client.get("/slow")).rejects.toThrow("timed out");
    });
  });

  describe("network errors", () => {
    it("wraps network errors in AgentVaultError", async () => {
      const mockFetch = vi
        .fn<typeof globalThis.fetch>()
        .mockRejectedValue(new TypeError("fetch failed"));

      const client = new HttpClient({
        baseUrl: "http://localhost:14321",
        token: "test",
        fetchFn: mockFetch,
      });

      await expect(client.get("/test")).rejects.toThrow(AgentVaultError);
      await expect(client.get("/test")).rejects.toThrow("Network error");
    });
  });
});
