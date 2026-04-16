import { describe, it, expect } from "vitest";
import { AgentVault } from "../src/client.js";
import { VaultClient } from "../src/vault.js";
import { AgentVaultError, ProxyForbiddenError, ApiError } from "../src/errors.js";
import { createMockFetch } from "./helpers.js";

describe("ProxyResource", () => {
  // -------------------------------------------------------------------------
  // URL construction
  // -------------------------------------------------------------------------

  describe("URL construction", () => {
    it("builds /proxy/{host}/{path} URL", async () => {
      const mockFetch = createMockFetch({ body: { ok: true } });
      const vault = new VaultClient({
        token: "test-token",
        address: "http://localhost:14321",
        fetch: mockFetch,
      });

      await vault.proxy.get("api.stripe.com", "/v1/charges");

      const [url, init] = mockFetch.mock.calls[0]!;
      expect(url).toBe("http://localhost:14321/proxy/api.stripe.com/v1/charges");
      expect(init?.method).toBe("GET");
    });

    it("defaults path to / when omitted", async () => {
      const mockFetch = createMockFetch({ body: {} });
      const vault = new VaultClient({
        token: "test-token",
        address: "http://localhost:14321",
        fetch: mockFetch,
      });

      await vault.proxy.get("api.stripe.com");

      const [url] = mockFetch.mock.calls[0]!;
      expect(url).toBe("http://localhost:14321/proxy/api.stripe.com/");
    });

    it("normalizes path without leading slash", async () => {
      const mockFetch = createMockFetch({ body: {} });
      const vault = new VaultClient({
        token: "test-token",
        address: "http://localhost:14321",
        fetch: mockFetch,
      });

      await vault.proxy.get("api.stripe.com", "v1/charges");

      const [url] = mockFetch.mock.calls[0]!;
      expect(url).toBe("http://localhost:14321/proxy/api.stripe.com/v1/charges");
    });

    it("appends query parameters", async () => {
      const mockFetch = createMockFetch({ body: {} });
      const vault = new VaultClient({
        token: "test-token",
        address: "http://localhost:14321",
        fetch: mockFetch,
      });

      await vault.proxy.get("api.stripe.com", "/v1/charges", {
        query: { limit: 10, active: true },
      });

      const [url] = mockFetch.mock.calls[0]!;
      expect(url).toContain("/proxy/api.stripe.com/v1/charges?");
      expect(url).toContain("limit=10");
      expect(url).toContain("active=true");
    });
  });

  // -------------------------------------------------------------------------
  // HTTP methods
  // -------------------------------------------------------------------------

  describe("HTTP methods", () => {
    it.each([
      ["get", "GET"],
      ["post", "POST"],
      ["put", "PUT"],
      ["patch", "PATCH"],
      ["delete", "DELETE"],
    ] as const)(".%s() sends %s method", async (method, httpMethod) => {
      const mockFetch = createMockFetch({ body: {} });
      const vault = new VaultClient({
        token: "test-token",
        address: "http://localhost:14321",
        fetch: mockFetch,
      });

      await (vault.proxy[method] as Function)("api.example.com", "/path");

      const [, init] = mockFetch.mock.calls[0]!;
      expect(init?.method).toBe(httpMethod);
    });

    it("request() supports arbitrary HTTP methods", async () => {
      const mockFetch = createMockFetch({ body: {} });
      const vault = new VaultClient({
        token: "test-token",
        address: "http://localhost:14321",
        fetch: mockFetch,
      });

      await vault.proxy.request("OPTIONS", "api.example.com", { path: "/v1" });

      const [, init] = mockFetch.mock.calls[0]!;
      expect(init?.method).toBe("OPTIONS");
    });
  });

  // -------------------------------------------------------------------------
  // Headers
  // -------------------------------------------------------------------------

  describe("headers", () => {
    it("includes Authorization header for Agent Vault auth", async () => {
      const mockFetch = createMockFetch({ body: {} });
      const vault = new VaultClient({
        token: "my-session-token",
        address: "http://localhost:14321",
        fetch: mockFetch,
      });

      await vault.proxy.get("api.example.com", "/");

      const [, init] = mockFetch.mock.calls[0]!;
      const headers = init?.headers as Record<string, string>;
      expect(headers["Authorization"]).toBe("Bearer my-session-token");
    });

    it("includes X-Vault header when created via AgentVault.vault()", async () => {
      const mockFetch = createMockFetch({ body: {} });
      const av = new AgentVault({
        token: "agent-token",
        address: "http://localhost:14321",
        fetch: mockFetch,
      });

      await av.vault("production").proxy.get("api.stripe.com", "/v1/charges");

      const [, init] = mockFetch.mock.calls[0]!;
      const headers = init?.headers as Record<string, string>;
      expect(headers["X-Vault"]).toBe("production");
    });

    it("forwards caller headers to the request", async () => {
      const mockFetch = createMockFetch({ body: {} });
      const vault = new VaultClient({
        token: "test-token",
        address: "http://localhost:14321",
        fetch: mockFetch,
      });

      await vault.proxy.get("api.example.com", "/", {
        headers: { "Idempotency-Key": "abc-123" },
      });

      const [, init] = mockFetch.mock.calls[0]!;
      const headers = init?.headers as Record<string, string>;
      expect(headers["Idempotency-Key"]).toBe("abc-123");
    });

    it("protects Authorization header from caller override", async () => {
      const mockFetch = createMockFetch({ body: {} });
      const vault = new VaultClient({
        token: "my-session-token",
        address: "http://localhost:14321",
        fetch: mockFetch,
      });

      await vault.proxy.get("api.example.com", "/", {
        headers: { Authorization: "Bearer upstream-token" },
      });

      const [, init] = mockFetch.mock.calls[0]!;
      const headers = init?.headers as Record<string, string>;
      expect(headers["Authorization"]).toBe("Bearer my-session-token");
    });
  });

  // -------------------------------------------------------------------------
  // Body handling
  // -------------------------------------------------------------------------

  describe("body handling", () => {
    it("JSON-stringifies plain object bodies", async () => {
      const mockFetch = createMockFetch({ body: {} });
      const vault = new VaultClient({
        token: "test-token",
        address: "http://localhost:14321",
        fetch: mockFetch,
      });

      await vault.proxy.post("api.github.com", "/repos/o/r/issues", {
        body: { title: "Bug", body: "steps" },
      });

      const [, init] = mockFetch.mock.calls[0]!;
      expect(init?.body).toBe('{"title":"Bug","body":"steps"}');
      const headers = init?.headers as Record<string, string>;
      expect(headers["Content-Type"]).toBe("application/json");
    });

    it("JSON-stringifies array bodies", async () => {
      const mockFetch = createMockFetch({ body: {} });
      const vault = new VaultClient({
        token: "test-token",
        address: "http://localhost:14321",
        fetch: mockFetch,
      });

      await vault.proxy.post("api.example.com", "/batch", {
        body: [{ id: 1 }, { id: 2 }],
      });

      const [, init] = mockFetch.mock.calls[0]!;
      expect(init?.body).toBe('[{"id":1},{"id":2}]');
    });

    it("passes string bodies through without JSON-stringifying", async () => {
      const mockFetch = createMockFetch({ body: {} });
      const vault = new VaultClient({
        token: "test-token",
        address: "http://localhost:14321",
        fetch: mockFetch,
      });

      await vault.proxy.post("api.example.com", "/raw", {
        body: "raw-body-content",
        headers: { "Content-Type": "text/plain" },
      });

      const [, init] = mockFetch.mock.calls[0]!;
      expect(init?.body).toBe("raw-body-content");
    });
  });

  // -------------------------------------------------------------------------
  // Response handling
  // -------------------------------------------------------------------------

  describe("response handling", () => {
    it("returns ProxyResponse with status and ok for success", async () => {
      const mockFetch = createMockFetch({
        ok: true,
        status: 200,
        body: { data: [{ id: "ch_1" }] },
      });
      const vault = new VaultClient({
        token: "test-token",
        address: "http://localhost:14321",
        fetch: mockFetch,
      });

      const res = await vault.proxy.get("api.stripe.com", "/v1/charges");

      expect(res.ok).toBe(true);
      expect(res.status).toBe(200);
      const data = await res.json<{ data: { id: string }[] }>();
      expect(data.data[0].id).toBe("ch_1");
    });

    it("returns ProxyResponse for upstream non-2xx (does not throw)", async () => {
      const mockFetch = createMockFetch({
        ok: false,
        status: 404,
        statusText: "Not Found",
        body: { error: { message: "No such customer" } },
      });
      const vault = new VaultClient({
        token: "test-token",
        address: "http://localhost:14321",
        fetch: mockFetch,
      });

      const res = await vault.proxy.get("api.stripe.com", "/v1/customers/cus_missing");

      expect(res.ok).toBe(false);
      expect(res.status).toBe(404);
      const data = await res.json();
      expect(data).toEqual({ error: { message: "No such customer" } });
    });
  });

  // -------------------------------------------------------------------------
  // Broker error handling
  // -------------------------------------------------------------------------

  describe("broker error handling", () => {
    it("throws ProxyForbiddenError for 403 with proposal_hint", async () => {
      const mockFetch = createMockFetch({
        ok: false,
        status: 403,
        statusText: "Forbidden",
        headers: { "X-Agent-Vault-Proxy-Error": "true" },
        body: {
          error: "forbidden",
          message: 'No broker service matching host "api.unknown.com" in vault "default"',
          proposal_hint: {
            host: "api.unknown.com",
            endpoint: "POST /v1/proposals",
            supported_auth_types: ["bearer", "basic", "api-key", "custom"],
          },
        },
      });
      const vault = new VaultClient({
        token: "test-token",
        address: "http://localhost:14321",
        fetch: mockFetch,
      });

      try {
        await vault.proxy.get("api.unknown.com", "/");
        expect.fail("should have thrown");
      } catch (err) {
        expect(err).toBeInstanceOf(ProxyForbiddenError);
        const e = err as ProxyForbiddenError;
        expect(e.status).toBe(403);
        expect(e.proposalHint.host).toBe("api.unknown.com");
        expect(e.proposalHint.endpoint).toBe("POST /v1/proposals");
        expect(e.proposalHint.supportedAuthTypes).toEqual([
          "bearer",
          "basic",
          "api-key",
          "custom",
        ]);
      }
    });

    it("throws ApiError for 502 broker error (credential_not_found)", async () => {
      const mockFetch = createMockFetch({
        ok: false,
        status: 502,
        statusText: "Bad Gateway",
        headers: { "X-Agent-Vault-Proxy-Error": "true" },
        body: {
          error: "credential_not_found",
          message: "A required credential could not be resolved; check vault configuration",
        },
      });
      const vault = new VaultClient({
        token: "test-token",
        address: "http://localhost:14321",
        fetch: mockFetch,
      });

      try {
        await vault.proxy.get("api.stripe.com", "/v1/charges");
        expect.fail("should have thrown");
      } catch (err) {
        expect(err).toBeInstanceOf(ApiError);
        const e = err as ApiError;
        expect(e.status).toBe(502);
        expect(e.code).toBe("credential_not_found");
      }
    });

    it("throws ApiError for 400 broker error (bad_request)", async () => {
      const mockFetch = createMockFetch({
        ok: false,
        status: 400,
        statusText: "Bad Request",
        headers: { "X-Agent-Vault-Proxy-Error": "true" },
        body: {
          error: "bad_request",
          message: "Missing target host in proxy URL",
        },
      });
      const vault = new VaultClient({
        token: "test-token",
        address: "http://localhost:14321",
        fetch: mockFetch,
      });

      try {
        await vault.proxy.request("GET", "example.com", { path: "/" });
        expect.fail("should have thrown");
      } catch (err) {
        expect(err).toBeInstanceOf(ApiError);
        expect((err as ApiError).code).toBe("bad_request");
      }
    });

    it("does NOT throw for upstream 403 without sentinel header", async () => {
      const mockFetch = createMockFetch({
        ok: false,
        status: 403,
        statusText: "Forbidden",
        body: { error: "forbidden", message: "Upstream denied" },
      });
      const vault = new VaultClient({
        token: "test-token",
        address: "http://localhost:14321",
        fetch: mockFetch,
      });

      const res = await vault.proxy.get("api.example.com", "/protected");
      expect(res.ok).toBe(false);
      expect(res.status).toBe(403);
    });
  });

  // -------------------------------------------------------------------------
  // Validation
  // -------------------------------------------------------------------------

  describe("validation", () => {
    it("rejects empty host", async () => {
      const vault = new VaultClient({
        token: "test-token",
        address: "http://localhost:14321",
        fetch: createMockFetch({ body: {} }),
      });

      await expect(vault.proxy.get("", "/")).rejects.toThrow(AgentVaultError);
    });

    it("rejects host with @ character", async () => {
      const vault = new VaultClient({
        token: "test-token",
        address: "http://localhost:14321",
        fetch: createMockFetch({ body: {} }),
      });

      await expect(vault.proxy.get("user@evil.com", "/")).rejects.toThrow(
        "forbidden characters",
      );
    });

    it("rejects host with / character", async () => {
      const vault = new VaultClient({
        token: "test-token",
        address: "http://localhost:14321",
        fetch: createMockFetch({ body: {} }),
      });

      await expect(vault.proxy.get("host/path", "/")).rejects.toThrow(
        "forbidden characters",
      );
    });

    it("rejects host with non-numeric port", async () => {
      const vault = new VaultClient({
        token: "test-token",
        address: "http://localhost:14321",
        fetch: createMockFetch({ body: {} }),
      });

      await expect(vault.proxy.get("host:abc", "/")).rejects.toThrow(
        "Invalid port",
      );
    });

    it("allows host with numeric port", async () => {
      const mockFetch = createMockFetch({ body: {} });
      const vault = new VaultClient({
        token: "test-token",
        address: "http://localhost:14321",
        fetch: mockFetch,
      });

      await vault.proxy.get("api.example.com:8443", "/");

      const [url] = mockFetch.mock.calls[0]!;
      expect(url).toContain("/proxy/api.example.com:8443/");
    });

    it("rejects path with .. segments (path traversal)", async () => {
      const vault = new VaultClient({
        token: "test-token",
        address: "http://localhost:14321",
        fetch: createMockFetch({ body: {} }),
      });

      await expect(
        vault.proxy.get("api.example.com", "/../../../v1/credentials"),
      ).rejects.toThrow("path traversal");
    });

    it("rejects path with .. in middle", async () => {
      const vault = new VaultClient({
        token: "test-token",
        address: "http://localhost:14321",
        fetch: createMockFetch({ body: {} }),
      });

      await expect(
        vault.proxy.get("api.example.com", "/v1/../admin"),
      ).rejects.toThrow("path traversal");
    });
  });
});
