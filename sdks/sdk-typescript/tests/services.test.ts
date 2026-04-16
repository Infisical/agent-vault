import { describe, it, expect } from "vitest";
import { AgentVault } from "../src/client.js";
import { createMockFetch } from "./helpers.js";

describe("ServicesResource", () => {
  describe("list()", () => {
    it("sends GET /v1/vaults/{name}/services", async () => {
      const mockFetch = createMockFetch({
        body: { vault: "my-project", services: [] },
      });

      const av = new AgentVault({
        token: "agent-token",
        address: "http://localhost:14321",
        fetch: mockFetch,
      });
      await av.vault("my-project").services!.list();

      expect(mockFetch).toHaveBeenCalledOnce();
      const [url, init] = mockFetch.mock.calls[0]!;
      expect(url).toBe("http://localhost:14321/v1/vaults/my-project/services");
      expect(init?.method).toBe("GET");
    });

    it("returns services array from response", async () => {
      const mockFetch = createMockFetch({
        body: {
          vault: "default",
          services: [
            {
              host: "api.stripe.com",
              description: "Stripe API",
              auth: { type: "bearer", token: "STRIPE_KEY" },
            },
          ],
        },
      });

      const av = new AgentVault({
        token: "agent-token",
        address: "http://localhost:14321",
        fetch: mockFetch,
      });
      const result = await av.vault("default").services!.list();

      expect(result.vault).toBe("default");
      expect(result.services).toHaveLength(1);
      expect(result.services[0]).toEqual({
        host: "api.stripe.com",
        description: "Stripe API",
        auth: { type: "bearer", token: "STRIPE_KEY" },
      });
    });

    it("includes X-Vault header when created via AgentVault.vault()", async () => {
      const mockFetch = createMockFetch({
        body: { vault: "production", services: [] },
      });

      const av = new AgentVault({
        token: "agent-token",
        address: "http://localhost:14321",
        fetch: mockFetch,
      });
      await av.vault("production").services!.list();

      const init = mockFetch.mock.calls[0]![1]!;
      const headers = init.headers as Record<string, string>;
      expect(headers["X-Vault"]).toBe("production");
    });

    it("returns empty services array for vault with no services", async () => {
      const mockFetch = createMockFetch({
        body: { vault: "empty-vault", services: [] },
      });

      const av = new AgentVault({
        token: "agent-token",
        address: "http://localhost:14321",
        fetch: mockFetch,
      });
      const result = await av.vault("empty-vault").services!.list();

      expect(result.services).toEqual([]);
    });
  });

  describe("set()", () => {
    it("sends POST /v1/vaults/{name}/services with services array", async () => {
      const mockFetch = createMockFetch({
        body: {
          vault: "my-project",
          upserted: ["api.stripe.com"],
          services_count: 1,
        },
      });

      const av = new AgentVault({
        token: "agent-token",
        address: "http://localhost:14321",
        fetch: mockFetch,
      });
      await av.vault("my-project").services!.set([
        {
          host: "api.stripe.com",
          auth: { type: "bearer", token: "STRIPE_KEY" },
        },
      ]);

      expect(mockFetch).toHaveBeenCalledOnce();
      const [url, init] = mockFetch.mock.calls[0]!;
      expect(url).toBe("http://localhost:14321/v1/vaults/my-project/services");
      expect(init?.method).toBe("POST");

      const body = JSON.parse(init?.body as string);
      expect(body.services).toEqual([
        {
          host: "api.stripe.com",
          auth: { type: "bearer", token: "STRIPE_KEY" },
        },
      ]);
    });

    it("returns upserted hosts and servicesCount", async () => {
      const mockFetch = createMockFetch({
        body: {
          vault: "default",
          upserted: ["api.stripe.com", "api.github.com"],
          services_count: 5,
        },
      });

      const av = new AgentVault({
        token: "agent-token",
        address: "http://localhost:14321",
        fetch: mockFetch,
      });
      const result = await av.vault("default").services!.set([
        { host: "api.stripe.com", auth: { type: "bearer", token: "STRIPE_KEY" } },
        { host: "api.github.com", auth: { type: "bearer", token: "GITHUB_TOKEN" } },
      ]);

      expect(result.vault).toBe("default");
      expect(result.upserted).toEqual(["api.stripe.com", "api.github.com"]);
      expect(result.servicesCount).toBe(5);
    });

    it("includes X-Vault header", async () => {
      const mockFetch = createMockFetch({
        body: { vault: "production", upserted: ["api.stripe.com"], services_count: 1 },
      });

      const av = new AgentVault({
        token: "agent-token",
        address: "http://localhost:14321",
        fetch: mockFetch,
      });
      await av.vault("production").services!.set([
        { host: "api.stripe.com", auth: { type: "bearer", token: "KEY" } },
      ]);

      const init = mockFetch.mock.calls[0]![1]!;
      const headers = init.headers as Record<string, string>;
      expect(headers["X-Vault"]).toBe("production");
    });
  });

  describe("remove()", () => {
    it("sends DELETE /v1/vaults/{name}/services/{host}", async () => {
      const mockFetch = createMockFetch({
        body: { vault: "my-project", removed: "api.stripe.com", services_count: 2 },
      });

      const av = new AgentVault({
        token: "agent-token",
        address: "http://localhost:14321",
        fetch: mockFetch,
      });
      await av.vault("my-project").services!.remove("api.stripe.com");

      expect(mockFetch).toHaveBeenCalledOnce();
      const [url, init] = mockFetch.mock.calls[0]!;
      expect(url).toBe(
        "http://localhost:14321/v1/vaults/my-project/services/api.stripe.com",
      );
      expect(init?.method).toBe("DELETE");
    });

    it("handles wildcard host patterns in URL", async () => {
      const mockFetch = createMockFetch({
        body: { vault: "default", removed: "*.github.com", services_count: 0 },
      });

      const av = new AgentVault({
        token: "agent-token",
        address: "http://localhost:14321",
        fetch: mockFetch,
      });
      await av.vault("default").services!.remove("*.github.com");

      const url = mockFetch.mock.calls[0]![0] as string;
      // * is unreserved per RFC 3986, so encodeURIComponent preserves it
      expect(url).toContain("*.github.com");
    });

    it("returns removed host and servicesCount", async () => {
      const mockFetch = createMockFetch({
        body: { vault: "default", removed: "api.stripe.com", services_count: 3 },
      });

      const av = new AgentVault({
        token: "agent-token",
        address: "http://localhost:14321",
        fetch: mockFetch,
      });
      const result = await av.vault("default").services!.remove("api.stripe.com");

      expect(result.vault).toBe("default");
      expect(result.removed).toBe("api.stripe.com");
      expect(result.servicesCount).toBe(3);
    });

    it("includes X-Vault header", async () => {
      const mockFetch = createMockFetch({
        body: { vault: "production", removed: "api.stripe.com", services_count: 0 },
      });

      const av = new AgentVault({
        token: "agent-token",
        address: "http://localhost:14321",
        fetch: mockFetch,
      });
      await av.vault("production").services!.remove("api.stripe.com");

      const init = mockFetch.mock.calls[0]![1]!;
      const headers = init.headers as Record<string, string>;
      expect(headers["X-Vault"]).toBe("production");
    });
  });

  describe("replaceAll()", () => {
    it("sends PUT /v1/vaults/{name}/services with services array", async () => {
      const mockFetch = createMockFetch({
        body: { vault: "my-project", services_count: 2 },
      });

      const av = new AgentVault({
        token: "agent-token",
        address: "http://localhost:14321",
        fetch: mockFetch,
      });
      await av.vault("my-project").services!.replaceAll([
        { host: "api.stripe.com", auth: { type: "bearer", token: "STRIPE_KEY" } },
        { host: "api.github.com", auth: { type: "bearer", token: "GITHUB_TOKEN" } },
      ]);

      expect(mockFetch).toHaveBeenCalledOnce();
      const [url, init] = mockFetch.mock.calls[0]!;
      expect(url).toBe("http://localhost:14321/v1/vaults/my-project/services");
      expect(init?.method).toBe("PUT");

      const body = JSON.parse(init?.body as string);
      expect(body.services).toHaveLength(2);
    });

    it("returns servicesCount", async () => {
      const mockFetch = createMockFetch({
        body: { vault: "default", services_count: 3 },
      });

      const av = new AgentVault({
        token: "agent-token",
        address: "http://localhost:14321",
        fetch: mockFetch,
      });
      const result = await av.vault("default").services!.replaceAll([
        { host: "a.com", auth: { type: "bearer", token: "A" } },
        { host: "b.com", auth: { type: "bearer", token: "B" } },
        { host: "c.com", auth: { type: "bearer", token: "C" } },
      ]);

      expect(result.vault).toBe("default");
      expect(result.servicesCount).toBe(3);
    });

    it("includes X-Vault header", async () => {
      const mockFetch = createMockFetch({
        body: { vault: "production", services_count: 0 },
      });

      const av = new AgentVault({
        token: "agent-token",
        address: "http://localhost:14321",
        fetch: mockFetch,
      });
      await av.vault("production").services!.replaceAll([]);

      const init = mockFetch.mock.calls[0]![1]!;
      const headers = init.headers as Record<string, string>;
      expect(headers["X-Vault"]).toBe("production");
    });
  });

  describe("clear()", () => {
    it("sends DELETE /v1/vaults/{name}/services", async () => {
      const mockFetch = createMockFetch({
        body: { vault: "my-project", cleared: true },
      });

      const av = new AgentVault({
        token: "agent-token",
        address: "http://localhost:14321",
        fetch: mockFetch,
      });
      await av.vault("my-project").services!.clear();

      expect(mockFetch).toHaveBeenCalledOnce();
      const [url, init] = mockFetch.mock.calls[0]!;
      expect(url).toBe("http://localhost:14321/v1/vaults/my-project/services");
      expect(init?.method).toBe("DELETE");
      // No body should be sent for clear
      expect(init?.body).toBeUndefined();
    });

    it("returns cleared: true", async () => {
      const mockFetch = createMockFetch({
        body: { vault: "default", cleared: true },
      });

      const av = new AgentVault({
        token: "agent-token",
        address: "http://localhost:14321",
        fetch: mockFetch,
      });
      const result = await av.vault("default").services!.clear();

      expect(result.vault).toBe("default");
      expect(result.cleared).toBe(true);
    });

    it("includes X-Vault header", async () => {
      const mockFetch = createMockFetch({
        body: { vault: "production", cleared: true },
      });

      const av = new AgentVault({
        token: "agent-token",
        address: "http://localhost:14321",
        fetch: mockFetch,
      });
      await av.vault("production").services!.clear();

      const init = mockFetch.mock.calls[0]![1]!;
      const headers = init.headers as Record<string, string>;
      expect(headers["X-Vault"]).toBe("production");
    });
  });

  describe("credentialUsage()", () => {
    it("sends GET with key query param", async () => {
      const mockFetch = createMockFetch({
        body: {
          services: [{ host: "api.stripe.com", description: "Stripe API" }],
        },
      });

      const av = new AgentVault({
        token: "agent-token",
        address: "http://localhost:14321",
        fetch: mockFetch,
      });
      await av.vault("my-project").services!.credentialUsage("STRIPE_KEY");

      expect(mockFetch).toHaveBeenCalledOnce();
      const [url, init] = mockFetch.mock.calls[0]!;
      expect(url).toBe(
        "http://localhost:14321/v1/vaults/my-project/services/credential-usage?key=STRIPE_KEY",
      );
      expect(init?.method).toBe("GET");
    });

    it("returns services that reference the credential", async () => {
      const mockFetch = createMockFetch({
        body: {
          services: [
            { host: "api.stripe.com", description: "Stripe API" },
            { host: "api.example.com" },
          ],
        },
      });

      const av = new AgentVault({
        token: "agent-token",
        address: "http://localhost:14321",
        fetch: mockFetch,
      });
      const result = await av
        .vault("default")
        .services!.credentialUsage("SHARED_KEY");

      expect(result.services).toHaveLength(2);
      expect(result.services[0]).toEqual({
        host: "api.stripe.com",
        description: "Stripe API",
      });
      expect(result.services[1]).toEqual({
        host: "api.example.com",
      });
    });

    it("includes X-Vault header", async () => {
      const mockFetch = createMockFetch({
        body: { services: [] },
      });

      const av = new AgentVault({
        token: "agent-token",
        address: "http://localhost:14321",
        fetch: mockFetch,
      });
      await av.vault("production").services!.credentialUsage("KEY");

      const init = mockFetch.mock.calls[0]![1]!;
      const headers = init.headers as Record<string, string>;
      expect(headers["X-Vault"]).toBe("production");
    });
  });
});
