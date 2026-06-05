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
              auth: { type: "bearer", token: "STRIPE_KEY" },
            },
            {
              host: "proxy.example.com",
              enabled: false,
              auth: { type: "passthrough" },
              substitutions: [
                { key: "ACCOUNT_ID", placeholder: "__ACCOUNT__", in: ["path"] },
              ],
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
      expect(result.services).toHaveLength(2);
      expect(result.services[0]).toEqual({
        host: "api.stripe.com",
        auth: { type: "bearer", token: "STRIPE_KEY" },
      });
      expect(result.services[1]).toEqual({
        host: "proxy.example.com",
        enabled: false,
        auth: { type: "passthrough" },
        substitutions: [
          { key: "ACCOUNT_ID", placeholder: "__ACCOUNT__", in: ["path"] },
        ],
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

    it("forwards passthrough auth, enabled, and substitutions verbatim", async () => {
      const mockFetch = createMockFetch({
        body: { vault: "default", upserted: ["proxy.example.com"], services_count: 1 },
      });

      const av = new AgentVault({
        token: "agent-token",
        address: "http://localhost:14321",
        fetch: mockFetch,
      });
      await av.vault("default").services!.set([
        {
          host: "proxy.example.com",
          enabled: false,
          auth: { type: "passthrough" },
          substitutions: [
            { key: "ACCOUNT_ID", placeholder: "__ACCOUNT__", in: ["path", "query"] },
          ],
        },
      ]);

      const body = JSON.parse(mockFetch.mock.calls[0]![1]?.body as string);
      expect(body.services[0]).toEqual({
        host: "proxy.example.com",
        enabled: false,
        auth: { type: "passthrough" },
        substitutions: [
          { key: "ACCOUNT_ID", placeholder: "__ACCOUNT__", in: ["path", "query"] },
        ],
      });
    });

    it("sends inline-form host for path-scoped services", async () => {
      const mockFetch = createMockFetch({
        body: { vault: "default", upserted: ["slack-bot", "slack-conn"], services_count: 2 },
      });

      const av = new AgentVault({
        token: "agent-token",
        address: "http://localhost:14321",
        fetch: mockFetch,
      });
      const result = await av.vault("default").services!.set([
        {
          name: "slack-bot",
          host: "slack.com/api/*",
          auth: { type: "bearer", token: "SLACK_BOT_TOKEN" },
        },
        {
          name: "slack-conn",
          host: "slack.com/api/apps.connections.*",
          auth: { type: "bearer", token: "SLACK_CONNECTION_TOKEN" },
        },
      ]);

      const body = JSON.parse(mockFetch.mock.calls[0]![1]?.body as string);
      expect(body.services).toHaveLength(2);
      expect(body.services[0]).toMatchObject({
        name: "slack-bot",
        host: "slack.com/api/*",
      });
      expect(body.services[1]).toMatchObject({
        name: "slack-conn",
        host: "slack.com/api/apps.connections.*",
      });
      expect(result.upserted).toEqual(["slack-bot", "slack-conn"]);
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

    it("surfaces removedHost when the server returns it", async () => {
      const mockFetch = createMockFetch({
        body: {
          vault: "default",
          removed: "slack-bot",
          removed_host: "slack.com",
          services_count: 1,
        },
      });

      const av = new AgentVault({
        token: "agent-token",
        address: "http://localhost:14321",
        fetch: mockFetch,
      });
      const result = await av.vault("default").services!.remove("slack-bot");

      expect(result.removed).toBe("slack-bot");
      expect(result.removedHost).toBe("slack.com");
    });
  });

  describe("removeByName()", () => {
    it("sends DELETE /v1/vaults/{name}/services/{name}", async () => {
      const mockFetch = createMockFetch({
        body: {
          vault: "default",
          removed: "slack-bot",
          removed_host: "slack.com",
          services_count: 0,
        },
      });

      const av = new AgentVault({
        token: "agent-token",
        address: "http://localhost:14321",
        fetch: mockFetch,
      });
      const result = await av.vault("default").services!.removeByName("slack-bot");

      expect(mockFetch).toHaveBeenCalledOnce();
      const [url, init] = mockFetch.mock.calls[0]!;
      expect(url).toBe(
        "http://localhost:14321/v1/vaults/default/services/slack-bot",
      );
      expect(init?.method).toBe("DELETE");
      expect(result.removed).toBe("slack-bot");
      expect(result.removedHost).toBe("slack.com");
    });

    it("throws ApiError with status 404 when the name does not exist", async () => {
      const mockFetch = createMockFetch({
        ok: false,
        status: 404,
        body: { error: "service_not_found", message: 'Service not found for "slack-bot"' },
      });

      const av = new AgentVault({
        token: "agent-token",
        address: "http://localhost:14321",
        fetch: mockFetch,
      });
      await expect(
        av.vault("default").services!.removeByName("slack-bot"),
      ).rejects.toMatchObject({
        name: "ApiError",
        status: 404,
        code: "service_not_found",
      });
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
          services: [{ host: "api.stripe.com" }],
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
            { host: "api.stripe.com" },
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
