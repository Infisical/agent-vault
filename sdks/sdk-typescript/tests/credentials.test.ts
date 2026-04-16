import { describe, it, expect } from "vitest";
import { AgentVault } from "../src/client.js";
import { VaultClient } from "../src/vault.js";
import { createMockFetch } from "./helpers.js";

describe("CredentialsResource", () => {
  describe("list()", () => {
    it("sends GET /v1/credentials with vault query param", async () => {
      const mockFetch = createMockFetch({
        body: { keys: ["STRIPE_KEY", "GITHUB_TOKEN"] },
      });

      const av = new AgentVault({
        token: "agent-token",
        address: "http://localhost:14321",
        fetch: mockFetch,
      });
      await av.vault("my-project").credentials.list();

      expect(mockFetch).toHaveBeenCalledOnce();
      const [url, init] = mockFetch.mock.calls[0]!;
      expect(url).toBe(
        "http://localhost:14321/v1/credentials?vault=my-project",
      );
      expect(init?.method).toBe("GET");
    });

    it("sends reveal=true query param when requested", async () => {
      const mockFetch = createMockFetch({
        body: {
          keys: ["STRIPE_KEY"],
          credentials: [{ key: "STRIPE_KEY", value: "sk_test_123" }],
        },
      });

      const av = new AgentVault({
        token: "agent-token",
        address: "http://localhost:14321",
        fetch: mockFetch,
      });
      await av.vault("my-project").credentials.list({ reveal: true });

      const url = mockFetch.mock.calls[0]![0] as string;
      expect(url).toContain("reveal=true");
      expect(url).toContain("vault=my-project");
    });

    it("sends key query param with reveal", async () => {
      const mockFetch = createMockFetch({
        body: {
          keys: ["API_KEY"],
          credentials: [{ key: "API_KEY", value: "secret123" }],
        },
      });

      const av = new AgentVault({
        token: "agent-token",
        address: "http://localhost:14321",
        fetch: mockFetch,
      });
      await av
        .vault("my-project")
        .credentials.list({ reveal: true, key: "API_KEY" });

      const url = mockFetch.mock.calls[0]![0] as string;
      expect(url).toContain("key=API_KEY");
      expect(url).toContain("reveal=true");
    });

    it("omits vault query param for standalone VaultClient", async () => {
      const mockFetch = createMockFetch({
        body: { keys: ["STRIPE_KEY"] },
      });

      const vault = new VaultClient({
        token: "scoped-token",
        address: "http://localhost:14321",
        fetch: mockFetch,
      });
      await vault.credentials.list();

      const url = mockFetch.mock.calls[0]![0] as string;
      expect(url).toBe("http://localhost:14321/v1/credentials");
    });

    it("returns keys array from response", async () => {
      const mockFetch = createMockFetch({
        body: { keys: ["STRIPE_KEY", "GITHUB_TOKEN"] },
      });

      const av = new AgentVault({
        token: "agent-token",
        address: "http://localhost:14321",
        fetch: mockFetch,
      });
      const result = await av.vault("default").credentials.list();

      expect(result.keys).toEqual(["STRIPE_KEY", "GITHUB_TOKEN"]);
      expect(result.credentials).toBeUndefined();
    });

    it("returns credentials array when reveal=true", async () => {
      const mockFetch = createMockFetch({
        body: {
          keys: ["STRIPE_KEY"],
          credentials: [{ key: "STRIPE_KEY", value: "sk_live_abc" }],
        },
      });

      const av = new AgentVault({
        token: "agent-token",
        address: "http://localhost:14321",
        fetch: mockFetch,
      });
      const result = await av
        .vault("default")
        .credentials.list({ reveal: true });

      expect(result.credentials).toEqual([
        { key: "STRIPE_KEY", value: "sk_live_abc" },
      ]);
    });

    it("includes X-Vault header when created via AgentVault.vault()", async () => {
      const mockFetch = createMockFetch({
        body: { keys: [] },
      });

      const av = new AgentVault({
        token: "agent-token",
        address: "http://localhost:14321",
        fetch: mockFetch,
      });
      await av.vault("production").credentials.list();

      const init = mockFetch.mock.calls[0]![1]!;
      const headers = init.headers as Record<string, string>;
      expect(headers["X-Vault"]).toBe("production");
    });
  });

  describe("set()", () => {
    it("sends POST /v1/credentials with credentials map", async () => {
      const mockFetch = createMockFetch({
        body: { set: ["STRIPE_KEY", "GITHUB_TOKEN"] },
      });

      const av = new AgentVault({
        token: "agent-token",
        address: "http://localhost:14321",
        fetch: mockFetch,
      });
      await av
        .vault("my-project")
        .credentials.set({ STRIPE_KEY: "sk_live_abc", GITHUB_TOKEN: "ghp_xyz" });

      expect(mockFetch).toHaveBeenCalledOnce();
      const [url, init] = mockFetch.mock.calls[0]!;
      expect(url).toBe("http://localhost:14321/v1/credentials");
      expect(init?.method).toBe("POST");

      const body = JSON.parse(init?.body as string);
      expect(body.credentials).toEqual({
        STRIPE_KEY: "sk_live_abc",
        GITHUB_TOKEN: "ghp_xyz",
      });
    });

    it("includes vault in request body when vault name is known", async () => {
      const mockFetch = createMockFetch({
        body: { set: ["API_KEY"] },
      });

      const av = new AgentVault({
        token: "agent-token",
        address: "http://localhost:14321",
        fetch: mockFetch,
      });
      await av.vault("staging").credentials.set({ API_KEY: "secret" });

      const body = JSON.parse(mockFetch.mock.calls[0]![1]?.body as string);
      expect(body.vault).toBe("staging");
    });

    it("omits vault from body for standalone VaultClient", async () => {
      const mockFetch = createMockFetch({
        body: { set: ["API_KEY"] },
      });

      const vault = new VaultClient({
        token: "scoped-token",
        address: "http://localhost:14321",
        fetch: mockFetch,
      });
      await vault.credentials.set({ API_KEY: "value123" });

      const body = JSON.parse(mockFetch.mock.calls[0]![1]?.body as string);
      expect(body.credentials).toEqual({ API_KEY: "value123" });
      expect(body.vault).toBeUndefined();
    });

    it("returns set array from response", async () => {
      const mockFetch = createMockFetch({
        body: { set: ["STRIPE_KEY", "GITHUB_TOKEN"] },
      });

      const av = new AgentVault({
        token: "agent-token",
        address: "http://localhost:14321",
        fetch: mockFetch,
      });
      const result = await av
        .vault("default")
        .credentials.set({ STRIPE_KEY: "sk_live_abc", GITHUB_TOKEN: "ghp_xyz" });

      expect(result.set).toEqual(["STRIPE_KEY", "GITHUB_TOKEN"]);
    });

    it("includes X-Vault header when created via AgentVault.vault()", async () => {
      const mockFetch = createMockFetch({
        body: { set: ["KEY"] },
      });

      const av = new AgentVault({
        token: "agent-token",
        address: "http://localhost:14321",
        fetch: mockFetch,
      });
      await av.vault("production").credentials.set({ KEY: "val" });

      const init = mockFetch.mock.calls[0]![1]!;
      const headers = init.headers as Record<string, string>;
      expect(headers["X-Vault"]).toBe("production");
    });
  });

  describe("delete()", () => {
    it("sends DELETE /v1/credentials with keys array", async () => {
      const mockFetch = createMockFetch({
        body: { deleted: ["STRIPE_KEY", "GITHUB_TOKEN"] },
      });

      const av = new AgentVault({
        token: "agent-token",
        address: "http://localhost:14321",
        fetch: mockFetch,
      });
      await av
        .vault("my-project")
        .credentials.delete(["STRIPE_KEY", "GITHUB_TOKEN"]);

      expect(mockFetch).toHaveBeenCalledOnce();
      const [url, init] = mockFetch.mock.calls[0]!;
      expect(url).toBe("http://localhost:14321/v1/credentials");
      expect(init?.method).toBe("DELETE");

      const body = JSON.parse(init?.body as string);
      expect(body.keys).toEqual(["STRIPE_KEY", "GITHUB_TOKEN"]);
    });

    it("includes vault in request body when vault name is known", async () => {
      const mockFetch = createMockFetch({
        body: { deleted: ["API_KEY"] },
      });

      const av = new AgentVault({
        token: "agent-token",
        address: "http://localhost:14321",
        fetch: mockFetch,
      });
      await av.vault("staging").credentials.delete(["API_KEY"]);

      const body = JSON.parse(mockFetch.mock.calls[0]![1]?.body as string);
      expect(body.vault).toBe("staging");
    });

    it("omits vault from body for standalone VaultClient", async () => {
      const mockFetch = createMockFetch({
        body: { deleted: ["API_KEY"] },
      });

      const vault = new VaultClient({
        token: "scoped-token",
        address: "http://localhost:14321",
        fetch: mockFetch,
      });
      await vault.credentials.delete(["API_KEY"]);

      const body = JSON.parse(mockFetch.mock.calls[0]![1]?.body as string);
      expect(body.keys).toEqual(["API_KEY"]);
      expect(body.vault).toBeUndefined();
    });

    it("returns deleted array from response", async () => {
      const mockFetch = createMockFetch({
        body: { deleted: ["STRIPE_KEY"] },
      });

      const av = new AgentVault({
        token: "agent-token",
        address: "http://localhost:14321",
        fetch: mockFetch,
      });
      const result = await av.vault("default").credentials.delete(["STRIPE_KEY"]);

      expect(result.deleted).toEqual(["STRIPE_KEY"]);
    });

    it("includes X-Vault header when created via AgentVault.vault()", async () => {
      const mockFetch = createMockFetch({
        body: { deleted: ["KEY"] },
      });

      const av = new AgentVault({
        token: "agent-token",
        address: "http://localhost:14321",
        fetch: mockFetch,
      });
      await av.vault("production").credentials.delete(["KEY"]);

      const init = mockFetch.mock.calls[0]![1]!;
      const headers = init.headers as Record<string, string>;
      expect(headers["X-Vault"]).toBe("production");
    });
  });
});
