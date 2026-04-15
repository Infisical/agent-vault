import { describe, it, expect } from "vitest";
import { AgentVault } from "../src/client.js";
import { createMockFetch } from "./helpers.js";

describe("SessionsResource", () => {
  describe("create()", () => {
    it("sends POST /v1/sessions with vault name", async () => {
      const mockFetch = createMockFetch({
        body: {
          token: "scoped-token",
          expires_at: "2026-04-16T00:00:00Z",
          av_addr: "http://localhost:14321",
          proxy_url: "http://localhost:14321/proxy",
        },
      });

      const av = new AgentVault({
        token: "agent-token",
        address: "http://localhost:14321",
        fetch: mockFetch,
      });
      const vault = av.vault("my-project");
      const session = await vault.sessions!.create();

      expect(mockFetch).toHaveBeenCalledOnce();
      const [url, init] = mockFetch.mock.calls[0]!;
      expect(url).toBe("http://localhost:14321/v1/sessions");
      expect(init?.method).toBe("POST");

      const body = JSON.parse(init?.body as string);
      expect(body.vault).toBe("my-project");
    });

    it("sends vault_role and ttl_seconds when provided", async () => {
      const mockFetch = createMockFetch({
        body: {
          token: "t",
          expires_at: "2026-04-16T00:00:00Z",
          av_addr: "",
          proxy_url: "",
        },
      });

      const av = new AgentVault({
        token: "agent-token",
        address: "http://localhost:14321",
        fetch: mockFetch,
      });
      const vault = av.vault("prod");
      await vault.sessions!.create({
        vaultRole: "member",
        ttlSeconds: 7200,
      });

      const body = JSON.parse(mockFetch.mock.calls[0]![1]?.body as string);
      expect(body.vault_role).toBe("member");
      expect(body.ttl_seconds).toBe(7200);
    });

    it("returns camelCased response", async () => {
      const mockFetch = createMockFetch({
        body: {
          token: "scoped-token-123",
          expires_at: "2026-04-16T12:00:00Z",
          av_addr: "http://my-server:14321",
          proxy_url: "http://my-server:14321/proxy",
        },
      });

      const av = new AgentVault({
        token: "agent-token",
        address: "http://localhost:14321",
        fetch: mockFetch,
      });
      const session = await av.vault("test").sessions!.create();

      expect(session.token).toBe("scoped-token-123");
      expect(session.expiresAt).toBe("2026-04-16T12:00:00Z");
      expect(session.address).toBe("http://my-server:14321");
      expect(session.proxyUrl).toBe("http://my-server:14321/proxy");
    });

    it("includes X-Vault header in the request", async () => {
      const mockFetch = createMockFetch({
        body: {
          token: "t",
          expires_at: "",
          av_addr: "",
          proxy_url: "",
        },
      });

      const av = new AgentVault({
        token: "agent-token",
        address: "http://localhost:14321",
        fetch: mockFetch,
      });
      await av.vault("special-vault").sessions!.create();

      const init = mockFetch.mock.calls[0]![1]!;
      const headers = init.headers as Record<string, string>;
      expect(headers["X-Vault"]).toBe("special-vault");
    });
  });
});
