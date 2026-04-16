import { describe, it, expect } from "vitest";
import { AgentVault } from "../src/client.js";
import { ApiError } from "../src/errors.js";
import { createMockFetch } from "./helpers.js";

describe("AgentVault vault operations", () => {
  describe("createVault()", () => {
    it("sends POST /v1/vaults with name", async () => {
      const mockFetch = createMockFetch({
        status: 201,
        body: {
          id: "vault-uuid-123",
          name: "my-project",
          created_at: "2026-04-15T16:30:45Z",
        },
      });

      const av = new AgentVault({
        token: "agent-token",
        address: "http://localhost:14321",
        fetch: mockFetch,
      });
      await av.createVault({ name: "my-project" });

      expect(mockFetch).toHaveBeenCalledOnce();
      const [url, init] = mockFetch.mock.calls[0]!;
      expect(url).toBe("http://localhost:14321/v1/vaults");
      expect(init?.method).toBe("POST");

      const body = JSON.parse(init?.body as string);
      expect(body.name).toBe("my-project");
    });

    it("returns camelCased response", async () => {
      const mockFetch = createMockFetch({
        status: 201,
        body: {
          id: "vault-uuid-456",
          name: "production",
          created_at: "2026-04-15T18:00:00Z",
        },
      });

      const av = new AgentVault({
        token: "agent-token",
        address: "http://localhost:14321",
        fetch: mockFetch,
      });
      const vault = await av.createVault({ name: "production" });

      expect(vault.id).toBe("vault-uuid-456");
      expect(vault.name).toBe("production");
      expect(vault.createdAt).toBe("2026-04-15T18:00:00Z");
    });

    it("does not send X-Vault header", async () => {
      const mockFetch = createMockFetch({
        status: 201,
        body: {
          id: "id",
          name: "test",
          created_at: "2026-04-15T00:00:00Z",
        },
      });

      const av = new AgentVault({
        token: "agent-token",
        address: "http://localhost:14321",
        fetch: mockFetch,
      });
      await av.createVault({ name: "test" });

      const init = mockFetch.mock.calls[0]![1]!;
      const headers = init.headers as Record<string, string>;
      expect(headers["X-Vault"]).toBeUndefined();
    });

    it("throws ApiError on 409 conflict", async () => {
      const mockFetch = createMockFetch({
        ok: false,
        status: 409,
        statusText: "Conflict",
        body: { error: 'Vault "my-project" already exists' },
      });

      const av = new AgentVault({
        token: "agent-token",
        address: "http://localhost:14321",
        fetch: mockFetch,
      });

      await expect(av.createVault({ name: "my-project" })).rejects.toThrow(
        ApiError,
      );
      await expect(
        av.createVault({ name: "my-project" }),
      ).rejects.toMatchObject({ status: 409 });
    });
  });

  describe("deleteVault()", () => {
    it("sends DELETE /v1/vaults/{name}", async () => {
      const mockFetch = createMockFetch({
        body: { name: "my-vault", deleted: true },
      });

      const av = new AgentVault({
        token: "agent-token",
        address: "http://localhost:14321",
        fetch: mockFetch,
      });
      await av.deleteVault("my-vault");

      expect(mockFetch).toHaveBeenCalledOnce();
      const [url, init] = mockFetch.mock.calls[0]!;
      expect(url).toBe("http://localhost:14321/v1/vaults/my-vault");
      expect(init?.method).toBe("DELETE");
    });

    it("returns the deletion result", async () => {
      const mockFetch = createMockFetch({
        body: { name: "staging", deleted: true },
      });

      const av = new AgentVault({
        token: "agent-token",
        address: "http://localhost:14321",
        fetch: mockFetch,
      });
      const result = await av.deleteVault("staging");

      expect(result.name).toBe("staging");
      expect(result.deleted).toBe(true);
    });

    it("URL-encodes the vault name", async () => {
      const mockFetch = createMockFetch({
        body: { name: "my vault", deleted: true },
      });

      const av = new AgentVault({
        token: "agent-token",
        address: "http://localhost:14321",
        fetch: mockFetch,
      });
      await av.deleteVault("my vault");

      const [url] = mockFetch.mock.calls[0]!;
      expect(url).toBe("http://localhost:14321/v1/vaults/my%20vault");
    });
  });
});
