import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { AgentVaultError } from "../src/errors.js";
import { VaultClient } from "../src/vault.js";
import { AgentVault } from "../src/client.js";

describe("VaultClient", () => {
  const originalEnv = process.env;

  beforeEach(() => {
    process.env = { ...originalEnv };
    delete process.env.AGENT_VAULT_SESSION_TOKEN;
    delete process.env.AGENT_VAULT_ADDR;
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  describe("standalone constructor", () => {
    it("creates client with explicit token", () => {
      const vault = new VaultClient({ token: "scoped-token" });
      expect(vault).toBeInstanceOf(VaultClient);
    });

    it("throws if no token in config or env", () => {
      expect(() => new VaultClient()).toThrow(AgentVaultError);
      expect(() => new VaultClient()).toThrow("Token is required");
    });

    it("reads token from AGENT_VAULT_SESSION_TOKEN env var", () => {
      process.env.AGENT_VAULT_SESSION_TOKEN = "env-token";
      const vault = new VaultClient();
      expect(vault).toBeInstanceOf(VaultClient);
    });

    it("has undefined name for standalone construction", () => {
      const vault = new VaultClient({ token: "scoped-token" });
      expect(vault.name).toBeUndefined();
    });

    it("has undefined sessions for standalone construction", () => {
      const vault = new VaultClient({ token: "scoped-token" });
      expect(vault.sessions).toBeUndefined();
    });
  });

  describe("via AgentVault.vault()", () => {
    it("has the vault name set", () => {
      const av = new AgentVault({ token: "agent-token" });
      const vault = av.vault("production");
      expect(vault.name).toBe("production");
    });

    it("has sessions resource wired up", () => {
      const av = new AgentVault({ token: "agent-token" });
      const vault = av.vault("production");
      expect(vault.sessions).toBeDefined();
    });

    it("exposes _httpClient for future resource extensions", () => {
      const av = new AgentVault({ token: "agent-token" });
      const vault = av.vault("production");
      expect(vault._httpClient).toBeDefined();
    });
  });
});
