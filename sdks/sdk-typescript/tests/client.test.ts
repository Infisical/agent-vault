import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { AgentVault } from "../src/client.js";
import { AgentVaultError } from "../src/errors.js";
import { VaultClient } from "../src/vault.js";

describe("AgentVault", () => {
  const originalEnv = process.env;

  beforeEach(() => {
    process.env = { ...originalEnv };
    delete process.env.AGENT_VAULT_SESSION_TOKEN;
    delete process.env.AGENT_VAULT_ADDR;
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  describe("constructor", () => {
    it("creates client with explicit token", () => {
      const av = new AgentVault({ token: "test-token" });
      expect(av).toBeInstanceOf(AgentVault);
    });

    it("throws if no token in config or env", () => {
      expect(() => new AgentVault()).toThrow(AgentVaultError);
      expect(() => new AgentVault()).toThrow("Token is required");
    });

    it("reads token from AGENT_VAULT_SESSION_TOKEN env var", () => {
      process.env.AGENT_VAULT_SESSION_TOKEN = "env-token";
      const av = new AgentVault();
      expect(av).toBeInstanceOf(AgentVault);
    });

    it("prefers config token over env var", () => {
      process.env.AGENT_VAULT_SESSION_TOKEN = "env-token";
      // Should not throw — config token takes precedence
      const av = new AgentVault({ token: "config-token" });
      expect(av).toBeInstanceOf(AgentVault);
    });

    it("reads address from AGENT_VAULT_ADDR env var", () => {
      process.env.AGENT_VAULT_SESSION_TOKEN = "test-token";
      process.env.AGENT_VAULT_ADDR = "http://custom:9999";
      const av = new AgentVault();
      expect(av).toBeInstanceOf(AgentVault);
    });
  });

  describe("vault()", () => {
    it("returns a VaultClient instance", () => {
      const av = new AgentVault({ token: "test-token" });
      const vault = av.vault("my-project");
      expect(vault).toBeInstanceOf(VaultClient);
    });

    it("sets the vault name on the returned VaultClient", () => {
      const av = new AgentVault({ token: "test-token" });
      const vault = av.vault("production");
      expect(vault.name).toBe("production");
    });

    it("returns different VaultClient instances for different vaults", () => {
      const av = new AgentVault({ token: "test-token" });
      const v1 = av.vault("vault-a");
      const v2 = av.vault("vault-b");
      expect(v1).not.toBe(v2);
      expect(v1.name).toBe("vault-a");
      expect(v2.name).toBe("vault-b");
    });

    it("returns a VaultClient with sessions resource", () => {
      const av = new AgentVault({ token: "test-token" });
      const vault = av.vault("my-project");
      expect(vault.sessions).toBeDefined();
    });
  });
});
