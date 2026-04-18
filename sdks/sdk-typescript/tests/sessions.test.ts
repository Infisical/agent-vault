import { describe, it, expect } from "vitest";
import { AgentVault } from "../src/client.js";
import { buildProxyEnv } from "../src/resources/sessions.js";
import type { ContainerConfig } from "../src/resources/sessions.js";
import { createRoutedMockFetch } from "./helpers.js";

const FAKE_PEM = "-----BEGIN CERTIFICATE-----\nFAKECERT\n-----END CERTIFICATE-----\n";

describe("SessionsResource", () => {
  describe("create()", () => {
    it("sends POST /v1/sessions with vault name", async () => {
      const mockFetch = createRoutedMockFetch({
        "/v1/sessions": {
          body: {
            token: "scoped-token",
            expires_at: "2026-04-16T00:00:00Z",
            av_addr: "http://localhost:14321",
          },
        },
        "/v1/mitm/ca.pem": {
          body: FAKE_PEM,
          headers: { "X-MITM-Port": "14322" },
        },
      });

      const av = new AgentVault({
        token: "agent-token",
        address: "http://localhost:14321",
        fetch: mockFetch,
      });
      const vault = av.vault("my-project");
      await vault.sessions!.create();

      const sessionCall = mockFetch.mock.calls.find(
        ([url]) => (url as string).includes("/v1/sessions"),
      )!;
      expect(sessionCall).toBeDefined();
      const [url, init] = sessionCall;
      expect(url).toBe("http://localhost:14321/v1/sessions");
      expect(init?.method).toBe("POST");

      const body = JSON.parse(init?.body as string);
      expect(body.vault).toBe("my-project");
    });

    it("sends vault_role and ttl_seconds when provided", async () => {
      const mockFetch = createRoutedMockFetch({
        "/v1/sessions": {
          body: {
            token: "t",
            expires_at: "2026-04-16T00:00:00Z",
            av_addr: "",
          },
        },
        "/v1/mitm/ca.pem": {
          ok: false,
          status: 404,
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

      const sessionCall = mockFetch.mock.calls.find(
        ([url]) => (url as string).includes("/v1/sessions"),
      )!;
      const body = JSON.parse(sessionCall[1]?.body as string);
      expect(body.vault_role).toBe("member");
      expect(body.ttl_seconds).toBe(7200);
    });

    it("returns session with containerConfig when MITM is enabled", async () => {
      const mockFetch = createRoutedMockFetch({
        "/v1/sessions": {
          body: {
            token: "scoped-token-123",
            expires_at: "2026-04-16T12:00:00Z",
            av_addr: "http://my-server:14321",
          },
        },
        "/v1/mitm/ca.pem": {
          body: FAKE_PEM,
          headers: { "X-MITM-Port": "14322" },
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

      expect(session.containerConfig).not.toBeNull();
      expect(session.containerConfig!.env.HTTPS_PROXY).toContain("scoped-token-123");
      expect(session.containerConfig!.env.HTTPS_PROXY).toContain("test");
      expect(session.containerConfig!.env.HTTPS_PROXY).toContain("14322");
      expect(session.containerConfig!.env.NO_PROXY).toBe("localhost,127.0.0.1");
      expect(session.containerConfig!.caCertificate).toBe(FAKE_PEM);
    });

    it("returns containerConfig as null when MITM is disabled", async () => {
      const mockFetch = createRoutedMockFetch({
        "/v1/sessions": {
          body: {
            token: "scoped-token",
            expires_at: "2026-04-16T00:00:00Z",
            av_addr: "http://localhost:14321",
          },
        },
        "/v1/mitm/ca.pem": {
          ok: false,
          status: 404,
        },
      });

      const av = new AgentVault({
        token: "agent-token",
        address: "http://localhost:14321",
        fetch: mockFetch,
      });
      const session = await av.vault("default").sessions!.create();

      expect(session.token).toBe("scoped-token");
      expect(session.containerConfig).toBeNull();
    });

    it("uses custom MITM port from X-MITM-Port header", async () => {
      const mockFetch = createRoutedMockFetch({
        "/v1/sessions": {
          body: {
            token: "tok",
            expires_at: "2026-04-16T00:00:00Z",
            av_addr: "http://localhost:14321",
          },
        },
        "/v1/mitm/ca.pem": {
          body: FAKE_PEM,
          headers: { "X-MITM-Port": "9999" },
        },
      });

      const av = new AgentVault({
        token: "agent-token",
        address: "http://localhost:14321",
        fetch: mockFetch,
      });
      const session = await av.vault("default").sessions!.create();

      expect(session.containerConfig!.env.HTTPS_PROXY).toContain(":9999");
    });

    it("includes X-Vault header in the request", async () => {
      const mockFetch = createRoutedMockFetch({
        "/v1/sessions": {
          body: {
            token: "t",
            expires_at: "",
            av_addr: "",
          },
        },
        "/v1/mitm/ca.pem": {
          ok: false,
          status: 404,
        },
      });

      const av = new AgentVault({
        token: "agent-token",
        address: "http://localhost:14321",
        fetch: mockFetch,
      });
      await av.vault("special-vault").sessions!.create();

      const sessionCall = mockFetch.mock.calls.find(
        ([url]) => (url as string).includes("/v1/sessions"),
      )!;
      const init = sessionCall[1]!;
      const headers = init.headers as Record<string, string>;
      expect(headers["X-Vault"]).toBe("special-vault");
    });
  });
});

describe("buildProxyEnv()", () => {
  it("builds complete env with cert path variables", () => {
    const config: ContainerConfig = {
      env: {
        HTTPS_PROXY: "http://tok:vault@127.0.0.1:14322",
        NO_PROXY: "localhost,127.0.0.1",
      },
      caCertificate: FAKE_PEM,
    };

    const env = buildProxyEnv(config, "/etc/ssl/agent-vault-ca.pem");

    expect(env.HTTPS_PROXY).toBe("http://tok:vault@127.0.0.1:14322");
    expect(env.NO_PROXY).toBe("localhost,127.0.0.1");
    expect(env.NODE_USE_ENV_PROXY).toBe("1");
    expect(env.SSL_CERT_FILE).toBe("/etc/ssl/agent-vault-ca.pem");
    expect(env.NODE_EXTRA_CA_CERTS).toBe("/etc/ssl/agent-vault-ca.pem");
    expect(env.REQUESTS_CA_BUNDLE).toBe("/etc/ssl/agent-vault-ca.pem");
    expect(env.CURL_CA_BUNDLE).toBe("/etc/ssl/agent-vault-ca.pem");
    expect(env.GIT_SSL_CAINFO).toBe("/etc/ssl/agent-vault-ca.pem");
    expect(env.DENO_CERT).toBe("/etc/ssl/agent-vault-ca.pem");
  });
});
