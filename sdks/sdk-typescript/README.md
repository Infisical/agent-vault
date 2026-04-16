# Agent Vault TypeScript SDK

The official TypeScript SDK for [Agent Vault](https://github.com/Infisical/agent-vault), an open-source credential brokerage layer for AI agents. Agent Vault sits between development agents and target services, proxying requests and injecting credentials so agents never see raw keys or tokens.

## Installation

```bash
npm install @infisical/agent-vault-sdk
```

## Quickstart

This example walks through one possible flow end-to-end: initialize the SDK, set up a vault with a Stripe API key, configure the proxy rule, mint a scoped token for an agent, and make a proxied request — all without the agent ever seeing the raw secret. Depending on your use case, some of these steps (like creating the vault or proxy rule) may already be done out-of-band via the CLI or dashboard.

### Set up a vault

```typescript
import { AgentVault } from "@infisical/agent-vault-sdk";

// Initialize the SDK (auto-detects AGENT_VAULT_SESSION_TOKEN and AGENT_VAULT_ADDR env vars)
const av = new AgentVault({
  token: "YOUR_AGENT_TOKEN",
  address: "http://localhost:14321",
});

// Create a vault and get a scoped client
await av.createVault({ name: "my-project" });
const vault = av.vault("my-project");

// Store a credential
await vault.credentials.set({ STRIPE_KEY: "sk_live_abc" });

// Configure a proxy rule — the token field references the credential key above
await vault.services.set([
  {
    host: "api.stripe.com",
    description: "Stripe API",
    auth: { type: "bearer", token: "STRIPE_KEY" },
  },
]);

// Mint a short-lived, limited-permission token for a sandboxed agent
const session = await vault.sessions.create({
  vaultRole: "proxy",
  ttlSeconds: 3600,
});
console.log(session.token); // pass this into your agent sandbox
```

### Agent makes a proxied request

Inside the sandbox, the agent uses `VaultClient` with the scoped token:

```typescript
import { VaultClient } from "@infisical/agent-vault-sdk";

const client = new VaultClient({
  token: session.token,
  address: "http://localhost:14321",
});

const res = await client.proxy.get("api.stripe.com", "/v1/charges", {
  query: { limit: 10 },
});

if (res.ok) {
  const charges = await res.json<{ data: { id: string }[] }>();
  console.log(charges.data);
}
```

The agent never sees `sk_live_abc` — Agent Vault injects it into the request automatically. All standard HTTP methods are available: `get`, `post`, `put`, `patch`, `delete`, and `request` for arbitrary methods.

## Error handling

The SDK distinguishes between broker errors (thrown as exceptions) and upstream errors (returned as responses):

```typescript
import { ProxyForbiddenError } from "@infisical/agent-vault-sdk";

try {
  await client.proxy.get("api.unknown-service.com", "/");
} catch (err) {
  if (err instanceof ProxyForbiddenError) {
    // No proxy rule configured for this host
    console.log(err.proposalHint.host);
  }
}
```

- **Upstream non-2xx** (e.g. Stripe 404): resolves normally with `res.ok === false`
- **`ProxyForbiddenError`**: no proxy rule matches the target host
- **`ApiError`**: other broker-level failures

## Documentation

For comprehensive SDK reference and advanced usage, see the [documentation](https://agent-vault.infisical.com).

## Releasing

Releases are automated via GitHub Actions using [npm OIDC trusted publishing](https://docs.npmjs.com/generating-provenance-statements). Push a git tag matching `node-sdk/v<version>` (e.g., `node-sdk/v0.2.0`) to trigger a publish.
