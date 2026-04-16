# Agent Vault TypeScript SDK

The official TypeScript SDK for [Agent Vault](https://github.com/Infisical/agent-vault), an open-source credential brokerage layer for AI agents. Agent Vault sits between development agents and target services, proxying requests and injecting credentials so agents never see raw keys or tokens.

The SDK provides a programmatic interface for managing vaults, minting scoped session tokens, and interacting with Agent Vault from TypeScript applications. For more information, see the [documentation](https://agent-vault.infisical.com).

## Installation

Install the package using npm:

```bash
npm install @infisical/agent-vault-sdk
```

or using yarn:

```bash
yarn add @infisical/agent-vault-sdk
```

## Configuration

Configure the SDK using environment variables or by passing a configuration object:

- `AGENT_VAULT_SESSION_TOKEN`: Your Agent Vault session token
- `AGENT_VAULT_ADDR`: The Agent Vault server URL

```typescript
import { AgentVault, VaultClient } from "@infisical/agent-vault-sdk";

// Initialize with environment variables (auto-detected)
const av = new AgentVault();

// Initialize with configuration object
const av = new AgentVault({
  token: "YOUR_AGENT_TOKEN",
  address: "http://localhost:14321",
});
```

## Manage vaults

Create and delete vaults using an instance-level token:

```typescript
import { AgentVault } from "@infisical/agent-vault-sdk";

const av = new AgentVault({ token: "YOUR_AGENT_TOKEN" });

// Create a vault (caller becomes vault admin)
const vault = await av.createVault({ name: "my-project" });
console.log(vault.id, vault.createdAt);

// Delete a vault (requires vault admin or instance owner)
await av.deleteVault("my-project");
```

## Mint a vault-scoped session

Use an instance-level agent token to mint a scoped session token for an agent sandbox:

```typescript
import { AgentVault } from "@infisical/agent-vault-sdk";

const av = new AgentVault({ token: "YOUR_AGENT_TOKEN" });
const session = await av.vault("my-project").sessions.create({
  vaultRole: "proxy",
  ttlSeconds: 3600,
});
console.log(session.token); // pass this into your agent sandbox
```

## Use a vault-scoped token

Inside an agent sandbox, use the scoped token directly:

```typescript
import { VaultClient } from "@infisical/agent-vault-sdk";

// Auto-detect from environment variables
const vault = new VaultClient();

// Or pass config explicitly
const vault = new VaultClient({
  token: "SCOPED_TOKEN",
  address: "http://localhost:14321",
});
```

## Manage credentials

Read, write, and delete credentials (secrets) stored in a vault. Available on both instance-level and vault-scoped clients.

```typescript
// Via instance-level client
const vault = av.vault("my-project");

// Or via standalone vault-scoped client
const vault = new VaultClient();
```

### List credential keys

```typescript
const { keys } = await vault.credentials.list();
// keys: ["STRIPE_KEY", "GITHUB_TOKEN"]
```

### Reveal credential values

Requires member+ role:

```typescript
const { credentials } = await vault.credentials.list({ reveal: true });
// credentials: [{ key: "STRIPE_KEY", value: "sk_live_..." }, ...]

// Filter to a single credential
const { credentials } = await vault.credentials.list({ reveal: true, key: "STRIPE_KEY" });
```

### Set credentials

Keys must be SCREAMING_SNAKE_CASE. Existing credentials with the same key are overwritten. Requires member+ role:

```typescript
const { set } = await vault.credentials.set({
  STRIPE_KEY: "sk_live_abc",
  GITHUB_TOKEN: "ghp_xyz",
});
// set: ["STRIPE_KEY", "GITHUB_TOKEN"]
```

### Delete credentials

Requires member+ role:

```typescript
const { deleted } = await vault.credentials.delete(["STRIPE_KEY", "GITHUB_TOKEN"]);
// deleted: ["STRIPE_KEY", "GITHUB_TOKEN"]
```

## Manage services

Manage vault services (proxy rules) that define how Agent Vault authenticates to target hosts. Only available via `AgentVault.vault(name)` (requires vault name).

### List services

```typescript
const vault = av.vault("my-project");
const { services } = await vault.services.list();
// services: [{ host: "api.stripe.com", auth: { type: "bearer", token: "STRIPE_KEY" } }, ...]
```

### Add or update services (upsert by host)

If a service with the same host already exists, it is replaced. Requires admin role:

```typescript
const { upserted, servicesCount } = await vault.services.set([
  {
    host: "api.stripe.com",
    description: "Stripe API",
    auth: { type: "bearer", token: "STRIPE_KEY" },
  },
]);
// upserted: ["api.stripe.com"], servicesCount: 5
```

### Remove a service by host

Requires admin role:

```typescript
const { removed, servicesCount } = await vault.services.remove("api.stripe.com");
// removed: "api.stripe.com", servicesCount: 4
```

### Replace all services

Requires admin role. This is destructive — removes all existing services and sets the provided list:

```typescript
await vault.services.replaceAll([
  { host: "api.stripe.com", auth: { type: "bearer", token: "STRIPE_KEY" } },
  { host: "api.github.com", auth: { type: "bearer", token: "GITHUB_TOKEN" } },
]);
```

### Clear all services

Requires admin role:

```typescript
await vault.services.clear();
```

### Check credential usage

Find which services reference a given credential key:

```typescript
const { services } = await vault.services.credentialUsage("STRIPE_KEY");
// services: [{ host: "api.stripe.com", description: "Stripe API" }]
```

## Releasing

Releases are automated via GitHub Actions using [npm OIDC trusted publishing](https://docs.npmjs.com/generating-provenance-statements). To publish a new version:

1. Push a git tag matching the pattern `node-sdk/v<version>` (e.g., `node-sdk/v0.2.0`).
2. The CI workflow extracts the version from the tag, sets it in `package.json`, and publishes to npm with provenance attestation.

The `version` field in `package.json` is a placeholder — the actual published version is always derived from the git tag.
