# Agent Vault TypeScript SDK

The official TypeScript SDK for [Agent Vault](https://github.com/Infisical/agent-vault), an open-source credential brokerage layer for AI agents. Agent Vault sits between development agents and target services, proxying requests and injecting credentials so agents never see raw keys or tokens.

The SDK provides a programmatic interface for proxying HTTP requests through Agent Vault, managing vaults, minting scoped session tokens, and interacting with Agent Vault from TypeScript applications. For more information, see the [documentation](https://agent-vault.infisical.com).

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

## Proxy requests

Send HTTP requests through the Agent Vault proxy. The broker matches the target host against configured services, injects credentials, and forwards the request to `https://{host}/{path}`. Your agent never sees raw API keys or tokens.

### Basic usage with a vault-scoped token

```typescript
import { VaultClient } from "@infisical/agent-vault-sdk";

const vault = new VaultClient(); // auto-detects from env vars

// GET request through the proxy
const res = await vault.proxy.get("api.stripe.com", "/v1/charges", {
  query: { limit: 10 },
});

if (res.ok) {
  const data = await res.json<{ data: { id: string }[] }>();
  console.log(data.data);
}
```

### Instance-level token with vault selection

When using an instance-level agent token, the SDK automatically injects the `X-Vault` header:

```typescript
import { AgentVault } from "@infisical/agent-vault-sdk";

const av = new AgentVault({ token: "av_agt_..." });

const res = await av.vault("my-project").proxy.post(
  "api.github.com",
  "/repos/owner/repo/issues",
  { body: { title: "Bug report", body: "Repro steps..." } },
);
```

### Available methods

```typescript
vault.proxy.get(host, path?, options?)
vault.proxy.post(host, path?, options?)
vault.proxy.put(host, path?, options?)
vault.proxy.patch(host, path?, options?)
vault.proxy.delete(host, path?, options?)
vault.proxy.request(method, host, options?)  // arbitrary HTTP method
```

### Response

`ProxyResponse` wraps the upstream service's response without auto-parsing. Call `.json()`, `.text()`, or `.arrayBuffer()` to consume the body:

```typescript
interface ProxyResponse {
  status: number;
  statusText: string;
  ok: boolean;        // true if status is 200-299
  headers: Headers;
  json<T>(): Promise<T>;
  text(): Promise<string>;
  arrayBuffer(): Promise<ArrayBuffer>;
  body: ReadableStream<Uint8Array> | null;
}
```

### Error handling

The SDK distinguishes between broker errors (thrown as exceptions) and upstream errors (returned as responses):

- **Upstream non-2xx** (e.g. Stripe returns 404): resolves normally with `res.ok === false`. Handle it yourself.
- **`ProxyForbiddenError`**: thrown when no broker service matches the target host. Includes a `proposalHint` with the information needed to create a proposal.
- **`ApiError`**: thrown for other broker-level failures (missing credentials, auth errors, bad request).

```typescript
import { ProxyForbiddenError } from "@infisical/agent-vault-sdk";

try {
  await vault.proxy.get("api.unknown-service.com", "/");
} catch (err) {
  if (err instanceof ProxyForbiddenError) {
    console.log(err.proposalHint.host);               // "api.unknown-service.com"
    console.log(err.proposalHint.endpoint);            // "POST /v1/proposals"
    console.log(err.proposalHint.supportedAuthTypes);  // ["bearer", "basic", ...]
  }
}
```

### Important notes

- **Authorization header**: The broker strips any `Authorization` header you set and replaces it with credentials from the vault's service configuration. Do not pass upstream auth tokens in headers — they will be ignored.
- **Header allowlist**: Only certain headers are forwarded to the upstream service: `Content-Type`, `Accept`, `User-Agent`, `Idempotency-Key`, `X-Request-Id`, and a few others. Other headers are dropped.
- **Body encoding**: Plain objects and arrays are automatically JSON-stringified with `Content-Type: application/json`. Pass strings or buffers for other content types.
- **Timeout**: Defaults to 30 seconds. Override per-request with `timeout` in options. Set `timeout: 0` to disable.
- **Underlying endpoint**: The proxy is served at `/proxy/{host}/{path}` on the Agent Vault server.

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
