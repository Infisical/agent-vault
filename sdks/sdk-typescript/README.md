# Agent Vault TypeScript SDK

The official TypeScript SDK for [Agent Vault](https://github.com/Infisical/agent-vault), an open-source credential brokerage layer for AI agents. Agent Vault sits between development agents and target services, proxying requests and injecting credentials so agents never see raw keys or tokens.

## Installation

```bash
npm install @infisical/agent-vault-sdk
```

## Quickstart

### Configure a sandbox with transparent proxy

The primary use case: your backend orchestrates agent sandboxes (Docker, Daytona, E2B, etc.) and needs to route their HTTPS traffic through Agent Vault so agents never see credentials. One call gives you everything you need.

```typescript
import { AgentVault, buildProxyEnv } from "@infisical/agent-vault-sdk";

const av = new AgentVault({
  token: "YOUR_AGENT_TOKEN",
  address: "http://localhost:14321",
});

const vault = av.vault("my-project");

// Mint a scoped session — returns the token + container config in one call
const session = await vault.sessions.create({
  vaultRole: "proxy",
  ttlSeconds: 3600,
});

// Build the full env var set with your chosen CA cert mount path
const certPath = "/etc/ssl/agent-vault-ca.pem";
const env = buildProxyEnv(session.containerConfig!, certPath);

// Pass to your container runtime — the agent inside just calls
// fetch("https://api.stripe.com/v1/charges") normally.
// Agent Vault intercepts, injects credentials, and forwards.
```

`session.containerConfig` includes:

| Field | Description |
|---|---|
| `env.HTTPS_PROXY` | MITM proxy URL with the scoped token embedded |
| `env.NO_PROXY` | Bypass list (`localhost,127.0.0.1`) |
| `caCertificate` | Root CA PEM content — mount this into the container |

`buildProxyEnv()` expands the config with CA trust variables (`SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, `GIT_SSL_CAINFO`, `DENO_CERT`) all pointing at `certPath`.

`containerConfig` is `null` when the server has MITM disabled (`--mitm-port 0`).

### Example: Docker

```typescript
import { execSync } from "child_process";
import { writeFileSync } from "fs";

const certPath = "/etc/ssl/agent-vault-ca.pem";
const env = buildProxyEnv(session.containerConfig!, certPath);

// Write the CA cert to a temp file for mounting
const tmpCert = "/tmp/agent-vault-ca.pem";
writeFileSync(tmpCert, session.containerConfig!.caCertificate);

const envFlags = Object.entries(env).map(([k, v]) => `-e ${k}=${v}`).join(" ");
execSync(`docker run --rm ${envFlags} -v ${tmpCert}:${certPath}:ro my-agent-image`);
```

### Example: Daytona

```typescript
import { Daytona } from "@daytonaio/sdk";

const daytona = new Daytona();
const certPath = "/etc/ssl/agent-vault-ca.pem";
const env = buildProxyEnv(session.containerConfig!, certPath);

const workspace = await daytona.create({
  image: "my-agent-image",
  envVars: env,
  // Mount session.containerConfig.caCertificate at certPath
});
```

### Set up a vault

Depending on your use case, vault setup may already be done via the CLI or dashboard. Here's the programmatic equivalent:

```typescript
import { AgentVault } from "@infisical/agent-vault-sdk";

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
```

### Explicit proxy (alternative)

If you can't use the transparent MITM proxy, the agent can route requests through the explicit `/proxy` endpoint using `VaultClient`:

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
