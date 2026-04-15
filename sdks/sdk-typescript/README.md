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
