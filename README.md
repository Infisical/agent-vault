<p align="center">
  <img src="assets/banner.png" alt="Agent Vault" />
</p>

<p align="center"><strong>Authenticated HTTP Proxy and Vault for AI Agents</strong></p>

<p align="center">
An open-source credential broker by <a href="https://infisical.com">Infisical</a> that sits between your agents and the APIs they call.<br>
Agents should not possess credentials. Agent Vault eliminates credential exfiltration risk with brokered access.
</p>

<p align="center">
<a href="https://docs.agent-vault.dev">Documentation</a> | <a href="https://docs.agent-vault.dev/installation">Installation</a> | <a href="https://docs.agent-vault.dev/reference/cli">CLI Reference</a> | <a href="https://infisical.com/slack">Slack</a>
</p>

## Why Agent Vault

Secret managers return credentials directly to the caller. This breaks down with AI agents, which are non-deterministic systems vulnerable to prompt injection that can be tricked into exfiltrating secrets.

Agent Vault takes a different approach: **Agent Vault never reveals vault-stored credentials to agents**. Instead, agents route HTTP requests through a local proxy that injects the right credentials at the network layer.

- **Brokered access, not retrieval** - Your agent gets a token and a proxy URL. It sends requests to `proxy/{host}/{path}` and Agent Vault authenticates them. Credentials stored in the vault are never returned to the agent. [Learn more](https://docs.agent-vault.dev/learn/security)
- **Works with any agent** - Custom Python/TypeScript agents, sandboxed processes, coding agents (Claude Code, Cursor, Codex), anything that can make HTTP requests. [Learn more](https://docs.agent-vault.dev/quickstart)
- **Self-service access** - Agents discover available services at runtime and [propose access](https://docs.agent-vault.dev/learn/proposals) for anything missing. You review and approve in your browser with one click.
- **Encrypted at rest** - Credentials are encrypted with AES-256-GCM using an Argon2id-derived key. The master password never touches disk. [Learn more](https://docs.agent-vault.dev/learn/credentials)
- **Multi-user, multi-vault** - Role-based access control with instance and vault-level [permissions](https://docs.agent-vault.dev/learn/permissions). Invite teammates, scope agents to specific [vaults](https://docs.agent-vault.dev/learn/vaults), and audit everything.

<p align="center">
  <img src="docs/images/architecture.png" alt="Agent Vault architecture diagram" />
</p>

## Installation

See the [installation guide](https://docs.agent-vault.dev/installation) for full details.

### Script (macOS / Linux)

```bash
curl -fsSL https://raw.githubusercontent.com/Infisical/agent-vault/main/install.sh | sh
agent-vault server -d
```

Supports macOS (Intel + Apple Silicon) and Linux (x86_64 + ARM64).

### [Docker](https://docs.agent-vault.dev/self-hosting/docker)

```bash
docker run -it -p 14321:14321 -p 14322:14322 -v agent-vault-data:/data infisical/agent-vault
```

For non-interactive environments (Docker Compose, CI, detached mode), pass the master password as an env var:

```bash
docker run -d -p 14321:14321 -p 14322:14322 \
  -e AGENT_VAULT_MASTER_PASSWORD=your-password \
  -v agent-vault-data:/data infisical/agent-vault
```

### From source

Requires [Go 1.25+](https://go.dev/dl/) and [Node.js 22+](https://nodejs.org/).

```bash
git clone https://github.com/Infisical/agent-vault.git
cd agent-vault
make build
sudo mv agent-vault /usr/local/bin/
agent-vault server -d
```

The server starts the HTTP API on port `14321` and a transparent HTTPS proxy on port `14322`. A web UI is available at `http://localhost:14321`.

## Quickstart

### Coding agents (Claude Code, Cursor, Codex)

```bash
agent-vault vault run -- claude
```

### Sandboxed agents (Docker, Daytona, E2B)

Install the SDK in your orchestrator (the backend that launches sandboxes):

```bash
npm install @infisical/agent-vault-sdk
```

Mint a session and configure the sandbox. The SDK returns the proxy env vars and a CA certificate — pass them into your container so the agent's HTTPS traffic routes through Agent Vault transparently:

```typescript
import { AgentVault, buildProxyEnv } from "@infisical/agent-vault-sdk";
import { writeFileSync } from "fs";
import { execSync } from "child_process";

const av = new AgentVault({ token: "YOUR_TOKEN", address: "http://localhost:14321" });
const session = await av.vault("default").sessions.create({ vaultRole: "proxy" });

// Build env vars with CA trust paths for the container
const certPath = "/etc/ssl/agent-vault-ca.pem";
const env = buildProxyEnv(session.containerConfig!, certPath);

// Write the CA cert to a temp file and mount it into the container
writeFileSync("/tmp/av-ca.pem", session.containerConfig!.caCertificate);

const envFlags = Object.entries(env).map(([k, v]) => `-e ${k}=${v}`).join(" ");
execSync(`docker run --rm ${envFlags} -v /tmp/av-ca.pem:${certPath}:ro my-agent-image`);

// Inside the container, the agent just calls fetch("https://api.github.com/...")
// normally — no SDK, no credentials, no special configuration needed.
```

See the [TypeScript SDK README](sdks/sdk-typescript/README.md) for full documentation.

### API

```bash
curl https://api.github.com/user/repos \
  -x http://localhost:14322
```

The agent never sees credentials. Agent Vault intercepts HTTPS traffic via its transparent proxy, matches the host, and injects the right credential before forwarding upstream. If a service isn't configured yet, the agent can [propose access](https://docs.agent-vault.dev/learn/proposals) — you approve in the web UI and the agent retries.

## Development

```bash
make build      # Build frontend + Go binary
make test       # Run tests
make web-dev    # Vite dev server with hot reload (port 5173)
make dev        # Go + Vite dev servers with hot reload
make docker     # Build Docker image
```

---

> **Preview.** Agent Vault is in active development and the API is subject to change. Please review the [security documentation](https://docs.agent-vault.dev/learn/security) before deploying.
