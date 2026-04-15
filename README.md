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

Agent Vault takes a different approach: **agents never see credentials at all**. Instead, they route HTTP requests through a local proxy that injects the right credentials at the network layer.

- **Brokered access, not retrieval** - Your agent gets a session token and a proxy URL. It sends requests to `proxy/{host}/{path}` and Agent Vault authenticates them. There is nothing to leak. [Learn more](https://docs.agent-vault.dev/learn/security)
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

Auto-detects your OS and architecture, downloads the latest release, and installs. Works for both fresh installs and upgrades (backs up your database before upgrading).

```bash
curl -fsSL https://raw.githubusercontent.com/Infisical/agent-vault/main/install.sh | sh
```

Supports macOS (Intel + Apple Silicon) and Linux (x86_64 + ARM64).

### [Docker](https://docs.agent-vault.dev/self-hosting/docker)

```bash
docker run -it -p 14321:14321 -v agent-vault-data:/data infisical/agent-vault
```

### From source

Requires [Go 1.25+](https://go.dev/dl/) and [Node.js 22+](https://nodejs.org/).

```bash
git clone https://github.com/Infisical/agent-vault.git
cd agent-vault
make build
sudo mv agent-vault /usr/local/bin/
```

## Quickstart

```bash
# Start the server (runs on localhost:14321 by default)
agent-vault server -d

# Add a credential
agent-vault vault credential set GITHUB_TOKEN=ghp_xxx

# Configure a service proxy rule
agent-vault vault service set -f - <<EOF
services:
  - host: api.github.com
    auth:
      type: bearer
      token: GITHUB_TOKEN
EOF
```

Any command that needs authentication will walk you through setup automatically. Just run it and follow the prompts. You can also run `agent-vault vault service set` interactively or browse templates with `agent-vault catalog`.

The server includes a web UI at `http://localhost:14321` for managing services, credentials, approving proposals, and inviting users and agents.

### Building custom agents

Mint a session token and pass it to your agent process. The agent authenticates every request through the proxy. No credentials in its environment.

```bash
# Mint a scoped session token
export AGENT_VAULT_SESSION_TOKEN=$(agent-vault vault token)
export AGENT_VAULT_ADDR=http://localhost:14321
```

From your agent code, proxy requests through Agent Vault:

```typescript
const vault = process.env.AGENT_VAULT_ADDR;
const token = process.env.AGENT_VAULT_SESSION_TOKEN;

// Proxy an authenticated request (Agent Vault injects the credentials)
const resp = await fetch(`${vault}/proxy/api.github.com/user/repos`, {
  headers: { Authorization: `Bearer ${token}` },
});
```

If a service isn't configured yet, the agent can [propose access](https://docs.agent-vault.dev/learn/proposals) via `POST /v1/proposals`. You approve in your browser and the agent retries.

### Using with coding agents

Wrap your coding agent with `vault run` for automatic session management:

```bash
agent-vault vault run -- claude    # Claude Code
agent-vault vault run -- cursor    # Cursor
agent-vault vault run -- codex     # Codex

# Or create an invite for any agent
agent-vault agent invite my-agent
```

`vault run` injects `AGENT_VAULT_SESSION_TOKEN`, `AGENT_VAULT_ADDR`, and `AGENT_VAULT_VAULT` into the child process. The agent discovers services, proxies requests, and proposes access for anything missing.

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
