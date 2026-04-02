<h1 align="center">Agent Vault</h1>

<p align="center"><strong>Secure Credential Access for AI Agents</strong></p>

<p align="center">
An open-source credential broker project by <a href="https://infisical.com">Infisical</a> that sits between your agents and the APIs they call.<br>
Agent Vault eliminates credential exfiltration risk - just brokered access out of the box.
</p>

<p align="center">
<a href="https://docs.agent-vault.dev">Documentation</a> | <a href="https://docs.agent-vault.dev/installation">Installation</a> | <a href="https://docs.agent-vault.dev/reference/cli">CLI Reference</a> | <a href="https://infisical.com/slack">Slack</a>
</p>

## Why Agent Vault

Traditional secret managers return credentials directly to the caller. This breaks down with AI agents, which are non-deterministic and vulnerable to prompt injection. An attacker can craft a malicious prompt and exfiltrate credentials from the agent.

- **Brokered access, not retrieval** - Agents route requests through a proxy. There is nothing to leak because agents never have credentials. [Learn more](https://docs.agent-vault.dev/learn/security)
- **Self-onboarding** - Paste an invite prompt into any agent's chat and it connects itself. No env setup, no config files. Works with [Claude Code](https://docs.agent-vault.dev/quickstart/claude-code), [Cursor](https://docs.agent-vault.dev/quickstart/cursor), and any HTTP-capable agent.
- **Agent-led access** - The agent discovers what it needs at runtime and raises a [proposal](https://docs.agent-vault.dev/learn/proposals). You review and approve in your browser with one click.
- **Encrypted at rest** - Credentials are encrypted with AES-256-GCM using an Argon2id-derived key. The master password never touches disk. [Learn more](https://docs.agent-vault.dev/learn/credentials)
- **Multi-user, multi-vault** - Role-based access control with instance-level and vault-level [permissions](https://docs.agent-vault.dev/learn/permissions). Invite teammates, scope agents to specific [vaults](https://docs.agent-vault.dev/learn/vaults), and audit everything.

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
agent-vault register
agent-vault login

# Create an agent invite
agent-vault vault agent invite create
```

This prints an invite prompt. Paste it into your agent's chat ([Claude Code](https://docs.agent-vault.dev/quickstart/claude-code), [Cursor](https://docs.agent-vault.dev/quickstart/cursor), or any HTTP-capable agent) and it connects itself.

Once connected, ask the agent to call any external API. It will discover available services, [propose access](https://docs.agent-vault.dev/first-proposal) for anything missing, and give you a browser link to approve.

## Development

```bash
make build      # Build frontend + Go binary
make test       # Run tests
make web-dev    # Vite dev server with hot reload (port 5173)
make dev        # Go + Vite dev servers with hot reload
make docker     # Build Docker image
```

---

> **Beta software.** Agent Vault is under active development and may have breaking changes. Use at your own risk. Please review the [security documentation](https://docs.agent-vault.dev/learn/security) before deploying.
