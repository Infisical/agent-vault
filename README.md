# Agent Vault

**Secure Credential Access for AI Agents**

An open-source credential broker by [Infisical](https://infisical.com) that sits between your agents and the APIs they call.
No credential exposure, no prompt injection risk — just brokered access out of the box.

> **Beta software.** Agent Vault is under active development and may have breaking changes. Use at your own risk. Please review the [security documentation](https://docs.agent-vault.dev/learn/security) before deploying.

[Documentation](https://docs.agent-vault.dev) — [Installation](https://docs.agent-vault.dev/installation) — [CLI Reference](https://docs.agent-vault.dev/reference/cli) — [Slack](https://infisical.com/slack)

```bash
curl -fsSL https://raw.githubusercontent.com/Infisical/agent-vault/main/install.sh | sh
```

### Example: Agent-led access with zero pre-configuration

Give your agent a task that requires an external API. Agent Vault handles the rest.

```
You:    "Fetch my recent Stripe charges"

Agent:  calls /discover — Stripe isn't configured yet
        raises a proposal requesting access
        presents you with an approval link

You:    click the link, paste your API key, click Allow

Agent:  retries through the proxy — request succeeds
        "Here are your 10 most recent charges..."
```

The agent never saw your Stripe key. Agent Vault attached it on the wire.

## Why Agent Vault

Traditional secret managers return credentials directly to the caller. This breaks down with AI agents, which are non-deterministic and vulnerable to prompt injection. An attacker can craft a malicious prompt and exfiltrate credentials from the agent.

- **Brokered access, not retrieval** — Agents route requests through a proxy. There is nothing to leak because agents never have credentials.
- **Self-onboarding** — Paste an invite prompt into any agent's chat and it connects itself. No env setup, no config files. Works with Claude Code, Cursor, and any HTTP-capable agent.
- **Agent-led access** — The agent discovers what it needs at runtime and raises a proposal. You review and approve in your browser with one click.
- **Encrypted at rest** — Credentials are encrypted with AES-256-GCM using an Argon2id-derived key. The master password never touches disk.
- **Multi-user, multi-vault** — Role-based access control with instance-level and vault-level permissions. Invite teammates, scope agents to specific vaults, and audit everything.

## Install

### Script (macOS / Linux)

Auto-detects your OS and architecture, downloads the latest release, and installs. Works for both fresh installs and upgrades (backs up your database before upgrading).

```bash
curl -fsSL https://raw.githubusercontent.com/Infisical/agent-vault/main/install.sh | sh
```

Supports macOS (Intel + Apple Silicon) and Linux (x86_64 + ARM64).

### Docker

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

### Verify a release (optional)

Every release includes SHA-256 checksums and a [cosign](https://github.com/sigstore/cosign) signature for supply-chain security. No keys to manage — verification uses GitHub's OIDC identity.

```bash
# Download the checksums and signature bundle from the release page, then:

# 1. Verify the binary hasn't been tampered with
sha256sum --check checksums.txt

# 2. Verify the checksums were signed by the Infisical/agent-vault GitHub Actions workflow
cosign verify-blob \
  --bundle checksums.txt.bundle \
  --certificate-identity-regexp "github.com/Infisical/agent-vault" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  checksums.txt
```

## Quick start

```bash
agent-vault server -d

# Register (first user becomes owner) and log in
agent-vault register
agent-vault login

# Launch your agent through Agent Vault
agent-vault vault run -- claude
```

Ask the agent to call an external API. It discovers available services, proposes access for anything missing, and presents you with a browser link to approve.

## Development

```bash
make build      # Build frontend + Go binary
make test       # Run tests
make web-dev    # Vite dev server with hot reload (port 5173)
make dev        # Go + Vite dev servers with hot reload
make docker     # Build Docker image
```
