# Agent Vault

Open-source credential broker for AI agents. Agents access services without ever seeing the underlying credentials.

## Why

Traditional secret managers return credentials directly to the caller. This breaks down with AI agents, which are non-deterministic and vulnerable to prompt injection. An attacker can craft a malicious prompt and exfiltrate credentials from the agent.

Agent Vault takes a different approach: agents never receive credentials. They route requests through Agent Vault, and Agent Vault attaches credentials on their behalf.

```
Agent ────▶ Agent Vault Proxy ────▶ api.stripe.com
(no creds)    (attaches              (receives real
               credentials)           Authorization header)
```

- **Brokered access, not retrieval.** Agents route requests through a proxy. There is nothing to leak because agents never have credentials.
- **Self-onboarding.** Paste an invite prompt into any agent's chat and it connects itself. No env setup, no config files.
- **Agent-led access.** The agent discovers what it needs at runtime and raises a proposal. You approve in your browser.

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

## Documentation

Full documentation at **[docs.agent-vault.dev](https://docs.agent-vault.dev)**

- [Quickstart: Claude Code](https://docs.agent-vault.dev/quickstart/claude-code)
- [Quickstart: Cursor](https://docs.agent-vault.dev/quickstart/cursor)
- [Self-Hosting](https://docs.agent-vault.dev/self-hosting/local) (Local, Docker, Fly.io)
- [Agent Protocol](https://docs.agent-vault.dev/agents/protocol)
- [CLI Reference](https://docs.agent-vault.dev/reference/cli)

## Development

```bash
make build      # Build frontend + Go binary
make test       # Run tests
make web-dev    # Vite dev server with hot reload (port 5173)
make dev        # Go + Vite dev servers with hot reload
make docker     # Build Docker image
```
