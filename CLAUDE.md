# Agent Vault (agent-vault)

An HTTP brokerage layer for AI agents. Sits between development agents (Claude Code, Cursor) and target services (Stripe, GitHub, etc.), proxying requests and injecting credentials so agents never see raw keys or tokens. Typically deployed to a remote host that agents reach over the network.

## Build, run, test

```bash
make build        # Builds frontend (React/Vite) then Go binary → ./agent-vault
make web-dev      # Frontend-only hot reload (Vite on 5173, proxies API to Go on 14321)
make test         # go test ./...
make docker       # Multi-stage Docker image; data persisted at /data/.agent-vault/
```

**TDD rule: tests must pass before work is considered complete.** Command smoke tests live in [cmd/cmd_test.go](cmd/cmd_test.go).

## Top-level layout

- [main.go](main.go) — entrypoint, calls `cmd.Execute()`
- [cmd/](cmd/) — Cobra CLI commands, flat package, one file per command group. Commands self-register via `init()`.
- [web/](web/) — React + TypeScript + Vite frontend; builds into `internal/server/webdist/` which is embedded in the binary via `go:embed`.
- [internal/](internal/) — business logic: `broker`, `brokercore`, `proposal`, `server`, `mitm`, `ca`, `notify`, `auth`, `session`, `store`, `crypto`, `netguard`, `pidfile`, `catalog`. Each subpackage is self-describing; read the package docstring when you need detail.

## Core concepts (mental model)

- **Single ingress into the broker — transparent MITM** (on by default, port 14322, disable with `--mitm-port 0`): plain HTTP forward-proxy ingress backed by [internal/mitm](internal/mitm/) + [internal/ca](internal/ca/) (software CA, root key encrypted with the master key). The listener accepts both `CONNECT host:port` (HTTPS upstreams) and absolute-form forward-proxy requests (`POST http://host/path HTTP/1.1`, RFC 7230 §5.3.2) for plain-HTTP upstreams on the same port. Clients use `HTTPS_PROXY=http://...` and `HTTP_PROXY=http://...` — both point at the same proxy URL. Deploy on a trusted/private network. Credential injection lives in `brokercore`. HTTP/1.1 at the ingress, with transparent WebSocket upgrade support (HTTP/2 not yet). Bind failures are non-fatal — the core HTTP server keeps running.
- **Proposals = GitHub-PR-style change requests.** Agents cannot edit services or credentials directly; they create proposals, a human approves in CLI or browser, and apply merges atomically. Per-vault sequential IDs. 7-day TTL.
- **Two independent permission axes**:
  - Instance role: `no-access` < `member` < `owner` (applies to both users and agents). `no-access` actors can authenticate and operate inside vaults they're granted to, but cannot create vaults, issue invites, or list other actors at the instance scope.
  - Vault role: `proxy` < `member` < `admin`. Proxy can use the proxy and raise proposals; member can manage credentials/services; admin can invite humans.
- **KEK/DEK key wrapping**: A random DEK (Data Encryption Key) encrypts credentials and the CA key at rest (AES-256-GCM). If a master password is set, Argon2id derives a KEK (Key Encryption Key) that wraps the DEK; changing the password re-wraps the DEK without re-encrypting credentials. If no password is set (passwordless mode), the DEK is stored in plaintext — suitable for PaaS deploys where volume security is the trust boundary. Login uses email+password. The first user to register becomes the instance owner and is auto-granted vault admin on `default`.
- **Agent skill is the agent-facing contract.** [cmd/skill_cli.md](cmd/skill_cli.md) is embedded into the binary, installed by `vault run`, and served publicly at `/v1/skills/cli`. It teaches agents how to create proposals when API access is needed.
- **Two isolation modes for `vault run`** (selected via `--isolation` or `AGENT_VAULT_ISOLATION`): `host` (default, cooperative — fork+exec on the host with `HTTPS_PROXY`/`HTTP_PROXY` envvars) and `container` (non-cooperative — Docker container with iptables egress locked to the Agent Vault proxy). Container mode lives in [internal/isolation/](internal/isolation/) with an embedded Dockerfile + init-firewall.sh + entrypoint.sh, built on first use and cached by content hash.

## Where to look for details

- **CLI surface** — `./agent-vault --help` (recursive on every subcommand) + [cmd/skill_cli.md](cmd/skill_cli.md).
- **HTTP API surface** — handlers under [internal/server/](internal/server/).
- **Types & validation** — broker service/auth shapes in [internal/broker/](internal/broker/); proposal shapes in [internal/proposal/](internal/proposal/).
- **User-facing operator docs** — [README.md](README.md).
- **Environment variables** — [.env.example](.env.example) is the canonical list.
- **Public docs site** — Mintlify source lives under [docs/](docs/). Flag reference: [docs/reference/cli.mdx](docs/reference/cli.mdx). Env var reference: [docs/self-hosting/environment-variables.mdx](docs/self-hosting/environment-variables.mdx).
- **Go module**: `github.com/Infisical/agent-vault`. CLI framework: [spf13/cobra](https://github.com/spf13/cobra).

## Conventions

- When the agent-facing surface changes (endpoints, request/response fields, auth behavior), update [cmd/skill_cli.md](cmd/skill_cli.md).
- When adding or consuming an environment variable (even platform-injected ones like `PORT` or `FLY_APP_NAME`), update [.env.example](.env.example), [docs/self-hosting/environment-variables.mdx](docs/self-hosting/environment-variables.mdx), **and** the env-var table in [docs/reference/cli.mdx](docs/reference/cli.mdx). If it changes fallback behavior of an existing variable, update that variable's description too.
- When adding or changing a CLI flag, update the flag table in [docs/reference/cli.mdx](docs/reference/cli.mdx) for the affected command.
- When a change affects operator-facing behavior, update [README.md](README.md).
- Whenever a new feature lands, scan [docs/](docs/) for pages that need a matching update — quickstart, guides, self-hosting, learn, and reference all mirror runtime behavior and drift fast.
- When the *mental model* in this file drifts (new core concept, renamed ingress path, changed permission axes), update this file — but don't re-bloat it with reference material that belongs in the skill files or `--help`.
