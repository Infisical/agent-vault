# Agent Vault (agent-vault)

A local-first HTTP brokerage layer for AI agents. Sits between development agents (Claude Code, Cursor) and target services (Stripe, GitHub, etc.), proxying requests and injecting credentials so agents never see raw keys or tokens.

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
- [internal/](internal/) — business logic: `broker`, `brokercore`, `proposal`, `server`, `mitm`, `ca`, `oauth`, `notify`, `auth`, `session`, `store`, `crypto`, `netguard`, `pidfile`, `catalog`. Each subpackage is self-describing; read the package docstring when you need detail.

## Core concepts (mental model)

- **Two ingress paths into the broker**:
  - Explicit proxy: `GET/POST /proxy/{target_host}/{path}` with a vault-scoped session token. Agent Vault matches the host against broker services, strips client auth, and injects credentials from the vault.
  - Transparent MITM (on by default, port 14322, disable with `--mitm-port 0`): HTTPS_PROXY-compatible ingress backed by [internal/mitm](internal/mitm/) + [internal/ca](internal/ca/) (software CA, root key encrypted with the master key). Same credential-injection code path as `/proxy` via `brokercore`. HTTP/1.1 only today. Bind failures are non-fatal — the core HTTP server keeps running.
- **Proposals = GitHub-PR-style change requests.** Agents cannot edit services or credentials directly; they create proposals, a human approves in CLI or browser, and apply merges atomically. Per-vault sequential IDs. 7-day TTL.
- **Two independent permission axes**:
  - Instance role: `owner` vs `member` (applies to both users and agents).
  - Vault role: `proxy` < `member` < `admin`. Proxy can use the proxy and raise proposals; member can manage credentials/services; admin can invite humans.
- **Master password vs login password**: the master password encrypts credentials at rest (AES-256-GCM / Argon2id) and is only used at server startup. Login uses email+password or Google OAuth. The first user to register becomes the instance owner and is auto-granted vault admin on `default`.
- **Agent skills are the agent-facing contract.** [cmd/skill_cli.md](cmd/skill_cli.md) and [cmd/skill_http.md](cmd/skill_http.md) are embedded into the binary, installed by `vault run`, and served publicly at `/v1/skills/{cli,http}`. They are the authoritative reference for what agents can do.

## Where to look for details

- **CLI surface** — `./agent-vault --help` (recursive on every subcommand) + [cmd/skill_cli.md](cmd/skill_cli.md).
- **HTTP API surface** — [cmd/skill_http.md](cmd/skill_http.md) + handlers under [internal/server/](internal/server/).
- **Types & validation** — broker service/auth shapes in [internal/broker/](internal/broker/); proposal shapes in [internal/proposal/](internal/proposal/).
- **User-facing operator docs** — [README.md](README.md).
- **Environment variables** — [.env.example](.env.example) is the canonical list.
- **Go module**: `github.com/Infisical/agent-vault`. CLI framework: [spf13/cobra](https://github.com/spf13/cobra).

## Conventions

- When the agent-facing surface changes (endpoints, request/response fields, auth behavior), update **both** [cmd/skill_cli.md](cmd/skill_cli.md) and [cmd/skill_http.md](cmd/skill_http.md) together — they are versioned as a pair.
- When adding an environment variable, update [.env.example](.env.example).
- When a change affects operator-facing behavior, update [README.md](README.md).
- When the *mental model* in this file drifts (new core concept, renamed ingress path, changed permission axes), update this file — but don't re-bloat it with reference material that belongs in the skill files or `--help`.
