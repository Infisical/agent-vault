# Architecture Notes

This is a template for custom Slack agents that run behind [Agent Vault](https://github.com/Infisical/agent-vault). Keep the repo generic unless a fork is intentionally becoming a single-purpose agent.

## Entry Points

- `src/index.ts` - one-shot CLI. Reads a prompt from argv, calls `runAgent()`, prints the response. Useful for local development and testing.
- `src/slack.ts` - Slack Socket Mode server. The Dockerfile's default command. Handles `app_mention` and DMs, maintains thread context, posts a "Thinking..." placeholder, and updates it with the final response. Health check on `GET /health`.

Both entry points call `runAgent()` from `src/run-agent.ts`.

## Agent Core

`src/run-agent.ts` wraps the SDK's `query()` async iterator. This is where the model, MCP server registration, allowed tools, and progress labels are applied.

`src/config.ts` reads runtime customization from env vars:

- `AGENT_NAME`
- `AGENT_DESCRIPTION`
- `AGENT_MISSION`
- `AGENT_AUDIENCE`
- `AGENT_TONE`
- `AGENT_MODEL`
- `AGENT_MCP_SERVER_NAME`
- `AGENT_EXTRA_INSTRUCTIONS`
- `AGENT_ALLOWLIST`

`src/personality.ts` builds the system prompt from those values and shared safety rules.

## Tools

Tools live under `src/tools/` or a service-specific directory such as `src/linear/`. They are registered in `src/agent.ts` via `createSdkMcpServer`. Each tool is exposed as `mcp__<server-name>__<tool-name>`, and `runAgent()` derives allowed tool globs from every server in the `mcpServers` registry.

The template ships only two primitives:

- `src/tools/echo.ts` - no-credential registration smoke test.
- `src/tools/example-api.ts` - constrained read-only HTTP example for a configured base URL.

When the agent grows beyond one or two tools, group by service:

```text
src/
  linear/
    client.ts
    types.ts
    tools/
      index.ts
      list-issues.ts
      create-issue-draft.ts
  agent.ts
```

## Agent Vault Wiring

Outgoing HTTP(S) requests should go through Agent Vault, which swaps placeholder tokens for real credentials. The Dockerfile and `slack.ts` handle two important details:

1. `@slack/web-api` ignores proxy env vars because it hardcodes `proxy: false` on its axios client. `src/slack.ts` passes an explicit `HttpsProxyAgent` via `clientOptions.agent`.
2. Slack tokens must stay in Authorization headers behind Agent Vault. Do not pass per-call Slack `token` arguments, because those become form-body parameters the proxy cannot rewrite.
3. The Claude Agent SDK can pick the wrong native binary on glibc Linux. The Dockerfile pins `CLAUDE_CODE_EXECUTABLE` to the glibc binary, and `run-agent.ts` reads that env var.

Do not remove `agent-vault run` from the Docker command for hosted deployments.

## Runtime User

The container runs as the unprivileged `node` user, not root. The Claude binary refuses `--permission-mode bypassPermissions` under root, and this template uses `bypassPermissions` because tool calls are controlled by the registered tool allowlist rather than interactive approval.

## Change Map

| Want to change... | Edit... |
|---|---|
| Agent persona / instructions | `.env` first, then `src/personality.ts` |
| Model | `AGENT_MODEL` |
| Add a tool | New file under `src/tools/`, then register in `src/agent.ts` |
| MCP server name | `AGENT_MCP_SERVER_NAME` |
| Slack display name | `slack-app-manifest.json` and `AGENT_NAME` |
| Slack allowlist | `AGENT_ALLOWLIST` |
| Per-tool progress label in Slack | `src/run-agent.ts` (`toolProgressLabel`) |
| Container start command | `Dockerfile` |
| Example API base URL | `EXAMPLE_API_BASE_URL` |
