# Agent Vault Slack Agent Template

A TypeScript starter for building custom Slack agents that run behind [Agent Vault](https://github.com/Infisical/agent-vault). It gives you a working Slack Socket Mode bot, a Claude Agent SDK runtime, MCP-style tool registration, Docker deployment, and Agent Vault credential brokering defaults.

Use this repo when you want to fork a working Slack agent and replace the persona plus tools with your own workflow.

## What You Get

- Slack bot entrypoint with `app_mention` and DM handling.
- Thread transcript context for replies.
- Claude Agent SDK runtime with local MCP tools.
- Environment-driven agent name, mission, tone, model, and MCP server name.
- Two starter tools: `echo` and a constrained read-only HTTP API example.
- Optional Slack email allowlist via `AGENT_ALLOWLIST`.
- Dockerfile that launches the app through `agent-vault run`.
- Agent Vault-safe credential pattern: app code uses real API URLs and placeholder secrets; Agent Vault injects real credentials at the proxy boundary.

## Quickstart

```bash
cp -R examples/slack-agent-template my-slack-agent
cd my-slack-agent
npm install
cp .env.example .env
```

If you are reading this outside the Agent Vault repository, copy the full `examples/slack-agent-template` directory into a new repo for your agent.

Edit `.env`:

```text
AGENT_NAME="Support Triage Agent"
AGENT_MISSION="Help the support team summarize Slack requests and draft next steps."
ANTHROPIC_API_KEY=__anthropic_api_key__
SLACK_BOT_TOKEN=__slack_bot_token__
SLACK_APP_TOKEN=__slack_app_token__
EXAMPLE_API_BASE_URL=https://api.example.com
```

For local development without Agent Vault, use real local credentials in `.env`. For shared, hosted, or production environments, use placeholders and store the real values in Agent Vault.

Run the CLI harness:

```bash
npm start "Hello, what tools do you have?"
```

Run the Slack bot:

```bash
npm run start:slack
```

## Create The Slack App

1. Create a Slack app from `slack-app-manifest.json`.
2. Enable Socket Mode.
3. Create an app-level token with `connections:write`.
4. Install the app to your workspace.
5. Set `SLACK_BOT_TOKEN` and `SLACK_APP_TOKEN`.

The manifest enables the App Home messages tab so people can DM the agent directly.

The included manifest grants the minimum scopes this template uses:

- `app_mentions:read`
- `chat:write`
- `channels:history`
- `groups:history`
- `im:history`
- `mpim:history`
- `users:read`
- `users:read.email`

The `users:*` scopes are used only when `AGENT_ALLOWLIST` is set. They let the app resolve Slack user IDs to email addresses for access control.

## Customize The Agent

Most first-pass customization happens in `.env`:

```text
AGENT_NAME="Security Review Agent"
AGENT_DESCRIPTION="A Slack agent that helps review security-sensitive engineering changes."
AGENT_MISSION="Help engineers identify credential, logging, and deployment risks before review."
AGENT_AUDIENCE="engineering and security channels"
AGENT_TONE="precise, cautious, and brief"
AGENT_MODEL=claude-sonnet-4-6
AGENT_MCP_SERVER_NAME=security_tools
AGENT_EXTRA_INSTRUCTIONS="Never approve a risky change automatically. Return review notes and ask for explicit human confirmation."
```

For deeper changes:

- `src/personality.ts`: system prompt structure and shared safety rules.
- `src/agent.ts`: tool registration.
- `src/tools/`: starter tools. Replace or extend these with domain-specific tools.
- `src/run-agent.ts`: model selection, tool allowlist, and progress labels.
- `src/slack.ts`: Slack event handling and response behavior.

## Add Tools

Tools are registered through `createSdkMcpServer` in `src/agent.ts`. The starter includes two deliberately small tools:

```text
src/tools/echo.ts
src/tools/example-api.ts
```

`echo` proves tool registration works without credentials. `example-api` demonstrates the pattern for a read-only HTTP API call:

- validate structured input with Zod
- build URLs from a configured base URL rather than accepting arbitrary hosts
- call the real upstream URL with `fetch`
- omit raw credentials from code and tool inputs
- let Agent Vault inject credentials at the proxy boundary
- test with mocked network calls

This template intentionally does not ship GitHub, Linear, Notion, or write-action tools. Different agents need different access. Fork the template, delete the examples you do not need, and add the smallest tools that fit your agent's job.

When adding a real integration:

1. Add a typed client for the external API.
2. Add one or more narrow tools that call that client.
3. Register the tools in `src/agent.ts`.
4. Add only the env vars the integration needs to `.env.example`.
5. Add the real credential and service rule in Agent Vault.

Agent Vault works below the SDK/tool layer. Your tool should call the normal upstream API URL and omit real credentials or use placeholder credentials.

## Build On It With An Agent

This template is meant to be easy to extend with a coding agent. A good handoff is specific about the service, access level, and tests:

```text
Add read-only tools for <service>. Use Agent Vault for credentials.
Keep tools narrow and typed. Add mocked tests.
Update .env.example and docs/agent-vault.md.
Do not add write actions unless explicitly requested.
```

For write workflows, be more explicit:

```text
Add a tool that drafts a <service> update but does not submit it.
Return the draft and required confirmation phrase.
Do not call mutation endpoints until a user explicitly says "<confirmation phrase>".
```

## Agent Vault Deployment

Agent Vault is a credential proxy and vault. The agent process should not receive real production secrets. Instead:

1. Store the real credential in Agent Vault.
2. Configure an Agent Vault service for the upstream host, for example `api.anthropic.com` or `slack.com/api/*`.
3. Set this app's env var to a placeholder such as `__anthropic_api_key__`.
4. Run the app through `agent-vault run`.

Required hosted env vars:

```text
AGENT_VAULT_ADDR=http://<agent-vault-host>:14321
AGENT_VAULT_TOKEN=<agent-token>
AGENT_VAULT_VAULT=<vault-name>
ANTHROPIC_API_KEY=__anthropic_api_key__
SLACK_BOT_TOKEN=__slack_bot_token__
SLACK_APP_TOKEN=__slack_app_token__
PORT=3000
EXAMPLE_API_BASE_URL=https://api.example.com
```

The Dockerfile copies the Agent Vault CLI from `infisical/agent-vault:latest` and starts:

```bash
agent-vault run -- node dist/slack.js
```

`agent-vault run` sets `HTTPS_PROXY`, `HTTP_PROXY`, `NO_PROXY`, and CA trust variables for the child process. `src/slack.ts` also passes an explicit `HttpsProxyAgent` to Slack's Web API client because that client ignores proxy env vars by default.

## Deploy

Any Docker-capable host works. For Render:

1. Create a Web Service from this repo.
2. Choose Docker runtime.
3. Set health check path to `/health`.
4. Set the Agent Vault, Slack, model, and agent customization env vars.

The service exposes `GET /health` and `GET /` as plain `ok` responses.

## Test

```bash
npm run typecheck
npm test
npm run build
```

The production build uses `tsconfig.build.json` so test files and test helpers do not ship in `dist`.

## Security Defaults

- Do not commit `.env`.
- Do not put raw production credentials in hosted environment variables.
- Keep Agent Vault's proxy port private to the agent network.
- Use least-privilege Agent Vault service rules for each upstream host.
- Add write tools only after read tools are reliable.
- Require explicit human intent for tools that post, edit, delete, assign, close, or mutate external state.

## Current Limitations

- The model runtime is Claude Agent SDK. Switching providers is a runtime migration, not just a config change.
- The starter ships with an `echo` tool and one constrained HTTP API example, not a suite of domain integrations.
- Slack OAuth installation is manual through the manifest.
- Agent Vault is still evolving, so verify deployment commands against the Agent Vault docs before publishing a long-lived public tutorial.
