# Customization Guide

This template is designed to be forked. Start by changing runtime configuration, then add tools, then tighten Agent Vault service access.

## 1. Set The Agent Profile

Use environment variables for the first customization pass:

```text
AGENT_NAME="Launch Review Agent"
AGENT_DESCRIPTION="A Slack agent that helps prepare launch checklists."
AGENT_MISSION="Summarize launch readiness, identify missing owners, and draft follow-up messages."
AGENT_AUDIENCE="product, engineering, and marketing launch channels"
AGENT_TONE="clear, calm, and action-oriented"
AGENT_EXTRA_INSTRUCTIONS="Prefer checklists when summarizing readiness. Never mark a launch ready without explicit human confirmation."
AGENT_ALLOWLIST="alice@example.com,bob@example.com"
```

The shared safety and Slack behavior rules live in `src/personality.ts`.

Leave `AGENT_ALLOWLIST` empty to let every Slack user in the installed workspace use the agent.

## 2. Add A Real Tool

The starter registers `src/tools/echo.ts` plus `src/tools/example-api.ts`. They are intentionally small. Replace or extend them with focused tools that perform one clear job.

Recommended structure once you add a service:

```text
src/
  <service>/
    client.ts
    tools/
      read-something.ts
      draft-something.ts
      index.ts
  agent.ts
```

Keep tool inputs small and explicit. For example, prefer `owner`, `repo`, and `label` fields over a single free-form query when the upstream API expects structured parameters.

`example-api.ts` demonstrates the base pattern for an Agent Vault-backed read tool: configured base URL, relative path input, no raw credentials, normal `fetch`, and mocked tests.

## 3. Keep Writes Explicit

Any tool that posts, comments, edits, creates, closes, labels, assigns, or deletes should either:

- return a draft for human approval, or
- require explicit wording in the Slack request, such as "post this" or "create the issue".

Do not let a write tool mutate external systems based only on inferred intent.

## 4. Add Credential Placeholders

For each integration:

1. Add a placeholder env var to `.env.example`.
2. Store the real credential in Agent Vault.
3. Configure an Agent Vault service rule for the upstream host.
4. Use the placeholder in hosted environments.

Example:

```text
SERVICE_API_TOKEN=__service_api_token__
```

The tool should call the real upstream API URL normally. Agent Vault injects the real credential when the request matches the service rule.

## 5. Update Slack Permissions

If a tool or behavior needs more Slack API access, update `slack-app-manifest.json` and reinstall the app.

Keep scopes narrow. Add only the Slack scopes the code actually uses.

## 6. Rename The Package

After forking, update:

- `package.json`
- `package-lock.json`
- `slack-app-manifest.json`
- `README.md`

The runtime agent name should still come from `AGENT_NAME`, so one image can support multiple deployments.

## 7. Run Tests

```bash
npm run typecheck
npm test
npm run build
```

Tests use mocked network calls and do not require service credentials.

## 8. Agentic Development Handoff

This template is designed so a coding agent can safely extend it. Give the agent a concrete service and workflow, then point it at these files:

- `src/agent.ts` for registration
- `src/tools/example-api.ts` for a minimal read-only tool pattern
- `src/<service>/client.ts` for API client code
- `src/<service>/tools/*.ts` for tool definitions
- `.env.example` for placeholders
- `docs/agent-vault.md` for service setup notes

Good instructions:

```text
Add read-only Linear tools for listing issues by team and status.
Use Agent Vault for credentials. Do not add write actions.
Add mocked tests and update .env.example plus docs/agent-vault.md.
```

Avoid vague instructions like "make it useful with Linear"; they encourage oversized tools and broad permissions.
