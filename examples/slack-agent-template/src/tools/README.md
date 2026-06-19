# Tool Development

This directory is intentionally small. The template gives you primitives, not a prebuilt tool suite.

## Included Tools

- `echo.ts` proves local tool registration works without external credentials.
- `example-api.ts` shows the shape of a read-only HTTP tool that can run behind Agent Vault.

Delete either tool once your agent has real domain tools.

## Tool Pattern

Good tools are narrow, typed, and easy to test:

1. Define structured inputs with Zod.
2. Validate or constrain paths, IDs, and enum values before making requests.
3. Call real upstream URLs with normal HTTP clients.
4. Disable automatic redirects for user-influenced API calls unless you have a specific allowlist.
5. Do not accept raw credentials as tool input.
6. Do not read production secrets directly from env.
7. Let Agent Vault inject credentials at the proxy boundary.
8. Return compact, Slack-readable text.
9. Add mocked tests for success, empty, and error cases.

For authenticated APIs, use placeholders in `.env.example` and document the matching Agent Vault service rule.

## Service Layout

When a tool grows beyond one file, group it by service:

```text
src/
  linear/
    client.ts
    tools/
      list-issues.ts
      draft-comment.ts
      index.ts
```

Then register the tools in `src/agent.ts`.

## Write Actions

Read tools can act directly. Write tools should be conservative:

- return a draft by default, or
- require explicit user wording such as "post this", "create this", or "send it now".

Do not create, edit, delete, assign, close, post, or send based only on inferred intent.
