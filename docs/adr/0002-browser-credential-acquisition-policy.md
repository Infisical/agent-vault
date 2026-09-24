# ADR 0002: Browser and guided credential-acquisition policy

- Status: Accepted
- Decision date: 2026-09-21
- Scope: V1 browser and human-presence flows

## Context

The research compared guided human entry, extensions with native messaging,
isolated browser profiles, CDP automation, DOM and clipboard capture, and
provider-specific recipes. A browser agent that can inspect page text, DOM,
screenshots, HAR files, clipboard contents, or debugging traffic cannot be
shown a credential while preserving the invariant that plaintext never enters
agent context.

The original proposal allowed signed DOM recipes after vault opt-in. The threat
model could not close four high-risk questions: stable credential-to-principal
validation, attestable browser isolation, provider terms, and trustworthy peer
identity for native ingest. Documentation or a second confirmation does not
close those issues.

## Decision

V1 permanently prohibits real-provider DOM credential capture. This is a
removed capability, not a deferred implementation:

- no DOM selectors in proposals, policy, or MCP schemas;
- no CDP, clipboard, screenshot, HAR, DOM-dump, or page-text channel;
- `browser_dom` handlers cannot be enabled or started, even if a persisted
  compatibility flag says otherwise;
- browser automation may open a normal approval destination, but final approval
  and any secure entry remain a direct human action;
- existing OAuth authorization-code and token-upload flows remain available;
- device-code flows must render codes only on the trusted vault surface and
  must follow RFC 8628 polling rules;
- any future DOM capability requires a new research gate and explicit approval.

The previously stated “vault opt-in means no second confirmation” rule is moot
for DOM because the capability does not exist in V1. Proposal approval remains
the authorization event for permitted native and human-presence providers.

## Consequences

The implementation keeps the stored `browser_dom_enabled` field only for schema
compatibility and future migration, but runtime admission rejects the handler
kind unconditionally. Tests must assert that secrets and device codes never
appear in agent-reachable data, screenshots, logs, traces, or MCP payloads.

## Research provenance

See the [browser threat-model task](https://www.perplexity.ai/computer/tasks/7b9276d1-e0b5-4a3f-be81-6a32bd777446)
and the [final synthesis](https://www.perplexity.ai/computer/tasks/67f645ea-cf2f-4751-8c41-ba1e2ae686da).
Relevant primary guidance includes the
[MCP security best practices](https://modelcontextprotocol.io/docs/2025-06-18/tutorials/security/security_best_practices)
and [Chrome native messaging documentation](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging).
