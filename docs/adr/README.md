# Architecture decisions

Credential-acquisition V1 is governed by:

1. [ADR 0001: provider protocol](0001-delegated-credential-provider-protocol.md)
2. [ADR 0002: browser policy](0002-browser-credential-acquisition-policy.md)
3. [ADR 0003: MCP hub](0003-agent-vault-mcp-hub.md)

The Perplexity research gate completed on 2026-09-21. The synthesis approved an
amended V1 that removes real-provider DOM capture and treats context binding as
anti-replay/anti-misrouting rather than confidentiality.
