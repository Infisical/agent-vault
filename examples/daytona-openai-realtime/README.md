# Daytona + Agent Vault + OpenAI Realtime

Minimal end-to-end example:

- creates a Daytona sandbox from `docker:28.3.3-dind`
- clones and builds the configured Agent Vault repo/ref inside Daytona
- runs Agent Vault with the transparent MITM proxy enabled
- stores `OPENAI_API_KEY` in Agent Vault
- mints a scoped proxy session
- runs a nested agent container with egress locked to Agent Vault ports only
- connects to OpenAI Realtime WebSocket through Agent Vault
- prints actual model output
- verifies direct egress is blocked

## Run

```bash
cp .env.example .env
# fill DAYTONA_API_KEY and OPENAI_API_KEY
npm install
npm start
```

Expected output:

```text
OPENAI_REALTIME_RESULT={"ok":true,"directEgress":"BLOCKED","output":"I'm an AI assistant here to help you with anything you need.","status":"completed"}
```

The agent container receives a dummy `OPENAI_API_KEY`. Agent Vault injects the real key during the WebSocket handshake.

Set `AGENT_VAULT_REPO` and `AGENT_VAULT_REF` to test a different fork or branch.
