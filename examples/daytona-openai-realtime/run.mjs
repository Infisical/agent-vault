import { Daytona } from "@daytonaio/sdk";
import { config } from "dotenv";

config();

for (const name of ["DAYTONA_API_KEY", "OPENAI_API_KEY"]) {
  if (!process.env[name]) {
    throw new Error(`${name} is required.`);
  }
}

const script = String.raw`set -eu
trap 'echo FAILED_LINE=$LINENO >&2' ERR

(dockerd >/tmp/dockerd.log 2>&1 &)
for i in $(seq 1 45); do docker info >/dev/null 2>&1 && break; sleep 1; done
docker info >/dev/null

docker network create av-example >/dev/null 2>&1 || true
docker rm -f agent-vault-example agent-example >/dev/null 2>&1 || true

apk add --no-cache git >/tmp/apk.log
git clone --depth 1 --branch "$AGENT_VAULT_REF" "$AGENT_VAULT_REPO" /tmp/agent-vault >/tmp/git.log 2>&1
cd /tmp/agent-vault
mkdir -p internal/server/webdist
printf '<!doctype html><html><body>agent-vault-daytona-example</body></html>\n' > internal/server/webdist/index.html
docker run --rm -v /tmp/agent-vault:/src -w /src golang:1.25-alpine \
  sh -c 'CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /src/agent-vault .' >/tmp/build-agent-vault.log

cat > Dockerfile.example <<'DOCKER'
FROM infisical/agent-vault
USER root
COPY agent-vault /usr/local/bin/agent-vault
RUN chmod +x /usr/local/bin/agent-vault
USER agentvault
DOCKER
docker build -f Dockerfile.example -t agent-vault-example . >>/tmp/build-agent-vault.log

curl_net() { docker run -i --rm --network av-example curlimages/curl:8.11.1 "$@"; }
json_token() { sed -n 's/.*"token":"\([^"]*\)".*/\1/p'; }

docker run -d --name agent-vault-example --network av-example \
  -p 14321:14321 -p 14322:14322 \
  -v av-example-data:/data \
  -e AGENT_VAULT_MASTER_PASSWORD=example-master-password \
  -e AGENT_VAULT_ADDR=http://host.docker.internal:14321 \
  agent-vault-example >/tmp/av-container-id

for i in $(seq 1 90); do
  if curl_net -fsS http://agent-vault-example:14321/health >/dev/null 2>&1; then break; fi
  sleep 1
done
curl_net -fsS http://agent-vault-example:14321/health >/dev/null

owner_json=$(curl_net -fsS -X POST http://agent-vault-example:14321/v1/auth/register \
  -H 'content-type: application/json' \
  -d '{"email":"owner@example.com","password":"owner-password-123","device_label":"daytona-example"}')
OWNER_TOKEN=$(printf '%s' "$owner_json" | json_token)

curl_net -fsS -X POST http://agent-vault-example:14321/v1/credentials \
  -H "authorization: Bearer $OWNER_TOKEN" \
  -H 'content-type: application/json' \
  --data-binary @- >/dev/null <<JSON
{"vault":"default","credentials":{"OPENAI_API_KEY":"$OPENAI_API_KEY"}}
JSON

curl_net -fsS -X POST http://agent-vault-example:14321/v1/vaults/default/services \
  -H "authorization: Bearer $OWNER_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"services":[{"host":"api.openai.com","description":"OpenAI Realtime","auth":{"type":"bearer","token":"OPENAI_API_KEY"}}]}' >/dev/null

session_json=$(curl_net -fsS -X POST http://agent-vault-example:14321/v1/sessions \
  -H "authorization: Bearer $OWNER_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"vault":"default","vault_role":"proxy","ttl_seconds":3600}')
SESSION_TOKEN=$(printf '%s' "$session_json" | json_token)

curl_net -fsS http://agent-vault-example:14321/v1/mitm/ca.pem > /tmp/agent-vault-ca.pem

mkdir -p /tmp/agent
cat > /tmp/agent/package.json <<'JSON'
{
  "type": "module",
  "dependencies": {
    "https-proxy-agent": "latest",
    "ws": "latest"
  }
}
JSON

cat > /tmp/agent/index.js <<'JS'
import WebSocket from 'ws';
import { HttpsProxyAgent } from 'https-proxy-agent';
import { spawnSync } from 'node:child_process';

function testDirectEgress() {
  const env = { ...process.env };
  delete env.HTTPS_PROXY;
  delete env.https_proxy;
  const result = spawnSync('curl', ['--max-time', '5', '-fsS', 'https://example.com'], {
    env,
    stdio: 'ignore',
  });
  return result.status === 0 ? 'REACHED' : 'BLOCKED';
}

const ws = new WebSocket('wss://api.openai.com/v1/realtime?model=gpt-realtime', {
  agent: new HttpsProxyAgent(process.env.HTTPS_PROXY),
  headers: {
    Authorization: 'Bearer ' + process.env.OPENAI_API_KEY,
  },
});

let output = '';
const timeout = setTimeout(() => {
  ws.terminate();
  console.log(JSON.stringify({ ok: false, error: 'timeout', output }));
  process.exit(1);
}, 20_000);

ws.on('open', () => {
  ws.send(JSON.stringify({
    type: 'conversation.item.create',
    item: {
      type: 'message',
      role: 'user',
      content: [{ type: 'input_text', text: 'Hi, who are you? Answer in one concise sentence.' }],
    },
  }));
  ws.send(JSON.stringify({
    type: 'response.create',
    response: {
      output_modalities: ['text'],
      instructions: 'Answer naturally in one concise sentence.',
    },
  }));
});

ws.on('message', data => {
  const event = JSON.parse(data.toString());
  if (event.type === 'response.output_text.delta') output += event.delta ?? '';
  if (event.type === 'response.done') {
    clearTimeout(timeout);
    ws.close();
    console.log(JSON.stringify({
      ok: true,
      directEgress: testDirectEgress(),
      output,
      status: event.response?.status ?? null,
    }));
  }
  if (event.type === 'error') {
    clearTimeout(timeout);
    ws.close();
    console.log(JSON.stringify({ ok: false, error: event.error?.message ?? 'OpenAI realtime error', output }));
    process.exit(1);
  }
});

ws.on('error', error => {
  clearTimeout(timeout);
  console.log(JSON.stringify({ ok: false, error: error.message, output }));
  process.exit(1);
});
JS

cat > /tmp/agent/entrypoint.sh <<'SH'
#!/bin/sh
set -eu
GW_IP=$(getent ahostsv4 host.docker.internal | awk 'NR==1 {print $1}')
iptables -F OUTPUT
iptables -P OUTPUT DROP
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -d "$GW_IP" -p tcp --dport "$VAULT_HTTP_PORT" -j ACCEPT
iptables -A OUTPUT -d "$GW_IP" -p tcp --dport "$VAULT_MITM_PORT" -j ACCEPT
ip6tables -F OUTPUT || true
ip6tables -P OUTPUT DROP || true
ip6tables -A OUTPUT -o lo -j ACCEPT || true
ip6tables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT || true
exec gosu node "$@"
SH

cat > /tmp/agent/Dockerfile <<'DOCKER'
FROM node:22-bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates iptables gosu curl procps \
  && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY package.json package.json
RUN npm install --omit=dev
COPY index.js index.js
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh
USER root
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["node", "index.js"]
DOCKER

docker build -t av-openai-realtime-agent /tmp/agent >/tmp/build-agent.log

docker run -d --name agent-example --network av-example \
  --add-host=host.docker.internal:host-gateway \
  --cap-drop=ALL --cap-add=NET_ADMIN --cap-add=NET_RAW --cap-add=SETUID --cap-add=SETGID \
  --security-opt=no-new-privileges \
  -e VAULT_HTTP_PORT=14321 \
  -e VAULT_MITM_PORT=14322 \
  -e HTTPS_PROXY="https://$SESSION_TOKEN:default@host.docker.internal:14322" \
  -e NO_PROXY="localhost,127.0.0.1,host.docker.internal" \
  -e NODE_EXTRA_CA_CERTS=/etc/agent-vault/ca.pem \
  -e SSL_CERT_FILE=/etc/agent-vault/ca.pem \
  -e OPENAI_API_KEY=dummy-agent-visible-key \
  -v /tmp/agent-vault-ca.pem:/etc/agent-vault/ca.pem:ro \
  av-openai-realtime-agent >/tmp/agent-container-id

for i in $(seq 1 30); do
  if ! docker ps --format '{{.Names}}' | grep -q '^agent-example$'; then break; fi
  sleep 1
done

agent_output=$(docker logs agent-example)

printf 'OPENAI_REALTIME_RESULT=%s\n' "$agent_output"
`;

const command = `base64 -d > /tmp/example.sh <<'EOF'\n${Buffer.from(script).toString("base64")}\nEOF\nsh /tmp/example.sh`;
const daytona = new Daytona();
let sandbox;

try {
  sandbox = await daytona.create({
    autoDeleteInterval: 0,
    image: "docker:28.3.3-dind",
    name: `agent-vault-openai-realtime-${Date.now()}`,
    resources: { cpu: 2, memory: 4 },
  }, { timeout: 900 });

  const result = await sandbox.process.executeCommand(
    command,
    undefined,
    {
      AGENT_VAULT_REF: process.env.AGENT_VAULT_REF ?? "transparent-mitm-websocket",
      AGENT_VAULT_REPO: process.env.AGENT_VAULT_REPO ?? "https://github.com/suhjohn/agent-vault.git",
      OPENAI_API_KEY: process.env.OPENAI_API_KEY,
    },
    1800,
  );

  process.stdout.write(result.result);
  process.exitCode = result.exitCode;
} finally {
  if (sandbox) {
    await daytona.delete(sandbox, 180).catch(error => {
      console.error(`Failed to delete Daytona sandbox: ${error.message}`);
    });
  }
}
