#!/usr/bin/env bash
set -euo pipefail

chart_dir="${1:-charts/agent-vault}"
work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT

test_master="$(openssl rand -hex 32)"
master=(--set-string "secretEnv.AGENT_VAULT_MASTER_PASSWORD=$test_master")

helm lint "$chart_dir" --strict "${master[@]}"

helm template test "$chart_dir" "${master[@]}" \
  --show-only templates/service.yaml > "$work_dir/service.yaml"
test "$(grep -c '^kind: Service$' "$work_dir/service.yaml")" -eq 1
grep -q 'name: api' "$work_dir/service.yaml"
grep -q 'name: proxy' "$work_dir/service.yaml"

helm template test "$chart_dir" "${master[@]}" \
  --show-only templates/deployment.yaml > "$work_dir/deployment.yaml"
grep -q 'type: RuntimeDefault' "$work_dir/deployment.yaml"

helm template test "$chart_dir" "${master[@]}" \
  --set ingress.enabled=true \
  --show-only templates/ingress.yaml > "$work_dir/ingress.yaml"
grep -q 'name: api' "$work_dir/ingress.yaml"
if grep -Eq '14322|name: proxy' "$work_dir/ingress.yaml"; then
  echo "proxy listener must not be exposed through Ingress" >&2
  exit 1
fi

helm template test "$chart_dir" "${master[@]}" \
  --set replicaCount=2 \
  --set persistence.enabled=false \
  --set image.digest=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  > "$work_dir/postgres-ha.yaml"
grep -q 'infisical/agent-vault@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' "$work_dir/postgres-ha.yaml"
if grep -Eq '^ *volume(Mount)?s: *$' "$work_dir/postgres-ha.yaml"; then
  echo "disabled persistence must not render null volume fields" >&2
  exit 1
fi

if helm template invalid "$chart_dir" "${master[@]}" --set replicaCount=2 > /dev/null 2>&1; then
  echo "SQLite with multiple replicas must fail to render" >&2
  exit 1
fi

if helm template invalid "$chart_dir" > /dev/null 2>&1; then
  echo "missing AGENT_VAULT_MASTER_PASSWORD must fail to render" >&2
  exit 1
fi

if helm template invalid "$chart_dir" --set-string secretEnv.AGENT_VAULT_MASTER_PASSWORD= > /dev/null 2>&1; then
  echo "empty AGENT_VAULT_MASTER_PASSWORD must fail to render" >&2
  exit 1
fi

if helm template invalid "$chart_dir" \
  --set existingSecret=runtime \
  --set 'existingSecretKeys.required={AGENT_VAULT_MASTER_PASSWORD}' \
  --set 'existingSecretKeys.optional={AGENT_VAULT_MASTER_PASSWORD}' > /dev/null 2>&1; then
  echo "a secret key cannot be both required and optional" >&2
  exit 1
fi
