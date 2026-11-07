#!/usr/bin/env bash
# End-to-end demo of instance-level upstream (egress) proxies.
#
# Everything runs on loopback — no internet access, no third-party services,
# and no changes to your machine beyond a temporary directory. The demo proves:
#
#   1. With no profile configured, brokered requests dial their target directly.
#   2. An opt-in profile routes only the matched service/path; other paths stay direct.
#   3. An instance default profile routes otherwise-unmatched requests through the proxy.
#   4. New services dial direct unless opted into the default or a named profile.
#   5. no_proxy lets matching targets bypass that proxy again.
#   6. fail_closed refuses the request when the proxy is unreachable.
#   7. fail_open lets the same request through (directly) once flipped.
#   8. Services reference profiles by name, and a referenced profile cannot be
#      deleted out from under them.
#
# Usage: ./run.sh
set -euo pipefail

DEMO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$DEMO_DIR/../.." && pwd)"

API_PORT=14331
MITM_PORT=14332
TARGET_PORT=18099
PROXY_PORT=13128

OWNER_EMAIL="owner@example.com"
OWNER_PASSWORD="demo-password-123"
PROFILE_NAME="corp-egress"
TARGET_HOST="127.0.0.1:${TARGET_PORT}"
PROXY_HOST="127.0.0.1:${PROXY_PORT}"

umask 077
WORK_DIR="$(mktemp -d)"
LOG_DIR="$WORK_DIR/logs"
mkdir -p "$LOG_DIR"
PROXY_LOG="$LOG_DIR/egress-proxy.log"

TARGET_PID=""
TARGET_V6_PID=""
PROXY_PID=""
BROKER_PID=""

step() { printf '\n\033[1m%s\033[0m\n' "$1"; }
info() { printf '  %s\n' "$1"; }
ok() { printf '  \033[32m✓\033[0m %s\n' "$1"; }
fail() {
  printf '  \033[31m✗\033[0m %s\n' "$1"
  exit 1
}
cleanup() {
  for pid in "$TARGET_PID" "$TARGET_V6_PID" "$PROXY_PID" "$BROKER_PID"; do
    if [ -n "$pid" ]; then kill "$pid" 2>/dev/null || true; fi
  done
  for pid in "$TARGET_PID" "$TARGET_V6_PID" "$PROXY_PID" "$BROKER_PID"; do
    if [ -n "$pid" ]; then wait "$pid" 2>/dev/null || true; fi
  done
  rm -f -- "$WORK_DIR/api-curl.conf" "$WORK_DIR/proxy-curl.conf" \
    "$WORK_DIR/api-body.json" "$WORK_DIR/api-response.json"
}
trap cleanup EXIT

json_field() { python3 -c 'import json,sys; print(json.load(sys.stdin)[sys.argv[1]])' "$1"; }

api() { # api <method> <path> [json-body]; response on stdout, status in API_STATUS
  local method="$1" path="$2" body="${3:-}" status
  local config="$WORK_DIR/api-curl.conf" payload="$WORK_DIR/api-body.json"
  printf 'header = "Authorization: Bearer %s"\nheader = "Content-Type: application/json"\n' "${OWNER_TOKEN:-}" > "$config"
  local args=(-sS --noproxy "*" --config "$config" -X "$method" -o "$WORK_DIR/api-response.json" -w '%{http_code}')
  if [ -n "$body" ]; then
    printf '%s' "$body" > "$payload"
    args+=(--data-binary "@$payload")
  fi
  status="$(curl "${args[@]}" "http://127.0.0.1:${API_PORT}${path}")"
  API_STATUS="$status"
  cat "$WORK_DIR/api-response.json"
}

api_status() {
  api "$@" > /dev/null
  printf '%s' "$API_STATUS"
}

proxy_hit() {
  local path="$1" host="${2:-$TARGET_HOST}"
  grep -Fc "http://${host}${path} " "$PROXY_LOG" 2>/dev/null || true
}
target_hit() { grep -Fc "GET $1 " "$LOG_DIR/target.log" 2>/dev/null || true; }

wait_for() { # wait_for <curl-expr...>
  for _ in $(seq 1 60); do
    "$@" >/dev/null 2>&1 && return 0 || sleep 0.25
  done
  return 1
}

# request_status performs one brokered request and prints its HTTP status.
request_status() {
  local path="$1" host="${2:-$TARGET_HOST}" config="$WORK_DIR/proxy-curl.conf"
  printf 'proxy-user = "%s:default"\n' "$AGENT_TOKEN" > "$config"
  curl -sS -o "$WORK_DIR/target-response" -w '%{http_code}' \
    --config "$config" --noproxy "" -x "http://127.0.0.1:${MITM_PORT}" \
    --max-time 15 "http://${host}${path}"
}

python3 - "$API_PORT" "$MITM_PORT" "$TARGET_PORT" "$PROXY_PORT" <<'PY' || fail "one of the demo ports is occupied"
import socket, sys
sockets = []
try:
    for port in map(int, sys.argv[1:]):
        sock = socket.socket()
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", port))
        sockets.append(sock)
    # localhost.localdomain may resolve to ::1 before 127.0.0.1.
    sock = socket.socket(socket.AF_INET6)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    sock.bind(("::1", int(sys.argv[3])))
    sockets.append(sock)
finally:
    for sock in sockets:
        sock.close()
PY

# --- 0. Build ------------------------------------------------------------

step "0. Building the broker"
if [ -n "${AGENT_VAULT_BIN:-}" ]; then
  BIN="$AGENT_VAULT_BIN"
elif command -v agent-vault >/dev/null 2>&1; then
  BIN="$(command -v agent-vault)"
else
  BIN="$WORK_DIR/agent-vault"
  (cd "$REPO_ROOT" && go build -o "$BIN" .)
fi
ok "using broker binary ($BIN)"

# --- 1. Fake upstream target --------------------------------------------

step "1. Starting a stand-in upstream target on ${TARGET_HOST}"
echo '<html><body>hello from the demo target</body></html>' > "$WORK_DIR/index.html"
for path in baseline opt-in opt-out unmatched via-proxy default-direct default-opt-in default-named default-inherit bypass fail-closed fail-open; do
  cp "$WORK_DIR/index.html" "$WORK_DIR/$path"
done
(cd "$WORK_DIR" && exec python3 -m http.server "$TARGET_PORT" --bind 127.0.0.1) >"$LOG_DIR/target.log" 2>&1 &
TARGET_PID=$!
(cd "$WORK_DIR" && exec python3 -m http.server "$TARGET_PORT" --bind ::1) >>"$LOG_DIR/target.log" 2>&1 &
TARGET_V6_PID=$!
wait_for curl -sf --noproxy "*" "http://${TARGET_HOST}/" || fail "target did not come up"
wait_for curl -g -sf --noproxy "*" "http://[::1]:${TARGET_PORT}/" || fail "IPv6 target did not come up"
ok "target serves GET / (200)"

# --- 2. Stand-in egress proxy -------------------------------------------

step "2. Starting the logging egress proxy on ${PROXY_HOST}"
python3 "$DEMO_DIR/egress_proxy.py" "$PROXY_PORT" "$PROXY_LOG" >"$LOG_DIR/egress-proxy.stderr" 2>&1 &
PROXY_PID=$!
wait_for curl -sf --noproxy "" -x "http://${PROXY_HOST}" "http://${TARGET_HOST}/" || fail "egress proxy did not come up"
ok "proxy forwards requests and logs them to $(basename "$PROXY_LOG")"

# --- 3. Broker ----------------------------------------------------------

step "3. Starting the broker (ports ${API_PORT} / ${MITM_PORT})"
# Dev mode permits the loopback hostname used by the path-scoped services.
HOME="$WORK_DIR" \
AGENT_VAULT_ALLOW_PRIVATE_RANGES=true \
AGENT_VAULT_NO_TELEMETRY=1 \
AGENT_VAULT_LOG_LEVEL=debug \
AGENT_VAULT_DEV_MODE=true \
  "$BIN" server --host 127.0.0.1 --port "$API_PORT" --mitm-port "$MITM_PORT" \
  --password-stdin <<< "" >"$LOG_DIR/broker.log" 2>&1 &
BROKER_PID=$!
wait_for curl -sf --noproxy "*" "http://127.0.0.1:${API_PORT}/v1/status" || fail "broker did not come up"
ok "broker ready (isolated HOME=$WORK_DIR)"

# --- 4. Owner + agent session -------------------------------------------

step "4. Registering the owner and minting an agent token"
OWNER_TOKEN="$(api POST /v1/auth/register \
  "{\"email\":\"$OWNER_EMAIL\",\"password\":\"$OWNER_PASSWORD\"}" | json_field token)"
[ -n "$OWNER_TOKEN" ] || fail "owner registration returned no token"
ok "owner registered (first user becomes instance owner)"

AGENT_TOKEN="$(api POST /v1/sessions \
  "{\"vault\":\"default\",\"vault_role\":\"proxy\",\"ttl_seconds\":3600,\"label\":\"demo-agent\"}" | json_field token)"
[ -n "$AGENT_TOKEN" ] || fail "session minting returned no token"
ok "vault-scoped agent token minted"

# --- 5. Baseline: no profile --------------------------------------------

step "5. Baseline: with no profile, requests dial the target directly"
STATUS="$(request_status /baseline)"
[ "$STATUS" = "200" ] || fail "expected 200, got $STATUS"
[ "$(proxy_hit /baseline)" = "0" ] || fail "baseline request unexpectedly transited proxy"
[ "$(target_hit /baseline)" = "1" ] || fail "baseline did not reach target exactly once"
grep -Fq 'hello from the demo target' "$WORK_DIR/target-response" || fail "wrong baseline body"
ok "brokered request reached target directly (200)"

# --- 5a. Opt-in routing for selected paths -------------------------------

step "5a. Non-default profile: only a selected endpoint uses the proxy"
[ "$(api_status POST /v1/admin/upstream-proxies \
  "{\"name\":\"$PROFILE_NAME\",\"scheme\":\"http\",\"host\":\"$PROXY_HOST\",\"on_failure\":\"fail_closed\",\"is_default\":false,\"enabled\":true}")" = "201" ] || fail "opt-in profile creation failed"
SERVICE_HOST="localhost.localdomain:${TARGET_PORT}"
[ "$(api_status PUT /v1/vaults/default/services \
  "{\"services\":[{\"name\":\"proxied-endpoint\",\"host\":\"$SERVICE_HOST/opt-in\",\"auth\":{\"type\":\"passthrough\"},\"upstream_proxy\":\"$PROFILE_NAME\"},{\"name\":\"direct-endpoint\",\"host\":\"$SERVICE_HOST/opt-out\",\"auth\":{\"type\":\"passthrough\"}}]}")" = "200" ] || fail "path-scoped services were not saved: $(json_field error < "$WORK_DIR/api-response.json")"

for path in opt-in opt-out unmatched; do
  STATUS="$(request_status "/$path" "$SERVICE_HOST")"
  [ "$STATUS" = "200" ] || fail "$path returned $STATUS instead of 200"
  [ "$(target_hit "/$path")" = "1" ] || fail "$path did not reach target exactly once"
  grep -Fq 'hello from the demo target' "$WORK_DIR/target-response" || fail "$path returned the wrong body"
done
[ "$(proxy_hit /opt-in "$SERVICE_HOST")" = "1" ] || fail "selected endpoint did not transit proxy"
[ "$(proxy_hit /opt-out "$SERVICE_HOST")" = "0" ] || fail "unselected service transited proxy"
[ "$(proxy_hit /unmatched "$SERVICE_HOST")" = "0" ] || fail "unmatched endpoint transited proxy"
ok "selected path proxied; unselected service and unmatched path direct"

[ "$(api_status PUT /v1/vaults/default/services '{"services":[]}')" = "200" ] || fail "demo services could not be cleared"

# --- 6. Instance default profile ----------------------------------------

step "6. Promoting '${PROFILE_NAME}' to the instance default"
[ "$(api_status PATCH "/v1/admin/upstream-proxies/$PROFILE_NAME" '{"is_default":true}')" = "200" ] || fail "profile promotion failed"
ok "default fail_closed profile enabled"

STATUS="$(request_status /via-proxy)"
[ "$STATUS" = "200" ] || fail "expected 200, got $STATUS"
[ "$(proxy_hit /via-proxy)" = "1" ] || fail "request did not transit proxy"
[ "$(target_hit /via-proxy)" = "1" ] || fail "request did not reach target exactly once"
grep -Fq 'hello from the demo target' "$WORK_DIR/target-response" || fail "wrong proxy response body"
ok "request transited proxy and reached target (200)"

# --- 6a. New services default direct; proxy routing is explicit ------------

step "6a. New service direct by default with the instance default enabled"
[ "$(api_status PUT /v1/vaults/default/services \
  "{\"services\":[{\"name\":\"direct-endpoint\",\"host\":\"$SERVICE_HOST/default-direct\",\"auth\":{\"type\":\"passthrough\"}},{\"name\":\"opt-in-endpoint\",\"host\":\"$SERVICE_HOST/default-opt-in\",\"auth\":{\"type\":\"passthrough\"},\"use_upstream_proxy\":true},{\"name\":\"proxied-endpoint\",\"host\":\"$SERVICE_HOST/default-named\",\"auth\":{\"type\":\"passthrough\"},\"upstream_proxy\":\"$PROFILE_NAME\"}]}")" = "200" ] || fail "service egress selection was not saved: $(json_field error < "$WORK_DIR/api-response.json")"

for path in default-direct default-opt-in default-named default-inherit; do
  STATUS="$(request_status "/$path" "$SERVICE_HOST")"
  [ "$STATUS" = "200" ] || fail "$path returned $STATUS instead of 200"
  [ "$(target_hit "/$path")" = "1" ] || fail "$path did not reach target exactly once"
done
[ "$(proxy_hit /default-direct "$SERVICE_HOST")" = "0" ] || fail "new direct service transited instance default proxy"
[ "$(proxy_hit /default-opt-in "$SERVICE_HOST")" = "1" ] || fail "service opted into instance default did not transit proxy"
[ "$(proxy_hit /default-named "$SERVICE_HOST")" = "1" ] || fail "named service did not transit proxy"
[ "$(proxy_hit /default-inherit "$SERVICE_HOST")" = "1" ] || fail "unmatched endpoint did not use instance default"
ok "new service direct; default opt-in, named, and unmatched paths proxied"

[ "$(api_status PUT /v1/vaults/default/services \
  "{\"services\":[{\"name\":\"direct-endpoint\",\"host\":\"$SERVICE_HOST/default-direct\",\"auth\":{\"type\":\"passthrough\"},\"bypass_upstream_proxy\":true,\"upstream_proxy\":\"$PROFILE_NAME\"}]}")" = "400" ] || fail "conflicting direct and profile settings were not rejected"
STATUS="$(request_status /default-direct "$SERVICE_HOST")"
[ "$STATUS" = "200" ] || fail "rejected update changed direct service (status $STATUS)"
[ "$(target_hit /default-direct)" = "2" ] || fail "rejected update prevented direct target access"
[ "$(proxy_hit /default-direct "$SERVICE_HOST")" = "0" ] || fail "rejected update silently changed direct routing"
ok "conflicting settings rejected (400), existing direct route unchanged"

[ "$(api_status PUT /v1/vaults/default/services '{"services":[]}')" = "200" ] || fail "demo services could not be cleared"

# --- 7. no_proxy bypass -------------------------------------------------

step "7. no_proxy lets a target bypass the profile"
api PATCH "/v1/admin/upstream-proxies/$PROFILE_NAME" "{\"no_proxy\":\"127.0.0.1\"}" >/dev/null
STATUS="$(request_status /bypass)"
[ "$STATUS" = "200" ] || fail "expected 200, got $STATUS"
[ "$(proxy_hit /bypass)" = "0" ] || fail "no_proxy request reached proxy"
[ "$(target_hit /bypass)" = "1" ] || fail "bypass request did not reach target"
ok "request reached target without proxy"
api PATCH "/v1/admin/upstream-proxies/$PROFILE_NAME" '{"no_proxy":""}' >/dev/null

# --- 8. fail_closed -----------------------------------------------------

step "8. fail_closed when the proxy is unreachable"
kill "$PROXY_PID"
wait "$PROXY_PID" 2>/dev/null || true
PROXY_PID=""
STATUS="$(request_status /fail-closed)"
[ "$STATUS" = "502" ] || fail "expected 502 with proxy down, got $STATUS"
[ "$(target_hit /fail-closed)" = "0" ] || fail "fail_closed leaked to target"
ok "proxy down: 502, target untouched"

# --- 9. fail_open -------------------------------------------------------

step "9. fail_open lets the same request through"
api PATCH "/v1/admin/upstream-proxies/$PROFILE_NAME" '{"on_failure":"fail_open"}' >/dev/null
STATUS="$(request_status /fail-open)"
[ "$STATUS" = "200" ] || fail "expected 200 under fail_open, got $STATUS"
[ "$(target_hit /fail-open)" = "1" ] || fail "fail_open did not reach target exactly once"
grep -Fq 'hello from the demo target' "$WORK_DIR/target-response" || fail "wrong fail_open response body"
ok "request reached target directly after proxy refused connection"
api PATCH "/v1/admin/upstream-proxies/$PROFILE_NAME" '{"on_failure":"fail_closed"}' >/dev/null

# --- 10. Per-service references -----------------------------------------

step "10. Services reference profiles by name"
SERVICE_HOST="example.test"

# A missing profile reference must be rejected without persistence.
[ "$(api_status PUT /v1/vaults/default/services \
  "{\"services\":[{\"name\":\"demo-api\",\"host\":\"$SERVICE_HOST\",\"auth\":{\"type\":\"passthrough\"},\"upstream_proxy\":\"does-not-exist\"}]}")" = "400" ] || fail "unknown profile reference was not rejected with 400"
ok "unknown profile reference rejected (400)"

api PUT /v1/vaults/default/services \
  "{\"services\":[{\"name\":\"demo-api\",\"host\":\"$SERVICE_HOST\",\"auth\":{\"type\":\"passthrough\"},\"upstream_proxy\":\"$PROFILE_NAME\"}]}" \
  >/dev/null
ok "service references profile"

[ "$(api_status DELETE "/v1/admin/upstream-proxies/$PROFILE_NAME")" = "409" ] || fail "referenced profile delete did not return 409"
ok "referenced profile delete refused (409)"

api PUT /v1/vaults/default/services \
  "{\"services\":[{\"name\":\"demo-api\",\"host\":\"$SERVICE_HOST\",\"auth\":{\"type\":\"passthrough\"},\"bypass_upstream_proxy\":true}]}" \
  >/dev/null
[ "$(api_status DELETE "/v1/admin/upstream-proxies/$PROFILE_NAME")" = "200" ] || fail "unreferenced profile deletion failed"
ok "unreferenced profile deleted"

# --- Summary ------------------------------------------------------------

step "Demo complete"
cat <<EOF
  profile ......... ${PROFILE_NAME} (${PROXY_HOST})
  target .......... http://${TARGET_HOST}/  (python3 -m http.server)
  egress proxy .... ${PROXY_HOST} (logging proxy, $(basename "$DEMO_DIR")/egress_proxy.py)
  broker .......... api :${API_PORT} / mitm :${MITM_PORT}
  evidence ........ ${PROXY_LOG}

  Distinct URLs identify routes in target and proxy logs; a rejected update
  rechecks the same direct URL without changing its route.

  New services dial directly by default. Select a named profile or opt into
  the instance default only for services that need proxy routing; unmatched
  and broker control-plane traffic still use the instance default.
  In the UI: Manage Instance -> Upstream Proxies, then select the route in
  the service editor's "Upstream Proxy" dropdown.
EOF

info "logs are in $LOG_DIR"
