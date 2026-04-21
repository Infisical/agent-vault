#!/bin/bash
# Default-deny egress. The one hostname we need (host.docker.internal)
# comes from /etc/hosts via `docker run --add-host`, so there's no DNS
# rule — closing the DNS-exfil channel.
set -euo pipefail

[ -n "${VAULT_HTTP_PORT:-}" ] || { echo "init-firewall: VAULT_HTTP_PORT unset" >&2; exit 1; }
[ -n "${VAULT_MITM_PORT:-}" ] || { echo "init-firewall: VAULT_MITM_PORT unset" >&2; exit 1; }

GW_IP=$(getent hosts host.docker.internal | awk '{print $1}' | head -1)
if [ -z "$GW_IP" ]; then
  echo "init-firewall: host.docker.internal not resolvable (missing --add-host?)" >&2
  exit 1
fi
if ! echo "$GW_IP" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
  echo "init-firewall: gateway $GW_IP is not a plain IPv4 literal" >&2
  exit 1
fi

# Flush and default-deny OUTPUT. INPUT stays default-ACCEPT; only the
# reply traffic to our allowed outbound conns matters, and it's caught
# by the conntrack rule.
iptables -F OUTPUT
iptables -P OUTPUT DROP
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -d "$GW_IP" -p tcp --dport "$VAULT_HTTP_PORT" -j ACCEPT
iptables -A OUTPUT -d "$GW_IP" -p tcp --dport "$VAULT_MITM_PORT" -j ACCEPT

{
  echo "agent-vault: egress locked to $GW_IP:{$VAULT_HTTP_PORT,$VAULT_MITM_PORT}"
  iptables -S OUTPUT
} >&2
