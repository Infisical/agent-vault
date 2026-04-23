#!/bin/bash
# Default-deny egress. The one hostname we need (host.docker.internal)
# comes from /etc/hosts via `docker run --add-host`, so there's no DNS
# rule — closing the DNS-exfil channel.
set -euo pipefail

[ -n "${VAULT_HTTP_PORT:-}" ] || { echo "init-firewall: VAULT_HTTP_PORT unset" >&2; exit 1; }
[ -n "${VAULT_MITM_PORT:-}" ] || { echo "init-firewall: VAULT_MITM_PORT unset" >&2; exit 1; }

# getent ahostsv4 returns only A records — using plain `hosts` picks up
# the AAAA first on Docker Desktop, but our iptables rules are IPv4.
GW_IP=$(getent ahostsv4 host.docker.internal | awk 'NR==1 {print $1}')
if [ -z "$GW_IP" ]; then
  echo "init-firewall: host.docker.internal has no IPv4 entry (missing --add-host?)" >&2
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

# IPv6 lockdown. We resolved host.docker.internal via ahostsv4, so the
# forwarder path is IPv4 only — there's no destination we need to ACCEPT
# over v6. If the Docker daemon has IPv6 enabled, this closes the
# parallel egress channel that iptables rules alone would miss.
ip6tables -F OUTPUT
ip6tables -P OUTPUT DROP
ip6tables -A OUTPUT -o lo -j ACCEPT
ip6tables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

{
  echo "agent-vault: egress locked to $GW_IP:{$VAULT_HTTP_PORT,$VAULT_MITM_PORT} (v4); all v6 dropped"
  iptables -S OUTPUT
  ip6tables -S OUTPUT
} >&2
