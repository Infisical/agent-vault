#!/bin/bash
# Runs as root (from tini/--init), sets up egress, drops to unprivileged
# claude user via gosu. gosu (not sudo) keeps signals + TTY clean.
set -euo pipefail

if [ "${AGENT_VAULT_NO_FIREWALL:-0}" = "1" ]; then
  echo "agent-vault: WARNING --no-firewall active, egress UNRESTRICTED" >&2
else
  /usr/local/sbin/init-firewall.sh
fi

# Install the MITM CA into the container's system trust store so TLS
# clients that ignore SSL_CERT_FILE / NODE_EXTRA_CA_CERTS / etc. (anything
# using the system bundle) still trust the proxy. Egress is already
# iptables-locked to the MITM port, so globally trusting this CA inside
# the container doesn't widen the attack surface.
cp /etc/agent-vault/ca.pem /usr/local/share/ca-certificates/agent-vault-mitm.crt
update-ca-certificates >/dev/null

# When --share-agent-dir bind-mounts a host directory in at /home/claude,
# the baked-in claude user's UID won't match the host owner. Remap so
# writes through the bind mount land as the invoking user on the host.
# Firewall setup already ran as root above; gosu below drops to the
# (now-remapped) claude uid/gid.
if [ -n "${HOST_UID:-}" ] && [ -n "${HOST_GID:-}" ]; then
  groupmod -g "$HOST_GID" claude
  usermod  -u "$HOST_UID" claude
  chown "$HOST_UID:$HOST_GID" /home/claude
fi

# Strip the internal plumbing vars so claude's env is clean.
unset VAULT_HTTP_PORT VAULT_MITM_PORT AGENT_VAULT_NO_FIREWALL HOST_UID HOST_GID

exec gosu claude "$@"
