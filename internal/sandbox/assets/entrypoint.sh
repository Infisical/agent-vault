#!/bin/bash
# Runs as root (from tini/--init), sets up egress, drops to unprivileged
# claude user via gosu. gosu (not sudo) keeps signals + TTY clean.
set -euo pipefail

if [ "${AGENT_VAULT_NO_FIREWALL:-0}" = "1" ]; then
  echo "agent-vault: WARNING --no-firewall active, egress UNRESTRICTED" >&2
else
  /usr/local/sbin/init-firewall.sh
fi

# Strip the internal plumbing vars so claude's env is clean.
unset VAULT_HTTP_PORT VAULT_MITM_PORT AGENT_VAULT_NO_FIREWALL

exec gosu claude "$@"
