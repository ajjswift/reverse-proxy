#!/usr/bin/env bash
# Remove the proxy-agent service. Keeps state/certs by default; pass PURGE=true
# to also delete /var/lib/proxy-agent (certs, keys, state) and the config.
set -euo pipefail

STATE_DIR="${STATE_DIR:-/var/lib/proxy-agent}"
SERVICE_USER="${SERVICE_USER:-proxy-agent}"
PURGE="${PURGE:-false}"

[[ "${EUID}" -eq 0 ]] || { echo "run as root" >&2; exit 1; }

echo ">> stopping service"
systemctl stop proxy-agent 2>/dev/null || true
systemctl disable proxy-agent 2>/dev/null || true

rm -f /etc/systemd/system/proxy-agent.service
systemctl daemon-reload
rm -f /usr/local/bin/proxy-agent

if [[ "${PURGE}" == "true" ]]; then
  echo ">> purging state and config"
  rm -rf "${STATE_DIR}" /etc/proxy-agent
  if id -u "${SERVICE_USER}" >/dev/null 2>&1; then
    userdel "${SERVICE_USER}" 2>/dev/null || true
  fi
else
  echo ">> keeping ${STATE_DIR} and /etc/proxy-agent (set PURGE=true to remove)"
fi

echo ">> done"
