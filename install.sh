#!/usr/bin/env bash
#
# proxy-agent installer. One command, re-runnable (upgrades in place).
# Targets apt-based distros (Debian/Ubuntu). Downloads a compiled binary from a
# URL you provide, verifies its SHA256, writes config, and installs + starts the
# systemd service.
#
# Required environment/flags:
#   API_KEY              Bearer token the panel presents to the control API
#   HOSTNAME             The agent's own public FQDN
#   PANEL_CALLBACK_URL   URL the agent POSTs status to
#   NODE_TOKEN           Bearer token the agent presents on callbacks
#   LETSENCRYPT_EMAIL    Email for Let's Encrypt registration
# Optional:
#   BINARY_URL           URL of the compiled proxy-agent binary. Omit to auto-
#                        resolve the right one for this machine's CPU from the
#                        latest GITHUB_REPO release.
#   GITHUB_REPO          Repo to resolve the binary from (default ajjswift/reverse-proxy)
#   BINARY_SHA256        Expected SHA256 hex of the binary  (or use CHECKSUM_URL)
#   CHECKSUM_URL         URL of a "<sha256>  <name>" file    (alternative to BINARY_SHA256)
#   CONTROL_PORT         Control API port (default 8443)
#   ACME_STAGING         "true" to use Let's Encrypt staging (default false)
#   STATE_DIR            State/cert directory (default /var/lib/proxy-agent)
#   LOG_LEVEL            debug|info|warn|error (default info)
#
# Example:
#   sudo BINARY_URL=https://.../proxy-agent-0.1.0-linux-x64 \
#        BINARY_SHA256=abc123... \
#        API_KEY=... HOSTNAME=node1.example.com \
#        PANEL_CALLBACK_URL=https://panel.example.com/api/agent/callback \
#        NODE_TOKEN=... LETSENCRYPT_EMAIL=ops@example.com \
#        bash install.sh
set -euo pipefail

BIN_PATH="/usr/local/bin/proxy-agent"
CONFIG_DIR="/etc/proxy-agent"
CONFIG_FILE="${CONFIG_DIR}/config.json"
UNIT_FILE="/etc/systemd/system/proxy-agent.service"
STATE_DIR="${STATE_DIR:-/var/lib/proxy-agent}"
CONTROL_PORT="${CONTROL_PORT:-8443}"
ACME_STAGING="${ACME_STAGING:-false}"
LOG_LEVEL="${LOG_LEVEL:-info}"

# Normalise ACME_STAGING to a JSON boolean literal.
case "$(printf '%s' "${ACME_STAGING}" | tr '[:upper:]' '[:lower:]')" in
  true|1|yes|on) ACME_STAGING="true" ;;
  *) ACME_STAGING="false" ;;
esac

die() { echo "ERROR: $*" >&2; exit 1; }
info() { echo ">> $*"; }
# Minimal JSON string escaper (backslash + double-quote). Sufficient for the
# tokens, hostnames, URLs and emails this installer handles; avoids a python/jq
# dependency.
json_escape() { printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'; }

# --- Preconditions -----------------------------------------------------------
[[ "${EUID}" -eq 0 ]] || die "must run as root (use sudo)"

command -v apt-get >/dev/null 2>&1 || die "this installer supports apt-based distros (Debian/Ubuntu) only"
if [[ -r /etc/os-release ]]; then
  . /etc/os-release
  case "${ID:-} ${ID_LIKE:-}" in
    *debian*|*ubuntu*) : ;;
    *) die "unsupported distro '${ID:-unknown}'; this installer supports Debian/Ubuntu" ;;
  esac
fi

: "${API_KEY:?API_KEY is required}"
: "${HOSTNAME:?HOSTNAME is required}"
: "${PANEL_CALLBACK_URL:?PANEL_CALLBACK_URL is required}"
: "${NODE_TOKEN:?NODE_TOKEN is required}"
: "${LETSENCRYPT_EMAIL:?LETSENCRYPT_EMAIL is required}"

# --- Dependencies ------------------------------------------------------------
info "installing dependencies (certbot, curl, ca-certificates)"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq certbot curl ca-certificates >/dev/null

# --- Resolve binary + checksum from the release ------------------------------
# The compiled binaries and their .sha256 files ship in the same GitHub release
# as this installer, so we pick the one matching this machine's architecture
# automatically. Override any of this by passing BINARY_URL (and optionally
# BINARY_SHA256 or CHECKSUM_URL), or point at a different repo with GITHUB_REPO.
GITHUB_REPO="${GITHUB_REPO:-ajjswift/reverse-proxy}"
if [[ -z "${BINARY_URL:-}" ]]; then
  case "$(uname -m)" in
    x86_64|amd64) ARCH="x64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *) die "unsupported CPU architecture '$(uname -m)'; pass BINARY_URL explicitly" ;;
  esac
  info "resolving latest proxy-agent binary for linux-${ARCH} from ${GITHUB_REPO}"
  RELEASE_JSON="$(curl -fsSL -H 'Accept: application/vnd.github+json' \
    "https://api.github.com/repos/${GITHUB_REPO}/releases/latest")" \
    || die "could not query the GitHub releases API for ${GITHUB_REPO}"
  # Each browser_download_url is on its own line; the binary asset ends in the
  # arch, its checksum in "<arch>.sha256", so an end-anchored match separates them.
  BINARY_URL="$(printf '%s' "${RELEASE_JSON}" \
    | grep -o 'https://github.com/[^"]*' | grep "linux-${ARCH}$" | head -n1)"
  [[ -n "${BINARY_URL}" ]] || die "no linux-${ARCH} binary found in the latest ${GITHUB_REPO} release"
  if [[ -z "${BINARY_SHA256:-}" && -z "${CHECKSUM_URL:-}" ]]; then
    CHECKSUM_URL="${BINARY_URL}.sha256"
  fi
  info "using ${BINARY_URL}"
fi

if [[ -z "${BINARY_SHA256:-}" && -z "${CHECKSUM_URL:-}" ]]; then
  die "provide BINARY_SHA256 or CHECKSUM_URL to verify the download"
fi


# --- Directories -------------------------------------------------------------
info "creating directories"
install -d -m 0750 "${STATE_DIR}"
install -d -m 0755 "${CONFIG_DIR}"

# --- Download + verify binary ------------------------------------------------
TMP="$(mktemp -d)"
trap 'rm -rf "${TMP}"' EXIT
info "downloading binary from ${BINARY_URL}"
curl -fsSL "${BINARY_URL}" -o "${TMP}/proxy-agent"

if [[ -n "${CHECKSUM_URL:-}" && -z "${BINARY_SHA256:-}" ]]; then
  info "downloading checksum from ${CHECKSUM_URL}"
  curl -fsSL "${CHECKSUM_URL}" -o "${TMP}/checksum.txt"
  BINARY_SHA256="$(awk '{print $1}' "${TMP}/checksum.txt" | head -n1)"
fi

info "verifying checksum"
ACTUAL="$(sha256sum "${TMP}/proxy-agent" | awk '{print $1}')"
if [[ "${ACTUAL}" != "${BINARY_SHA256}" ]]; then
  die "checksum mismatch: expected ${BINARY_SHA256}, got ${ACTUAL}"
fi
info "checksum OK (${ACTUAL})"

# --- Install binary (atomic replace so a running service isn't corrupted) ----
info "installing binary to ${BIN_PATH}"
install -m 0755 "${TMP}/proxy-agent" "${BIN_PATH}.new"
mv -f "${BIN_PATH}.new" "${BIN_PATH}"

# --- Write config ------------------------------------------------------------
# Written 0640 root:service-user so the agent can read it but it is not world-
# readable (it contains secrets).
info "writing ${CONFIG_FILE}"
umask 077
cat > "${CONFIG_FILE}.new" <<JSON
{
  "control_port": ${CONTROL_PORT},
  "api_key": "$(json_escape "${API_KEY}")",
  "hostname": "$(json_escape "${HOSTNAME}")",
  "panel_callback_url": "$(json_escape "${PANEL_CALLBACK_URL}")",
  "node_token": "$(json_escape "${NODE_TOKEN}")",
  "letsencrypt_email": "$(json_escape "${LETSENCRYPT_EMAIL}")",
  "acme_staging": ${ACME_STAGING},
  "state_dir": "$(json_escape "${STATE_DIR}")",
  "log_level": "${LOG_LEVEL}"
}
JSON
mv -f "${CONFIG_FILE}.new" "${CONFIG_FILE}"
chown root:root "${CONFIG_FILE}"
chmod 0600 "${CONFIG_FILE}"

# --- systemd unit ------------------------------------------------------------
info "installing systemd unit"
cat > "${UNIT_FILE}" <<UNIT
[Unit]
Description=Managed reverse-proxy agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
ExecStart=${BIN_PATH} --config ${CONFIG_FILE}
Restart=always
RestartSec=3
StartLimitIntervalSec=60
StartLimitBurst=5
TimeoutStopSec=45
KillSignal=SIGTERM
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=${STATE_DIR}
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
ProtectClock=true
ProtectHostname=true
RestrictNamespaces=true
RestrictRealtime=true
LockPersonality=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM

[Install]
WantedBy=multi-user.target
UNIT

# --- Enable + (re)start ------------------------------------------------------
info "enabling and starting service"
systemctl daemon-reload
systemctl enable proxy-agent >/dev/null 2>&1 || true
systemctl restart proxy-agent

# --- Verify ------------------------------------------------------------------
sleep 2
if systemctl is-active --quiet proxy-agent; then
  info "service is active"
else
  echo "----- recent logs -----"
  journalctl -u proxy-agent --no-pager -n 40 || true
  die "service failed to start; see logs above"
fi

cat <<DONE

proxy-agent installed and running.

  Binary:  ${BIN_PATH}
  Config:  ${CONFIG_FILE}
  State:   ${STATE_DIR}
  Version: $(${BIN_PATH} --version)

Open these inbound ports in your firewall / security group:
  - 80/tcp    (Let's Encrypt HTTP-01 challenge + HTTPS redirect)
  - 443/tcp   (public HTTPS reverse proxy)
  - ${CONTROL_PORT}/tcp  (control API for the panel)

Manage the service:
  systemctl status proxy-agent
  journalctl -u proxy-agent -f
DONE
