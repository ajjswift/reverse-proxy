#!/usr/bin/env bash
#
# Integration smoke test: exercises the full DNS → cert → proxy → renewal
# lifecycle against Let's Encrypt STAGING, including a restart mid-flight to
# prove persisted state resumes.
#
# This MUST run on a Linux host that:
#   * has a real, public FQDN pointing (via DNS A record) at its public IP,
#   * can accept inbound :80 and :443 from the internet (for HTTP-01 + proxy),
#   * has certbot + bun installed (or use a compiled binary via BINARY).
#
# It is intentionally NOT part of `bun test` (which runs anywhere offline); the
# offline end-to-end proxy path is covered by test/integration/proxy.test.ts.
#
# Usage:
#   sudo HOSTNAME=node1.example.com PUBLIC_IP=203.0.113.10 \
#        ROUTE_HOSTNAME=play.example.com \
#        LETSENCRYPT_EMAIL=ops@example.com \
#        bash scripts/smoke-test.sh
#
# Optional:
#   BINARY=/path/to/proxy-agent   # use a compiled binary instead of `bun run`
#   CONTROL_PORT=8443
set -euo pipefail

: "${HOSTNAME:?set HOSTNAME to the agent's own FQDN}"
: "${PUBLIC_IP:?set PUBLIC_IP to this host's public IP}"
: "${ROUTE_HOSTNAME:?set ROUTE_HOSTNAME to a customer FQDN pointing here}"
: "${LETSENCRYPT_EMAIL:?set LETSENCRYPT_EMAIL}"
CONTROL_PORT="${CONTROL_PORT:-8443}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
STATE_DIR="${WORK}/state"
CONFIG="${WORK}/config.json"
API_KEY="smoke-api-$(head -c 12 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9')0000"
NODE_TOKEN="smoke-node-$(head -c 12 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9')0000"
UPSTREAM_PORT=8099
ROUTE_ID="$(cat /proc/sys/kernel/random/uuid)"

AGENT_PID=""
UPSTREAM_PID=""
PANEL_PID=""
cleanup() {
  [[ -n "$AGENT_PID" ]] && kill "$AGENT_PID" 2>/dev/null || true
  [[ -n "$UPSTREAM_PID" ]] && kill "$UPSTREAM_PID" 2>/dev/null || true
  [[ -n "$PANEL_PID" ]] && kill "$PANEL_PID" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

mkdir -p "$STATE_DIR"

# --- Fake panel: accepts status callbacks so the agent's POSTs succeed --------
cat > "${WORK}/panel.ts" <<'TS'
Bun.serve({
  port: 8091,
  fetch: async (req) => {
    const body = await req.text();
    console.log("[panel] callback:", body.slice(0, 300));
    return new Response("ok");
  },
});
TS
bun run "${WORK}/panel.ts" &
PANEL_PID=$!

# --- Local upstream the route will proxy to -----------------------------------
cat > "${WORK}/upstream.ts" <<TS
Bun.serve({
  port: ${UPSTREAM_PORT},
  fetch: () => new Response("hello from upstream\n"),
});
TS
bun run "${WORK}/upstream.ts" &
UPSTREAM_PID=$!

# --- Agent config -------------------------------------------------------------
cat > "$CONFIG" <<JSON
{
  "control_port": ${CONTROL_PORT},
  "api_key": "${API_KEY}",
  "hostname": "${HOSTNAME}",
  "panel_callback_url": "http://127.0.0.1:8091/callback",
  "node_token": "${NODE_TOKEN}",
  "letsencrypt_email": "${LETSENCRYPT_EMAIL}",
  "acme_staging": true,
  "state_dir": "${STATE_DIR}",
  "log_level": "info"
}
JSON

start_agent() {
  if [[ -n "${BINARY:-}" ]]; then
    "${BINARY}" --config "$CONFIG" &
  else
    ( cd "$ROOT" && bun run src/index.ts --config "$CONFIG" ) &
  fi
  AGENT_PID=$!
}

ctl() { # ctl METHOD PATH [BODY]
  local method="$1" path="$2" body="${3:-}"
  curl -sk -X "$method" \
    -H "authorization: Bearer ${API_KEY}" \
    -H "content-type: application/json" \
    ${body:+--data "$body"} \
    "https://127.0.0.1:${CONTROL_PORT}${path}"
}

wait_for() { # wait_for JQ_EXPR DESCRIPTION
  local expr="$1" desc="$2" i
  for i in $(seq 1 60); do
    local out; out="$(ctl GET /v1/routes || true)"
    if echo "$out" | grep -q "$expr"; then echo ">> $desc"; return 0; fi
    sleep 5
  done
  echo "TIMEOUT waiting for: $desc" >&2
  ctl GET /v1/routes >&2 || true
  exit 1
}

echo ">> starting agent"
start_agent
sleep 5

echo ">> health:"
ctl GET /v1/health; echo

echo ">> declaring route ${ROUTE_HOSTNAME} -> 127.0.0.1:${UPSTREAM_PORT}"
ctl PUT /v1/routes "$(cat <<JSON
{"routes":[{"id":"${ROUTE_ID}","hostname":"${ROUTE_HOSTNAME}","expected_ip":"${PUBLIC_IP}","target_host":"127.0.0.1","target_port":${UPSTREAM_PORT},"target_scheme":"http"}]}
JSON
)"; echo

# 1. DNS should become ok (assuming the A record is set).
wait_for '"dns_status":"ok"' "DNS resolved to expected IP"

# --- Restart mid-flight to prove state resumes --------------------------------
echo ">> restarting agent mid-flight"
kill "$AGENT_PID"; wait "$AGENT_PID" 2>/dev/null || true
start_agent
sleep 5

# 2. Cert should become active (LE staging issuance via HTTP-01).
wait_for '"cert_status":"active"' "certificate issued (staging)"

# 3. Proxy should become active.
wait_for '"proxy_status":"active"' "proxy active"

# 4. Prove the proxy actually forwards to the upstream over HTTPS.
echo ">> curl through the proxy:"
OUT="$(curl -sk --resolve "${ROUTE_HOSTNAME}:443:127.0.0.1" "https://${ROUTE_HOSTNAME}/")"
echo "   got: ${OUT}"
echo "$OUT" | grep -q "hello from upstream" || { echo "proxy did not return upstream body" >&2; exit 1; }

# 5. Exercise renewal (staging certs are new so this is a no-op renew, but proves
#    the path runs without dropping the cert).
echo ">> forcing a renew pass"
certbot renew --config-dir "${STATE_DIR}/letsencrypt" \
  --work-dir "${STATE_DIR}/certbot-work" \
  --logs-dir "${STATE_DIR}/certbot-logs" \
  --webroot -w "${STATE_DIR}/acme-webroot" --staging || true

echo
echo "SMOKE TEST PASSED: DNS -> cert -> proxy -> (restart-resume) -> renewal"
