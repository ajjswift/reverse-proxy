# proxy-agent

A standalone, panel-controlled **reverse-proxy agent** for Linux game/app host
nodes. It is a single TypeScript program written for [Bun](https://bun.sh) and
compiled to a self-contained executable with `bun build --compile`. It runs as a
`systemd` service, obtains Let's Encrypt certificates via `certbot`, terminates
TLS, and reverse-proxies public HTTPS traffic for customer hostnames to local
ports — while continuously reporting DNS/cert/proxy status back to a central
panel.

The agent knows nothing about the panel's codebase. It only speaks the HTTP
contract below.

---

## Contents

- [Architecture](#architecture)
- [Route lifecycle](#route-lifecycle)
- [Configuration reference](#configuration-reference)
- [HTTP contract](#http-contract)
  - [Control API (panel → agent)](#a-control-api-panel--agent)
  - [Status callback (agent → panel)](#b-status-callback-agent--panel)
- [Install / upgrade / uninstall](#install--upgrade--uninstall)
- [Firewall requirements](#firewall-requirements)
- [Security model](#security-model)
- [Development](#development)
- [Testing](#testing)
- [Building binaries](#building-binaries)
- [Troubleshooting](#troubleshooting)

---

## Architecture

Three public/local listeners plus a set of timers, all driven by a single
authoritative **route manager**:

```
                          ┌────────────────────────── proxy-agent ──────────────────────────┐
   panel ──PUT /v1/routes─┤  Control API  (:control_port, TLS, bearer api_key)               │
        ◀─status callback─┤  Callback sender (POST panel_callback_url, bearer node_token)    │
                          │                                                                  │
 internet ──:80 ──────────┤  Challenge/redirect  (ACME HTTP-01 files + 301 → HTTPS)          │
 internet ──:443 ─────────┤  Reverse proxy  (SNI TLS termination → target_host:target_port)  │
                          │                                                                  │
                          │  Route manager ── DNS check ─→ certbot (issue/renew) ─→ proxy    │
                          │       │                                                          │
                          │  state_dir/  (persisted route state + certbot config/live certs) │
                          └──────────────────────────────────────────────────────────────────┘
```

- **Route manager** (`src/manager.ts`) is the single source of truth for status.
  A periodic *tick* advances each route's DNS → cert → proxy state machine.
- **certbot** is driven as a child process (`certonly --webroot` / `renew`),
  with all cert operations **serialized** through an internal queue. certbot's
  config/work/logs/live dirs all live inside `state_dir` so the whole agent is
  self-contained and the filesystem can be locked down by systemd.
- **State** is persisted atomically to `state_dir/state.json`; on restart the
  agent resumes without re-issuing certificates.
- The agent obtains a Let's Encrypt cert for **its own** control-API hostname on
  first boot. Until that succeeds it serves the control API with a self-signed
  bootstrap cert and reports `control_cert_ready: false`.

Source map:

| File | Responsibility |
|------|----------------|
| `src/index.ts` | Entry point, flags, boot, timers, graceful shutdown |
| `src/config.ts` | Config load + strict validation (fail fast) |
| `src/manager.ts` | Route state machine, reconciliation, persistence |
| `src/reconciler.ts` | Pure add/update/remove diff + route validation |
| `src/dns.ts` | DNS resolution + pending/ok/mismatch decision |
| `src/certbot.ts` | Serialized certbot child-process integration |
| `src/certstore.ts` | Loaded certs + SNI selection + expiry parsing |
| `src/proxy.ts` | :443 SNI TLS termination + HTTP/WS reverse proxy |
| `src/challenge-server.ts` | :80 ACME responder + HTTPS redirect |
| `src/control-api.ts` | Control API (`/v1`, bearer auth) |
| `src/callback.ts` | Status callbacks with backoff |
| `src/ssrf.ts` | Target/hostname validation + link-local guard |
| `src/logger.ts` | Structured logging with secret redaction |

---

## Route lifecycle

For each route in the desired set the agent runs this state machine and reports
progress continuously:

1. **DNS check** — periodically resolve `hostname` and compare to `expected_ip`.
   Reports `dns_status: pending | ok | mismatch` with `resolved_ip`.
2. **Certificate** — once DNS is `ok`, obtain an LE cert via certbot HTTP-01
   (`certonly --webroot`, challenge files served on :80). Reports
   `cert_status: pending | issuing | active | failed | renewing` with
   `cert_expires_at`. Failures back off exponentially (1 min → 30 min).
3. **Proxy** — once the cert is `active`, terminate TLS for that hostname on
   :443 (SNI-selected cert) and reverse-proxy to `target_host:target_port` over
   `target_scheme`. Reports `proxy_status: pending | active | failed`.
4. **Renewal** — `certbot renew` runs on a 12-hour timer; renewed certs are
   hot-reloaded into the TLS listener **without dropping live connections**.
5. **Removal** — when a route disappears from the desired set the agent stops
   proxying it and, if `cleanup_certs_on_removal` is set, deletes its cert.

---

## Configuration reference

Config is read from a single JSON file (default `/etc/proxy-agent/config.json`,
override with `--config` or `$PROXY_AGENT_CONFIG`). Any field can be overridden
by an environment variable of the same name (upper-cased), optionally prefixed
`PROXY_AGENT_`. Validated on boot — the process exits `78` with a clear message
listing **every** problem if invalid.

| Key | Type | Default | Notes |
|-----|------|---------|-------|
| `control_port` | int | `8443` | Control API port. Must not be 80/443. |
| `api_key` | string | — **required** | Bearer token the panel presents. ≥16 chars. |
| `hostname` | string | — **required** | The agent's own public FQDN (its control-API cert + self-check). |
| `panel_callback_url` | string | — **required** | http(s) URL the agent POSTs status to. |
| `node_token` | string | — **required** | Bearer token the agent presents on callbacks. ≥16 chars. |
| `letsencrypt_email` | string | — **required** | LE registration email. |
| `acme_staging` | bool | `false` | Use LE staging (untrusted certs; high rate limits). |
| `state_dir` | string | `/var/lib/proxy-agent` | Certs + persisted state. Absolute path. |
| `log_level` | enum | `info` | `debug` \| `info` \| `warn` \| `error`. |
| `callback_interval_ms` | int | `30000` | Status callback heartbeat interval. |
| `tick_interval_ms` | int | `15000` | DNS/cert/proxy reconcile interval. |
| `renew_before_days` | int | `30` | Renewal window (certbot decides per-cert). |
| `allow_link_local_targets` | bool | `false` | Allow proxy targets in 169.254.0.0/16 (SSRF guard off). |
| `cleanup_certs_on_removal` | bool | `false` | Delete a cert when its route is removed. |

`api_key`, `node_token`, and private keys are **never** written to logs.

Example `config.json`:

```json
{
  "control_port": 8443,
  "api_key": "REDACTED-panel-token",
  "hostname": "node1.example.com",
  "panel_callback_url": "https://panel.example.com/api/agent/callback",
  "node_token": "REDACTED-node-token",
  "letsencrypt_email": "ops@example.com",
  "acme_staging": false,
  "state_dir": "/var/lib/proxy-agent",
  "log_level": "info"
}
```

---

## HTTP contract

### A. Control API (panel → agent)

Served over TLS on `https://{hostname}:{control_port}`, JSON, versioned under
`/v1`. **Every** endpoint requires `Authorization: Bearer {api_key}` (validated
with a constant-time compare); unauthenticated calls get `401`.

#### `GET /v1/health`

```json
{ "version": "0.1.0", "uptime_seconds": 1234, "control_cert_ready": true, "acme_staging": false }
```

#### `PUT /v1/routes` — declarative full sync (primary control mechanism)

Request:

```json
{ "routes": [
  { "id": "550e8400-e29b-41d4-a716-446655440000",
    "hostname": "play.example.com",
    "expected_ip": "203.0.113.10",
    "target_host": "127.0.0.1", "target_port": 8080, "target_scheme": "http" }
]}
```

The agent reconciles to **exactly** this set (adds new, updates changed, removes
absent). Idempotent. Returns the current status list (same shape as
`GET /v1/routes`). Invalid input (bad UUID/IP/scheme, blocked SSRF target,
duplicate hostname) returns `400` with a message.

#### `GET /v1/routes`

```json
{ "routes": [ <RouteStatus>, ... ] }
```

#### `GET /v1/routes/{id}` → `<RouteStatus>` (or `404`)

#### `DELETE /v1/routes/{id}` → `{ "removed": true, "id": "..." }` (or `404`)

Convenience only; `PUT` remains the source of truth.

#### `RouteStatus`

```json
{ "id": "550e8400-e29b-41d4-a716-446655440000",
  "hostname": "play.example.com",
  "dns_status": "pending|ok|mismatch",
  "resolved_ip": "203.0.113.10|null",
  "expected_ip": "203.0.113.10",
  "cert_status": "pending|issuing|active|failed|renewing",
  "cert_expires_at": "ISO8601|null",
  "proxy_status": "pending|active|failed",
  "last_error_code": "string|null",
  "sanitized_message": "human-readable, no secrets|null",
  "updated_at": "ISO8601" }
```

### B. Status callback (agent → panel)

The agent `POST`s to `panel_callback_url` on a fixed interval (default 30s) **and
immediately on any state change**, with `Authorization: Bearer {node_token}`:

```json
{ "agent": { "version": "0.1.0", "healthy": true, "acme_staging": false },
  "routes": [ <RouteStatus>, ... ] }
```

Failures are retried with exponential backoff (1s → 60s) and never crash the
agent or affect proxying. The panel is treated as untrusted input on the way in;
the agent is the source of truth for status.

---

## Install / upgrade / uninstall

The installer targets **apt-based distros (Debian/Ubuntu)** and fails clearly on
others. It installs certbot, creates a service user + directories, downloads the
compiled binary from a URL you provide, **verifies its SHA256**, writes the
config, and installs + starts the systemd unit. See [RELEASE.md](RELEASE.md) for
how binaries are produced and named.

### Install / upgrade (same command; idempotent)

```bash
sudo BINARY_URL=https://dl.example.com/proxy-agent-0.1.0-linux-x64 \
     BINARY_SHA256=<hex>   # or CHECKSUM_URL=https://.../....sha256 \
     API_KEY=... \
     HOSTNAME=node1.example.com \
     PANEL_CALLBACK_URL=https://panel.example.com/api/agent/callback \
     NODE_TOKEN=... \
     LETSENCRYPT_EMAIL=ops@example.com \
     CONTROL_PORT=8443 \
     ACME_STAGING=false \
     bash install.sh
```

Re-running with a new `BINARY_URL`/checksum upgrades in place: the binary is
atomically replaced and the service restarted. Persisted state under `state_dir`
is preserved, so routes resume without re-issuing certificates.

### Uninstall

```bash
sudo bash uninstall.sh              # remove service + binary, keep certs/state
sudo PURGE=true bash uninstall.sh   # also delete state_dir, config, and user
```

### systemd

The unit (`systemd/proxy-agent.service`) runs as an unprivileged `proxy-agent`
user with `Restart=always`, starts after the network is online, and is granted
only `CAP_NET_BIND_SERVICE` so it can bind :80/:443. Hardening includes
`NoNewPrivileges`, `ProtectSystem=strict` (with `state_dir` as the sole
`ReadWritePaths`), `ProtectHome`, `PrivateTmp`, a restricted syscall filter, and
address-family and namespace restrictions.

```bash
systemctl status proxy-agent
journalctl -u proxy-agent -f
```

---

## Firewall requirements

Open these inbound TCP ports:

| Port | Purpose |
|------|---------|
| `80` | Let's Encrypt HTTP-01 challenge + 301 redirect to HTTPS |
| `443` | Public HTTPS reverse proxy |
| `{control_port}` (default `8443`) | Control API for the panel |

`:80` must be reachable from the public internet for certificate issuance/renewal
to succeed. Restrict `{control_port}` to the panel's source addresses where
possible.

---

## Security model

- **Auth:** every control-API call requires the bearer `api_key`, compared in
  constant time. Callbacks present the `node_token`.
- **TLS:** TLS 1.2+; SNI-selected per-route certs on :443. Names the agent does
  not serve get no valid cert (client rejects the handshake) and a `421` at the
  HTTP layer — they never reach an upstream.
- **SSRF guard:** proxy targets are validated; link-local / cloud-metadata
  addresses (169.254.0.0/16, fe80::/10) are blocked unless
  `allow_link_local_targets` is set. Loopback and private ranges are allowed on
  purpose (the agent's job is forwarding to local servers). The agent only ever
  proxies to the exact `target_host:target_port` in the desired set.
- **Least privilege:** unprivileged service user, `CAP_NET_BIND_SERVICE` only,
  strict systemd sandbox. Private keys are written `600`; the config file is
  `640 root:proxy-agent`.
- **No secret leakage:** `api_key`, `node_token`, and key material are redacted
  from logs; status payloads carry only sanitized messages, with detailed
  diagnostics kept to local logs.

---

## Development

Requires Bun ≥ 1.2.

```bash
bun install
bun run dev          # run from source with --watch
bun run typecheck    # tsc --noEmit (also the lint gate)
bun test             # unit + offline integration tests
```

---

## Testing

- **Unit + offline integration** (`bun test`, runs anywhere):
  - config validation, route reconciler (add/update/remove/idempotency),
    DNS-check logic, ACME challenge responder, SNI cert selection, status-payload
    construction, logger redaction, certbot output classification.
  - route-manager state machine with mocked DNS/certbot (DNS mismatch → ok →
    cert issued → proxy active, backoff, removal, **restart-resume**).
  - control API over real TLS (auth, all endpoints).
  - a full end-to-end proxy test (`test/integration/proxy.test.ts`): live local
    upstream + self-signed cert, exercising HTTP forwarding, forwarded headers,
    **WebSocket** proxying, and 502 on upstream failure.
- **Live LE-staging smoke test** (`scripts/smoke-test.sh`, run on a real host):
  drives DNS → cert (staging) → proxy → renewal end-to-end, including a restart
  mid-flight to prove state resumes. See the script header for required env.

---

## Building binaries

```bash
bun run build   # scripts/build.sh
```

Produces `dist/proxy-agent-<version>-linux-{x64,arm64}` plus a `.sha256` for each
via `bun build --compile`. See [RELEASE.md](RELEASE.md) for the versioning and
publishing process the installer consumes.

---

## Troubleshooting

| Symptom | Likely cause / fix |
|---------|--------------------|
| `dns_status` stuck `pending` | Hostname has no A/AAAA record yet, or DNS not propagated. |
| `dns_status: mismatch` | The record points elsewhere; `resolved_ip` shows where. Point it at `expected_ip`. |
| `cert_status: failed`, `acme_challenge_failed` | :80 not reachable from the internet, or a firewall/NAT blocks it. Verify inbound 80. |
| `cert_status: failed`, `acme_rate_limited` | Hit LE rate limits. Use `acme_staging: true` while testing; wait before retrying prod. |
| `cert_status: failed`, `certbot_missing` | certbot not installed. `apt-get install certbot` (the installer does this). |
| `control_cert_ready: false` | The agent hasn't obtained its own LE cert yet (needs DNS for `hostname` + reachable :80). It serves a self-signed cert meanwhile. |
| `502 Bad Gateway` through the proxy | The upstream `target_host:target_port` isn't responding. Check the local service. |
| `421` from :443 | Request arrived for a hostname with no active route/cert. Ensure the route is synced and its cert is `active`. |
| Service won't start | `journalctl -u proxy-agent -n 50`. Config errors exit `78` with a specific message. |
| Secrets in a bug report | They're redacted from logs by design; if you see one, file it — that's a bug. |

Detailed diagnostics are in the local logs (`journalctl -u proxy-agent`); status
payloads to the panel intentionally contain only sanitized messages.
