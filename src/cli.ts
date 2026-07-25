#!/usr/bin/env bun
// CLI for inspecting a running reverse-proxy agent. Reads the same config file
// as the agent to pick up the control port and API key, then queries the
// agent's control API over HTTPS. Also supports reading the persisted state
// file directly when the agent is not running.

import { loadConfig, type Config, ConfigError } from "./config.ts";
import { loadState } from "./state.ts";
import { makePaths } from "./paths.ts";
import type { RouteStatus, HealthResponse } from "./types.ts";

// ── Colours (auto-disabled when piped) ──────────────────────────────────────

const NO_COLOR = !process.stdout.isTTY || !!process.env.NO_COLOR;
const c = {
  reset: NO_COLOR ? "" : "\x1b[0m",
  bold: NO_COLOR ? "" : "\x1b[1m",
  dim: NO_COLOR ? "" : "\x1b[2m",
  red: NO_COLOR ? "" : "\x1b[31m",
  green: NO_COLOR ? "" : "\x1b[32m",
  yellow: NO_COLOR ? "" : "\x1b[33m",
  cyan: NO_COLOR ? "" : "\x1b[36m",
  magenta: NO_COLOR ? "" : "\x1b[35m",
  white: NO_COLOR ? "" : "\x1b[37m",
  gray: NO_COLOR ? "" : "\x1b[90m",
};

// ── Helpers ─────────────────────────────────────────────────────────────────

function statusColor(value: string): string {
  switch (value) {
    case "ok":
    case "active":
    case "online":
      return c.green;
    case "pending":
    case "issuing":
    case "renewing":
      return c.yellow;
    case "failed":
    case "mismatch":
    case "unhealthy":
      return c.red;
    default:
      return c.dim;
  }
}

function badge(label: string, value: string): string {
  return `${c.dim}${label}:${c.reset} ${statusColor(value)}${value}${c.reset}`;
}


function die(msg: string): never {
  process.stderr.write(`${c.red}error:${c.reset} ${msg}\n`);
  process.exit(1);
}

function loadConfigSafe(): Config {
  try {
    return loadConfig();
  } catch (err) {
    if (err instanceof ConfigError) {
      die(`cannot load config: ${err.message}`);
    }
    throw err;
  }
}

// ── API client ──────────────────────────────────────────────────────────────

async function apiGet(config: Config, path: string): Promise<unknown> {
  // This CLI runs on the node and inspects the already-running local agent.
  // Avoid DNS/hairpin routing through the node's public hostname.
  const url = `https://127.0.0.1:${config.control_port}/v1/${path}`;
  let res: Response;
  try {
    res = await fetch(url, {
      method: "GET",
      headers: {
        authorization: `Bearer ${config.api_key}`,
        accept: "application/json",
      },
      tls: { rejectUnauthorized: false },
    });
  } catch (err) {
    die(`cannot reach agent at ${url}: ${(err as Error).message}`);
  }
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    die(`agent returned HTTP ${res.status}: ${body}`);
  }
  return res.json();
}

// ── Commands ────────────────────────────────────────────────────────────────

async function cmdHealth(config: Config): Promise<void> {
  const data = (await apiGet(config, "health")) as HealthResponse;
  const upH = Math.floor(data.uptime_seconds / 3600);
  const upM = Math.floor((data.uptime_seconds % 3600) / 60);
  const upS = data.uptime_seconds % 60;

  console.log(`\n${c.bold}Agent Health${c.reset}`);
  console.log(`${c.dim}${"─".repeat(50)}${c.reset}`);
  console.log(`  Version:          ${c.cyan}${data.version}${c.reset}`);
  console.log(`  Uptime:           ${c.white}${upH}h ${upM}m ${upS}s${c.reset}`);
  console.log(`  Control cert:     ${data.control_cert_ready ? `${c.green}ready` : `${c.yellow}bootstrap`}${c.reset}`);
  console.log(`  ACME staging:     ${data.acme_staging ? `${c.yellow}yes` : `${c.green}no (production)`}${c.reset}`);
  console.log();
}

async function cmdRoutes(config: Config): Promise<void> {
  const data = (await apiGet(config, "routes")) as { routes: RouteStatus[] };
  const routes = data.routes;

  console.log(`\n${c.bold}Routes${c.reset} ${c.dim}(${routes.length} total)${c.reset}`);
  console.log(`${c.dim}${"─".repeat(100)}${c.reset}`);

  if (routes.length === 0) {
    console.log(`  ${c.dim}No routes configured.${c.reset}\n`);
    return;
  }

  for (const r of routes) {
    console.log(
      `  ${c.bold}${c.cyan}${r.hostname}${c.reset}  ${c.dim}→${c.reset}  ` +
        `${badge("dns", r.dns_status)}  ${badge("cert", r.cert_status)}  ${badge("proxy", r.proxy_status)}`
    );
    console.log(
      `    ${c.dim}id:${c.reset} ${r.id}  ` +
        `${c.dim}ip:${c.reset} ${r.resolved_ip ?? "—"} ${r.resolved_ip === r.expected_ip ? `${c.green}✓${c.reset}` : `${c.red}✗ expected ${r.expected_ip}${c.reset}`}`
    );
    if (r.cert_expires_at) {
      console.log(`    ${c.dim}cert expires:${c.reset} ${r.cert_expires_at}`);
    }
    if (r.last_error_code || r.sanitized_message) {
      console.log(
        `    ${c.red}error:${c.reset} ${r.last_error_code ?? ""}${r.sanitized_message ? ` — ${r.sanitized_message}` : ""}`
      );
    }
    console.log(`    ${c.dim}updated: ${r.updated_at}${c.reset}`);
    console.log();
  }
}

async function cmdRoute(config: Config, id: string): Promise<void> {
  const r = (await apiGet(config, `routes/${id}`)) as RouteStatus;

  console.log(`\n${c.bold}Route Detail${c.reset}`);
  console.log(`${c.dim}${"─".repeat(60)}${c.reset}`);
  console.log(`  Hostname:         ${c.bold}${c.cyan}${r.hostname}${c.reset}`);
  console.log(`  ID:               ${r.id}`);
  console.log(`  DNS:              ${statusColor(r.dns_status)}${r.dns_status}${c.reset}`);
  console.log(`  Resolved IP:      ${r.resolved_ip ?? `${c.dim}—${c.reset}`}`);
  console.log(`  Expected IP:      ${r.expected_ip}`);
  console.log(
    `  IP match:         ${r.resolved_ip === r.expected_ip ? `${c.green}yes${c.reset}` : `${c.red}NO${c.reset}`}`
  );
  console.log(`  Certificate:      ${statusColor(r.cert_status)}${r.cert_status}${c.reset}`);
  console.log(`  Cert expires:     ${r.cert_expires_at ?? `${c.dim}—${c.reset}`}`);
  console.log(`  Proxy:            ${statusColor(r.proxy_status)}${r.proxy_status}${c.reset}`);
  if (r.last_error_code) {
    console.log(`  Error code:       ${c.red}${r.last_error_code}${c.reset}`);
  }
  if (r.sanitized_message) {
    console.log(`  Error message:    ${c.red}${r.sanitized_message}${c.reset}`);
  }
  console.log(`  Updated:          ${r.updated_at}`);
  console.log();
}

function cmdState(config: Config): void {
  const paths = makePaths(config.state_dir);
  const persisted = loadState(paths.stateFile);

  console.log(`\n${c.bold}Persisted State${c.reset} ${c.dim}(${paths.stateFile})${c.reset}`);
  console.log(`${c.dim}${"─".repeat(100)}${c.reset}`);

  if (persisted.length === 0) {
    console.log(`  ${c.dim}No persisted routes.${c.reset}\n`);
    return;
  }

  for (const p of persisted) {
    const d = p.desired;
    console.log(
      `  ${c.bold}${c.cyan}${d.hostname}${c.reset}  ${c.dim}→${c.reset}  ` +
        `${d.target_scheme}://${d.target_host}:${d.target_port}`
    );
    console.log(
      `    ${c.dim}id:${c.reset} ${d.id}  ` +
        `${badge("dns", p.dns_status)}  ${badge("cert", p.cert_status)}  ${badge("proxy", p.proxy_status)}`
    );
    console.log(
      `    ${c.dim}expected ip:${c.reset} ${d.expected_ip}  ` +
        `${c.dim}resolved:${c.reset} ${p.resolved_ip ?? "—"}`
    );
    if (p.last_error_code || p.sanitized_message) {
      console.log(
        `    ${c.red}error:${c.reset} ${p.last_error_code ?? ""}${p.sanitized_message ? ` — ${p.sanitized_message}` : ""}`
      );
    }
    console.log(`    ${c.dim}updated: ${p.updated_at}${c.reset}`);
    console.log();
  }
}

function cmdConfig(config: Config): void {
  const redact = (s: string) => s.length > 8 ? s.slice(0, 4) + "•".repeat(8) + s.slice(-4) : "••••••••";

  console.log(`\n${c.bold}Configuration${c.reset}`);
  console.log(`${c.dim}${"─".repeat(60)}${c.reset}`);
  console.log(`  hostname:               ${c.cyan}${config.hostname}${c.reset}`);
  console.log(`  control_port:           ${config.control_port}`);
  console.log(`  panel_callback_url:     ${config.panel_callback_url}`);
  console.log(`  letsencrypt_email:      ${config.letsencrypt_email}`);
  console.log(`  acme_staging:           ${config.acme_staging ? `${c.yellow}true` : `${c.green}false`}${c.reset}`);
  console.log(`  state_dir:              ${config.state_dir}`);
  console.log(`  log_level:              ${config.log_level}`);
  console.log(`  callback_interval_ms:   ${config.callback_interval_ms}`);
  console.log(`  tick_interval_ms:       ${config.tick_interval_ms}`);
  console.log(`  renew_before_days:      ${config.renew_before_days}`);
  console.log(`  allow_link_local:       ${config.allow_link_local_targets}`);
  console.log(`  cleanup_certs:          ${config.cleanup_certs_on_removal}`);
  console.log(`  api_key:                ${c.dim}${redact(config.api_key)}${c.reset}`);
  console.log(`  node_token:             ${c.dim}${redact(config.node_token)}${c.reset}`);
  console.log();
}

// ── Usage ───────────────────────────────────────────────────────────────────

function usage(): never {
  console.log(`
${c.bold}proxy-agent ctl${c.reset} — inspect a running reverse-proxy agent

${c.bold}USAGE${c.reset}
  proxy-agent ctl <command> [args]
  proxy-agent-ctl <command> [args]

${c.bold}COMMANDS${c.reset}
  ${c.cyan}status${c.reset}              Show agent health and uptime
  ${c.cyan}routes${c.reset}              List all routes with DNS/cert/proxy status
  ${c.cyan}route${c.reset} <id>           Show detailed status for a single route
  ${c.cyan}state${c.reset}               Read persisted state file (works when agent is down)
  ${c.cyan}config${c.reset}              Show active config (secrets redacted)
  ${c.cyan}help${c.reset}                Show this help

${c.bold}OPTIONS${c.reset}
  ${c.dim}PROXY_AGENT_CONFIG=/path/to/config.json${c.reset}   Override config file path

${c.bold}EXAMPLES${c.reset}
  proxy-agent ctl status
  proxy-agent ctl routes
  proxy-agent ctl route 550e8400-e29b-41d4-a716-446655440000
  proxy-agent ctl state
`);
  process.exit(0);
}

// ── Main ────────────────────────────────────────────────────────────────────

export async function runCli(args: string[] = process.argv.slice(2)): Promise<void> {
  const cmd = args[0]?.toLowerCase();

  if (!cmd || cmd === "help" || cmd === "--help" || cmd === "-h") usage();

  const config = loadConfigSafe();

  switch (cmd) {
    case "status":
    case "health":
      await cmdHealth(config);
      break;

    case "routes":
      await cmdRoutes(config);
      break;

    case "route": {
      const id = args[1];
      if (!id) die("usage: proxy-agent-ctl route <id>");
      await cmdRoute(config, id);
      break;
    }

    case "state":
      cmdState(config);
      break;

    case "config":
    case "cfg":
      cmdConfig(config);
      break;

    default:
      die(`unknown command: ${cmd}\nRun proxy-agent ctl help for usage.`);
  }
}

// Keep this file usable as the standalone proxy-agent-ctl build while making
// imports from the main proxy-agent entry point side-effect-free.
if (import.meta.main) {
  runCli().catch((err) => {
    die((err as Error).message);
  });
}
