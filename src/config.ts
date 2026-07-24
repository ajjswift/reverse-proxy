// Configuration loading and validation. Config comes from a single JSON file
// (default /etc/proxy-agent/config.json) with optional environment-variable
// overrides. Validation is strict and fails fast with a message listing every
// problem at once, so a misconfigured install never starts half-broken.

import { readFileSync } from "node:fs";
import type { LogLevel } from "./logger.ts";

export interface Config {
  control_port: number;
  api_key: string;
  hostname: string;
  panel_callback_url: string;
  node_token: string;
  letsencrypt_email: string;
  acme_staging: boolean;
  state_dir: string;
  log_level: LogLevel;
  /** How often to POST status to the panel, ms. */
  callback_interval_ms: number;
  /** How often to run the per-route DNS/cert/proxy reconcile tick, ms. */
  tick_interval_ms: number;
  /** Renew certs when they expire within this many days. */
  renew_before_days: number;
  /**
   * Allow proxy targets on link-local / cloud-metadata ranges (169.254.0.0/16).
   * Off by default as an SSRF guard; the installer never enables it.
   */
  allow_link_local_targets: boolean;
  /** Delete a route's certificate files when the route is removed. */
  cleanup_certs_on_removal: boolean;
}

export class ConfigError extends Error {
  constructor(public problems: string[]) {
    super("Invalid configuration:\n  - " + problems.join("\n  - "));
    this.name = "ConfigError";
  }
}

const DEFAULT_CONFIG_PATH = "/etc/proxy-agent/config.json";
const LOG_LEVELS: LogLevel[] = ["debug", "info", "warn", "error"];

const HOSTNAME_RE =
  /^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$/;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

type Raw = Record<string, unknown>;

/** Read a config file from disk. Returns {} if the file is absent. */
export function readConfigFile(path: string): Raw {
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch (err) {
    const e = err as NodeJS.ErrnoException;
    if (e.code === "ENOENT") return {};
    throw new ConfigError([`cannot read config file ${path}: ${e.message}`]);
  }
  try {
    const parsed = JSON.parse(text);
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new Error("top-level value must be a JSON object");
    }
    return parsed as Raw;
  } catch (err) {
    throw new ConfigError([`config file ${path} is not valid JSON: ${(err as Error).message}`]);
  }
}

/** Overlay recognised environment variables onto a raw config object. */
export function applyEnvOverrides(raw: Raw, env: Record<string, string | undefined>): Raw {
  const out: Raw = { ...raw };
  const map: Record<string, string> = {
    CONTROL_PORT: "control_port",
    API_KEY: "api_key",
    HOSTNAME: "hostname",
    PANEL_CALLBACK_URL: "panel_callback_url",
    NODE_TOKEN: "node_token",
    LETSENCRYPT_EMAIL: "letsencrypt_email",
    ACME_STAGING: "acme_staging",
    CLEANUP_CERTS_ON_REMOVAL: "cleanup_certs_on_removal",
    STATE_DIR: "state_dir",
    LOG_LEVEL: "log_level",
    CALLBACK_INTERVAL_MS: "callback_interval_ms",
    TICK_INTERVAL_MS: "tick_interval_ms",
    RENEW_BEFORE_DAYS: "renew_before_days",
    ALLOW_LINK_LOCAL_TARGETS: "allow_link_local_targets",
  };
  for (const [envKey, field] of Object.entries(map)) {
    const v = env[`PROXY_AGENT_${envKey}`] ?? env[envKey];
    if (v !== undefined && v !== "") out[field] = v;
  }
  return out;
}

function asInt(value: unknown): number | undefined {
  if (typeof value === "number" && Number.isInteger(value)) return value;
  if (typeof value === "string" && /^-?\d+$/.test(value.trim())) return parseInt(value, 10);
  return undefined;
}

function asBool(value: unknown): boolean | undefined {
  if (typeof value === "boolean") return value;
  if (typeof value === "string") {
    const v = value.trim().toLowerCase();
    if (["true", "1", "yes", "on"].includes(v)) return true;
    if (["false", "0", "no", "off"].includes(v)) return false;
  }
  return undefined;
}

/**
 * Validate a raw config object into a typed Config, or throw ConfigError with
 * all problems. Pure function (no filesystem/env access) so it is unit-testable.
 */
export function parseConfig(raw: Raw): Config {
  const problems: string[] = [];

  const str = (key: string, required: boolean): string => {
    const v = raw[key];
    if (v === undefined || v === null || v === "") {
      if (required) problems.push(`${key} is required`);
      return "";
    }
    if (typeof v !== "string") {
      problems.push(`${key} must be a string`);
      return "";
    }
    return v;
  };

  const api_key = str("api_key", true);
  if (api_key && api_key.length < 16) problems.push("api_key must be at least 16 characters");

  const node_token = str("node_token", true);
  if (node_token && node_token.length < 16)
    problems.push("node_token must be at least 16 characters");

  const hostname = str("hostname", true);
  if (hostname && !HOSTNAME_RE.test(hostname))
    problems.push(`hostname "${hostname}" is not a valid FQDN`);

  const letsencrypt_email = str("letsencrypt_email", true);
  if (letsencrypt_email && !EMAIL_RE.test(letsencrypt_email))
    problems.push(`letsencrypt_email "${letsencrypt_email}" is not a valid email address`);

  const panel_callback_url = str("panel_callback_url", true);
  if (panel_callback_url) {
    try {
      const u = new URL(panel_callback_url);
      if (u.protocol !== "http:" && u.protocol !== "https:")
        problems.push("panel_callback_url must be an http(s) URL");
    } catch {
      problems.push(`panel_callback_url "${panel_callback_url}" is not a valid URL`);
    }
  }

  let control_port = 8443;
  if (raw.control_port !== undefined) {
    const p = asInt(raw.control_port);
    if (p === undefined || p < 1 || p > 65535) problems.push("control_port must be 1..65535");
    else control_port = p;
  }
  if (control_port === 80 || control_port === 443)
    problems.push("control_port must not be 80 or 443 (reserved for ACME and proxy listeners)");

  let acme_staging = false;
  if (raw.acme_staging !== undefined) {
    const b = asBool(raw.acme_staging);
    if (b === undefined) problems.push("acme_staging must be a boolean");
    else acme_staging = b;
  }

  let allow_link_local_targets = false;
  if (raw.allow_link_local_targets !== undefined) {
    const b = asBool(raw.allow_link_local_targets);
    if (b === undefined) problems.push("allow_link_local_targets must be a boolean");
    else allow_link_local_targets = b;
  }

  let cleanup_certs_on_removal = false;
  if (raw.cleanup_certs_on_removal !== undefined) {
    const b = asBool(raw.cleanup_certs_on_removal);
    if (b === undefined) problems.push("cleanup_certs_on_removal must be a boolean");
    else cleanup_certs_on_removal = b;
  }

  const state_dir = typeof raw.state_dir === "string" && raw.state_dir ? raw.state_dir : "/var/lib/proxy-agent";
  if (!state_dir.startsWith("/")) problems.push("state_dir must be an absolute path");

  let log_level: LogLevel = "info";
  if (raw.log_level !== undefined) {
    if (typeof raw.log_level === "string" && LOG_LEVELS.includes(raw.log_level as LogLevel))
      log_level = raw.log_level as LogLevel;
    else problems.push(`log_level must be one of ${LOG_LEVELS.join(", ")}`);
  }

  const intField = (key: string, def: number, min: number, max: number): number => {
    if (raw[key] === undefined) return def;
    const n = asInt(raw[key]);
    if (n === undefined || n < min || n > max) {
      problems.push(`${key} must be an integer in ${min}..${max}`);
      return def;
    }
    return n;
  };
  const callback_interval_ms = intField("callback_interval_ms", 30_000, 1_000, 3_600_000);
  const tick_interval_ms = intField("tick_interval_ms", 15_000, 1_000, 3_600_000);
  const renew_before_days = intField("renew_before_days", 30, 1, 89);

  if (problems.length > 0) throw new ConfigError(problems);

  return {
    control_port,
    api_key,
    hostname,
    panel_callback_url,
    node_token,
    letsencrypt_email,
    acme_staging,
    state_dir,
    log_level,
    callback_interval_ms,
    tick_interval_ms,
    renew_before_days,
    allow_link_local_targets,
    cleanup_certs_on_removal,
  };
}

/** Full boot-time load: file + env overrides + validation. */
export function loadConfig(
  path: string = process.env.PROXY_AGENT_CONFIG ?? DEFAULT_CONFIG_PATH,
  env: Record<string, string | undefined> = process.env,
): Config {
  const fileRaw = readConfigFile(path);
  const merged = applyEnvOverrides(fileRaw, env);
  return parseConfig(merged);
}
