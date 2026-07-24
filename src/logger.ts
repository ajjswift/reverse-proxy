// Structured, leveled logging with hard guarantees that secrets never reach the
// output. Secrets are registered at boot (api_key, node_token, cert private key
// material) and scrubbed from every log line, including nested fields.

export type LogLevel = "debug" | "info" | "warn" | "error";

const LEVELS: Record<LogLevel, number> = { debug: 10, info: 20, warn: 30, error: 40 };

// Field names whose values are always redacted regardless of registration.
const SENSITIVE_KEYS = new Set([
  "api_key",
  "apikey",
  "node_token",
  "nodetoken",
  "token",
  "authorization",
  "bearer",
  "password",
  "privkey",
  "private_key",
  "secret",
]);

const REDACTED = "[REDACTED]";

/** Literal secret values registered at boot and stripped from all output. */
const registeredSecrets = new Set<string>();

let currentLevel: LogLevel = "info";

export function setLogLevel(level: LogLevel): void {
  currentLevel = level;
}

/**
 * Register a literal secret string so any occurrence of it (even embedded in a
 * larger message, e.g. a certbot error line) is scrubbed before logging.
 * Short/empty strings are ignored to avoid over-redacting common substrings.
 */
export function registerSecret(secret: string | undefined | null): void {
  if (secret && secret.length >= 6) registeredSecrets.add(secret);
}

function scrubString(s: string): string {
  let out = s;
  for (const secret of registeredSecrets) {
    if (out.includes(secret)) out = out.split(secret).join(REDACTED);
  }
  return out;
}

function scrubValue(value: unknown, keyHint?: string): unknown {
  if (keyHint && SENSITIVE_KEYS.has(keyHint.toLowerCase())) return REDACTED;
  if (typeof value === "string") return scrubString(value);
  if (Array.isArray(value)) return value.map((v) => scrubValue(v));
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[k] = scrubValue(v, k);
    }
    return out;
  }
  return value;
}

function emit(level: LogLevel, message: string, fields?: Record<string, unknown>): void {
  if (LEVELS[level] < LEVELS[currentLevel]) return;
  const record: Record<string, unknown> = {
    ts: new Date().toISOString(),
    level,
    msg: scrubString(message),
  };
  if (fields) {
    for (const [k, v] of Object.entries(fields)) {
      record[k] = scrubValue(v, k);
    }
  }
  const line = JSON.stringify(record);
  if (level === "error" || level === "warn") process.stderr.write(line + "\n");
  else process.stdout.write(line + "\n");
}

export const log = {
  debug: (msg: string, fields?: Record<string, unknown>) => emit("debug", msg, fields),
  info: (msg: string, fields?: Record<string, unknown>) => emit("info", msg, fields),
  warn: (msg: string, fields?: Record<string, unknown>) => emit("warn", msg, fields),
  error: (msg: string, fields?: Record<string, unknown>) => emit("error", msg, fields),
};

// Exposed for unit testing the redaction logic without going through stdout.
export const _internal = { scrubString, scrubValue, registeredSecrets };
