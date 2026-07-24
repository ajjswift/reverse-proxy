// certbot integration via child process. Certificate operations are serialized
// through an internal queue so concurrent route reconciles never run certbot
// against itself. The command runner is injectable so tests exercise argument
// construction and result parsing without invoking real certbot.

import { mkdirSync, existsSync } from "node:fs";
import { join } from "node:path";
import type { Paths } from "./paths.ts";
import { log } from "./logger.ts";

export interface CommandResult {
  code: number;
  stdout: string;
  stderr: string;
}

export type CommandRunner = (cmd: string, args: string[]) => Promise<CommandResult>;

/** Real runner backed by Bun.spawn. Never leaks child stdio into our stdout. */
export function createBunRunner(): CommandRunner {
  return async (cmd, args) => {
    const proc = Bun.spawn([cmd, ...args], { stdout: "pipe", stderr: "pipe" });
    const [stdout, stderr, code] = await Promise.all([
      new Response(proc.stdout).text(),
      new Response(proc.stderr).text(),
      proc.exited,
    ]);
    return { code, stdout, stderr };
  };
}

export interface CertOpResult {
  ok: boolean;
  errorCode: string | null;
  /** User-safe message (no secrets, no raw certbot dumps). */
  sanitizedMessage: string | null;
}

/** Structural interface the manager depends on (lets tests inject a fake). */
export interface CertbotLike {
  issue(hostname: string): Promise<CertOpResult>;
  renewAll(): Promise<CertOpResult>;
}

/**
 * Map raw certbot stderr/stdout to a stable error code + user-safe message.
 * The raw text is only ever written to local logs, never returned to the panel.
 */
export function classifyCertbotFailure(combined: string): { code: string; message: string } {
  const t = combined.toLowerCase();
  if (t.includes("too many certificates") || t.includes("rate limit"))
    return { code: "acme_rate_limited", message: "Certificate authority rate limit reached; will retry later." };
  if (t.includes("dns problem") || t.includes("nxdomain"))
    return { code: "acme_dns_problem", message: "DNS did not resolve for the ACME challenge." };
  if (t.includes("connection") || t.includes("timeout") || t.includes("unauthorized") || t.includes("challenge"))
    return { code: "acme_challenge_failed", message: "ACME HTTP-01 challenge could not be validated (check that port 80 is reachable)." };
  if (t.includes("certbot: command not found") || t.includes("enoent"))
    return { code: "certbot_missing", message: "certbot is not installed on this host." };
  return { code: "certbot_failed", message: "Certificate issuance failed; see agent logs on the host." };
}

export class Certbot {
  private tail: Promise<unknown> = Promise.resolve();

  constructor(
    private paths: Paths,
    private email: string,
    private staging: boolean,
    private runner: CommandRunner,
  ) {}

  /** Run a task under the serialization lock. */
  private serialize<T>(fn: () => Promise<T>): Promise<T> {
    const run = this.tail.then(fn, fn);
    // Keep the chain alive even if this task rejects.
    this.tail = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  }

  private baseArgs(): string[] {
    const args = [
      "--non-interactive",
      "--config-dir",
      this.paths.letsencryptDir,
      "--work-dir",
      this.paths.certbotWorkDir,
      "--logs-dir",
      this.paths.certbotLogsDir,
    ];
    if (this.staging) args.push("--staging");
    return args;
  }

  /**
   * Ensure the required directories exist before certbot runs. certbot will not
   * create parents for --config-dir etc.
   */
  private ensureDirs(): void {
    for (const d of [
      this.paths.letsencryptDir,
      this.paths.certbotWorkDir,
      this.paths.certbotLogsDir,
      join(this.paths.acmeWebroot, ".well-known", "acme-challenge"),
    ]) {
      if (!existsSync(d)) mkdirSync(d, { recursive: true, mode: 0o750 });
    }
  }

  /** Issue (or keep, if still valid) a cert for one hostname via HTTP-01 webroot. */
  issue(hostname: string): Promise<CertOpResult> {
    return this.serialize(async () => {
      this.ensureDirs();
      const args = [
        "certonly",
        ...this.baseArgs(),
        "--webroot",
        "-w",
        this.paths.acmeWebroot,
        "--agree-tos",
        "--email",
        this.email,
        "--cert-name",
        hostname,
        "-d",
        hostname,
        "--keep-until-expiring",
        "--expand",
      ];
      log.info("certbot issue", { hostname, staging: this.staging });
      let result: CommandResult;
      try {
        result = await this.runner("certbot", args);
      } catch (err) {
        log.error("certbot spawn failed", { hostname, err: (err as Error).message });
        return { ok: false, errorCode: "certbot_missing", sanitizedMessage: "certbot could not be executed on this host." };
      }
      if (result.code === 0) {
        log.info("certbot issue ok", { hostname });
        return { ok: true, errorCode: null, sanitizedMessage: null };
      }
      const combined = result.stdout + "\n" + result.stderr;
      const { code, message } = classifyCertbotFailure(combined);
      log.error("certbot issue failed", { hostname, exit: result.code, detail: combined.slice(0, 2000) });
      return { ok: false, errorCode: code, sanitizedMessage: message };
    });
  }

  /** Renew all due certs. Individual results are reflected by reloading certs. */
  renewAll(): Promise<CertOpResult> {
    return this.serialize(async () => {
      this.ensureDirs();
      const args = ["renew", ...this.baseArgs(), "--webroot", "-w", this.paths.acmeWebroot];
      log.info("certbot renew");
      let result: CommandResult;
      try {
        result = await this.runner("certbot", args);
      } catch (err) {
        log.error("certbot renew spawn failed", { err: (err as Error).message });
        return { ok: false, errorCode: "certbot_missing", sanitizedMessage: "certbot could not be executed on this host." };
      }
      if (result.code === 0) {
        log.info("certbot renew ok");
        return { ok: true, errorCode: null, sanitizedMessage: null };
      }
      const combined = result.stdout + "\n" + result.stderr;
      const { code, message } = classifyCertbotFailure(combined);
      log.error("certbot renew failed", { exit: result.code, detail: combined.slice(0, 2000) });
      return { ok: false, errorCode: code, sanitizedMessage: message };
    });
  }
}

/**
 * Generate a self-signed cert for the control-API hostname so the control API
 * can serve TLS immediately at boot, before a Let's Encrypt cert exists. Uses
 * openssl (present on the target distros). Idempotent: reuses an existing pair.
 */
export async function ensureBootstrapCert(
  paths: Paths,
  hostname: string,
  runner: CommandRunner,
): Promise<{ certPath: string; keyPath: string }> {
  if (!existsSync(paths.bootstrapDir)) mkdirSync(paths.bootstrapDir, { recursive: true, mode: 0o750 });
  const certPath = join(paths.bootstrapDir, "control-selfsigned.pem");
  const keyPath = join(paths.bootstrapDir, "control-selfsigned.key");
  if (existsSync(certPath) && existsSync(keyPath)) return { certPath, keyPath };
  const args = [
    "req", "-x509", "-newkey", "rsa:2048", "-nodes",
    "-keyout", keyPath,
    "-out", certPath,
    "-days", "3650",
    "-subj", `/CN=${hostname}`,
    "-addext", `subjectAltName=DNS:${hostname}`,
  ];
  const result = await runner("openssl", args);
  if (result.code !== 0) {
    throw new Error(`failed to generate bootstrap certificate (openssl exit ${result.code})`);
  }
  // Lock down the private key.
  try {
    await runner("chmod", ["600", keyPath]);
  } catch {
    /* best effort */
  }
  return { certPath, keyPath };
}
