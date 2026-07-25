// Entry point: parse flags, load + validate config, bootstrap TLS, start all
// listeners and timers, and shut down gracefully (drain connections, persist
// state, send a final status callback).

import { readFileSync, mkdirSync } from "node:fs";
import { loadConfig, ConfigError } from "./config.ts";
import { setLogLevel, registerSecret, log } from "./logger.ts";
import { VERSION } from "./version.ts";
import { makePaths, fullchainPath, privkeyPath } from "./paths.ts";
import { Certbot, createBunRunner, ensureBootstrapCert } from "./certbot.ts";
import { CertStore } from "./certstore.ts";
import { createDefaultResolver } from "./dns.ts";
import { RouteManager } from "./manager.ts";
import { ProxyServer } from "./proxy.ts";
import { startChallengeServer } from "./challenge-server.ts";
import { ControlServer, type ControlCert } from "./control-api.ts";
import { CallbackSender } from "./callback.ts";
import { buildCallbackBody } from "./status.ts";

import { runCli } from "./cli.ts";

const RENEW_INTERVAL_MS = 12 * 60 * 60 * 1000; // twice daily, standard for certbot
const DRAIN_TIMEOUT_MS = 25_000;

function printUsage(): void {
  process.stdout.write(
    `proxy-agent ${VERSION}\n\n` +
      `Usage: proxy-agent [--config <path>]\n` +
      `       proxy-agent ctl <command> [args]\n\n` +
      `Options:\n` +
      `  --config <path>   Path to config.json (default /etc/proxy-agent/config.json,\n` +
      `                    or $PROXY_AGENT_CONFIG)\n` +
      `  --version         Print version and exit\n` +
      `  --help            Print this help and exit\n\n` +
      `Subcommands:\n` +
      `  ctl status        Show agent health and uptime\n` +
      `  ctl routes        List all routes with DNS/cert/proxy status\n` +
      `  ctl route <id>    Show detailed status for a single route\n` +
      `  ctl state         Read persisted state file (works when agent is down)\n` +
      `  ctl config        Show active config (secrets redacted)\n`,
  );
}

function readPair(certPath: string, keyPath: string): ControlCert | null {
  try {
    return { cert: readFileSync(certPath, "utf8"), key: readFileSync(keyPath, "utf8") };
  } catch {
    return null;
  }
}

export async function main(args: string[] = process.argv.slice(2)): Promise<void> {
  // Delegate to the built-in CLI when invoked as `proxy-agent ctl ...`.
  if (args[0] === "ctl") {
    await runCli(args.slice(1));
    return;
  }

  if (args.includes("--version") || args.includes("-v")) {
    process.stdout.write(VERSION + "\n");
    return;
  }
  if (args.includes("--help") || args.includes("-h")) {
    printUsage();
    return;
  }
  const cfgIdx = args.indexOf("--config");
  const configPath = cfgIdx >= 0 ? args[cfgIdx + 1] : undefined;

  let config;
  try {
    config = loadConfig(configPath ?? process.env.PROXY_AGENT_CONFIG ?? "/etc/proxy-agent/config.json");
  } catch (err) {
    if (err instanceof ConfigError) {
      process.stderr.write(err.message + "\n");
      process.exit(78); // EX_CONFIG
    }
    throw err;
  }

  setLogLevel(config.log_level);
  registerSecret(config.api_key);
  registerSecret(config.node_token);

  log.info("starting proxy-agent", {
    version: VERSION,
    hostname: config.hostname,
    control_port: config.control_port,
    acme_staging: config.acme_staging,
  });

  const paths = makePaths(config.state_dir);
  for (const d of [paths.stateDir, paths.bootstrapDir]) {
    try {
      mkdirSync(d, { recursive: true, mode: 0o750 });
    } catch (err) {
      log.error("cannot create state directory", { dir: d, err: (err as Error).message });
      process.exit(1);
    }
  }

  const runner = createBunRunner();
  const certbot = new Certbot(paths, config.letsencrypt_email, config.acme_staging, runner);
  const certStore = new CertStore(paths);
  const resolver = createDefaultResolver();

  // --- Control certificate: self-signed bootstrap, upgraded to LE when ready ---
  const bootstrap = await ensureBootstrapCert(paths, config.hostname, runner);
  const bootstrapCert = readPair(bootstrap.certPath, bootstrap.keyPath);
  if (!bootstrapCert) {
    log.error("failed to load bootstrap control certificate");
    process.exit(1);
  }
  let controlCert: ControlCert = bootstrapCert;
  let controlCertReady = false;

  // If an LE cert for our own hostname already exists (restart), use it.
  {
    const le = readPair(fullchainPath(paths, config.hostname), privkeyPath(paths, config.hostname));
    if (le) {
      controlCert = le;
      controlCertReady = true;
      log.info("control API using existing Let's Encrypt certificate");
    }
  }

  const startedAtMs = Date.now();

  // Late-bound hooks break the manager ↔ listeners cycle without casts: the
  // manager calls through these, and we point them at the listeners once built.
  const hooks = {
    onCertsChanged: () => {},
    onStatusChanged: () => {},
  };

  const manager = new RouteManager({
    config,
    paths,
    certbot,
    certStore,
    resolver,
    onCertsChanged: () => hooks.onCertsChanged(),
    onStatusChanged: () => hooks.onStatusChanged(),
  });

  const proxy = new ProxyServer(manager, certStore, () => controlCert);
  const controlServer = new ControlServer({
    config,
    manager,
    getControlCert: () => controlCert,
    controlCertReady: () => controlCertReady,
    startedAtMs,
  });
  const callback = new CallbackSender({
    config,
    buildBody: () => buildCallbackBody(VERSION, true, config.acme_staging, manager.getStatuses()),
  });

  hooks.onCertsChanged = () => proxy.reload();
  hooks.onStatusChanged = () => callback.trigger();

  manager.init();

  startChallengeServer(paths);
  proxy.start();
  controlServer.start();
  callback.start();

  // Attempt to obtain the control-API LE cert (idempotent; retried on renew).
  const ensureControlCert = async (): Promise<void> => {
    if (controlCertReady) return;
    const res = await certbot.issue(config.hostname);
    if (res.ok) {
      const le = readPair(fullchainPath(paths, config.hostname), privkeyPath(paths, config.hostname));
      if (le) {
        controlCert = le;
        controlCertReady = true;
        controlServer.reload();
        proxy.reload();
        log.info("control API upgraded to Let's Encrypt certificate");
      }
    } else {
      log.warn("control cert not yet obtainable; will retry", { code: res.errorCode });
    }
  };
  void ensureControlCert();

  // --- Timers ---
  const tickTimer = setInterval(() => {
    void manager.tick();
    void ensureControlCert();
  }, config.tick_interval_ms);

  const renewTimer = setInterval(() => {
    void (async () => {
      await manager.renewTick();
      // Refresh the control cert from disk after a renewal cycle.
      const le = readPair(fullchainPath(paths, config.hostname), privkeyPath(paths, config.hostname));
      if (le) {
        controlCert = le;
        controlCertReady = true;
        controlServer.reload();
      }
    })();
  }, RENEW_INTERVAL_MS);

  // Kick an immediate first tick.
  void manager.tick();

  // --- Graceful shutdown ---
  let shuttingDown = false;
  const shutdown = async (signal: string): Promise<void> => {
    if (shuttingDown) return;
    shuttingDown = true;
    log.info("shutting down", { signal });
    clearInterval(tickTimer);
    clearInterval(renewTimer);
    callback.stop();

    // Stop accepting new connections; let in-flight ones drain.
    proxy.stop(false);
    controlServer.stop(false);

    await callback.flushFinal();

    // Give live connections a bounded window to finish.
    await new Promise((r) => setTimeout(r, DRAIN_TIMEOUT_MS));
    proxy.stop(true);
    controlServer.stop(true);
    log.info("shutdown complete");
    process.exit(0);
  };

  process.on("SIGTERM", () => void shutdown("SIGTERM"));
  process.on("SIGINT", () => void shutdown("SIGINT"));
  process.on("uncaughtException", (err) => {
    log.error("uncaught exception", { err: err.message, stack: err.stack });
  });
  process.on("unhandledRejection", (reason) => {
    log.error("unhandled rejection", { reason: String(reason) });
  });

  log.info("proxy-agent ready");
}

if (import.meta.main) {
  main().catch((err) => {
    log.error("fatal error during startup", { err: (err as Error).message, stack: (err as Error).stack });
    process.exit(1);
  });
}
