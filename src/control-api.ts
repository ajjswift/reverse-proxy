// Control API (panel → agent), served over TLS on the control port. Versioned
// under /v1, JSON, bearer-authenticated with a constant-time token compare.
// Every endpoint rejects unauthenticated calls.

import { timingSafeEqual } from "node:crypto";
import type { Server, TLSOptions } from "bun";
import type { Config } from "./config.ts";
import type { RouteManager } from "./manager.ts";
import type { HealthResponse } from "./types.ts";
import { VERSION } from "./version.ts";
import { log } from "./logger.ts";

export interface ControlCert {
  cert: string;
  key: string;
}

export interface ControlServerDeps {
  config: Config;
  manager: RouteManager;
  getControlCert: () => ControlCert;
  controlCertReady: () => boolean;
  startedAtMs: number;
}

/** Constant-time comparison that also doesn't leak length via early return. */
export function safeTokenEqual(provided: string, expected: string): boolean {
  const a = Buffer.from(provided);
  const b = Buffer.from(expected);
  if (a.length !== b.length) {
    // Compare a against itself to keep timing roughly constant, then fail.
    timingSafeEqual(a, a);
    return false;
  }
  return timingSafeEqual(a, b);
}

function extractBearer(req: Request): string | null {
  const h = req.headers.get("authorization");
  if (!h) return null;
  const m = h.match(/^Bearer\s+(.+)$/i);
  return m ? m[1]!.trim() : null;
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

const UUID_RE = /^[0-9a-fA-F-]{36}$/;

export class ControlServer {
  private server: Server<undefined> | null = null;

  constructor(private deps: ControlServerDeps) {}

  private tls(): TLSOptions {
    const c = this.deps.getControlCert();
    return { cert: c.cert, key: c.key };
  }

  private serveOptions() {
    const self = this;
    return {
      port: this.deps.config.control_port,
      hostname: "0.0.0.0",
      idleTimeout: 30,
      tls: this.tls(),
      async fetch(req: Request) {
        return self.handle(req);
      },
      error(err: Error) {
        log.error("control API error", { err: err.message });
        return json({ error: "internal_error" }, 500);
      },
    };
  }

  start(): Server<undefined> {
    this.server = Bun.serve(this.serveOptions());
    log.info("control API started", { port: this.deps.config.control_port });
    return this.server;
  }

  /** Hot-reload control-API TLS (e.g. when the LE cert supersedes bootstrap). */
  reload(): void {
    if (!this.server) return;
    try {
      this.server.reload(this.serveOptions());
      log.info("control API TLS reloaded");
    } catch (err) {
      log.error("control API TLS reload failed", { err: (err as Error).message });
    }
  }

  stop(closeActive = false): void {
    this.server?.stop(closeActive);
  }

  private authed(req: Request): boolean {
    const token = extractBearer(req);
    if (!token) return false;
    return safeTokenEqual(token, this.deps.config.api_key);
  }

  private async handle(req: Request): Promise<Response> {
    const url = new URL(req.url);
    const path = url.pathname.replace(/\/+$/, "") || "/";

    if (!path.startsWith("/v1/") && path !== "/v1") {
      return json({ error: "not_found" }, 404);
    }

    // Authenticate everything under /v1.
    if (!this.authed(req)) {
      return new Response(JSON.stringify({ error: "unauthorized" }), {
        status: 401,
        headers: { "content-type": "application/json", "www-authenticate": "Bearer" },
      });
    }

    const { manager } = this.deps;

    if (path === "/v1/health" && req.method === "GET") {
      const body: HealthResponse = {
        version: VERSION,
        uptime_seconds: Math.floor((Date.now() - this.deps.startedAtMs) / 1000),
        control_cert_ready: this.deps.controlCertReady(),
        acme_staging: this.deps.config.acme_staging,
      };
      return json(body);
    }

    if (path === "/v1/routes") {
      if (req.method === "GET") return json({ routes: manager.getStatuses() });
      if (req.method === "PUT") {
        let parsed: unknown;
        try {
          parsed = await req.json();
        } catch {
          return json({ error: "invalid_json" }, 400);
        }
        const routes = (parsed as { routes?: unknown })?.routes;
        try {
          const statuses = manager.applyDesired(routes);
          return json({ routes: statuses });
        } catch (err) {
          return json({ error: "invalid_routes", message: (err as Error).message }, 400);
        }
      }
      return json({ error: "method_not_allowed" }, 405);
    }

    const idMatch = path.match(/^\/v1\/routes\/([^/]+)$/);
    if (idMatch) {
      const id = decodeURIComponent(idMatch[1]!);
      if (!UUID_RE.test(id)) return json({ error: "invalid_id" }, 400);
      if (req.method === "GET") {
        const status = manager.getStatus(id);
        return status ? json(status) : json({ error: "not_found" }, 404);
      }
      if (req.method === "DELETE") {
        const removed = manager.removeRoute(id);
        return removed ? json({ removed: true, id }) : json({ error: "not_found" }, 404);
      }
      return json({ error: "method_not_allowed" }, 405);
    }

    return json({ error: "not_found" }, 404);
  }
}
