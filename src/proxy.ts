// Public :443 listener: SNI-selected TLS termination and reverse proxy to each
// route's upstream. Handles ordinary HTTP (streaming, correct forwarded
// headers), WebSocket upgrades, upstream failure (502), and hot-reload of the
// TLS certificate set without dropping live connections.

import type { Server, ServerWebSocket, TLSOptions } from "bun";
import type { CertStoreLike } from "./certstore.ts";
import type { RouteManager } from "./manager.ts";
import type { RouteRuntime } from "./status.ts";
import { log } from "./logger.ts";

// Hop-by-hop headers must not be forwarded (RFC 7230 §6.1).
const HOP_BY_HOP = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
]);

const UPSTREAM_CONNECT_TIMEOUT_MS = 15_000;
const UPSTREAM_IDLE_TIMEOUT_S = 120;

export interface DefaultCertProvider {
  (): { cert: string; key: string } | null;
}

interface WsData {
  targetUrl: string;
  protocol: string | null;
  clientAddr: string;
  upstream: WebSocket | null;
  /** Messages received from the client before upstream finished connecting. */
  pending: (string | Uint8Array)[];
  closed: boolean;
}

export class ProxyServer {
  private server: Server<WsData> | null = null;

  constructor(
    private manager: RouteManager,
    private certStore: CertStoreLike,
    private getDefaultCert: DefaultCertProvider,
    private listenPort = 443,
  ) {}

  private buildTls(): TLSOptions | TLSOptions[] | undefined {
    const entries: TLSOptions[] = [];
    const def = this.getDefaultCert();
    // A default cert lets the socket bind and terminate handshakes for names we
    // don't serve; those requests then get a 421 at the HTTP layer. Clients
    // still reject the mismatched SAN, so unknown SNI never reaches an upstream.
    if (def) entries.push({ cert: def.cert, key: def.key });
    for (const c of this.certStore.all()) {
      entries.push({ cert: c.cert, key: c.key, serverName: c.hostname });
    }
    if (entries.length === 0) return undefined;
    return entries.length === 1 ? entries[0] : entries;
  }

  /**
   * Build the full Bun.serve options. Retained so reload() can re-pass the fetch
   * and websocket handlers (Bun.serve().reload requires them) alongside new TLS.
   */
  private serveOptions() {
    const self = this;
    return {
      port: this.listenPort,
      hostname: "0.0.0.0",
      idleTimeout: UPSTREAM_IDLE_TIMEOUT_S,
      tls: this.buildTls(),
      async fetch(req: Request, server: Server<WsData>) {
        return self.handleRequest(req, server);
      },
      websocket: {
        open(ws: ServerWebSocket<WsData>) {
          self.onWsOpen(ws);
        },
        message(ws: ServerWebSocket<WsData>, message: string | Uint8Array) {
          const up = ws.data.upstream;
          if (up && up.readyState === WebSocket.OPEN) up.send(message);
          else ws.data.pending.push(message);
        },
        close(ws: ServerWebSocket<WsData>, code: number, reason: string) {
          ws.data.closed = true;
          const up = ws.data.upstream;
          if (up && (up.readyState === WebSocket.OPEN || up.readyState === WebSocket.CONNECTING)) {
            try {
              up.close(normalizeCloseCode(code), reason);
            } catch {
              /* ignore */
            }
          }
        },
      },
      error(err: Error) {
        log.error(":443 listener error", { err: err.message });
        return new Response("internal error", { status: 500 });
      },
    };
  }

  start(): Server<WsData> {
    this.server = Bun.serve<WsData>(this.serveOptions());
    log.info("proxy listener started", { port: this.listenPort, certs: this.certStore.all().length });
    return this.server;
  }

  /**
   * Hot-reload the TLS cert set without dropping live connections. Re-passes the
   * full options (fetch + websocket handlers) with the freshly-built TLS array,
   * as Bun.serve().reload() requires a handler to be present.
   */
  reload(): void {
    if (!this.server) return;
    try {
      this.server.reload(this.serveOptions());
      log.info("proxy TLS reloaded", { certs: this.certStore.all().length });
    } catch (err) {
      log.error("proxy TLS reload failed", { err: (err as Error).message });
    }
  }

  stop(closeActive = false): void {
    this.server?.stop(closeActive);
  }

  private clientAddress(req: Request, server: Server<WsData>): string {
    const ip = server.requestIP(req);
    return ip?.address ?? "";
  }

  private async handleRequest(req: Request, server: Server<WsData>): Promise<Response> {
    const url = new URL(req.url);
    const host = (req.headers.get("host") ?? url.hostname).split(":")[0]!.toLowerCase();
    const route = this.manager.targetForHostname(host);

    if (!route) {
      // Known cert but no active route, or unknown host entirely.
      return new Response("unknown host", { status: 421 });
    }

    const clientAddr = this.clientAddress(req, server);

    // WebSocket upgrade?
    if (req.headers.get("upgrade")?.toLowerCase() === "websocket") {
      return this.handleUpgrade(req, url, route, clientAddr, server);
    }

    return this.handleHttp(req, url, route, clientAddr);
  }

  private buildForwardHeaders(req: Request, route: RouteRuntime, clientAddr: string): Headers {
    const headers = new Headers();
    for (const [k, v] of req.headers) {
      if (HOP_BY_HOP.has(k.toLowerCase())) continue;
      headers.set(k, v);
    }
    const origHost = req.headers.get("host") ?? route.hostname;
    const priorXff = req.headers.get("x-forwarded-for");
    headers.set("x-forwarded-for", priorXff && clientAddr ? `${priorXff}, ${clientAddr}` : clientAddr || priorXff || "");
    headers.set("x-forwarded-proto", "https");
    headers.set("x-forwarded-host", origHost);
    headers.set("x-real-ip", clientAddr);
    // Preserve the original Host so name-based vhosts upstream resolve correctly.
    headers.set("host", origHost);
    return headers;
  }

  private async handleHttp(
    req: Request,
    url: URL,
    route: RouteRuntime,
    clientAddr: string,
  ): Promise<Response> {
    const targetUrl = `${route.target_scheme}://${route.target_host}:${route.target_port}${url.pathname}${url.search}`;
    const headers = this.buildForwardHeaders(req, route, clientAddr);
    const method = req.method;
    const hasBody = method !== "GET" && method !== "HEAD";

    const init: RequestInit & { duplex?: "half"; tls?: { rejectUnauthorized: boolean } } = {
      method,
      headers,
      redirect: "manual",
      signal: AbortSignal.timeout(UPSTREAM_CONNECT_TIMEOUT_MS),
    };
    if (hasBody && req.body) {
      init.body = req.body;
      init.duplex = "half";
    }

    let upstream: Response;
    try {
      upstream = await fetch(targetUrl, init as RequestInit);
    } catch (err) {
      log.warn("upstream request failed", {
        hostname: route.hostname,
        target: `${route.target_host}:${route.target_port}`,
        err: (err as Error).message,
      });
      return badGateway();
    }

    // Strip hop-by-hop headers from the response too.
    const respHeaders = new Headers();
    for (const [k, v] of upstream.headers) {
      if (HOP_BY_HOP.has(k.toLowerCase())) continue;
      respHeaders.set(k, v);
    }
    return new Response(upstream.body, { status: upstream.status, statusText: upstream.statusText, headers: respHeaders });
  }

  private handleUpgrade(
    req: Request,
    url: URL,
    route: RouteRuntime,
    clientAddr: string,
    server: Server<WsData>,
  ): Response {
    const wsScheme = route.target_scheme === "https" ? "wss" : "ws";
    const targetUrl = `${wsScheme}://${route.target_host}:${route.target_port}${url.pathname}${url.search}`;
    const protocol = req.headers.get("sec-websocket-protocol");
    const data: WsData = {
      targetUrl,
      protocol,
      clientAddr,
      upstream: null,
      pending: [],
      closed: false,
    };
    const ok = server.upgrade(req, { data });
    if (ok) {
      // Response is handled by Bun once upgraded.
      return undefined as unknown as Response;
    }
    return new Response("websocket upgrade failed", { status: 400 });
  }

  private onWsOpen(ws: ServerWebSocket<WsData>): void {
    const { targetUrl, protocol } = ws.data;
    let upstream: WebSocket;
    try {
      upstream = protocol ? new WebSocket(targetUrl, protocol.split(",").map((s) => s.trim())) : new WebSocket(targetUrl);
    } catch (err) {
      log.warn("upstream ws connect failed", { err: (err as Error).message });
      ws.close(1011, "upstream unavailable");
      return;
    }
    upstream.binaryType = "arraybuffer";
    ws.data.upstream = upstream;

    upstream.addEventListener("open", () => {
      for (const m of ws.data.pending) upstream.send(m);
      ws.data.pending = [];
    });
    upstream.addEventListener("message", (ev: MessageEvent) => {
      if (ws.data.closed) return;
      const d = ev.data;
      if (typeof d === "string") ws.send(d);
      else if (d instanceof ArrayBuffer) ws.send(new Uint8Array(d));
      else ws.send(d as Uint8Array);
    });
    upstream.addEventListener("close", (ev: CloseEvent) => {
      if (!ws.data.closed) {
        try {
          ws.close(normalizeCloseCode(ev.code), ev.reason);
        } catch {
          /* ignore */
        }
      }
    });
    upstream.addEventListener("error", () => {
      if (!ws.data.closed) {
        try {
          ws.close(1011, "upstream error");
        } catch {
          /* ignore */
        }
      }
    });
  }
}

/** Close codes 1005/1006/1015 are reserved and must not be sent on the wire. */
function normalizeCloseCode(code: number): number {
  if (code === 1005 || code === 1006 || code === 1015 || code < 1000 || code > 4999) return 1000;
  return code;
}

function badGateway(): Response {
  const body = `<!doctype html><meta charset="utf-8"><title>502 Bad Gateway</title>
<style>body{font-family:system-ui,sans-serif;margin:4rem auto;max-width:32rem;color:#333}</style>
<h1>502 Bad Gateway</h1><p>The upstream service is not responding. Please try again shortly.</p>`;
  return new Response(body, {
    status: 502,
    headers: { "content-type": "text/html; charset=utf-8" },
  });
}

// Exported for unit tests.
export const _internal = { HOP_BY_HOP, normalizeCloseCode };
