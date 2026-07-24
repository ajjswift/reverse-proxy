// End-to-end proxy integration test that runs anywhere (no real Let's Encrypt):
// a live local upstream, a self-signed cert, the real RouteManager + ProxyServer
// on a high port, exercising HTTP forwarding, forwarded headers, WebSocket
// proxying, and 502 on upstream failure. The full LE-staging lifecycle is
// covered separately by scripts/smoke-test.sh.

import { describe, it, expect, beforeAll, afterAll } from "bun:test";
import { mkdtempSync, rmSync, mkdirSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Server } from "bun";
import { ProxyServer } from "../../src/proxy.ts";
import { RouteManager } from "../../src/manager.ts";
import { makePaths, liveCertDir, fullchainPath, privkeyPath } from "../../src/paths.ts";
import type { CertStoreLike, LoadedCert } from "../../src/certstore.ts";
import type { CertbotLike, CertOpResult } from "../../src/certbot.ts";
import { parseCertExpiry } from "../../src/certstore.ts";
import type { Config } from "../../src/config.ts";

const HOST = "localhost";
const PROXY_PORT = 19500 + Math.floor(Math.random() * 300);

let dir: string;
let upstream: Server<undefined>;
let upstreamPort: number;
let proxy: ProxyServer;
let manager: RouteManager;
let savedRejectUnauthorized: string | undefined;

class SharedCertStore implements CertStoreLike {
  certs = new Map<string, LoadedCert>();
  load(h: string) {
    return this.certs.get(h) ?? null;
  }
  get(h: string) {
    return this.certs.get(h);
  }
  remove(h: string) {
    this.certs.delete(h);
  }
  all() {
    return [...this.certs.values()];
  }
  has(h: string) {
    return this.certs.has(h);
  }
}

const noopCertbot: CertbotLike = {
  async issue(): Promise<CertOpResult> {
    return { ok: true, errorCode: null, sanitizedMessage: null };
  },
  async renewAll(): Promise<CertOpResult> {
    return { ok: true, errorCode: null, sanitizedMessage: null };
  },
};

function config(): Config {
  return {
    control_port: 8443,
    api_key: "x".repeat(20),
    hostname: "node.example.com",
    panel_callback_url: "https://panel/cb",
    node_token: "y".repeat(20),
    letsencrypt_email: "ops@example.com",
    acme_staging: true,
    state_dir: dir,
    log_level: "error",
    callback_interval_ms: 30000,
    tick_interval_ms: 15000,
    renew_before_days: 30,
    allow_link_local_targets: false,
    cleanup_certs_on_removal: false,
  };
}

beforeAll(async () => {
  savedRejectUnauthorized = process.env.NODE_TLS_REJECT_UNAUTHORIZED;
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"; // self-signed cert in this test

  dir = mkdtempSync(join(tmpdir(), "proxy-int-"));

  // Self-signed cert for localhost.
  const paths = makePaths(dir);
  mkdirSync(liveCertDir(paths, HOST), { recursive: true });
  const res = Bun.spawnSync([
    "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
    "-keyout", privkeyPath(paths, HOST), "-out", fullchainPath(paths, HOST),
    "-days", "5", "-subj", `/CN=${HOST}`, "-addext", `subjectAltName=DNS:${HOST}`,
  ]);
  if (res.exitCode !== 0) throw new Error("openssl failed: " + res.stderr.toString());
  const cert = readFileSync(fullchainPath(paths, HOST), "utf8");
  const key = readFileSync(privkeyPath(paths, HOST), "utf8");

  // Live upstream: HTTP echo + WebSocket echo.
  upstream = Bun.serve({
    port: 0,
    fetch(req, server) {
      const url = new URL(req.url);
      if (url.pathname === "/ws") {
        if (server.upgrade(req)) return undefined as unknown as Response;
        return new Response("expected ws", { status: 400 });
      }
      return Response.json({
        method: req.method,
        path: url.pathname,
        xff: req.headers.get("x-forwarded-for"),
        xfproto: req.headers.get("x-forwarded-proto"),
        host: req.headers.get("host"),
      });
    },
    websocket: {
      message(ws, msg) {
        ws.send(`echo:${msg}`);
      },
    },
  });
  upstreamPort = upstream.port!;

  // Cert store shared by manager + proxy, pre-seeded with the localhost cert.
  const store = new SharedCertStore();
  store.certs.set(HOST, { hostname: HOST, cert, key, expiresAt: parseCertExpiry(cert) });

  manager = new RouteManager({
    config: config(),
    paths,
    certbot: noopCertbot,
    certStore: store,
    resolver: async () => ["127.0.0.1"],
    onCertsChanged: () => proxy.reload(),
    onStatusChanged: () => {},
  });
  manager.init();

  proxy = new ProxyServer(manager, store, () => ({ cert, key }), PROXY_PORT);
  proxy.start();

  // Declare the route and drive the state machine until proxy is active.
  manager.applyDesired([
    {
      id: "11111111-1111-4111-8111-111111111111",
      hostname: HOST,
      expected_ip: "127.0.0.1",
      target_host: "127.0.0.1",
      target_port: upstreamPort,
      target_scheme: "http",
    },
  ]);
  await manager.tick();
  proxy.reload();
});

afterAll(() => {
  proxy?.stop(true);
  upstream?.stop(true);
  rmSync(dir, { recursive: true, force: true });
  if (savedRejectUnauthorized === undefined) delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;
  else process.env.NODE_TLS_REJECT_UNAUTHORIZED = savedRejectUnauthorized;
});

describe("proxy integration (HTTP)", () => {
  it("forwards a GET to the upstream with forwarded headers", async () => {
    const res = await fetch(`https://${HOST}:${PROXY_PORT}/hello`);
    expect(res.status).toBe(200);
    const body = (await res.json()) as any;
    expect(body.path).toBe("/hello");
    expect(body.xfproto).toBe("https");
    expect(body.host).toBe(`${HOST}:${PROXY_PORT}`);
    expect(body.xff).toBeTruthy();
  });

  it("streams a POST body to the upstream", async () => {
    const res = await fetch(`https://${HOST}:${PROXY_PORT}/echo`, { method: "POST", body: "payload" });
    const body = (await res.json()) as any;
    expect(body.method).toBe("POST");
    expect(body.path).toBe("/echo");
  });

  it("returns 421 for an unknown host / no active route", async () => {
    // Connect with SNI for a name we don't serve → handled at HTTP layer as 421.
    const res = await fetch(`https://127.0.0.1:${PROXY_PORT}/`, { headers: { host: "nope.example.com" } });
    expect(res.status).toBe(421);
  });
});

describe("proxy integration (WebSocket)", () => {
  it("proxies a websocket echo end-to-end", async () => {
    const ws = new WebSocket(`wss://${HOST}:${PROXY_PORT}/ws`);
    const reply = await new Promise<string>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("ws timeout")), 5000);
      ws.addEventListener("open", () => ws.send("ping"));
      ws.addEventListener("message", (ev) => {
        clearTimeout(timer);
        resolve(String((ev as MessageEvent).data));
      });
      ws.addEventListener("error", () => {
        clearTimeout(timer);
        reject(new Error("ws error"));
      });
    });
    expect(reply).toBe("echo:ping");
    ws.close();
  });
});

describe("proxy integration (upstream failure)", () => {
  it("returns 502 when the upstream is down", async () => {
    upstream.stop(true); // kill the upstream
    const res = await fetch(`https://${HOST}:${PROXY_PORT}/hello`);
    expect(res.status).toBe(502);
    expect(await res.text()).toContain("502 Bad Gateway");
  });
});
