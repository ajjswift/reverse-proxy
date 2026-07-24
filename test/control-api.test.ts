import { describe, it, expect, beforeAll, afterAll } from "bun:test";
import { mkdtempSync, rmSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ControlServer, safeTokenEqual } from "../src/control-api.ts";
import type { RouteManager } from "../src/manager.ts";
import type { Config } from "../src/config.ts";
import type { RouteStatus } from "../src/types.ts";

const API_KEY = "test-api-key-0123456789";
const PORT = 18443 + Math.floor(Math.random() * 500);

// A minimal stand-in for RouteManager exposing just what the API calls.
class StubManager {
  routes = new Map<string, RouteStatus>();
  applyCalls: unknown[] = [];
  getStatuses(): RouteStatus[] {
    return [...this.routes.values()];
  }
  getStatus(id: string) {
    return this.routes.get(id);
  }
  applyDesired(raw: unknown): RouteStatus[] {
    this.applyCalls.push(raw);
    if (!Array.isArray(raw)) throw new Error("routes must be an array");
    for (const r of raw as { id: string; hostname: string }[]) {
      this.routes.set(r.id, sampleStatus(r.id, r.hostname));
    }
    return this.getStatuses();
  }
  removeRoute(id: string): boolean {
    return this.routes.delete(id);
  }
}

function sampleStatus(id: string, hostname: string): RouteStatus {
  return {
    id,
    hostname,
    dns_status: "ok",
    resolved_ip: "203.0.113.10",
    expected_ip: "203.0.113.10",
    cert_status: "active",
    cert_expires_at: "2026-10-01T00:00:00.000Z",
    proxy_status: "active",
    last_error_code: null,
    sanitized_message: null,
    updated_at: "2026-07-24T00:00:00.000Z",
  };
}

let dir: string;
let server: ControlServer;
let manager: StubManager;
const ID = "11111111-1111-4111-8111-111111111111";

function config(): Config {
  return {
    control_port: PORT,
    api_key: API_KEY,
    hostname: "node1.example.com",
    panel_callback_url: "https://panel/cb",
    node_token: "n".repeat(20),
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

// Bun fetch to a self-signed endpoint.
function api(path: string, init: RequestInit = {}, token = API_KEY) {
  const headers = new Headers(init.headers);
  if (token) headers.set("authorization", `Bearer ${token}`);
  return fetch(`https://127.0.0.1:${PORT}${path}`, {
    ...init,
    headers,
    tls: { rejectUnauthorized: false },
  } as RequestInit);
}

beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), "ctl-test-"));
  const certPath = join(dir, "cert.pem");
  const keyPath = join(dir, "key.pem");
  const res = Bun.spawnSync([
    "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
    "-keyout", keyPath, "-out", certPath, "-days", "5",
    "-subj", "/CN=node1.example.com",
    "-addext", "subjectAltName=DNS:node1.example.com",
  ]);
  if (res.exitCode !== 0) throw new Error("openssl failed: " + res.stderr.toString());
  const cert = readFileSync(certPath, "utf8");
  const key = readFileSync(keyPath, "utf8");

  manager = new StubManager();
  server = new ControlServer({
    config: config(),
    manager: manager as unknown as RouteManager,
    getControlCert: () => ({ cert, key }),
    controlCertReady: () => true,
    startedAtMs: Date.now() - 5000,
  });
  server.start();
});

afterAll(() => {
  server.stop(true);
  rmSync(dir, { recursive: true, force: true });
});

describe("control API auth", () => {
  it("rejects missing token with 401", async () => {
    const res = await api("/v1/health", {}, "");
    expect(res.status).toBe(401);
  });
  it("rejects wrong token with 401", async () => {
    const res = await api("/v1/health", {}, "wrong-token-value-123456");
    expect(res.status).toBe(401);
  });
});

describe("control API endpoints", () => {
  it("GET /v1/health returns agent info", async () => {
    const res = await api("/v1/health");
    expect(res.status).toBe(200);
    const body = (await res.json()) as any;
    expect(body.control_cert_ready).toBe(true);
    expect(body.acme_staging).toBe(true);
    expect(typeof body.uptime_seconds).toBe("number");
    expect(typeof body.version).toBe("string");
  });

  it("PUT /v1/routes syncs and returns statuses", async () => {
    const res = await api("/v1/routes", {
      method: "PUT",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        routes: [
          {
            id: ID,
            hostname: "play.example.com",
            expected_ip: "203.0.113.10",
            target_host: "127.0.0.1",
            target_port: 8080,
            target_scheme: "http",
          },
        ],
      }),
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as any;
    expect(body.routes.length).toBe(1);
    expect(body.routes[0].hostname).toBe("play.example.com");
  });

  it("GET /v1/routes lists routes", async () => {
    const res = await api("/v1/routes");
    const body = (await res.json()) as any;
    expect(body.routes.some((r: RouteStatus) => r.id === ID)).toBe(true);
  });

  it("GET /v1/routes/{id} returns one route or 404", async () => {
    const ok = await api(`/v1/routes/${ID}`);
    expect(ok.status).toBe(200);
    const missing = await api("/v1/routes/22222222-2222-4222-8222-222222222222");
    expect(missing.status).toBe(404);
  });

  it("PUT with invalid JSON → 400", async () => {
    const res = await api("/v1/routes", {
      method: "PUT",
      headers: { "content-type": "application/json" },
      body: "{not json",
    });
    expect(res.status).toBe(400);
  });

  it("DELETE removes a route", async () => {
    const res = await api(`/v1/routes/${ID}`, { method: "DELETE" });
    expect(res.status).toBe(200);
    const again = await api(`/v1/routes/${ID}`, { method: "DELETE" });
    expect(again.status).toBe(404);
  });

  it("unknown path → 404", async () => {
    const res = await api("/v1/nope");
    expect(res.status).toBe(404);
  });
});

describe("safeTokenEqual", () => {
  it("matches equal tokens and rejects others", () => {
    expect(safeTokenEqual("abc123", "abc123")).toBe(true);
    expect(safeTokenEqual("abc123", "abc124")).toBe(false);
    expect(safeTokenEqual("short", "longertoken")).toBe(false);
    expect(safeTokenEqual("", "")).toBe(true);
  });
});
