import { describe, it, expect, beforeEach, afterEach } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { RouteManager, type ManagerDeps } from "../src/manager.ts";
import { makePaths } from "../src/paths.ts";
import type { CertStoreLike, LoadedCert } from "../src/certstore.ts";
import type { CertbotLike, CertOpResult } from "../src/certbot.ts";
import type { Config } from "../src/config.ts";
import type { RouteDesired } from "../src/types.ts";

// --- Fakes -------------------------------------------------------------------
class FakeCertStore implements CertStoreLike {
  certs = new Map<string, LoadedCert>();
  issue(hostname: string) {
    this.certs.set(hostname, {
      hostname,
      cert: "CERT",
      key: "KEY",
      expiresAt: new Date(Date.now() + 60 * 86400_000),
    });
  }
  load(hostname: string) {
    return this.certs.get(hostname) ?? null;
  }
  get(hostname: string) {
    return this.certs.get(hostname);
  }
  remove(hostname: string) {
    this.certs.delete(hostname);
  }
  all() {
    return [...this.certs.values()];
  }
  has(hostname: string) {
    return this.certs.has(hostname);
  }
}

class FakeCertbot implements CertbotLike {
  issueCalls = 0;
  renewCalls = 0;
  fail = false;
  constructor(private store: FakeCertStore) {}
  async issue(hostname: string): Promise<CertOpResult> {
    this.issueCalls++;
    if (this.fail) return { ok: false, errorCode: "acme_challenge_failed", sanitizedMessage: "nope" };
    this.store.issue(hostname); // simulate certbot writing the cert to disk
    return { ok: true, errorCode: null, sanitizedMessage: null };
  }
  async renewAll(): Promise<CertOpResult> {
    this.renewCalls++;
    return { ok: true, errorCode: null, sanitizedMessage: null };
  }
}

function baseConfig(over: Partial<Config> = {}): Config {
  return {
    control_port: 8443,
    api_key: "x".repeat(20),
    hostname: "node1.example.com",
    panel_callback_url: "https://panel/cb",
    node_token: "y".repeat(20),
    letsencrypt_email: "ops@example.com",
    acme_staging: true,
    state_dir: "/unused",
    log_level: "error",
    callback_interval_ms: 30000,
    tick_interval_ms: 15000,
    renew_before_days: 30,
    allow_link_local_targets: false,
    cleanup_certs_on_removal: false,
    ...over,
  };
}

const ROUTE: RouteDesired = {
  id: "11111111-1111-4111-8111-111111111111",
  hostname: "play.example.com",
  expected_ip: "203.0.113.10",
  target_host: "127.0.0.1",
  target_port: 8080,
  target_scheme: "http",
};

const settle = () => new Promise((r) => setTimeout(r, 5));

let dir: string;
let store: FakeCertStore;
let certbot: FakeCertbot;
let resolved: string[];
let certsChanged: number;
let statusChanged: number;

function makeManager(cfg?: Partial<Config>): RouteManager {
  const paths = makePaths(dir);
  const deps: ManagerDeps = {
    config: baseConfig(cfg),
    paths,
    certbot,
    certStore: store,
    resolver: async () => resolved,
    onCertsChanged: () => {
      certsChanged++;
    },
    onStatusChanged: () => {
      statusChanged++;
    },
  };
  return new RouteManager(deps);
}

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "mgr-test-"));
  store = new FakeCertStore();
  certbot = new FakeCertbot(store);
  resolved = [];
  certsChanged = 0;
  statusChanged = 0;
});

afterEach(() => rmSync(dir, { recursive: true, force: true }));

describe("RouteManager state machine", () => {
  it("progresses DNS pending → mismatch → ok → cert active → proxy active", async () => {
    const mgr = makeManager();
    mgr.init();

    // Add route; DNS not resolving yet.
    mgr.applyDesired([ROUTE]);
    await settle();
    let s = mgr.getStatus(ROUTE.id)!;
    expect(s.dns_status).toBe("pending");
    expect(s.cert_status).toBe("pending");
    expect(s.proxy_status).toBe("pending");

    // DNS resolves to the wrong IP -> mismatch, still no cert.
    resolved = ["198.51.100.9"];
    await mgr.tick();
    s = mgr.getStatus(ROUTE.id)!;
    expect(s.dns_status).toBe("mismatch");
    expect(s.resolved_ip).toBe("198.51.100.9");
    expect(certbot.issueCalls).toBe(0);

    // DNS correct -> cert issued -> proxy active.
    resolved = ["203.0.113.10"];
    await mgr.tick();
    s = mgr.getStatus(ROUTE.id)!;
    expect(s.dns_status).toBe("ok");
    expect(certbot.issueCalls).toBe(1);
    expect(s.cert_status).toBe("active");
    expect(s.cert_expires_at).not.toBeNull();
    expect(s.proxy_status).toBe("active");

    // Proxy target is resolvable.
    expect(mgr.targetForHostname("play.example.com")?.target_port).toBe(8080);
  });

  it("does not re-issue when a cert is already active (idempotent ticks)", async () => {
    const mgr = makeManager();
    mgr.init();
    resolved = ["203.0.113.10"];
    mgr.applyDesired([ROUTE]);
    await settle();
    await mgr.tick();
    expect(certbot.issueCalls).toBe(1);
    await mgr.tick();
    await mgr.tick();
    expect(certbot.issueCalls).toBe(1);
  });

  it("applyDesired is idempotent (same set = no duplicate routes)", async () => {
    const mgr = makeManager();
    mgr.init();
    mgr.applyDesired([ROUTE]);
    mgr.applyDesired([ROUTE]);
    await settle();
    expect(mgr.routeCount()).toBe(1);
  });

  it("backs off on cert failure and retries later", async () => {
    const mgr = makeManager();
    mgr.init();
    certbot.fail = true;
    resolved = ["203.0.113.10"];
    mgr.applyDesired([ROUTE]);
    await settle();
    await mgr.tick();
    const s = mgr.getStatus(ROUTE.id)!;
    expect(s.cert_status).toBe("failed");
    expect(s.last_error_code).toBe("acme_challenge_failed");
    const callsAfterFirst = certbot.issueCalls;
    // Immediate next tick should NOT retry (backoff window not elapsed).
    await mgr.tick();
    expect(certbot.issueCalls).toBe(callsAfterFirst);
  });

  it("removes a route on sync and via DELETE", async () => {
    const mgr = makeManager();
    mgr.init();
    resolved = ["203.0.113.10"];
    mgr.applyDesired([ROUTE]);
    await settle();
    await mgr.tick();
    expect(mgr.routeCount()).toBe(1);

    // Full sync to empty removes it.
    mgr.applyDesired([]);
    expect(mgr.routeCount()).toBe(0);
    expect(mgr.getStatus(ROUTE.id)).toBeUndefined();

    // Re-add then DELETE.
    mgr.applyDesired([ROUTE]);
    expect(mgr.removeRoute(ROUTE.id)).toBe(true);
    expect(mgr.removeRoute(ROUTE.id)).toBe(false);
  });

  it("cleans up cert files only when configured", async () => {
    const mgr = makeManager({ cleanup_certs_on_removal: true });
    mgr.init();
    resolved = ["203.0.113.10"];
    mgr.applyDesired([ROUTE]);
    await settle();
    await mgr.tick();
    expect(store.has("play.example.com")).toBe(true);
    mgr.applyDesired([]);
    expect(store.has("play.example.com")).toBe(false);
  });

  it("resumes from persisted state after restart without re-issuing", async () => {
    const mgr1 = makeManager();
    mgr1.init();
    resolved = ["203.0.113.10"];
    mgr1.applyDesired([ROUTE]);
    await settle();
    await mgr1.tick();
    expect(certbot.issueCalls).toBe(1);

    // Simulate restart: new manager, same state dir + same (persisted) cert store.
    const mgr2 = makeManager();
    mgr2.init();
    const s = mgr2.getStatus(ROUTE.id)!;
    // Cert was loaded from "disk" on init -> active immediately.
    expect(s.cert_status).toBe("active");
    await mgr2.tick();
    // No new issuance needed.
    expect(certbot.issueCalls).toBe(1);
    expect(mgr2.getStatus(ROUTE.id)!.proxy_status).toBe("active");
  });

  it("renewTick renews and keeps certs active", async () => {
    const mgr = makeManager();
    mgr.init();
    resolved = ["203.0.113.10"];
    mgr.applyDesired([ROUTE]);
    await settle();
    await mgr.tick();
    await mgr.renewTick();
    expect(certbot.renewCalls).toBe(1);
    expect(mgr.getStatus(ROUTE.id)!.cert_status).toBe("active");
  });

  it("rejects invalid desired routes (throws → 400)", () => {
    const mgr = makeManager();
    mgr.init();
    expect(() => mgr.applyDesired([{ ...ROUTE, target_host: "169.254.169.254" }])).toThrow(/link-local/);
    expect(() => mgr.applyDesired("nope")).toThrow(/must be an array/);
  });
});
