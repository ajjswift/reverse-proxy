// The route manager: owns the desired/observed state for every route and drives
// the DNS → cert → proxy state machine. It is the single source of truth for
// status. All mutation goes through here so persistence and change-notification
// stay consistent.

import { rmSync } from "node:fs";
import type { Config } from "./config.ts";
import type { Paths } from "./paths.ts";
import { liveCertDir } from "./paths.ts";
import type { RouteDesired, RouteStatus, PersistedRoute } from "./types.ts";
import type { CertbotLike } from "./certbot.ts";
import type { CertStoreLike } from "./certstore.ts";
import { checkDns, type HostResolver } from "./dns.ts";
import { reconcile, validateDesiredRoute } from "./reconciler.ts";
import { buildRouteStatus, type RouteRuntime } from "./status.ts";
import { saveState, loadState } from "./state.ts";
import { log } from "./logger.ts";

export interface ManagerDeps {
  config: Config;
  paths: Paths;
  certbot: CertbotLike;
  certStore: CertStoreLike;
  resolver: HostResolver;
  /** Called when the set of usable certs changes so listeners can hot-reload TLS. */
  onCertsChanged: () => void;
  /** Called (debounced by the caller) whenever any route status changes. */
  onStatusChanged: () => void;
  /** Clock, injectable for tests. */
  now?: () => number;
}

const MAX_ISSUE_BACKOFF_MS = 30 * 60 * 1000; // 30 min
const INITIAL_ISSUE_BACKOFF_MS = 60 * 1000; // 1 min

function nowIso(now: number): string {
  return new Date(now).toISOString();
}

export class RouteManager {
  private routes = new Map<string, RouteRuntime>();
  private now: () => number;
  private ticking = false;

  constructor(private deps: ManagerDeps) {
    this.now = deps.now ?? Date.now;
  }

  /** Load persisted state and certs from disk on boot. */
  init(): void {
    const persisted = loadState(this.deps.paths.stateFile);
    for (const p of persisted) {
      const rt = this.runtimeFromPersisted(p);
      this.routes.set(rt.id, rt);
      // Warm the cert cache so proxying resumes immediately after restart.
      const loaded = this.deps.certStore.load(rt.hostname);
      if (loaded) {
        rt.cert_status = "active";
        rt.cert_expires_at = loaded.expiresAt.toISOString();
      }
    }
    log.info("manager initialised", { routes: this.routes.size });
  }

  private runtimeFromPersisted(p: PersistedRoute): RouteRuntime {
    return {
      id: p.desired.id,
      hostname: p.desired.hostname,
      expected_ip: p.desired.expected_ip,
      target_host: p.desired.target_host,
      target_port: p.desired.target_port,
      target_scheme: p.desired.target_scheme,
      dns_status: p.dns_status,
      resolved_ip: p.resolved_ip,
      cert_status: p.cert_status === "issuing" || p.cert_status === "renewing" ? "pending" : p.cert_status,
      cert_expires_at: p.cert_expires_at,
      proxy_status: p.proxy_status === "active" ? "pending" : p.proxy_status,
      last_error_code: p.last_error_code,
      sanitized_message: p.sanitized_message,
      updated_at: p.updated_at,
      nextIssueAttempt: 0,
      issueBackoffMs: INITIAL_ISSUE_BACKOFF_MS,
    };
  }

  private newRuntime(d: RouteDesired): RouteRuntime {
    return {
      id: d.id,
      hostname: d.hostname,
      expected_ip: d.expected_ip,
      target_host: d.target_host,
      target_port: d.target_port,
      target_scheme: d.target_scheme,
      dns_status: "pending",
      resolved_ip: null,
      cert_status: "pending",
      cert_expires_at: null,
      proxy_status: "pending",
      last_error_code: null,
      sanitized_message: null,
      updated_at: nowIso(this.now()),
      nextIssueAttempt: 0,
      issueBackoffMs: INITIAL_ISSUE_BACKOFF_MS,
    };
  }

  private applyDesiredFields(rt: RouteRuntime, d: RouteDesired): void {
    rt.expected_ip = d.expected_ip;
    rt.target_host = d.target_host;
    rt.target_port = d.target_port;
    rt.target_scheme = d.target_scheme;
    if (rt.hostname !== d.hostname) {
      rt.hostname = d.hostname;
      // Hostname change invalidates the cert; restart that leg of the machine.
      rt.cert_status = "pending";
      rt.cert_expires_at = null;
      rt.proxy_status = "pending";
    }
  }

  private persist(): void {
    const rows: PersistedRoute[] = [...this.routes.values()].map((rt) => ({
      desired: {
        id: rt.id,
        hostname: rt.hostname,
        expected_ip: rt.expected_ip,
        target_host: rt.target_host,
        target_port: rt.target_port,
        target_scheme: rt.target_scheme,
      },
      dns_status: rt.dns_status,
      resolved_ip: rt.resolved_ip,
      cert_status: rt.cert_status,
      cert_expires_at: rt.cert_expires_at,
      proxy_status: rt.proxy_status,
      last_error_code: rt.last_error_code,
      sanitized_message: rt.sanitized_message,
      updated_at: rt.updated_at,
    }));
    try {
      saveState(this.deps.paths.stateFile, rows);
    } catch (err) {
      log.error("failed to persist state", { err: (err as Error).message });
    }
  }

  private touch(rt: RouteRuntime): void {
    rt.updated_at = nowIso(this.now());
  }

  /**
   * Declarative full sync: validate the incoming set, reconcile to it, and
   * kick a tick. Throws (→ 400) if any route is invalid. Returns current status.
   */
  applyDesired(rawRoutes: unknown): RouteStatus[] {
    if (!Array.isArray(rawRoutes)) throw new Error("routes must be an array");
    const allowLinkLocal = this.deps.config.allow_link_local_targets;
    const desired = rawRoutes.map((r) => validateDesiredRoute(r, { allowLinkLocal }));

    const current = new Map<string, RouteDesired>();
    for (const rt of this.routes.values()) {
      current.set(rt.id, {
        id: rt.id,
        hostname: rt.hostname,
        expected_ip: rt.expected_ip,
        target_host: rt.target_host,
        target_port: rt.target_port,
        target_scheme: rt.target_scheme,
      });
    }

    const plan = reconcile(current, desired);

    for (const d of plan.toAdd) {
      this.routes.set(d.id, this.newRuntime(d));
      log.info("route added", { id: d.id, hostname: d.hostname });
    }
    for (const d of plan.toUpdate) {
      const rt = this.routes.get(d.id)!;
      this.applyDesiredFields(rt, d);
      this.touch(rt);
      log.info("route updated", { id: d.id, hostname: d.hostname });
    }
    for (const id of plan.toRemove) {
      this.deleteRoute(id, "removed via sync");
    }

    this.persist();
    // Run the machine promptly, then report. Fire-and-forget; status returned
    // reflects current known state (a fresh add is 'pending' until the tick).
    void this.tick();
    this.deps.onStatusChanged();
    return this.getStatuses();
  }

  /** Remove one route (convenience DELETE). */
  removeRoute(id: string): boolean {
    if (!this.routes.has(id)) return false;
    this.deleteRoute(id, "removed via DELETE");
    this.persist();
    this.deps.onStatusChanged();
    return true;
  }

  private deleteRoute(id: string, reason: string): void {
    const rt = this.routes.get(id);
    if (!rt) return;
    this.routes.delete(id);
    this.deps.certStore.remove(rt.hostname);
    log.info("route deleted", { id, hostname: rt.hostname, reason });
    if (this.deps.config.cleanup_certs_on_removal) {
      // Only remove if no other route still uses this hostname.
      const stillUsed = [...this.routes.values()].some((r) => r.hostname === rt.hostname);
      if (!stillUsed) {
        try {
          rmSync(liveCertDir(this.deps.paths, rt.hostname), { recursive: true, force: true });
          log.info("cert files removed", { hostname: rt.hostname });
        } catch (err) {
          log.warn("cert cleanup failed", { hostname: rt.hostname, err: (err as Error).message });
        }
      }
    }
    this.deps.onCertsChanged();
  }

  /**
   * One pass of the state machine over every route. Serialized against itself
   * so overlapping timers can't double-issue. Persists + notifies if anything
   * changed.
   */
  async tick(): Promise<void> {
    if (this.ticking) return;
    this.ticking = true;
    let changed = false;
    let certsChanged = false;
    try {
      for (const rt of this.routes.values()) {
        const before = snapshot(rt);
        await this.stepRoute(rt);
        if (rt.cert_status === "active" && before.cert !== "active") certsChanged = true;
        if (!sameSnapshot(before, snapshot(rt))) {
          this.touch(rt);
          changed = true;
        }
      }
    } finally {
      this.ticking = false;
    }
    if (certsChanged) this.deps.onCertsChanged();
    if (changed) {
      this.persist();
      this.deps.onStatusChanged();
    }
  }

  /** Advance a single route by one step. */
  private async stepRoute(rt: RouteRuntime): Promise<void> {
    // 1. DNS
    const dns = await checkDns(rt.hostname, rt.expected_ip, this.deps.resolver);
    rt.dns_status = dns.status;
    rt.resolved_ip = dns.resolved_ip;

    // 2. Certificate
    const existing = this.deps.certStore.get(rt.hostname) ?? this.deps.certStore.load(rt.hostname);
    if (existing) {
      rt.cert_status = "active";
      rt.cert_expires_at = existing.expiresAt.toISOString();
    } else if (rt.dns_status === "ok" && rt.cert_status !== "active") {
      const now = this.now();
      if (now >= rt.nextIssueAttempt) {
        rt.cert_status = "issuing";
        const res = await this.deps.certbot.issue(rt.hostname);
        if (res.ok) {
          const loaded = this.deps.certStore.load(rt.hostname);
          if (loaded) {
            rt.cert_status = "active";
            rt.cert_expires_at = loaded.expiresAt.toISOString();
            rt.last_error_code = null;
            rt.sanitized_message = null;
            rt.issueBackoffMs = INITIAL_ISSUE_BACKOFF_MS;
          } else {
            rt.cert_status = "failed";
            rt.last_error_code = "cert_load_failed";
            rt.sanitized_message = "Certificate was issued but could not be loaded.";
            this.scheduleRetry(rt, now);
          }
        } else {
          rt.cert_status = "failed";
          rt.last_error_code = res.errorCode;
          rt.sanitized_message = res.sanitizedMessage;
          this.scheduleRetry(rt, now);
        }
      }
    } else if (rt.dns_status !== "ok" && rt.cert_status !== "active") {
      rt.cert_status = "pending";
    }

    // 3. Proxy availability follows cert status.
    if (rt.cert_status === "active") {
      rt.proxy_status = "active";
      if (rt.last_error_code === "cert_load_failed") {
        rt.last_error_code = null;
        rt.sanitized_message = null;
      }
    } else if (rt.proxy_status === "active") {
      rt.proxy_status = "pending";
    }
  }

  private scheduleRetry(rt: RouteRuntime, now: number): void {
    rt.nextIssueAttempt = now + rt.issueBackoffMs;
    rt.issueBackoffMs = Math.min(rt.issueBackoffMs * 2, MAX_ISSUE_BACKOFF_MS);
  }

  /** Renew all certs (called on a timer), then refresh loaded certs + expiries. */
  async renewTick(): Promise<void> {
    if (this.routes.size === 0) {
      // Still renew the control cert, which lives in the same certbot config.
      await this.deps.certbot.renewAll();
      this.deps.onCertsChanged();
      return;
    }
    for (const rt of this.routes.values()) {
      if (rt.cert_status === "active") rt.cert_status = "renewing";
    }
    this.deps.onStatusChanged();
    await this.deps.certbot.renewAll();
    let changed = false;
    for (const rt of this.routes.values()) {
      const loaded = this.deps.certStore.load(rt.hostname);
      if (loaded) {
        rt.cert_status = "active";
        rt.cert_expires_at = loaded.expiresAt.toISOString();
      } else if (rt.cert_status === "renewing") {
        rt.cert_status = "active"; // renew was a no-op (not yet due); keep serving.
      }
      this.touch(rt);
      changed = true;
    }
    this.deps.onCertsChanged();
    if (changed) {
      this.persist();
      this.deps.onStatusChanged();
    }
  }

  getStatuses(): RouteStatus[] {
    return [...this.routes.values()].map(buildRouteStatus);
  }

  getStatus(id: string): RouteStatus | undefined {
    const rt = this.routes.get(id);
    return rt ? buildRouteStatus(rt) : undefined;
  }

  /** Look up the active proxy target for an SNI/Host name. */
  targetForHostname(hostname: string): RouteRuntime | undefined {
    const host = hostname.toLowerCase();
    for (const rt of this.routes.values()) {
      if (rt.hostname === host && rt.proxy_status === "active") return rt;
    }
    return undefined;
  }

  /** True if any route currently has a usable cert (affects health). */
  hasActiveRoutes(): boolean {
    return [...this.routes.values()].some((r) => r.proxy_status === "active");
  }

  routeCount(): number {
    return this.routes.size;
  }
}

interface Snap {
  dns: string;
  ip: string | null;
  cert: string;
  exp: string | null;
  proxy: string;
  err: string | null;
  msg: string | null;
}
function snapshot(rt: RouteRuntime): Snap {
  return {
    dns: rt.dns_status,
    ip: rt.resolved_ip,
    cert: rt.cert_status,
    exp: rt.cert_expires_at,
    proxy: rt.proxy_status,
    err: rt.last_error_code,
    msg: rt.sanitized_message,
  };
}
function sameSnapshot(a: Snap, b: Snap): boolean {
  return (
    a.dns === b.dns &&
    a.ip === b.ip &&
    a.cert === b.cert &&
    a.exp === b.exp &&
    a.proxy === b.proxy &&
    a.err === b.err &&
    a.msg === b.msg
  );
}
