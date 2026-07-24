// Pure route reconciliation: given the currently-known desired routes and a new
// desired set from the panel, compute what to add, update, and remove. Also
// validates the incoming set (well-formed, no duplicate hostnames). No I/O here
// so it is fully unit-testable and deterministic.

import type { RouteDesired, TargetScheme } from "./types.ts";
import { isValidHostname, validateTarget } from "./ssrf.ts";
import { isIP } from "node:net";

export interface ReconcilePlan {
  toAdd: RouteDesired[];
  /** Routes whose id already exists but whose config changed. */
  toUpdate: RouteDesired[];
  /** Ids present now but absent from the desired set. */
  toRemove: string[];
  /** Ids present in both and unchanged. */
  unchanged: string[];
  /** True when the hostname (and therefore the cert) changed for an update. */
  hostnameChanged: Set<string>;
}

const SCHEMES: TargetScheme[] = ["http", "https"];
const UUID_RE = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

/**
 * Validate and normalise a raw desired route. Throws with a specific message on
 * the first problem; the caller surfaces this as a 400 to the panel.
 */
export function validateDesiredRoute(
  raw: unknown,
  opts: { allowLinkLocal: boolean },
): RouteDesired {
  if (!raw || typeof raw !== "object") throw new Error("route must be an object");
  const r = raw as Record<string, unknown>;

  if (typeof r.id !== "string" || !UUID_RE.test(r.id)) throw new Error("route.id must be a UUID");
  if (typeof r.hostname !== "string" || !isValidHostname(r.hostname))
    throw new Error(`route.hostname "${String(r.hostname)}" is not a valid hostname`);
  if (typeof r.expected_ip !== "string" || isIP(r.expected_ip) === 0)
    throw new Error(`route.expected_ip must be a valid IP address (got "${String(r.expected_ip)}")`);
  if (typeof r.target_host !== "string") throw new Error("route.target_host must be a string");
  const target_port =
    typeof r.target_port === "number"
      ? r.target_port
      : typeof r.target_port === "string" && /^\d+$/.test(r.target_port)
        ? parseInt(r.target_port, 10)
        : NaN;
  const scheme = r.target_scheme;
  if (typeof scheme !== "string" || !SCHEMES.includes(scheme as TargetScheme))
    throw new Error("route.target_scheme must be 'http' or 'https'");

  const targetErr = validateTarget(r.target_host, target_port, { allowLinkLocal: opts.allowLinkLocal });
  if (targetErr) throw new Error(`route ${r.hostname}: ${targetErr}`);

  return {
    id: r.id,
    hostname: r.hostname.toLowerCase(),
    expected_ip: r.expected_ip,
    target_host: r.target_host,
    target_port,
    target_scheme: scheme as TargetScheme,
  };
}

export function desiredEqual(a: RouteDesired, b: RouteDesired): boolean {
  return (
    a.hostname === b.hostname &&
    a.expected_ip === b.expected_ip &&
    a.target_host === b.target_host &&
    a.target_port === b.target_port &&
    a.target_scheme === b.target_scheme
  );
}

/**
 * Diff current vs desired. `desired` must already be validated. Rejects a
 * desired set that reuses the same hostname across two different ids.
 */
export function reconcile(
  current: Map<string, RouteDesired>,
  desired: RouteDesired[],
): ReconcilePlan {
  const byHostname = new Map<string, string>();
  for (const d of desired) {
    const existing = byHostname.get(d.hostname);
    if (existing && existing !== d.id)
      throw new Error(`duplicate hostname "${d.hostname}" across routes ${existing} and ${d.id}`);
    byHostname.set(d.hostname, d.id);
  }

  const desiredIds = new Set(desired.map((d) => d.id));
  const plan: ReconcilePlan = {
    toAdd: [],
    toUpdate: [],
    toRemove: [],
    unchanged: [],
    hostnameChanged: new Set(),
  };

  for (const d of desired) {
    const prev = current.get(d.id);
    if (!prev) {
      plan.toAdd.push(d);
    } else if (!desiredEqual(prev, d)) {
      plan.toUpdate.push(d);
      if (prev.hostname !== d.hostname) plan.hostnameChanged.add(d.id);
    } else {
      plan.unchanged.push(d.id);
    }
  }
  for (const id of current.keys()) {
    if (!desiredIds.has(id)) plan.toRemove.push(id);
  }
  return plan;
}
