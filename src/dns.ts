// DNS resolution and the pending/ok/mismatch decision. The comparison logic is
// pure and unit-tested; the resolver is injectable so tests never hit the
// network.

import { Resolver } from "node:dns/promises";
import type { DnsStatus } from "./types.ts";

export interface DnsResult {
  status: DnsStatus;
  resolved_ip: string | null;
}

/** Resolver abstraction — returns the set of A/AAAA records for a hostname. */
export type HostResolver = (hostname: string) => Promise<string[]>;

/**
 * Default resolver: A and AAAA records via the system's DNS, with a short
 * timeout so a slow lookup can't stall the reconcile loop.
 */
export function createDefaultResolver(timeoutMs = 5_000): HostResolver {
  return async (hostname: string): Promise<string[]> => {
    const resolver = new Resolver({ timeout: timeoutMs, tries: 2 });
    const results = await Promise.allSettled([resolver.resolve4(hostname), resolver.resolve6(hostname)]);
    const ips: string[] = [];
    for (const r of results) {
      if (r.status === "fulfilled") ips.push(...r.value);
    }
    return ips;
  };
}

/**
 * Decide DNS status from a resolved set and the expected IP.
 * - `ok`: expected IP is among the resolved records.
 * - `mismatch`: records exist but none match the expected IP.
 * - `pending`: no records resolved (not yet propagated).
 * `resolved_ip` reports the matching record when ok, otherwise the first
 * resolved record (so the panel can show what DNS currently points at).
 */
export function decideDnsStatus(resolvedIps: string[], expectedIp: string): DnsResult {
  const ips = resolvedIps.map((s) => s.trim()).filter(Boolean);
  if (ips.length === 0) return { status: "pending", resolved_ip: null };
  if (ips.includes(expectedIp)) return { status: "ok", resolved_ip: expectedIp };
  return { status: "mismatch", resolved_ip: ips[0] ?? null };
}

/** Resolve a hostname and decide its DNS status. Never throws. */
export async function checkDns(
  hostname: string,
  expectedIp: string,
  resolve: HostResolver,
): Promise<DnsResult> {
  try {
    const ips = await resolve(hostname);
    return decideDnsStatus(ips, expectedIp);
  } catch {
    // NXDOMAIN / SERVFAIL / timeout all mean "not usable yet".
    return { status: "pending", resolved_ip: null };
  }
}
