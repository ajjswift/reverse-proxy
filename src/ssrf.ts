// Target and hostname validation, including an SSRF guard that blocks proxying
// to link-local / cloud-metadata addresses (169.254.0.0/16, fe80::/10) unless
// explicitly allowed. Loopback and private ranges are permitted on purpose:
// the agent's whole job is forwarding to local game/app servers on this node.

import { isIP } from "node:net";

const HOSTNAME_RE =
  /^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$/;

export interface TargetValidationOptions {
  allowLinkLocal: boolean;
}

/** True if an IPv4 literal is in 169.254.0.0/16 (link-local incl. metadata). */
export function isIpv4LinkLocal(ip: string): boolean {
  const parts = ip.split(".");
  if (parts.length !== 4) return false;
  return parts[0] === "169" && parts[1] === "254";
}

/** True if an IPv6 literal is in fe80::/10 (link-local) or maps to v4 metadata. */
export function isIpv6LinkLocal(ip: string): boolean {
  const lower = ip.toLowerCase();
  if (lower.startsWith("fe8") || lower.startsWith("fe9") || lower.startsWith("fea") || lower.startsWith("feb"))
    return true;
  // IPv4-mapped (::ffff:169.254.x.x)
  const mapped = lower.match(/::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped && mapped[1]) return isIpv4LinkLocal(mapped[1]);
  return false;
}

export function isLinkLocal(ip: string): boolean {
  const fam = isIP(ip);
  if (fam === 4) return isIpv4LinkLocal(ip);
  if (fam === 6) return isIpv6LinkLocal(ip);
  return false;
}

/** Validate a hostname label (used for route hostnames and SNI matching). */
export function isValidHostname(hostname: string): boolean {
  return typeof hostname === "string" && HOSTNAME_RE.test(hostname);
}

/**
 * Validate a proxy target. Returns an error string, or null if acceptable.
 * The target_host may be an IP literal or a hostname; hostnames are allowed
 * (the SSRF guard applies to IP literals — resolved-name guarding would need a
 * pinned resolver, out of scope for a same-host target).
 */
export function validateTarget(
  target_host: string,
  target_port: number,
  opts: TargetValidationOptions,
): string | null {
  if (typeof target_host !== "string" || target_host.length === 0)
    return "target_host is empty";
  if (!Number.isInteger(target_port) || target_port < 1 || target_port > 65535)
    return "target_port must be 1..65535";

  const fam = isIP(target_host);
  if (fam === 0) {
    // Not an IP literal — must be a valid hostname.
    if (!isValidHostname(target_host)) return `target_host "${target_host}" is not a valid host`;
    return null;
  }
  if (!opts.allowLinkLocal && isLinkLocal(target_host))
    return `target_host ${target_host} is a link-local/metadata address (blocked)`;
  return null;
}
