// Construction of the wire status payloads (RouteStatus and the callback body).
// Kept pure and separate so the exact shape the panel sees is easy to unit-test
// and impossible to accidentally leak internal fields through.

import type { CallbackBody, RouteStatus } from "./types.ts";

/** The internal per-route record the manager keeps. Superset of RouteStatus. */
export interface RouteRuntime {
  id: string;
  hostname: string;
  expected_ip: string;
  target_host: string;
  target_port: number;
  target_scheme: "http" | "https";
  dns_status: RouteStatus["dns_status"];
  resolved_ip: string | null;
  cert_status: RouteStatus["cert_status"];
  cert_expires_at: string | null;
  proxy_status: RouteStatus["proxy_status"];
  last_error_code: string | null;
  sanitized_message: string | null;
  updated_at: string;
  // Internal-only scheduling fields (never serialized to the wire):
  nextIssueAttempt: number;
  issueBackoffMs: number;
}

/** Project the internal runtime down to exactly the public RouteStatus shape. */
export function buildRouteStatus(rt: RouteRuntime): RouteStatus {
  return {
    id: rt.id,
    hostname: rt.hostname,
    dns_status: rt.dns_status,
    resolved_ip: rt.resolved_ip,
    expected_ip: rt.expected_ip,
    cert_status: rt.cert_status,
    cert_expires_at: rt.cert_expires_at,
    proxy_status: rt.proxy_status,
    last_error_code: rt.last_error_code,
    sanitized_message: rt.sanitized_message,
    updated_at: rt.updated_at,
  };
}

export function buildCallbackBody(
  version: string,
  healthy: boolean,
  acme_staging: boolean,
  statuses: RouteStatus[],
): CallbackBody {
  return {
    agent: { version, healthy, acme_staging },
    routes: statuses,
  };
}
