// Shared type definitions for the reverse-proxy agent and the HTTP contract it
// speaks with the panel. These types mirror the wire format exactly; changing
// them changes the public contract.

export type TargetScheme = "http" | "https";

export type DnsStatus = "pending" | "ok" | "mismatch";
export type CertStatus = "pending" | "issuing" | "active" | "failed" | "renewing";
export type ProxyStatus = "pending" | "active" | "failed";

/** A single desired route as sent by the panel in `PUT /v1/routes`. */
export interface RouteDesired {
  id: string;
  hostname: string;
  expected_ip: string;
  target_host: string;
  target_port: number;
  target_scheme: TargetScheme;
}

/** The status the agent reports for a route (over the API and in callbacks). */
export interface RouteStatus {
  id: string;
  hostname: string;
  dns_status: DnsStatus;
  resolved_ip: string | null;
  expected_ip: string;
  cert_status: CertStatus;
  cert_expires_at: string | null; // ISO8601
  proxy_status: ProxyStatus;
  last_error_code: string | null;
  sanitized_message: string | null;
  updated_at: string; // ISO8601
}

/** Body of `PUT /v1/routes`. */
export interface PutRoutesBody {
  routes: RouteDesired[];
}

/** Response of `GET /v1/routes` and `PUT /v1/routes`. */
export interface RoutesResponse {
  routes: RouteStatus[];
}

/** Response of `GET /v1/health`. */
export interface HealthResponse {
  version: string;
  uptime_seconds: number;
  control_cert_ready: boolean;
  acme_staging: boolean;
}

/** Body of the agent → panel status callback. */
export interface CallbackBody {
  agent: {
    version: string;
    healthy: boolean;
    acme_staging: boolean;
  };
  routes: RouteStatus[];
}

/**
 * Persisted per-route state kept under `state_dir`. Deliberately a superset of
 * the wire status so a restart can resume the state machine without re-issuing
 * certs or re-running DNS from scratch.
 */
export interface PersistedRoute {
  desired: RouteDesired;
  dns_status: DnsStatus;
  resolved_ip: string | null;
  cert_status: CertStatus;
  cert_expires_at: string | null;
  proxy_status: ProxyStatus;
  last_error_code: string | null;
  sanitized_message: string | null;
  updated_at: string;
}
