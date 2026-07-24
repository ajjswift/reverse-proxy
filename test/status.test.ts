import { describe, it, expect } from "bun:test";
import { buildRouteStatus, buildCallbackBody, type RouteRuntime } from "../src/status.ts";
import { _internal, registerSecret, log } from "../src/logger.ts";
import { classifyCertbotFailure } from "../src/certbot.ts";

function runtime(): RouteRuntime {
  return {
    id: "11111111-1111-4111-8111-111111111111",
    hostname: "play.example.com",
    expected_ip: "203.0.113.10",
    target_host: "127.0.0.1",
    target_port: 8080,
    target_scheme: "http",
    dns_status: "ok",
    resolved_ip: "203.0.113.10",
    cert_status: "active",
    cert_expires_at: "2026-10-01T00:00:00.000Z",
    proxy_status: "active",
    last_error_code: null,
    sanitized_message: null,
    updated_at: "2026-07-24T00:00:00.000Z",
    nextIssueAttempt: 0,
    issueBackoffMs: 60000,
  };
}

describe("buildRouteStatus", () => {
  it("projects exactly the wire fields (no internal scheduling fields)", () => {
    const s = buildRouteStatus(runtime());
    expect(Object.keys(s).sort()).toEqual(
      [
        "cert_expires_at",
        "cert_status",
        "dns_status",
        "expected_ip",
        "hostname",
        "id",
        "last_error_code",
        "proxy_status",
        "resolved_ip",
        "sanitized_message",
        "updated_at",
      ].sort(),
    );
    expect("nextIssueAttempt" in s).toBe(false);
    expect("target_host" in s).toBe(false);
  });
});

describe("buildCallbackBody", () => {
  it("wraps agent metadata and routes", () => {
    const body = buildCallbackBody("1.2.3", true, false, [buildRouteStatus(runtime())]);
    expect(body.agent).toEqual({ version: "1.2.3", healthy: true, acme_staging: false });
    expect(body.routes.length).toBe(1);
  });
});

describe("logger secret redaction", () => {
  it("redacts registered secret substrings", () => {
    registerSecret("supersecrettoken123");
    const out = _internal.scrubString("bearer supersecrettoken123 used");
    expect(out).not.toContain("supersecrettoken123");
    expect(out).toContain("[REDACTED]");
  });

  it("redacts by sensitive key name", () => {
    const scrubbed = _internal.scrubValue({ api_key: "whatever", ok: "visible" }) as Record<string, string>;
    expect(scrubbed.api_key).toBe("[REDACTED]");
    expect(scrubbed.ok).toBe("visible");
  });

  it("does not register very short secrets", () => {
    registerSecret("abc");
    expect(_internal.registeredSecrets.has("abc")).toBe(false);
  });

  it("log methods do not throw", () => {
    expect(() => log.info("test", { api_key: "x" })).not.toThrow();
  });
});

describe("classifyCertbotFailure", () => {
  it("maps rate limits", () => {
    expect(classifyCertbotFailure("Error: too many certificates already issued").code).toBe("acme_rate_limited");
  });
  it("maps challenge failures", () => {
    expect(classifyCertbotFailure("The challenge failed: Connection refused").code).toBe("acme_challenge_failed");
  });
  it("maps missing certbot", () => {
    expect(classifyCertbotFailure("certbot: command not found").code).toBe("certbot_missing");
  });
  it("falls back to a generic code", () => {
    expect(classifyCertbotFailure("something weird happened").code).toBe("certbot_failed");
  });
  it("never leaks raw detail in the message", () => {
    const { message } = classifyCertbotFailure("secret path /etc/letsencrypt/keys/0000_key.pem exploded");
    expect(message).not.toContain("/etc/letsencrypt");
  });
});
