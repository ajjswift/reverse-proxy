import { describe, it, expect } from "bun:test";
import { reconcile, validateDesiredRoute, desiredEqual } from "../src/reconciler.ts";
import type { RouteDesired } from "../src/types.ts";

function route(over: Partial<RouteDesired> = {}): RouteDesired {
  return {
    id: "11111111-1111-4111-8111-111111111111",
    hostname: "play.example.com",
    expected_ip: "203.0.113.10",
    target_host: "127.0.0.1",
    target_port: 8080,
    target_scheme: "http",
    ...over,
  };
}

const opts = { allowLinkLocal: false };

describe("validateDesiredRoute", () => {
  it("accepts a well-formed route and lowercases the hostname", () => {
    const r = validateDesiredRoute({ ...route(), hostname: "Play.Example.COM" }, opts);
    expect(r.hostname).toBe("play.example.com");
  });

  it("rejects a bad uuid", () => {
    expect(() => validateDesiredRoute({ ...route(), id: "nope" }, opts)).toThrow(/UUID/);
  });

  it("rejects an invalid expected_ip", () => {
    expect(() => validateDesiredRoute({ ...route(), expected_ip: "999.1.1.1" }, opts)).toThrow(/IP address/);
  });

  it("rejects a bad scheme", () => {
    expect(() => validateDesiredRoute({ ...route(), target_scheme: "ftp" }, opts)).toThrow(/target_scheme/);
  });

  it("blocks link-local targets by default (SSRF guard)", () => {
    expect(() => validateDesiredRoute({ ...route(), target_host: "169.254.169.254" }, opts)).toThrow(
      /link-local\/metadata/,
    );
  });

  it("allows link-local when explicitly configured", () => {
    const r = validateDesiredRoute({ ...route(), target_host: "169.254.169.254" }, { allowLinkLocal: true });
    expect(r.target_host).toBe("169.254.169.254");
  });

  it("allows loopback and private targets (the intended use)", () => {
    expect(validateDesiredRoute({ ...route(), target_host: "127.0.0.1" }, opts).target_host).toBe("127.0.0.1");
    expect(validateDesiredRoute({ ...route(), target_host: "10.0.0.5" }, opts).target_host).toBe("10.0.0.5");
  });

  it("coerces string ports", () => {
    expect(validateDesiredRoute({ ...route(), target_port: "8080" }, opts).target_port).toBe(8080);
  });
});

describe("reconcile", () => {
  const empty = () => new Map<string, RouteDesired>();

  it("adds new routes", () => {
    const plan = reconcile(empty(), [route()]);
    expect(plan.toAdd.length).toBe(1);
    expect(plan.toUpdate.length).toBe(0);
    expect(plan.toRemove.length).toBe(0);
  });

  it("is idempotent: same set yields no changes", () => {
    const cur = new Map([[route().id, route()]]);
    const plan = reconcile(cur, [route()]);
    expect(plan.toAdd.length).toBe(0);
    expect(plan.toUpdate.length).toBe(0);
    expect(plan.toRemove.length).toBe(0);
    expect(plan.unchanged).toEqual([route().id]);
  });

  it("updates changed routes and flags hostname changes", () => {
    const cur = new Map([[route().id, route()]]);
    const changed = route({ target_port: 9090 });
    const plan = reconcile(cur, [changed]);
    expect(plan.toUpdate.length).toBe(1);
    expect(plan.hostnameChanged.has(route().id)).toBe(false);

    const hostChanged = route({ hostname: "new.example.com" });
    const plan2 = reconcile(cur, [hostChanged]);
    expect(plan2.hostnameChanged.has(route().id)).toBe(true);
  });

  it("removes absent routes", () => {
    const cur = new Map([[route().id, route()]]);
    const plan = reconcile(cur, []);
    expect(plan.toRemove).toEqual([route().id]);
  });

  it("rejects duplicate hostnames across different ids", () => {
    const a = route({ id: "11111111-1111-4111-8111-111111111111" });
    const b = route({ id: "22222222-2222-4222-8222-222222222222" });
    expect(() => reconcile(empty(), [a, b])).toThrow(/duplicate hostname/);
  });
});

describe("desiredEqual", () => {
  it("detects any field change", () => {
    expect(desiredEqual(route(), route())).toBe(true);
    expect(desiredEqual(route(), route({ target_scheme: "https" }))).toBe(false);
  });
});
