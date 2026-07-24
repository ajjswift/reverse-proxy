import { describe, it, expect } from "bun:test";
import { decideDnsStatus, checkDns } from "../src/dns.ts";

describe("decideDnsStatus", () => {
  it("returns ok when the expected IP is present", () => {
    expect(decideDnsStatus(["203.0.113.10"], "203.0.113.10")).toEqual({ status: "ok", resolved_ip: "203.0.113.10" });
  });

  it("returns ok when expected is among several records", () => {
    const r = decideDnsStatus(["198.51.100.2", "203.0.113.10"], "203.0.113.10");
    expect(r.status).toBe("ok");
    expect(r.resolved_ip).toBe("203.0.113.10");
  });

  it("returns mismatch and reports what DNS points at", () => {
    expect(decideDnsStatus(["198.51.100.2"], "203.0.113.10")).toEqual({
      status: "mismatch",
      resolved_ip: "198.51.100.2",
    });
  });

  it("returns pending when nothing resolves", () => {
    expect(decideDnsStatus([], "203.0.113.10")).toEqual({ status: "pending", resolved_ip: null });
  });

  it("ignores blank entries", () => {
    expect(decideDnsStatus(["", "  "], "203.0.113.10").status).toBe("pending");
  });
});

describe("checkDns", () => {
  it("uses the injected resolver", async () => {
    const r = await checkDns("play.example.com", "203.0.113.10", async () => ["203.0.113.10"]);
    expect(r.status).toBe("ok");
  });

  it("treats resolver errors as pending (never throws)", async () => {
    const r = await checkDns("play.example.com", "203.0.113.10", async () => {
      throw new Error("NXDOMAIN");
    });
    expect(r).toEqual({ status: "pending", resolved_ip: null });
  });
});
