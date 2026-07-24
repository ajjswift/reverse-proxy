import { describe, it, expect } from "bun:test";
import { isLinkLocal, isValidHostname, validateTarget } from "../src/ssrf.ts";

describe("isLinkLocal", () => {
  it("flags IPv4 link-local/metadata", () => {
    expect(isLinkLocal("169.254.169.254")).toBe(true);
    expect(isLinkLocal("169.254.0.1")).toBe(true);
  });
  it("does not flag loopback or private ranges", () => {
    expect(isLinkLocal("127.0.0.1")).toBe(false);
    expect(isLinkLocal("10.0.0.1")).toBe(false);
    expect(isLinkLocal("192.168.1.1")).toBe(false);
  });
  it("flags IPv6 link-local and mapped metadata", () => {
    expect(isLinkLocal("fe80::1")).toBe(true);
    expect(isLinkLocal("::ffff:169.254.169.254")).toBe(true);
    expect(isLinkLocal("::1")).toBe(false);
  });
});

describe("isValidHostname", () => {
  it("accepts normal hostnames and single labels", () => {
    expect(isValidHostname("play.example.com")).toBe(true);
    expect(isValidHostname("localhost")).toBe(true);
  });
  it("rejects malformed hostnames", () => {
    expect(isValidHostname("bad_host!")).toBe(false);
    expect(isValidHostname("-leading.example.com")).toBe(false);
    expect(isValidHostname("")).toBe(false);
  });
});

describe("validateTarget", () => {
  const allow = { allowLinkLocal: true };
  const deny = { allowLinkLocal: false };

  it("accepts loopback + valid port", () => {
    expect(validateTarget("127.0.0.1", 8080, deny)).toBeNull();
  });
  it("rejects bad ports", () => {
    expect(validateTarget("127.0.0.1", 0, deny)).toMatch(/target_port/);
    expect(validateTarget("127.0.0.1", 70000, deny)).toMatch(/target_port/);
  });
  it("blocks link-local unless allowed", () => {
    expect(validateTarget("169.254.169.254", 80, deny)).toMatch(/link-local/);
    expect(validateTarget("169.254.169.254", 80, allow)).toBeNull();
  });
  it("accepts hostname targets", () => {
    expect(validateTarget("game-server.local", 25565, deny)).toBeNull();
  });
  it("rejects empty/garbage host", () => {
    expect(validateTarget("", 80, deny)).toMatch(/empty/);
    expect(validateTarget("bad host!", 80, deny)).toMatch(/not a valid host/);
  });
});
