import { describe, it, expect, beforeAll, afterAll } from "bun:test";
import { mkdtempSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CertStore, parseCertExpiry } from "../src/certstore.ts";
import { makePaths, liveCertDir, fullchainPath, privkeyPath, type Paths } from "../src/paths.ts";

let dir: string;
let paths: Paths;

/** Generate a self-signed cert for `host` into certbot's live/<host>/ layout. */
function genCert(host: string): void {
  const outDir = liveCertDir(paths, host);
  mkdirSync(outDir, { recursive: true });
  const res = Bun.spawnSync([
    "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
    "-keyout", privkeyPath(paths, host),
    "-out", fullchainPath(paths, host),
    "-days", "5",
    "-subj", `/CN=${host}`,
    "-addext", `subjectAltName=DNS:${host}`,
  ]);
  if (res.exitCode !== 0) throw new Error("openssl failed: " + res.stderr.toString());
}

beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), "sni-test-"));
  paths = makePaths(dir);
  genCert("a.example.com");
  genCert("b.example.com");
});

afterAll(() => rmSync(dir, { recursive: true, force: true }));

describe("CertStore SNI selection", () => {
  it("loads certs and selects by exact server name", () => {
    const store = new CertStore(paths);
    expect(store.load("a.example.com")).not.toBeNull();
    expect(store.load("b.example.com")).not.toBeNull();

    expect(store.select("a.example.com")?.hostname).toBe("a.example.com");
    expect(store.select("b.example.com")?.hostname).toBe("b.example.com");
  });

  it("is case-insensitive on SNI", () => {
    const store = new CertStore(paths);
    store.load("a.example.com");
    expect(store.select("A.Example.COM")?.hostname).toBe("a.example.com");
  });

  it("returns undefined for unknown SNI (rejected at :443)", () => {
    const store = new CertStore(paths);
    store.load("a.example.com");
    expect(store.select("unknown.example.com")).toBeUndefined();
    expect(store.select(undefined)).toBeUndefined();
  });

  it("returns null when cert files are absent", () => {
    const store = new CertStore(paths);
    expect(store.load("missing.example.com")).toBeNull();
  });

  it("exposes all loaded certs for the tls array", () => {
    const store = new CertStore(paths);
    store.load("a.example.com");
    store.load("b.example.com");
    expect(store.all().map((c) => c.hostname).sort()).toEqual(["a.example.com", "b.example.com"]);
  });

  it("removes a cert", () => {
    const store = new CertStore(paths);
    store.load("a.example.com");
    store.remove("a.example.com");
    expect(store.has("a.example.com")).toBe(false);
  });
});

describe("parseCertExpiry", () => {
  it("parses a valid future expiry", () => {
    const store = new CertStore(paths);
    const c = store.load("a.example.com")!;
    expect(c.expiresAt.getTime()).toBeGreaterThan(Date.now());
    // Round-trip via parseCertExpiry directly.
    expect(parseCertExpiry(c.cert).getTime()).toBe(c.expiresAt.getTime());
  });
});
