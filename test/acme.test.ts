import { describe, it, expect, beforeAll, afterAll } from "bun:test";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { makeChallengeHandler } from "../src/challenge-server.ts";
import { makePaths } from "../src/paths.ts";

let dir: string;
let handler: (req: Request) => Promise<Response>;

beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), "acme-test-"));
  const paths = makePaths(dir);
  const challengeDir = join(paths.acmeWebroot, ".well-known", "acme-challenge");
  mkdirSync(challengeDir, { recursive: true });
  writeFileSync(join(challengeDir, "token123"), "token123.keyauth");
  handler = makeChallengeHandler(paths);
});

afterAll(() => rmSync(dir, { recursive: true, force: true }));

describe("ACME challenge responder", () => {
  it("serves an existing challenge token", async () => {
    const res = await handler(new Request("http://play.example.com/.well-known/acme-challenge/token123"));
    expect(res.status).toBe(200);
    expect(await res.text()).toBe("token123.keyauth");
  });

  it("404s a missing token", async () => {
    const res = await handler(new Request("http://play.example.com/.well-known/acme-challenge/missing"));
    expect(res.status).toBe(404);
  });

  it("rejects path traversal in the token", async () => {
    const res = await handler(
      new Request("http://play.example.com/.well-known/acme-challenge/..%2f..%2fetc%2fpasswd"),
    );
    // decoded contains slashes/dots -> fails the token regex -> 400
    expect(res.status).toBe(400);
  });

  it("301-redirects everything else to HTTPS preserving host + path", async () => {
    const res = await handler(new Request("http://play.example.com/some/path?q=1"));
    expect(res.status).toBe(301);
    expect(res.headers.get("location")).toBe("https://play.example.com/some/path?q=1");
  });
});
