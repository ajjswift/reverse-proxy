// Public :80 listener. Its only jobs are (1) serving ACME HTTP-01 challenge
// files that certbot --webroot drops under the webroot, and (2) redirecting all
// other traffic to HTTPS. It never proxies anything.

import { join } from "node:path";
import type { Server } from "bun";
import type { Paths } from "./paths.ts";
import { log } from "./logger.ts";

const CHALLENGE_PREFIX = "/.well-known/acme-challenge/";
// ACME tokens are base64url; refuse anything else to prevent path traversal.
const TOKEN_RE = /^[A-Za-z0-9_-]+$/;

/**
 * The :80 request handler. Extracted (and pure w.r.t. the port) so it can be
 * unit-tested without binding a privileged port.
 */
export function makeChallengeHandler(paths: Paths): (req: Request) => Promise<Response> {
  return async (req) => {
    const url = new URL(req.url);
    if (url.pathname.startsWith(CHALLENGE_PREFIX)) {
      const token = url.pathname.slice(CHALLENGE_PREFIX.length);
      if (!TOKEN_RE.test(token)) return new Response("bad request", { status: 400 });
      const file = Bun.file(join(paths.acmeWebroot, ".well-known", "acme-challenge", token));
      if (await file.exists()) {
        return new Response(file, { headers: { "content-type": "text/plain" } });
      }
      return new Response("not found", { status: 404 });
    }
    // Everything else: permanent redirect to HTTPS, preserving host + path.
    const host = req.headers.get("host") ?? url.host;
    const location = `https://${host}${url.pathname}${url.search}`;
    return new Response(null, { status: 301, headers: { location } });
  };
}

export function startChallengeServer(paths: Paths): Server<undefined> {
  const handler = makeChallengeHandler(paths);
  const server = Bun.serve({
    port: 80,
    hostname: "0.0.0.0",
    idleTimeout: 30,
    fetch: handler,
    error(err) {
      log.error(":80 listener error", { err: err.message });
      return new Response("internal error", { status: 500 });
    },
  });
  log.info("challenge/redirect listener started", { port: 80 });
  return server;
}
