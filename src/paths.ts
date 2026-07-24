// Centralised layout of everything the agent keeps under `state_dir`. Keeping
// certbot's config/work/logs dirs inside state_dir makes the whole agent
// self-contained and lets systemd lock the filesystem down to just this tree.

import { join } from "node:path";

export interface Paths {
  stateDir: string;
  /** certbot --config-dir; live certs land under here in live/<host>/. */
  letsencryptDir: string;
  certbotWorkDir: string;
  certbotLogsDir: string;
  /** certbot --webroot; challenge files served on :80 from here. */
  acmeWebroot: string;
  /** Persisted route state (JSON). */
  stateFile: string;
  /** Self-signed bootstrap cert dir for the control API before LE is ready. */
  bootstrapDir: string;
}

export function makePaths(stateDir: string): Paths {
  return {
    stateDir,
    letsencryptDir: join(stateDir, "letsencrypt"),
    certbotWorkDir: join(stateDir, "certbot-work"),
    certbotLogsDir: join(stateDir, "certbot-logs"),
    acmeWebroot: join(stateDir, "acme-webroot"),
    stateFile: join(stateDir, "state.json"),
    bootstrapDir: join(stateDir, "bootstrap"),
  };
}

/** Directory certbot writes a live cert into for a given hostname. */
export function liveCertDir(paths: Paths, hostname: string): string {
  return join(paths.letsencryptDir, "live", hostname);
}

export function fullchainPath(paths: Paths, hostname: string): string {
  return join(liveCertDir(paths, hostname), "fullchain.pem");
}

export function privkeyPath(paths: Paths, hostname: string): string {
  return join(liveCertDir(paths, hostname), "privkey.pem");
}
