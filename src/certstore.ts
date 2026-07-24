// In-memory store of loaded certificates keyed by hostname, providing SNI
// selection for the :443 listener and expiry inspection for the state machine.
// Certs live on disk (written by certbot); this caches the PEM bytes and hot-
// reloads them when a new cert is issued or renewed.

import { readFileSync } from "node:fs";
import { X509Certificate } from "node:crypto";
import { fullchainPath, privkeyPath, type Paths } from "./paths.ts";
import { log } from "./logger.ts";

export interface LoadedCert {
  hostname: string;
  cert: string; // fullchain PEM
  key: string; // private key PEM
  expiresAt: Date;
}

/** Structural interface the manager depends on (lets tests inject a fake). */
export interface CertStoreLike {
  load(hostname: string): LoadedCert | null;
  get(hostname: string): LoadedCert | undefined;
  remove(hostname: string): void;
  all(): LoadedCert[];
  has(hostname: string): boolean;
}

/** Parse the leaf certificate's notAfter from a fullchain PEM. */
export function parseCertExpiry(fullchainPem: string): Date {
  const x509 = new X509Certificate(fullchainPem);
  const notAfter = new Date(x509.validTo);
  if (Number.isNaN(notAfter.getTime())) throw new Error("could not parse certificate validTo");
  return notAfter;
}

export class CertStore {
  private certs = new Map<string, LoadedCert>();

  constructor(private paths: Paths) {}

  /** Load (or reload) a hostname's cert from disk. Returns null if absent. */
  load(hostname: string): LoadedCert | null {
    try {
      const cert = readFileSync(fullchainPath(this.paths, hostname), "utf8");
      const key = readFileSync(privkeyPath(this.paths, hostname), "utf8");
      const expiresAt = parseCertExpiry(cert);
      const loaded: LoadedCert = { hostname, cert, key, expiresAt };
      this.certs.set(hostname, loaded);
      return loaded;
    } catch (err) {
      log.debug("cert not loadable", { hostname, err: (err as Error).message });
      return null;
    }
  }

  get(hostname: string): LoadedCert | undefined {
    return this.certs.get(hostname);
  }

  /** SNI selection for the TLS listener. Returns undefined for unknown names. */
  select(serverName: string | undefined): LoadedCert | undefined {
    if (!serverName) return undefined;
    return this.certs.get(serverName.toLowerCase());
  }

  remove(hostname: string): void {
    this.certs.delete(hostname);
  }

  /** All loaded certs (used to build the Bun.serve tls array). */
  all(): LoadedCert[] {
    return [...this.certs.values()];
  }

  has(hostname: string): boolean {
    return this.certs.has(hostname);
  }
}
