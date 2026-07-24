// Persistent per-route state under state_dir. Written atomically so a crash
// mid-write can never corrupt the file, and read back on boot so restarts
// resume the state machine without re-issuing certificates.

import { readFileSync, writeFileSync, renameSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import type { PersistedRoute } from "./types.ts";
import { log } from "./logger.ts";

interface StateFile {
  version: 1;
  routes: PersistedRoute[];
}

export function loadState(path: string): PersistedRoute[] {
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
    log.warn("could not read state file; starting empty", { path, err: (err as Error).message });
    return [];
  }
  try {
    const parsed = JSON.parse(text) as StateFile;
    if (!parsed || !Array.isArray(parsed.routes)) return [];
    return parsed.routes;
  } catch (err) {
    log.warn("state file corrupt; starting empty", { path, err: (err as Error).message });
    return [];
  }
}

export function saveState(path: string, routes: PersistedRoute[]): void {
  const dir = dirname(path);
  try {
    mkdirSync(dir, { recursive: true, mode: 0o750 });
  } catch {
    /* already exists */
  }
  const body: StateFile = { version: 1, routes };
  const tmp = `${path}.tmp.${process.pid}`;
  writeFileSync(tmp, JSON.stringify(body, null, 2), { mode: 0o640 });
  renameSync(tmp, path); // atomic on the same filesystem
}
