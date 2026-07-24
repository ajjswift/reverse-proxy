// Agent → panel status callbacks. POSTs the full status on a fixed interval and
// immediately (debounced) on any state change. Failures are retried with
// exponential backoff and can never crash the agent or disturb proxying.

import type { Config } from "./config.ts";
import type { CallbackBody } from "./types.ts";
import { log } from "./logger.ts";

const DEBOUNCE_MS = 250;
const INITIAL_BACKOFF_MS = 1_000;
const MAX_BACKOFF_MS = 60_000;
const REQUEST_TIMEOUT_MS = 10_000;

export interface CallbackSenderDeps {
  config: Config;
  buildBody: () => CallbackBody;
  /** Injectable for tests; defaults to global fetch. */
  fetchImpl?: typeof fetch;
}

export class CallbackSender {
  private intervalTimer: ReturnType<typeof setInterval> | null = null;
  private debounceTimer: ReturnType<typeof setTimeout> | null = null;
  private backoffTimer: ReturnType<typeof setTimeout> | null = null;
  private backoffMs = INITIAL_BACKOFF_MS;
  private sending = false;
  private pendingWhileSending = false;
  private stopped = false;
  private fetchImpl: typeof fetch;

  constructor(private deps: CallbackSenderDeps) {
    this.fetchImpl = deps.fetchImpl ?? fetch;
  }

  start(): void {
    this.stopped = false;
    this.intervalTimer = setInterval(() => this.send(), this.deps.config.callback_interval_ms);
    // First heartbeat shortly after boot.
    this.trigger();
  }

  /** Request a send soon (coalesces bursts of state changes). */
  trigger(): void {
    if (this.stopped) return;
    if (this.debounceTimer) return;
    this.debounceTimer = setTimeout(() => {
      this.debounceTimer = null;
      void this.send();
    }, DEBOUNCE_MS);
  }

  private async send(): Promise<void> {
    if (this.stopped) return;
    if (this.sending) {
      this.pendingWhileSending = true;
      return;
    }
    this.sending = true;
    try {
      await this.postOnce();
      this.backoffMs = INITIAL_BACKOFF_MS; // success resets backoff
      if (this.backoffTimer) {
        clearTimeout(this.backoffTimer);
        this.backoffTimer = null;
      }
    } catch (err) {
      log.warn("status callback failed; will retry", {
        err: (err as Error).message,
        backoff_ms: this.backoffMs,
      });
      this.scheduleBackoffRetry();
    } finally {
      this.sending = false;
      if (this.pendingWhileSending) {
        this.pendingWhileSending = false;
        this.trigger();
      }
    }
  }

  private scheduleBackoffRetry(): void {
    if (this.stopped || this.backoffTimer) return;
    const delay = this.backoffMs;
    this.backoffMs = Math.min(this.backoffMs * 2, MAX_BACKOFF_MS);
    this.backoffTimer = setTimeout(() => {
      this.backoffTimer = null;
      void this.send();
    }, delay);
  }

  private async postOnce(): Promise<void> {
    const body = this.deps.buildBody();
    const res = await this.fetchImpl(this.deps.config.panel_callback_url, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${this.deps.config.node_token}`,
      },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
    if (!res.ok) throw new Error(`panel returned ${res.status}`);
    // Drain body so the connection can be reused/closed cleanly.
    await res.text().catch(() => undefined);
  }

  /** Best-effort final callback on shutdown (bounded, never throws). */
  async flushFinal(): Promise<void> {
    try {
      await this.postOnce();
    } catch (err) {
      log.warn("final status callback failed", { err: (err as Error).message });
    }
  }

  stop(): void {
    this.stopped = true;
    if (this.intervalTimer) clearInterval(this.intervalTimer);
    if (this.debounceTimer) clearTimeout(this.debounceTimer);
    if (this.backoffTimer) clearTimeout(this.backoffTimer);
    this.intervalTimer = this.debounceTimer = this.backoffTimer = null;
  }
}
