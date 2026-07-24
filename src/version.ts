// Single source of truth for the agent version. Kept in sync with package.json
// by the build script. Injected into --version, /v1/health and status callbacks.
export const VERSION = "0.1.0";
