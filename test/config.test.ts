import { describe, it, expect } from "bun:test";
import { parseConfig, applyEnvOverrides, ConfigError } from "../src/config.ts";

const base = {
  api_key: "0123456789abcdef0123",
  node_token: "abcdef0123456789abcd",
  hostname: "node1.example.com",
  panel_callback_url: "https://panel.example.com/cb",
  letsencrypt_email: "ops@example.com",
};

describe("parseConfig", () => {
  it("accepts a valid config and applies defaults", () => {
    const c = parseConfig({ ...base });
    expect(c.control_port).toBe(8443);
    expect(c.acme_staging).toBe(false);
    expect(c.state_dir).toBe("/var/lib/proxy-agent");
    expect(c.log_level).toBe("info");
    expect(c.callback_interval_ms).toBe(30_000);
    expect(c.allow_link_local_targets).toBe(false);
  });

  it("requires all secrets and identity fields", () => {
    expect(() => parseConfig({})).toThrow(ConfigError);
    try {
      parseConfig({});
    } catch (e) {
      const problems = (e as ConfigError).problems.join("\n");
      expect(problems).toContain("api_key is required");
      expect(problems).toContain("node_token is required");
      expect(problems).toContain("hostname is required");
      expect(problems).toContain("panel_callback_url is required");
      expect(problems).toContain("letsencrypt_email is required");
    }
  });

  it("rejects short tokens", () => {
    expect(() => parseConfig({ ...base, api_key: "short" })).toThrow(/at least 16/);
  });

  it("rejects invalid hostname and email", () => {
    expect(() => parseConfig({ ...base, hostname: "not_a_host!" })).toThrow(/not a valid FQDN/);
    expect(() => parseConfig({ ...base, letsencrypt_email: "nope" })).toThrow(/not a valid email/);
  });

  it("rejects non-http callback url", () => {
    expect(() => parseConfig({ ...base, panel_callback_url: "ftp://x/y" })).toThrow(/http\(s\)/);
  });

  it("rejects reserved control ports", () => {
    expect(() => parseConfig({ ...base, control_port: 443 })).toThrow(/must not be 80 or 443/);
    expect(() => parseConfig({ ...base, control_port: 70000 })).toThrow(/1\.\.65535/);
  });

  it("coerces string booleans and ints (from env)", () => {
    const c = parseConfig({ ...base, acme_staging: "true", control_port: "9000", allow_link_local_targets: "1" });
    expect(c.acme_staging).toBe(true);
    expect(c.control_port).toBe(9000);
    expect(c.allow_link_local_targets).toBe(true);
  });

  it("validates log level enum", () => {
    expect(() => parseConfig({ ...base, log_level: "loud" })).toThrow(/log_level must be/);
  });

  it("collects multiple problems at once", () => {
    try {
      parseConfig({ ...base, hostname: "bad!", control_port: 80 });
    } catch (e) {
      expect((e as ConfigError).problems.length).toBeGreaterThanOrEqual(2);
    }
  });
});

describe("applyEnvOverrides", () => {
  it("overlays PROXY_AGENT_* and bare env names", () => {
    const raw = applyEnvOverrides(
      { control_port: 8443 },
      { PROXY_AGENT_CONTROL_PORT: "9443", API_KEY: "envkey0123456789xyz", ACME_STAGING: "true" },
    );
    expect(raw.control_port).toBe("9443");
    expect(raw.api_key).toBe("envkey0123456789xyz");
    expect(raw.acme_staging).toBe("true");
  });

  it("ignores empty env values", () => {
    const raw = applyEnvOverrides({ hostname: "keep.example.com" }, { HOSTNAME: "" });
    expect(raw.hostname).toBe("keep.example.com");
  });
});
