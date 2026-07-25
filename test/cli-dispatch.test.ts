import { afterEach, describe, expect, it, spyOn } from "bun:test";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { main } from "../src/index.ts";

const originalConfigPath = process.env.PROXY_AGENT_CONFIG;
const dirs: string[] = [];

afterEach(() => {
  if (originalConfigPath === undefined) delete process.env.PROXY_AGENT_CONFIG;
  else process.env.PROXY_AGENT_CONFIG = originalConfigPath;
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

describe("proxy-agent CLI dispatch", () => {
  it("runs ctl commands without starting daemon listeners", async () => {
    const dir = mkdtempSync(join(tmpdir(), "proxy-agent-cli-"));
    dirs.push(dir);
    const configPath = join(dir, "config.json");
    writeFileSync(
      configPath,
      JSON.stringify({
        api_key: "0123456789abcdef0123",
        node_token: "abcdef0123456789abcd",
        hostname: "node1.example.com",
        panel_callback_url: "https://panel.example.com/callback",
        letsencrypt_email: "ops@example.com",
        state_dir: dir,
      }),
    );
    process.env.PROXY_AGENT_CONFIG = configPath;

    const output = spyOn(console, "log").mockImplementation(() => {});
    try {
      await main(["ctl", "state"]);
      expect(output).toHaveBeenCalled();
    } finally {
      output.mockRestore();
    }
  });
});
