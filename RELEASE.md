# Release & versioning

The installer downloads a **compiled binary** from a URL and verifies its
SHA256. This document describes how those artifacts are produced and named so
the installer can consume them.

## Version source of truth

The version lives in two places that MUST match (the build script enforces it):

- `src/version.ts` — compiled into the binary; surfaced via `--version`,
  `GET /v1/health`, and every status callback.
- `package.json` `"version"`.

To cut a release, bump both to the same value (e.g. `0.2.0`), commit, and tag:

```bash
git tag v0.2.0
git push --tags
```

## Building artifacts

```bash
bun run build      # == bash scripts/build.sh
```

This produces, in `dist/`, for each target:

```
proxy-agent-<version>-linux-x64            proxy-agent-<version>-linux-arm64
proxy-agent-<version>-linux-x64.sha256     proxy-agent-<version>-linux-arm64.sha256
```

- Targets: `bun-linux-x64` and `bun-linux-arm64` via `bun build --compile`.
- Each `.sha256` is a standard `sha256sum` line (`<hash>  <filename>`).
- The build is deterministic in naming; artifact bytes depend on the pinned Bun
  version (see `engines.bun` in `package.json`). Pin Bun in CI for reproducible
  hashes.

## Publishing

Upload the four files to your artifact host (GitHub Releases, S3, etc.). The
installer needs two URLs per host architecture:

- `BINARY_URL` → the binary
- `BINARY_SHA256` (hex) **or** `CHECKSUM_URL` → the `.sha256` file

Example install command the panel hands operators (x64 host):

```bash
sudo BINARY_URL=https://dl.example.com/proxy-agent-0.2.0-linux-x64 \
     CHECKSUM_URL=https://dl.example.com/proxy-agent-0.2.0-linux-x64.sha256 \
     API_KEY=... HOSTNAME=node1.example.com \
     PANEL_CALLBACK_URL=https://panel.example.com/api/agent/callback \
     NODE_TOKEN=... LETSENCRYPT_EMAIL=ops@example.com \
     bash install.sh
```

## Upgrades

`install.sh` is idempotent and upgrades in place: point it at the new
`BINARY_URL`/checksum and re-run. It atomically replaces `/usr/local/bin/proxy-agent`
and restarts the service. Persisted state under `state_dir` (certs + route
state) is untouched, so routes resume without re-issuing certificates.
